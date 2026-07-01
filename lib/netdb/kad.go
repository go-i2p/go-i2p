package netdb

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/go-i2p/go-i2p/lib/util/logutil"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// LookupTransport defines the interface for sending DatabaseLookup messages
// and receiving responses. This enables the KademliaResolver to perform
// network-based DHT lookups.
type LookupTransport interface {
	// SendDatabaseLookup sends a DatabaseLookup message to a peer and waits for a response.
	// Returns the response (either DatabaseStore or DatabaseSearchReply data) or an error.
	// The timeout parameter specifies how long to wait for a response.
	SendDatabaseLookup(ctx context.Context, peerRI router_info.RouterInfo, lookup *i2np.DatabaseLookup) ([]byte, int, error)
}

// LookupResponseHandler handles incoming DatabaseStore and DatabaseSearchReply messages
// for pending lookups. It correlates responses with outstanding requests using message IDs.
type LookupResponseHandler struct {
	pending map[int]chan lookupResponse // maps message ID to response channel
	mu      sync.Mutex
}

// lookupResponse holds the response data from a DatabaseLookup request
type lookupResponse struct {
	msgType int    // I2NP message type (DatabaseStore or DatabaseSearchReply)
	data    []byte // Raw message data
}

// NewLookupResponseHandler creates a new handler for lookup responses
func NewLookupResponseHandler() *LookupResponseHandler {
	return &LookupResponseHandler{
		pending: make(map[int]chan lookupResponse),
	}
}

// RegisterPending registers a pending lookup with the given message ID
func (h *LookupResponseHandler) RegisterPending(messageID int) chan lookupResponse {
	h.mu.Lock()
	defer h.mu.Unlock()
	ch := make(chan lookupResponse, 1)
	h.pending[messageID] = ch
	return ch
}

// UnregisterPending removes a pending lookup registration
func (h *LookupResponseHandler) UnregisterPending(messageID int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if ch, ok := h.pending[messageID]; ok {
		close(ch)
		delete(h.pending, messageID)
	}
}

// HandleResponse delivers a response to the waiting lookup if one exists
func (h *LookupResponseHandler) HandleResponse(messageID, msgType int, data []byte) bool {
	h.mu.Lock()
	ch, ok := h.pending[messageID]
	if ok {
		delete(h.pending, messageID)
	}
	h.mu.Unlock()

	if !ok {
		return false
	}

	select {
	case ch <- lookupResponse{msgType: msgType, data: data}:
		return true
	default:
		return false
	}
}

// KademliaResolver resolves router infos with recursive kademlia lookup.
type KademliaResolver struct {
	// netdb to store result into
	NetworkDatabase
	// what tunnel pool to use when doing lookup
	// if nil the lookup will be done directly
	pool *tunnel.Pool
	// mu protects transport and ourHash which may be set after construction
	// via SetTransport / SetOurHash while queryPeer reads them concurrently.
	mu sync.RWMutex
	// transport for sending lookup messages (optional)
	transport LookupTransport
	// our router hash for constructing lookup messages
	ourHash common.Hash
	// response handler for correlating responses
	responseHandler *LookupResponseHandler
	// exploration marks this resolver as performing NetDB exploration. When set,
	// queryPeer sends DatabaseLookup messages with the exploration lookup type so
	// floodfills return previously-unknown routers (matching i2pd's exploratory
	// lookups) instead of treating the request as a direct RouterInfo lookup.
	// Guarded by mu like transport/ourHash.
	exploration bool
}

// peerDistance represents a peer with its calculated XOR distance
type peerDistance struct {
	hash     common.Hash
	distance []byte
}

// Lookup performs a Kademlia-based iterative lookup for the RouterInfo identified by the given hash,
// trying the local NetDB first and querying progressively closer peers until the timeout expires.
func (kr *KademliaResolver) Lookup(h common.Hash, timeout time.Duration) (*router_info.RouterInfo, error) {
	log.WithFields(logger.Fields{
		"at":      "(KademliaResolver) Lookup",
		"reason":  "starting kademlia lookup",
		"hash":    logutil.HashPrefix(h),
		"timeout": timeout,
	}).Debug("starting Kademlia lookup")

	// Create a context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Try local lookup first
	if ri := kr.attemptLocalLookup(h); ri != nil {
		return ri, nil
	}

	// Validate remote lookup capability
	if err := kr.validateRemoteLookupCapability(); err != nil {
		return nil, err
	}

	// Set up channels for the result and errors
	resultChan := make(chan *router_info.RouterInfo, 1)
	errChan := make(chan error, 1)

	// Start the remote lookup process
	kr.performRemoteLookup(ctx, h, timeout, resultChan, errChan)

	// Wait for result, error, or timeout
	return kr.collectLookupResult(resultChan, errChan, ctx, timeout)
}

// attemptLocalLookup tries to find the RouterInfo locally first.
func (kr *KademliaResolver) attemptLocalLookup(h common.Hash) *router_info.RouterInfo {
	ri, ok := kr.receiveRouterInfo(h)
	if !ok {
		return nil
	}

	if !kr.isRouterInfoUsable(ri, h) {
		return nil
	}

	log.WithFields(logger.Fields{
		"at":     "(KademliaResolver) attemptLocalLookup",
		"reason": "local cache hit",
		"hash":   logutil.HashPrefix(h),
	}).Debug("routerInfo found locally")
	return &ri
}

// receiveRouterInfo fetches a RouterInfo from the network database channel.
// Returns the RouterInfo and true on success, or a zero-value and false if
// the channel closed without delivering a result.
func (kr *KademliaResolver) receiveRouterInfo(h common.Hash) (router_info.RouterInfo, bool) {
	riChan := kr.NetworkDatabase.GetRouterInfo(h)
	ri, ok := <-riChan
	if !ok {
		log.WithFields(logger.Fields{
			"at":     "(KademliaResolver) attemptLocalLookup",
			"reason": "channel closed without result",
			"hash":   logutil.HashPrefix(h),
		}).Debug("channel closed, no RouterInfo available")
	}
	return ri, ok
}

// isRouterInfoUsable checks that a locally cached RouterInfo has a valid
// identity hash and is not stale (older than RouterInfoMaxAge).
func (kr *KademliaResolver) isRouterInfoUsable(ri router_info.RouterInfo, h common.Hash) bool {
	var emptyHash common.Hash
	identHash, err := ri.IdentHash()
	if err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"at":     "(KademliaResolver) attemptLocalLookup",
			"reason": "failed to extract router hash",
			"hash":   logutil.HashPrefix(h),
		}).Debug("failed to get router hash from local lookup")
		return false
	}
	if identHash == emptyHash {
		return false
	}

	return !kr.isRouterInfoStale(ri, h)
}

// isRouterInfoStale returns true if the RouterInfo was published longer ago
// than RouterInfoMaxAge, indicating the entry may reference rotated keys or
// changed addresses.
func (kr *KademliaResolver) isRouterInfoStale(ri router_info.RouterInfo, h common.Hash) bool {
	if published := ri.Published(); published != nil && !published.Time().IsZero() {
		age := time.Since(published.Time())
		if age > RouterInfoMaxAge {
			log.WithFields(logger.Fields{
				"at":     "(KademliaResolver) attemptLocalLookup",
				"reason": "stale RouterInfo",
				"hash":   logutil.HashPrefix(h),
				"age":    age.Round(time.Second),
			}).Debug("local RouterInfo is stale, will attempt remote lookup")
			return true
		}
	}
	return false
}

// validateRemoteLookupCapability checks if remote lookups are possible.
func (kr *KademliaResolver) validateRemoteLookupCapability() error {
	kr.mu.RLock()
	hasTransport := kr.transport != nil
	hasPool := kr.pool != nil
	kr.mu.RUnlock()

	if !hasTransport {
		log.WithFields(logger.Fields{
			"at":      "validateRemoteLookupCapability",
			"reason":  "lookup transport not configured",
			"hasPool": hasPool,
		}).Error("Cannot perform remote lookup")
		return oops.Errorf("lookup transport required for remote lookups")
	}

	// The lookup transport is the actual network dependency for iterative
	// lookups; a tunnel pool is optional and may be nil for direct lookups.
	return nil
}

const (
	// MaxIterativeLookupHops is the maximum number of iterative lookup rounds.
	// Each round queries the closest unqueried peers and follows suggestions.
	MaxIterativeLookupHops = 5

	// MaxConcurrentQueries is the number of peers queried in parallel per round.
	MaxConcurrentQueries = 3

	// peerResolutionTimeout bounds the on-demand lookup used to resolve a
	// suggested peer's RouterInfo before querying it for the original target.
	peerResolutionTimeout = 5 * time.Second
)

// performRemoteLookup executes an iterative Kademlia lookup in a goroutine.
// It queries the closest known peers, follows peer suggestions from
// DatabaseSearchReply messages, and repeats up to MaxIterativeLookupHops rounds.
func (kr *KademliaResolver) performRemoteLookup(ctx context.Context, h common.Hash, timeout time.Duration, resultChan chan *router_info.RouterInfo, errChan chan error) {
	log.WithFields(logger.Fields{
		"at":       "performRemoteLookup",
		"hash":     logutil.HashPrefixPlain(h),
		"timeout":  timeout,
		"max_hops": MaxIterativeLookupHops,
	}).Debug("Starting iterative Kademlia lookup")
	go func() {
		ri, err := kr.iterativeLookup(ctx, h)
		if ri != nil {
			resultChan <- ri
		} else if err != nil {
			errChan <- err
		} else {
			errChan <- oops.Errorf("router info not found in kademlia lookup")
		}
	}()
}

// iterativeQueryResult holds the result from querying a single peer.
type iterativeQueryResult struct {
	ri          *router_info.RouterInfo
	suggestions []common.Hash
	err         error
}

// LookupState tracks the queried and unqueried peers for an iterative lookup.
type LookupState struct {
	queried   map[common.Hash]bool
	unqueried map[common.Hash]bool
}

func newLookupState() *LookupState {
	return &LookupState{
		queried:   make(map[common.Hash]bool),
		unqueried: make(map[common.Hash]bool),
	}
}

func (s *LookupState) addUnqueried(peer common.Hash) {
	s.unqueried[peer] = true
}

func (s *LookupState) markQueried(peer common.Hash) {
	s.queried[peer] = true
	delete(s.unqueried, peer)
}

func (s *LookupState) hasBeenQueried(peer common.Hash) bool {
	return s.queried[peer]
}

func (s *LookupState) hasPendingPeers() bool {
	return len(s.unqueried) > 0
}

// iterativeLookup performs an iterative Kademlia lookup following peer suggestions.
// It maintains sets of queried and unqueried peers, querying the closest unqueried
// peers each round and adding suggestions from DatabaseSearchReply responses.
func (kr *KademliaResolver) iterativeLookup(ctx context.Context, target common.Hash) (*router_info.RouterInfo, error) {
	return kr.iterativeLookupWithOptions(ctx, target, true)
}

func (kr *KademliaResolver) iterativeLookupWithOptions(ctx context.Context, target common.Hash, resolveSuggestedPeers bool) (*router_info.RouterInfo, error) {
	state, err := kr.initializeLookupState(target)
	if err != nil {
		return nil, err
	}

	return kr.executeLookupRounds(ctx, target, state, resolveSuggestedPeers)
}

// initializeLookupState prepares the initial state for an iterative lookup by finding
// the closest known peers to the target hash.
func (kr *KademliaResolver) initializeLookupState(target common.Hash) (*LookupState, error) {
	state := newLookupState()

	closestPeers := kr.findClosestPeers(target)
	if len(closestPeers) == 0 {
		return nil, oops.Errorf("insufficient peers available for lookup")
	}

	for _, p := range closestPeers {
		state.addUnqueried(p)
	}

	return state, nil
}

// executeLookupRounds performs iterative Kademlia lookup rounds until a RouterInfo is found,
// the search is exhausted, or the maximum hop count is reached.
func (kr *KademliaResolver) executeLookupRounds(ctx context.Context, target common.Hash, state *LookupState, resolveSuggestedPeers bool) (*router_info.RouterInfo, error) {
	for hop := 0; hop < MaxIterativeLookupHops; hop++ {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		ri, exhausted := kr.processLookupRound(ctx, target, state, hop, resolveSuggestedPeers)
		if ri != nil {
			return ri, nil
		}
		if exhausted {
			break
		}
	}

	return nil, oops.Errorf("router info not found after %d iterative hops", MaxIterativeLookupHops)
}

// processLookupRound executes a single round of the iterative Kademlia lookup.
// It selects the closest unqueried peers, queries them in parallel, and merges
// suggestions into the unqueried set. Returns a non-nil RouterInfo if found,
// or true for exhausted if no unqueried peers remain.
func (kr *KademliaResolver) processLookupRound(ctx context.Context, target common.Hash, state *LookupState, hop int, resolveSuggestedPeers bool) (ri *router_info.RouterInfo, exhausted bool) {
	batch := kr.selectClosestUnqueried(target, state.unqueried, MaxConcurrentQueries)
	if len(batch) == 0 {
		log.WithFields(logger.Fields{
			"at":   "iterativeLookup",
			"hop":  hop,
			"hash": logutil.HashPrefixPlain(target),
		}).Debug("No more unqueried peers, lookup exhausted")
		return nil, true
	}

	log.WithFields(logger.Fields{
		"at":         "iterativeLookup",
		"hop":        hop,
		"batch_size": len(batch),
		"unqueried":  len(state.unqueried),
		"queried":    len(state.queried),
	}).Debug("Starting iterative lookup round")

	results := kr.queryBatchParallel(ctx, batch, target, resolveSuggestedPeers)
	kr.markBatchQueried(batch, state)

	return kr.mergeQueryResults(results, state)
}

// markBatchQueried moves all peers in the batch from the unqueried set to the queried set.
func (kr *KademliaResolver) markBatchQueried(batch []common.Hash, state *LookupState) {
	for _, p := range batch {
		state.markQueried(p)
	}
}

// mergeQueryResults processes query results, returning a RouterInfo if found or merging
// new peer suggestions into the unqueried set for subsequent rounds.
func (kr *KademliaResolver) mergeQueryResults(results []iterativeQueryResult, state *LookupState) (*router_info.RouterInfo, bool) {
	for _, result := range results {
		if result.ri != nil {
			return result.ri, false
		}
		for _, suggestion := range result.suggestions {
			if !state.hasBeenQueried(suggestion) && !state.unqueried[suggestion] {
				state.addUnqueried(suggestion)
			}
		}
	}
	return nil, false
}

// selectClosestUnqueried picks the closest unqueried peers by XOR distance to the target.
func (kr *KademliaResolver) selectClosestUnqueried(target common.Hash, unqueried map[common.Hash]bool, count int) []common.Hash {
	// Convert map keys to slice for the generic helper.
	var peers []common.Hash
	for h := range unqueried {
		peers = append(peers, h)
	}

	// Use the generic helper; Hash items have identity getHash function.
	return selectClosestByDistance(peers, func(h common.Hash) common.Hash { return h }, target, count)
}

// queryBatchParallel queries multiple peers concurrently and collects their results.
func (kr *KademliaResolver) queryBatchParallel(ctx context.Context, peers []common.Hash, target common.Hash, resolveSuggestedPeers bool) []iterativeQueryResult {
	resultsCh := make(chan iterativeQueryResult, len(peers))
	var wg sync.WaitGroup

	for _, peer := range peers {
		wg.Add(1)
		go func(p common.Hash) {
			defer wg.Done()
			ri, err := kr.queryPeer(ctx, p, target, resolveSuggestedPeers)
			result := iterativeQueryResult{ri: ri, err: err}

			// Extract suggestions from SearchReplyError
			var searchReplyErr *SearchReplyError
			if errors.As(err, &searchReplyErr) {
				result.suggestions = searchReplyErr.Suggestions
				log.WithFields(logger.Fields{
					"at":          "queryBatchParallel",
					"peer":        logutil.HashPrefixPlain(p),
					"suggestions": len(searchReplyErr.Suggestions),
				}).Debug("Peer returned suggestions for iterative follow-up")
			}

			resultsCh <- result
		}(peer)
	}

	wg.Wait()
	close(resultsCh)

	results := make([]iterativeQueryResult, 0, len(peers))
	for r := range resultsCh {
		results = append(results, r)
	}
	return results
}

// collectLookupResult waits for and processes the lookup result.
func (kr *KademliaResolver) collectLookupResult(resultChan chan *router_info.RouterInfo, errChan chan error, ctx context.Context, timeout time.Duration) (*router_info.RouterInfo, error) {
	select {
	case result := <-resultChan:
		// Store the result in our local database
		kr.NetworkDatabase.StoreRouterInfo(*result)
		hashStr := "unknown"
		if ih, err := result.IdentHash(); err == nil {
			hashStr = logutil.HashPrefixPlain(ih)
		}
		log.WithFields(logger.Fields{
			"at":   "collectLookupResult",
			"hash": hashStr,
		}).Debug("Kademlia lookup successful, stored RouterInfo")
		return result, nil
	case err := <-errChan:
		log.WithFields(logger.Fields{
			"at": "collectLookupResult",
		}).WithError(err).Error("Kademlia lookup failed")
		return nil, err
	case <-ctx.Done():
		log.WithFields(logger.Fields{
			"at":      "collectLookupResult",
			"timeout": timeout,
		}).Error("Kademlia lookup timed out")
		return nil, oops.Errorf("lookup timed out after %s", timeout)
	}
}

// findClosestPeers returns peers closest to the target hash using XOR distance.
// Per the I2P spec, peer selection for a DHT lookup uses the routing key, not
// the raw target hash: routing_key = SHA256(target || yyyyMMdd_UTC).
func (kr *KademliaResolver) findClosestPeers(target common.Hash) []common.Hash {
	const K = 8 // Standard Kademlia parameter for number of closest peers to return
	rk := RoutingKey(target, time.Now())

	if seeds := kr.selectClosestFloodfillSeeds(rk, K); len(seeds) > 0 {
		return seeds
	}

	// Get all known router infos from the network database
	allRouterInfos := kr.NetworkDatabase.GetAllRouterInfos()
	if len(allRouterInfos) == 0 {
		log.WithFields(logger.Fields{"at": "findClosestPeers"}).Debug("No peers available in network database")
		return []common.Hash{}
	}

	// Calculate XOR distances for all peers using the routing key
	peers := kr.calculatePeerDistances(allRouterInfos, rk)
	if len(peers) == 0 {
		log.WithFields(logger.Fields{"at": "findClosestPeers"}).Debug("No suitable peers found after filtering")
		return []common.Hash{}
	}

	// Sort and select closest peers
	return kr.selectClosestPeers(peers, rk, K)
}

func (kr *KademliaResolver) selectClosestFloodfillSeeds(routingKey common.Hash, count int) []common.Hash {
	floodfills, err := kr.NetworkDatabase.SelectFloodfillRouters(routingKey, count)
	if err != nil || len(floodfills) == 0 {
		return nil
	}

	seeds := make([]common.Hash, 0, len(floodfills))
	for _, ri := range floodfills {
		hash, err := ri.IdentHash()
		if err != nil {
			continue
		}
		seeds = append(seeds, hash)
	}

	if len(seeds) > 0 {
		log.WithFields(logger.Fields{
			"at":    "findClosestPeers",
			"seeds": len(seeds),
		}).Debug("Seeded iterative lookup from floodfill routers")
	}

	return seeds
}

// calculatePeerDistances calculates XOR distances for all router infos.
func (kr *KademliaResolver) calculatePeerDistances(allRouterInfos []router_info.RouterInfo, target common.Hash) []peerDistance {
	peers := make([]peerDistance, 0, len(allRouterInfos))

	for _, ri := range allRouterInfos {
		peerHash, err := ri.IdentHash()
		if err != nil {
			log.WithError(err).Warn("Failed to get peer hash for distance calculation, skipping")
			continue
		}

		// Skip self or target if it's in our database
		if peerHash == target {
			continue
		}

		// Calculate XOR distance between target and peer
		distance := CalculateXORDistance(target, peerHash)

		peers = append(peers, peerDistance{
			hash:     peerHash,
			distance: distance,
		})
	}

	return peers
}

// selectClosestPeers sorts peers by distance and returns the K closest ones.
func (kr *KademliaResolver) selectClosestPeers(peers []peerDistance, target common.Hash, K int) []common.Hash {
	// Sort peers by XOR distance (closest first)
	sort.Slice(peers, func(i, j int) bool {
		return CompareXORDistances(peers[i].distance, peers[j].distance)
	})

	// Take up to K closest peers
	count := K
	if len(peers) < count {
		count = len(peers)
	}

	result := make([]common.Hash, count)
	for i := 0; i < count; i++ {
		result[i] = peers[i].hash
	}

	log.WithFields(logger.Fields{
		"target":        target,
		"total_peers":   len(peers),
		"closest_peers": len(result),
	}).Debug("Found closest peers by XOR distance")

	return result
}

// queryPeer sends a DatabaseLookup request to a specific peer and waits for a response.
// Returns the RouterInfo if found, or an error if the lookup failed or the peer doesn't have it.
func (kr *KademliaResolver) queryPeer(ctx context.Context, peer, target common.Hash, resolveSuggestedPeers bool) (*router_info.RouterInfo, error) {
	log.WithFields(logger.Fields{
		"at":     "queryPeer",
		"peer":   logutil.HashPrefixPlain(peer),
		"target": logutil.HashPrefixPlain(target),
	}).Debug("Querying peer for RouterInfo")

	// Snapshot transport, ourHash and exploration under read lock to avoid races
	// with SetTransport / SetOurHash / SetExploration called from another goroutine.
	kr.mu.RLock()
	transport := kr.transport
	ourHash := kr.ourHash
	exploration := kr.exploration
	kr.mu.RUnlock()

	// Check if transport is configured
	if transport == nil {
		log.WithFields(logger.Fields{
			"at":     "queryPeer",
			"peer":   logutil.HashPrefixPlain(peer),
			"target": logutil.HashPrefixPlain(target),
			"reason": "no_transport",
		}).Debug("Transport not configured, using local-only lookup")
		return nil, oops.Errorf("transport not configured for remote lookups")
	}

	// Get the peer's RouterInfo from our database
	peerRI, err := kr.resolvePeerRouterInfo(ctx, peer, resolveSuggestedPeers)
	if err != nil {
		return nil, err
	}

	// Determine which hash to use as "from" in the lookup
	fromHash := ourHash
	var emptyHash common.Hash
	if fromHash == emptyHash {
		return nil, oops.Errorf("cannot query peer: our router hash is not set")
	}

	// Choose the lookup type: exploration lookups ask floodfills for routers we
	// don't yet know about, while normal lookups use RouterInfo semantics so peers
	// may return the requested RI directly when they have it (with search-reply
	// fallback otherwise).
	lookupType := i2np.DatabaseLookupFlagTypeRI
	if exploration {
		lookupType = i2np.DatabaseLookupFlagTypeExploration
	}
	lookup := i2np.NewDatabaseLookup(target, fromHash, lookupType, nil)

	// Send the lookup and wait for response
	responseData, msgType, err := transport.SendDatabaseLookup(ctx, *peerRI, lookup)
	if err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"at":     "queryPeer",
			"peer":   logutil.HashPrefixPlain(peer),
			"target": logutil.HashPrefixPlain(target),
		}).Debug("DatabaseLookup failed")
		return nil, oops.Errorf("lookup failed: %w", err)
	}

	// Process the response based on message type
	return kr.processLookupResponse(responseData, msgType, target)
}

func (kr *KademliaResolver) resolvePeerRouterInfo(ctx context.Context, peerHash common.Hash, allowNetworkResolution bool) (*router_info.RouterInfo, error) {
	if peerRI := kr.getPeerRouterInfo(peerHash); peerRI != nil {
		return peerRI, nil
	}
	if !allowNetworkResolution {
		return nil, oops.Errorf("peer %x not found in local database", peerHash[:8])
	}

	resolveCtx, cancel := withClampedTimeout(ctx, peerResolutionTimeout)
	defer cancel()

	peerRI, err := kr.iterativeLookupWithOptions(resolveCtx, peerHash, false)
	if err != nil {
		return nil, oops.Errorf("peer %x not found in local database and resolution failed: %w", peerHash[:8], err)
	}
	return peerRI, nil
}

func withClampedTimeout(ctx context.Context, max time.Duration) (context.Context, context.CancelFunc) {
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return context.WithCancel(ctx)
		}
		if remaining < max {
			return context.WithTimeout(ctx, remaining)
		}
	}
	return context.WithTimeout(ctx, max)
}

// getPeerRouterInfo retrieves a peer's RouterInfo from the local database.
func (kr *KademliaResolver) getPeerRouterInfo(peerHash common.Hash) *router_info.RouterInfo {
	riChan := kr.NetworkDatabase.GetRouterInfo(peerHash)
	if riChan == nil {
		return nil
	}

	ri, ok := <-riChan
	if !ok {
		return nil
	}

	// Verify the RouterInfo is valid
	identHash, err := ri.IdentHash()
	if err != nil {
		return nil
	}

	var emptyHash common.Hash
	if identHash == emptyHash {
		return nil
	}

	return &ri
}

// processLookupResponse handles the response from a DatabaseLookup request.
// It parses either a DatabaseStore (success) or DatabaseSearchReply (not found, try these peers).
func (kr *KademliaResolver) processLookupResponse(data []byte, msgType int, targetHash common.Hash) (*router_info.RouterInfo, error) {
	switch msgType {
	case i2np.I2NPMessageTypeDatabaseStore:
		return kr.processDatabaseStoreResponse(data, targetHash)

	case i2np.I2NPMessageTypeDatabaseSearchReply:
		return kr.processDatabaseSearchReplyResponse(data, targetHash)

	default:
		return nil, oops.Errorf("unexpected response type: %d", msgType)
	}
}

// processDatabaseStoreResponse extracts a RouterInfo from a DatabaseStore message.
func (kr *KademliaResolver) processDatabaseStoreResponse(data []byte, targetHash common.Hash) (*router_info.RouterInfo, error) {
	dbStore, err := parseDatabaseStore(data, targetHash)
	if err != nil {
		return nil, err
	}

	decompressed, err := decompressRouterInfoPayload(dbStore.GetStoreData())
	if err != nil {
		return nil, err
	}

	ri, _, err := router_info.ReadRouterInfo(decompressed)
	if err != nil {
		return nil, oops.Errorf("failed to parse RouterInfo: %w", err)
	}

	kr.NetworkDatabase.StoreRouterInfo(ri)

	log.WithFields(logger.Fields{
		"at":     "processDatabaseStoreResponse",
		"target": logutil.HashPrefixPlain(targetHash),
	}).Debug("Successfully received RouterInfo from peer")

	return &ri, nil
}

// parseDatabaseStore unmarshals and validates a DatabaseStore message against
// the expected target hash and ensures it contains a RouterInfo.
func parseDatabaseStore(data []byte, targetHash common.Hash) (*i2np.DatabaseStore, error) {
	var dbStore i2np.DatabaseStore
	if err := dbStore.UnmarshalBinary(data); err != nil {
		return nil, oops.Errorf("failed to parse DatabaseStore: %w", err)
	}

	if dbStore.Key != targetHash {
		log.WithFields(logger.Fields{
			"at":       "processDatabaseStoreResponse",
			"expected": logutil.HashPrefixPlain(targetHash),
			"got":      logutil.HashPrefix(dbStore.Key),
		}).Warn("DatabaseStore key mismatch")
		return nil, oops.Errorf("key mismatch in response")
	}

	if !dbStore.IsRouterInfo() {
		return nil, oops.Errorf("response is not a RouterInfo (type=%d)", dbStore.StoreType)
	}

	return &dbStore, nil
}

// decompressRouterInfoPayload extracts and decompresses the gzip-compressed
// RouterInfo from a DatabaseStore payload. The payload format is a 2-byte
// big-endian compressed length followed by the compressed data.
func decompressRouterInfoPayload(storeData []byte) ([]byte, error) {
	if len(storeData) < 2 {
		return nil, oops.Errorf("RouterInfo data too short")
	}

	compressedLen := int(binary.BigEndian.Uint16(storeData[:2]))
	if len(storeData) < 2+compressedLen {
		return nil, oops.Errorf("RouterInfo data truncated: need %d bytes, have %d", 2+compressedLen, len(storeData))
	}

	compressedData := storeData[2 : 2+compressedLen]

	decompressed, err := gzipDecompress(compressedData)
	if err != nil {
		return nil, oops.Errorf("failed to decompress RouterInfo: %w", err)
	}

	log.WithFields(logger.Fields{
		"at":               "processDatabaseStoreResponse",
		"compressed_len":   compressedLen,
		"decompressed_len": len(decompressed),
	}).Debug("Decompressed RouterInfo from DatabaseStore")

	return decompressed, nil
}

// SearchReplyError is returned when a peer responds with a DatabaseSearchReply
// instead of a DatabaseStore. It contains the suggested peer hashes for iterative lookup.
type SearchReplyError struct {
	Suggestions []common.Hash
}

// Error returns a human-readable description of the SearchReplyError, including the number of suggested alternative peers.
func (e *SearchReplyError) Error() string {
	return fmt.Sprintf("peer did not have target, suggested %d alternatives", len(e.Suggestions))
}

// processDatabaseSearchReplyResponse handles a DatabaseSearchReply, which indicates
// the peer doesn't have the target but suggests other peers to try.
// Returns a SearchReplyError containing the suggested peer hashes for iterative lookup.
func (kr *KademliaResolver) processDatabaseSearchReplyResponse(data []byte, targetHash common.Hash) (*router_info.RouterInfo, error) {
	searchReply, err := i2np.ReadDatabaseSearchReply(data)
	if err != nil {
		return nil, oops.Errorf("failed to parse DatabaseSearchReply: %w", err)
	}

	if len(searchReply.PeerHashes) > 0 {
		log.WithFields(logger.Fields{
			"at":          "processDatabaseSearchReplyResponse",
			"target":      logutil.HashPrefixPlain(targetHash),
			"from":        logutil.HashPrefix(searchReply.From),
			"suggestions": len(searchReply.PeerHashes),
		}).Debug("Peer returned suggestions for iterative lookup")
	}

	return nil, &SearchReplyError{Suggestions: searchReply.PeerHashes}
}
