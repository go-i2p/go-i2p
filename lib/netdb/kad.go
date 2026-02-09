package netdb

import (
	"context"
	"encoding/binary"
	"fmt"
	"sort"
	"sync"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/go-i2p/logger"
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
func (h *LookupResponseHandler) HandleResponse(messageID int, msgType int, data []byte) bool {
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

// resolves router infos with recursive kademlia lookup
type KademliaResolver struct {
	// netdb to store result into
	NetworkDatabase
	// what tunnel pool to use when doing lookup
	// if nil the lookup will be done directly
	pool *tunnel.Pool
	// transport for sending lookup messages (optional)
	transport LookupTransport
	// our router hash for constructing lookup messages
	ourHash common.Hash
	// response handler for correlating responses
	responseHandler *LookupResponseHandler
}

// peerDistance represents a peer with its calculated XOR distance
type peerDistance struct {
	hash     common.Hash
	distance []byte
}

func (kr *KademliaResolver) Lookup(h common.Hash, timeout time.Duration) (*router_info.RouterInfo, error) {
	log.WithFields(logger.Fields{
		"at":      "(KademliaResolver) Lookup",
		"reason":  "starting kademlia lookup",
		"hash":    fmt.Sprintf("%x...", h[:8]),
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
	riChan := kr.NetworkDatabase.GetRouterInfo(h)
	ri, ok := <-riChan
	if !ok {
		log.WithFields(logger.Fields{
			"at":     "(KademliaResolver) attemptLocalLookup",
			"reason": "channel closed without result",
			"hash":   fmt.Sprintf("%x...", h[:8]),
		}).Debug("channel closed, no RouterInfo available")
		return nil
	}
	// Check if the RouterInfo is valid by comparing with an empty hash
	var emptyHash common.Hash
	identHash, err := ri.IdentHash()
	if err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"at":     "(KademliaResolver) attemptLocalLookup",
			"reason": "failed to extract router hash",
			"hash":   fmt.Sprintf("%x...", h[:8]),
		}).Debug("failed to get router hash from local lookup")
		return nil
	}
	if identHash != emptyHash {
		log.WithFields(logger.Fields{
			"at":     "(KademliaResolver) attemptLocalLookup",
			"reason": "local cache hit",
			"hash":   fmt.Sprintf("%x...", h[:8]),
		}).Debug("routerInfo found locally")
		return &ri
	}
	return nil
}

// validateRemoteLookupCapability checks if remote lookups are possible.
func (kr *KademliaResolver) validateRemoteLookupCapability() error {
	if kr.pool == nil {
		log.WithFields(logger.Fields{
			"at":     "validateRemoteLookupCapability",
			"reason": "tunnel pool not configured",
		}).Error("Cannot perform remote lookup")
		return fmt.Errorf("tunnel pool required for remote lookups")
	}
	return nil
}

// performRemoteLookup starts the Kademlia lookup process in a goroutine.
func (kr *KademliaResolver) performRemoteLookup(ctx context.Context, h common.Hash, timeout time.Duration, resultChan chan *router_info.RouterInfo, errChan chan error) {
	log.WithFields(logger.Fields{
		"at":      "performRemoteLookup",
		"hash":    fmt.Sprintf("%x", h[:8]),
		"timeout": timeout,
	}).Debug("Starting remote Kademlia lookup")
	go func() {
		// Find the closest peers we know to the target hash
		closestPeers := kr.findClosestPeers(h)
		if len(closestPeers) == 0 {
			log.WithFields(logger.Fields{
				"at":     "performRemoteLookup",
				"hash":   fmt.Sprintf("%x", h[:8]),
				"reason": "no peers available",
			}).Error("Kademlia lookup failed")
			errChan <- fmt.Errorf("insufficient peers available for lookup")
			return
		}

		log.WithFields(logger.Fields{
			"at":         "performRemoteLookup",
			"hash":       fmt.Sprintf("%x", h[:8]),
			"peer_count": len(closestPeers),
		}).Debug("Found closest peers for lookup")

		// Query each closest peer in parallel
		kr.queryClosestPeers(ctx, closestPeers, h, resultChan)

		// Allow some time for queries to complete, but eventually give up
		kr.handleLookupTimeout(ctx, timeout, errChan)
	}()
}

// queryClosestPeers queries each of the closest peers in parallel.
func (kr *KademliaResolver) queryClosestPeers(ctx context.Context, peers []common.Hash, target common.Hash, resultChan chan *router_info.RouterInfo) {
	for _, peer := range peers {
		go func(p common.Hash) {
			ri, err := kr.queryPeer(ctx, p, target)
			if err != nil {
				log.WithFields(logger.Fields{
					"peer":  p,
					"error": err,
				}).Debug("Peer query failed")
				return
			}

			if ri != nil {
				resultChan <- ri
			}
		}(peer)
	}
}

// handleLookupTimeout manages the timeout for the lookup operation.
func (kr *KademliaResolver) handleLookupTimeout(ctx context.Context, timeout time.Duration, errChan chan error) {
	select {
	case <-time.After(timeout - time.Second): // Leave 1s buffer for the main select
		errChan <- fmt.Errorf("router info not found in kademlia lookup")
	case <-ctx.Done():
		// Context was already canceled, main select will handle it
	}
}

// collectLookupResult waits for and processes the lookup result.
func (kr *KademliaResolver) collectLookupResult(resultChan chan *router_info.RouterInfo, errChan chan error, ctx context.Context, timeout time.Duration) (*router_info.RouterInfo, error) {
	select {
	case result := <-resultChan:
		// Store the result in our local database
		kr.NetworkDatabase.StoreRouterInfo(*result)
		log.WithFields(logger.Fields{
			"at":   "collectLookupResult",
			"hash": fmt.Sprintf("%x", result),
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
		return nil, fmt.Errorf("lookup timed out after %s", timeout)
	}
}

// findClosestPeers returns peers closest to the target hash using XOR distance
func (kr *KademliaResolver) findClosestPeers(target common.Hash) []common.Hash {
	const K = 8 // Standard Kademlia parameter for number of closest peers to return

	// Get all known router infos from the network database
	allRouterInfos := kr.NetworkDatabase.GetAllRouterInfos()
	if len(allRouterInfos) == 0 {
		log.Debug("No peers available in network database")
		return []common.Hash{}
	}

	// Calculate XOR distances for all peers
	peers := kr.calculatePeerDistances(allRouterInfos, target)
	if len(peers) == 0 {
		log.Debug("No suitable peers found after filtering")
		return []common.Hash{}
	}

	// Sort and select closest peers
	return kr.selectClosestPeers(peers, target, K)
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
		distance := kr.calculateXORDistance(target, peerHash)

		peers = append(peers, peerDistance{
			hash:     peerHash,
			distance: distance,
		})
	}

	return peers
}

// calculateXORDistance calculates the XOR distance between two hashes.
func (kr *KademliaResolver) calculateXORDistance(target, peer common.Hash) []byte {
	distance := make([]byte, len(target))
	for i := 0; i < len(target); i++ {
		distance[i] = target[i] ^ peer[i]
	}
	return distance
}

// selectClosestPeers sorts peers by distance and returns the K closest ones.
func (kr *KademliaResolver) selectClosestPeers(peers []peerDistance, target common.Hash, K int) []common.Hash {
	// Sort peers by XOR distance (closest first)
	sort.Slice(peers, func(i, j int) bool {
		return kr.compareDistances(peers[i].distance, peers[j].distance)
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

// compareDistances compares two distance byte arrays (big endian comparison).
func (kr *KademliaResolver) compareDistances(dist1, dist2 []byte) bool {
	for k := 0; k < len(dist1); k++ {
		if dist1[k] < dist2[k] {
			return true
		}
		if dist1[k] > dist2[k] {
			return false
		}
	}
	return false // Equal distances
}

// queryPeer sends a DatabaseLookup request to a specific peer and waits for a response.
// Returns the RouterInfo if found, or an error if the lookup failed or the peer doesn't have it.
func (kr *KademliaResolver) queryPeer(ctx context.Context, peer, target common.Hash) (*router_info.RouterInfo, error) {
	log.WithFields(logger.Fields{
		"at":     "queryPeer",
		"peer":   fmt.Sprintf("%x", peer[:8]),
		"target": fmt.Sprintf("%x", target[:8]),
	}).Debug("Querying peer for RouterInfo")

	// Check if transport is configured
	if kr.transport == nil {
		log.WithFields(logger.Fields{
			"at":     "queryPeer",
			"peer":   fmt.Sprintf("%x", peer[:8]),
			"target": fmt.Sprintf("%x", target[:8]),
			"reason": "no_transport",
		}).Debug("Transport not configured, using local-only lookup")
		return nil, fmt.Errorf("transport not configured for remote lookups")
	}

	// Get the peer's RouterInfo from our database
	peerRI := kr.getPeerRouterInfo(peer)
	if peerRI == nil {
		return nil, fmt.Errorf("peer %x not found in local database", peer[:8])
	}

	// Determine which hash to use as "from" in the lookup
	fromHash := kr.ourHash
	var emptyHash common.Hash
	if fromHash == emptyHash {
		// If ourHash is not set, use the peer hash as a fallback
		// This is not ideal but allows basic functionality
		log.WithFields(logger.Fields{
			"at":     "queryPeer",
			"reason": "our_hash_not_set",
		}).Warn("Our router hash not set, using fallback")
		fromHash = peer
	}

	// Create the DatabaseLookup message for RouterInfo lookup
	lookup := i2np.NewDatabaseLookup(target, fromHash, i2np.DatabaseLookupFlagTypeRI, nil)

	// Send the lookup and wait for response
	responseData, msgType, err := kr.transport.SendDatabaseLookup(ctx, *peerRI, lookup)
	if err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"at":     "queryPeer",
			"peer":   fmt.Sprintf("%x", peer[:8]),
			"target": fmt.Sprintf("%x", target[:8]),
		}).Debug("DatabaseLookup failed")
		return nil, fmt.Errorf("lookup failed: %w", err)
	}

	// Process the response based on message type
	return kr.processLookupResponse(responseData, msgType, target)
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
	case i2np.I2NP_MESSAGE_TYPE_DATABASE_STORE:
		return kr.processDatabaseStoreResponse(data, targetHash)

	case i2np.I2NP_MESSAGE_TYPE_DATABASE_SEARCH_REPLY:
		return kr.processDatabaseSearchReplyResponse(data, targetHash)

	default:
		return nil, fmt.Errorf("unexpected response type: %d", msgType)
	}
}

// processDatabaseStoreResponse extracts a RouterInfo from a DatabaseStore message.
func (kr *KademliaResolver) processDatabaseStoreResponse(data []byte, targetHash common.Hash) (*router_info.RouterInfo, error) {
	var dbStore i2np.DatabaseStore
	if err := dbStore.UnmarshalBinary(data); err != nil {
		return nil, fmt.Errorf("failed to parse DatabaseStore: %w", err)
	}

	// Verify the key matches our target
	if dbStore.Key != targetHash {
		log.WithFields(logger.Fields{
			"at":       "processDatabaseStoreResponse",
			"expected": fmt.Sprintf("%x", targetHash[:8]),
			"got":      fmt.Sprintf("%x", dbStore.Key[:8]),
		}).Warn("DatabaseStore key mismatch")
		return nil, fmt.Errorf("key mismatch in response")
	}

	// Check if this is a RouterInfo
	if !dbStore.IsRouterInfo() {
		return nil, fmt.Errorf("response is not a RouterInfo (type=%d)", dbStore.StoreType)
	}

	// Parse the RouterInfo from the data
	// For RouterInfo, the data is a 2-byte length followed by gzip-compressed RouterInfo
	storeData := dbStore.GetStoreData()
	if len(storeData) < 2 {
		return nil, fmt.Errorf("RouterInfo data too short")
	}

	// First 2 bytes are the compressed length
	compressedLen := int(binary.BigEndian.Uint16(storeData[:2]))
	if len(storeData) < 2+compressedLen {
		return nil, fmt.Errorf("RouterInfo data truncated")
	}

	// Parse the RouterInfo (it handles decompression internally)
	ri, _, err := router_info.ReadRouterInfo(storeData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse RouterInfo: %w", err)
	}

	// Store in our database
	kr.NetworkDatabase.StoreRouterInfo(ri)

	log.WithFields(logger.Fields{
		"at":     "processDatabaseStoreResponse",
		"target": fmt.Sprintf("%x", targetHash[:8]),
	}).Debug("Successfully received RouterInfo from peer")

	return &ri, nil
}

// processDatabaseSearchReplyResponse handles a DatabaseSearchReply, which indicates
// the peer doesn't have the target but suggests other peers to try.
func (kr *KademliaResolver) processDatabaseSearchReplyResponse(data []byte, targetHash common.Hash) (*router_info.RouterInfo, error) {
	searchReply, err := i2np.ReadDatabaseSearchReply(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DatabaseSearchReply: %w", err)
	}

	// Log the suggested peers (these could be used for iterative lookups)
	if len(searchReply.PeerHashes) > 0 {
		log.WithFields(logger.Fields{
			"at":          "processDatabaseSearchReplyResponse",
			"target":      fmt.Sprintf("%x", targetHash[:8]),
			"from":        fmt.Sprintf("%x", searchReply.From[:8]),
			"suggestions": len(searchReply.PeerHashes),
		}).Debug("Peer returned suggestions")

		// Store the suggested peer hashes for potential future lookups
		// In a full implementation, we would use these to continue iterative lookups
	}

	// Return nil RouterInfo - the peer didn't have it
	return nil, fmt.Errorf("peer did not have target, suggested %d alternatives", len(searchReply.PeerHashes))
}
