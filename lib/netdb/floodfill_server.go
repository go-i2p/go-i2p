package netdb

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"io"
	"sync"
	"sync/atomic"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/go-i2p/go-i2p/lib/util/logutil"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// FloodfillServer implements floodfill router functionality, handling incoming
// DatabaseLookup messages and responding with stored data or peer suggestions.
//
// When a DatabaseLookup is received:
//  1. If the requested key is in our NetDB, respond with a DatabaseStore containing the data.
//  2. If the key is not found, respond with a DatabaseSearchReply containing hashes of
//     the closest floodfill routers to the target key (by XOR distance).
//
// The server also handles flooding: when we receive a DatabaseStore with a non-zero
// reply token, we store the data and flood it to our closest floodfill peers.
type FloodfillServer struct {
	mu sync.RWMutex

	// db is the underlying network database for lookups and storage
	db *StdNetDB

	// transport is used to send I2NP response messages back to requesters
	transport FloodfillTransport

	// ourHash is the identity hash of this router
	ourHash common.Hash

	// enabled controls whether this server accepts and processes floodfill requests
	enabled bool

	// floodCount is how many closest floodfills to flood data to
	floodCount int

	// lookupLimiter provides per-peer rate limiting for lookup and flood requests
	lookupLimiter *FloodfillRateLimiter

	// ctx and cancel for lifecycle management
	ctx    context.Context
	cancel context.CancelFunc
}

// maxPeersDefault is the upper bound on the number of distinct peers tracked
// simultaneously by FloodfillRateLimiter. This prevents unbounded memory
// growth in the presence of many distinct or spoofed source identities.
// The default (10_000) is large enough for a healthy floodfill mesh but
// bounded against a Sybil-style map-exhaustion attack.
const maxPeersDefault = 10_000

// FloodfillRateLimiter provides per-peer rate limiting for floodfill operations.
// Uses a token-bucket algorithm with automatic cleanup of stale entries.
type FloodfillRateLimiter struct {
	mu         sync.Mutex
	peers      map[common.Hash]*peerLimit
	lastSeen   map[common.Hash]time.Time
	maxPeers   int     // M-NEW-2: upper bound on tracked peers (anti-DoS)
	maxBurst   int     // max tokens (requests) per peer
	refillRate float64 // tokens added per second

	globalTokens     float64
	globalLastUpdate time.Time
	globalMaxBurst   int
	globalRefillRate float64
	globalRejected   uint64

	stopChan chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
}

type peerLimit struct {
	tokens     float64
	lastUpdate time.Time
}

// NewFloodfillRateLimiter creates a rate limiter allowing maxPerMinute requests
// per peer per minute with burst capacity.
func NewFloodfillRateLimiter(maxPerMinute, burstSize int) *FloodfillRateLimiter {
	// Default global cap: 2000 requests/minute with burst 500.
	// This bounds aggregate work across many peer identities.
	return NewFloodfillRateLimiterWithGlobal(maxPerMinute, burstSize, 2000, 500)
}

// NewFloodfillRateLimiterWithGlobal creates a rate limiter with per-peer and
// aggregate global token buckets.
func NewFloodfillRateLimiterWithGlobal(maxPerMinute, burstSize, globalPerMinute, globalBurstSize int) *FloodfillRateLimiter {
	now := time.Now()
	rl := &FloodfillRateLimiter{
		peers:      make(map[common.Hash]*peerLimit),
		lastSeen:   make(map[common.Hash]time.Time),
		maxPeers:   maxPeersDefault,
		maxBurst:   burstSize,
		refillRate: float64(maxPerMinute) / 60.0,

		globalTokens:     float64(globalBurstSize),
		globalLastUpdate: now,
		globalMaxBurst:   globalBurstSize,
		globalRefillRate: float64(globalPerMinute) / 60.0,

		stopChan: make(chan struct{}),
	}
	rl.wg.Add(1)
	go rl.cleanupLoop()
	return rl
}

// Allow returns true if the peer is within its rate limit.
func (rl *FloodfillRateLimiter) Allow(peer common.Hash) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	if !rl.allowGlobal(now) {
		atomic.AddUint64(&rl.globalRejected, 1)
		return false
	}

	if !rl.allowPeer(peer, now) {
		// Global limiter is checked first to bound aggregate load.
		// Refund if peer-specific limiting rejects this request.
		rl.globalTokens += 1.0
		if rl.globalTokens > float64(rl.globalMaxBurst) {
			rl.globalTokens = float64(rl.globalMaxBurst)
		}
		return false
	}

	return true
}

func (rl *FloodfillRateLimiter) allowGlobal(now time.Time) bool {
	elapsed := now.Sub(rl.globalLastUpdate).Seconds()
	rl.globalTokens += elapsed * rl.globalRefillRate
	if rl.globalTokens > float64(rl.globalMaxBurst) {
		rl.globalTokens = float64(rl.globalMaxBurst)
	}
	rl.globalLastUpdate = now

	if rl.globalTokens >= 1.0 {
		rl.globalTokens -= 1.0
		return true
	}

	return false
}

func (rl *FloodfillRateLimiter) allowPeer(peer common.Hash, now time.Time) bool {
	pl, exists := rl.peers[peer]
	if !exists {
		// M-NEW-2 FIX: reject the new peer if we are already at capacity.
		// This prevents a Sybil attacker from exhausting the server's memory by
		// sending requests from an unbounded number of distinct identities.
		// The existing stale-entry cleanup (removeStalePeers every 5 min) will
		// naturally free capacity for legitimate callers.
		if len(rl.peers) >= rl.maxPeers {
			return false
		}
		rl.peers[peer] = &peerLimit{
			tokens:     float64(rl.maxBurst) - 1,
			lastUpdate: now,
		}
		rl.lastSeen[peer] = now
		return true
	}

	// Refill tokens based on elapsed time
	elapsed := now.Sub(pl.lastUpdate).Seconds()
	pl.tokens += elapsed * rl.refillRate
	if pl.tokens > float64(rl.maxBurst) {
		pl.tokens = float64(rl.maxBurst)
	}
	pl.lastUpdate = now

	if pl.tokens >= 1.0 {
		pl.tokens -= 1.0
		rl.lastSeen[peer] = now
		return true
	}
	rl.lastSeen[peer] = now
	return false
}

// GlobalRejectedCount returns how many requests were rejected by the global bucket.
func (rl *FloodfillRateLimiter) GlobalRejectedCount() uint64 {
	return atomic.LoadUint64(&rl.globalRejected)
}

// cleanupLoop periodically removes stale entries (peers with full token buckets
// that haven't been seen recently).
func (rl *FloodfillRateLimiter) cleanupLoop() {
	defer rl.wg.Done()
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			rl.removeStalePeers()
		case <-rl.stopChan:
			return
		}
	}
}

// removeStalePeers purges rate-limiter entries for peers that have been idle
// longer than the stale threshold (2 minutes). Must not be called concurrently
// with Allow; it acquires rl.mu internally.
func (rl *FloodfillRateLimiter) removeStalePeers() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	for peer, pl := range rl.peers {
		if now.Sub(pl.lastUpdate) > 2*time.Minute {
			delete(rl.peers, peer)
			delete(rl.lastSeen, peer)
		}
	}
}

// LastSeen returns the last observed time for a peer, if present.
func (rl *FloodfillRateLimiter) LastSeen(peer common.Hash) (time.Time, bool) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	seenAt, ok := rl.lastSeen[peer]
	return seenAt, ok
}

// Stop shuts down the rate limiter's cleanup goroutine. It is safe to call
// concurrently and more than once; only the first call closes the stop channel.
func (rl *FloodfillRateLimiter) Stop() {
	rl.stopOnce.Do(func() {
		close(rl.stopChan)
	})
	rl.wg.Wait()
}

// FloodfillTransport defines the interface for sending I2NP messages back to lookup
type FloodfillTransport interface {
	// SendI2NPMessage sends an I2NP message to the router identified by routerHash.
	SendI2NPMessage(ctx context.Context, routerHash common.Hash, msg i2np.Message) error
}

// FloodfillConfig holds configuration for the floodfill server.
type FloodfillConfig struct {
	// Enabled controls whether the router serves as a floodfill
	Enabled bool

	// OurHash is this router's identity hash
	OurHash common.Hash

	// FloodCount is how many peers to flood data to (default: 4)
	FloodCount int
}

// DefaultFloodfillConfig returns the default floodfill configuration (disabled by default).
func DefaultFloodfillConfig() FloodfillConfig {
	return FloodfillConfig{
		Enabled:    false,
		FloodCount: 4,
	}
}

// NewFloodfillServer creates a new floodfill server.
//
// Parameters:
//   - db: the underlying StdNetDB for data storage and retrieval
//   - transport: transport for sending responses (can be nil, set later via SetTransport)
//   - config: floodfill configuration
func NewFloodfillServer(db *StdNetDB, transport FloodfillTransport, config FloodfillConfig) *FloodfillServer {
	ctx, cancel := context.WithCancel(context.Background())

	floodCount := config.FloodCount
	if floodCount <= 0 {
		floodCount = 4
	}

	fs := &FloodfillServer{
		db:            db,
		transport:     transport,
		ourHash:       config.OurHash,
		enabled:       config.Enabled,
		floodCount:    floodCount,
		lookupLimiter: NewFloodfillRateLimiter(60, 10), // 60 requests/min per peer, burst of 10
		ctx:           ctx,
		cancel:        cancel,
	}

	log.WithFields(logger.Fields{
		"at":          "NewFloodfillServer",
		"enabled":     config.Enabled,
		"flood_count": floodCount,
	}).Debug("Created floodfill server")

	return fs
}

// SetTransport sets the transport used for sending responses.
func (fs *FloodfillServer) SetTransport(transport FloodfillTransport) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.transport = transport
}

// SetEnabled enables or disables floodfill serving.
func (fs *FloodfillServer) SetEnabled(enabled bool) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.enabled = enabled
	log.WithField("enabled", enabled).Info("Floodfill server enabled status changed")
}

// IsEnabled returns whether the floodfill server is enabled.
func (fs *FloodfillServer) IsEnabled() bool {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	return fs.enabled
}

// Stop shuts down the floodfill server.
func (fs *FloodfillServer) Stop() {
	fs.cancel()
	if fs.lookupLimiter != nil {
		fs.lookupLimiter.Stop()
	}
	log.WithFields(logger.Fields{"at": "Stop"}).Debug("Floodfill server stopped")
}

// HandleDatabaseLookup processes an incoming DatabaseLookup request.
// If the requested key is found locally, a DatabaseStore is sent back.
// If not found, a DatabaseSearchReply with closest floodfill peer suggestions is sent.
//
// Parameters:
//   - lookup: the incoming DatabaseLookup message
//
// Returns an error if the lookup cannot be processed or the response cannot be sent.
func (fs *FloodfillServer) HandleDatabaseLookup(lookup *i2np.DatabaseLookup) error {
	fs.mu.RLock()
	enabled := fs.enabled
	transport := fs.transport
	fs.mu.RUnlock()

	if !enabled {
		log.WithFields(logger.Fields{"at": "HandleDatabaseLookup"}).Debug("Floodfill server not enabled, ignoring lookup")
		return oops.Errorf("floodfill server not enabled")
	}

	// Rate limit per source peer
	if fs.lookupLimiter != nil && !fs.lookupLimiter.Allow(lookup.From) {
		log.WithField("from", logutil.HashPrefix(lookup.From)).
			Warn("Rate limiting DatabaseLookup from peer")
		return oops.Errorf("rate limited")
	}

	// Reject lookups with a zero-hash From field.
	// A zero From would bypass the per-peer rate limiter and could also
	// cause issues when used as a reply destination.
	var zeroHash common.Hash
	if lookup.From == zeroHash {
		log.WithFields(logger.Fields{"at": "HandleDatabaseLookup"}).Warn("Rejecting DatabaseLookup with zero-hash From field")
		return oops.Errorf("invalid From field: zero hash")
	}

	key := lookup.Key
	from := lookup.From

	log.WithFields(logger.Fields{
		"at":   "HandleDatabaseLookup",
		"key":  logutil.HashPrefix(key),
		"from": logutil.HashPrefix(from),
	}).Debug("Processing incoming DatabaseLookup")

	// Determine what type of lookup this is
	lookupType := fs.determineLookupType(lookup)

	// Attempt to find the data locally
	data, dataType, err := fs.lookupData(key, lookupType)
	if err == nil && len(data) > 0 {
		// Found locally — check delivery preference from lookup flags
		// deliveryFlag (bit 0): 0 = send directly, 1 = send through tunnel
		deliveryFlag := lookup.Flags & 0x01
		if deliveryFlag == 1 {
			// Send response through tunnel as requested
			return fs.sendDatabaseStoreThroughTunnel(key, data, dataType, lookup.ReplyTunnelID, from, transport)
		}
		// Send response directly (deliveryFlag == 0)
		return fs.sendDatabaseStore(key, data, dataType, from, transport)
	}

	// Not found — respond with DatabaseSearchReply containing closest floodfills
	// Also check delivery preference for search replies
	deliveryFlag := lookup.Flags & 0x01
	if deliveryFlag == 1 {
		return fs.sendDatabaseSearchReplyThroughTunnel(key, lookup.ReplyTunnelID, from, transport)
	}
	return fs.sendDatabaseSearchReply(key, from, transport)
}

// determineLookupType extracts the lookup type from the DatabaseLookup flags.
// Returns: "ri" for RouterInfo, "ls" for LeaseSet, "exploration" for exploratory,
// or "any" for normal lookup.
func (fs *FloodfillServer) determineLookupType(lookup *i2np.DatabaseLookup) string {
	typeBits := (lookup.Flags >> 2) & 0x03
	switch typeBits {
	case 0x00:
		return "any"
	case 0x01:
		return "ls"
	case 0x02:
		return "ri"
	case 0x03:
		return "exploration"
	default:
		return "any"
	}
}

// lookupData attempts to find the requested data in our NetDB.
// Returns the data bytes, the DatabaseStore type code, and an error if not found.
func (fs *FloodfillServer) lookupData(key common.Hash, lookupType string) ([]byte, byte, error) {
	switch lookupType {
	case "ri":
		return fs.lookupRouterInfo(key)
	case "ls":
		return fs.lookupLeaseSet(key)
	case "exploration":
		// Exploration lookups never return actual data; always return SearchReply
		return nil, 0, oops.Errorf("exploration lookup")
	default: // "any"
		// Try RouterInfo first, then LeaseSet
		data, dataType, err := fs.lookupRouterInfo(key)
		if err == nil {
			return data, dataType, nil
		}
		return fs.lookupLeaseSet(key)
	}
}

// lookupRouterInfo looks up a RouterInfo by hash.
func (fs *FloodfillServer) lookupRouterInfo(key common.Hash) ([]byte, byte, error) {
	data, err := fs.db.GetRouterInfoBytes(key)
	if err != nil {
		return nil, 0, err
	}
	if len(data) == 0 {
		return nil, 0, oops.Errorf("RouterInfo not found for %x", key[:8])
	}

	// Gzip-compress the RouterInfo data for DatabaseStore (per I2P spec)
	compressed, err := gzipCompress(data)
	if err != nil {
		log.WithError(err).Warn("Failed to gzip RouterInfo for DatabaseStore response")
		return nil, 0, err
	}

	return compressed, i2np.DatabaseStoreTypeRouterInfo, nil
}

// lookupLeaseSet looks up a LeaseSet by hash.
// Checks all LeaseSet variants: LeaseSet2, EncryptedLeaseSet, MetaLeaseSet,
// and original LeaseSet.
//
// PRIVACY NOTE: We serve all LeaseSets uniformly to avoid creating an oracle.
// Observers cannot infer whether a FloodFill "owns" a LeaseSet by observing
// differences in lookup behavior. This is required by I2P protocol for privacy.
//
// Future optimization: Only serve LeaseSets that we would have self-selected
// as a FloodFill when publishing them. This requires storing which FloodFills
// were chosen during publication and comparing with our own position in the
// DHT. This avoids serving LeaseSets that were published to us by others but
// we would never have received in normal operation.
func (fs *FloodfillServer) lookupLeaseSet(key common.Hash) ([]byte, byte, error) {
	// Try LeaseSet2 first (most common modern format)
	data, err := fs.db.GetLeaseSet2Bytes(key)
	if err == nil && len(data) > 0 {
		return data, i2np.DatabaseStoreTypeLeaseSet2, nil
	}

	// Try EncryptedLeaseSet
	data, err = fs.db.GetEncryptedLeaseSetBytes(key)
	if err == nil && len(data) > 0 {
		return data, i2np.DatabaseStoreTypeEncryptedLeaseSet, nil
	}

	// Try MetaLeaseSet
	data, err = fs.db.GetMetaLeaseSetBytes(key)
	if err == nil && len(data) > 0 {
		return data, i2np.DatabaseStoreTypeMetaLeaseSet, nil
	}

	// Try original LeaseSet
	data, err = fs.db.GetLeaseSetBytes(key)
	if err == nil && len(data) > 0 {
		return data, i2np.DatabaseStoreTypeLeaseSet, nil
	}

	return nil, 0, oops.Errorf("LeaseSet not found for %x", key[:8])
}

// sendDatabaseStore constructs and sends a DatabaseStore response to the requester.
func (fs *FloodfillServer) sendDatabaseStore(
	key common.Hash,
	data []byte,
	dataType byte,
	to common.Hash,
	transport FloodfillTransport,
) error {
	if transport == nil {
		return oops.Errorf("no transport available to send DatabaseStore response")
	}

	store := i2np.NewDatabaseStore(key, data, dataType)

	log.WithFields(logger.Fields{
		"at":        "sendDatabaseStore",
		"key":       logutil.HashPrefix(key),
		"to":        logutil.HashPrefix(to),
		"data_type": dataType,
		"data_size": len(data),
	}).Debug("Sending DatabaseStore response")

	return transport.SendI2NPMessage(fs.ctx, to, store)
}

// sendDatabaseStoreThroughTunnel sends a DatabaseStore response through a tunnel.
// This is used when the DatabaseLookup request specifies that the response should
// be sent through a tunnel (deliveryFlag=1 in the request flags).
//
// Per I2P specification, when the requester specifies a reply tunnel via the
// deliveryFlag, the response is wrapped in a TunnelGateway message and sent to
// the gateway router, which then encrypts and forwards through the tunnel.
func (fs *FloodfillServer) sendDatabaseStoreThroughTunnel(
	key common.Hash,
	data []byte,
	dataType byte,
	replyTunnelID [4]byte,
	gatewayHash common.Hash,
	transport FloodfillTransport,
) error {
	if transport == nil {
		return oops.Errorf("no transport available to send DatabaseStore response through tunnel")
	}

	// Create the DatabaseStore response
	store := i2np.NewDatabaseStore(key, data, dataType)

	// Serialize the DatabaseStore for wrapping in TunnelGateway
	storeBytes, err := store.MarshalBinary()
	if err != nil {
		log.WithFields(logger.Fields{
			"at":        "sendDatabaseStoreThroughTunnel",
			"key":       logutil.HashPrefix(key),
			"gateway":   logutil.HashPrefix(gatewayHash),
			"tunnel_id": binary.BigEndian.Uint32(replyTunnelID[:]),
		}).WithError(err).Error("Failed to marshal DatabaseStore for tunnel delivery")
		return oops.Wrapf(err, "failed to marshal DatabaseStore for tunnel delivery")
	}

	// Convert replyTunnelID bytes to tunnel.TunnelID
	tunnelID := tunnel.TunnelID(binary.BigEndian.Uint32(replyTunnelID[:]))

	// Wrap in TunnelGateway message for tunnel transmission
	tunnelGatewayMsg := i2np.NewTunnelGatewayMessage(tunnelID, storeBytes)

	log.WithFields(logger.Fields{
		"at":        "sendDatabaseStoreThroughTunnel",
		"key":       logutil.HashPrefix(key),
		"gateway":   logutil.HashPrefix(gatewayHash),
		"tunnel_id": tunnelID,
		"data_type": dataType,
		"data_size": len(data),
	}).Debug("Sending DatabaseStore response through tunnel")

	return transport.SendI2NPMessage(fs.ctx, gatewayHash, tunnelGatewayMsg)
}

// sendDatabaseSearchReply constructs and sends a DatabaseSearchReply with peer suggestions.
func (fs *FloodfillServer) sendDatabaseSearchReply(
	key common.Hash,
	to common.Hash,
	transport FloodfillTransport,
) error {
	if transport == nil {
		return oops.Errorf("no transport available to send DatabaseSearchReply")
	}

	// Select closest floodfill routers to suggest
	peerHashes := fs.selectClosestFloodfills(key)

	reply := i2np.NewDatabaseSearchReply(key, fs.ourHash, peerHashes)

	log.WithFields(logger.Fields{
		"at":         "sendDatabaseSearchReply",
		"key":        logutil.HashPrefix(key),
		"to":         logutil.HashPrefix(to),
		"peer_count": len(peerHashes),
	}).Debug("Sending DatabaseSearchReply response")

	return transport.SendI2NPMessage(fs.ctx, to, reply)
}

// sendDatabaseSearchReplyThroughTunnel sends a DatabaseSearchReply through a tunnel.
// This is used when the DatabaseLookup request specifies that the response should
// be sent through a tunnel (deliveryFlag=1 in the request flags).
//
// Per I2P specification, when the requester specifies a reply tunnel, the search
// reply is wrapped in a TunnelGateway message and sent to the gateway router.
func (fs *FloodfillServer) sendDatabaseSearchReplyThroughTunnel(
	key common.Hash,
	replyTunnelID [4]byte,
	gatewayHash common.Hash,
	transport FloodfillTransport,
) error {
	if transport == nil {
		return oops.Errorf("no transport available to send DatabaseSearchReply through tunnel")
	}

	// Select closest floodfill routers to suggest
	peerHashes := fs.selectClosestFloodfills(key)

	reply := i2np.NewDatabaseSearchReply(key, fs.ourHash, peerHashes)

	// Serialize the DatabaseSearchReply for wrapping in TunnelGateway
	replyBytes, err := reply.MarshalBinary()
	if err != nil {
		log.WithFields(logger.Fields{
			"at":        "sendDatabaseSearchReplyThroughTunnel",
			"key":       logutil.HashPrefix(key),
			"gateway":   logutil.HashPrefix(gatewayHash),
			"tunnel_id": binary.BigEndian.Uint32(replyTunnelID[:]),
		}).WithError(err).Error("Failed to marshal DatabaseSearchReply for tunnel delivery")
		return oops.Wrapf(err, "failed to marshal DatabaseSearchReply for tunnel delivery")
	}

	// Convert replyTunnelID bytes to tunnel.TunnelID
	tunnelID := tunnel.TunnelID(binary.BigEndian.Uint32(replyTunnelID[:]))

	// Wrap in TunnelGateway message for tunnel transmission
	tunnelGatewayMsg := i2np.NewTunnelGatewayMessage(tunnelID, replyBytes)

	log.WithFields(logger.Fields{
		"at":         "sendDatabaseSearchReplyThroughTunnel",
		"key":        logutil.HashPrefix(key),
		"gateway":    logutil.HashPrefix(gatewayHash),
		"tunnel_id":  tunnelID,
		"peer_count": len(peerHashes),
	}).Debug("Sending DatabaseSearchReply through tunnel")

	return transport.SendI2NPMessage(fs.ctx, gatewayHash, tunnelGatewayMsg)
}

// selectClosestFloodfills selects the closest floodfill routers to the target key.
func (fs *FloodfillServer) selectClosestFloodfills(targetKey common.Hash) []common.Hash {
	const maxPeers = 7

	floodfills, err := fs.db.SelectFloodfillRouters(targetKey, maxPeers)
	if err != nil {
		log.WithError(err).Warn("Failed to select floodfill routers for search reply")
		return []common.Hash{}
	}

	peerHashes := make([]common.Hash, 0, len(floodfills))
	for _, ri := range floodfills {
		hash, err := ri.IdentHash()
		if err != nil {
			continue
		}
		// Don't suggest ourselves
		if hash == fs.ourHash {
			continue
		}
		peerHashes = append(peerHashes, hash)
	}

	return peerHashes
}

// FloodDatabaseStore handles flooding a DatabaseStore to our closest floodfill peers.
// This should be called when we receive a DatabaseStore with a non-zero reply token,
// indicating that the sender expects us to flood the data.
func (fs *FloodfillServer) FloodDatabaseStore(key common.Hash, data []byte, dataType byte) {
	fs.mu.RLock()
	enabled := fs.enabled
	transport := fs.transport
	fs.mu.RUnlock()

	if !enabled || transport == nil {
		return
	}

	floodfills, err := fs.selectFloodPeers(key)
	if err != nil {
		log.WithError(err).Warn("Failed to select floodfill routers for flooding")
		return
	}

	store := i2np.NewDatabaseStore(key, data, dataType)
	flooded := fs.floodToSelectedPeers(floodfills, store, transport)

	log.WithFields(logger.Fields{
		"at":      "FloodDatabaseStore",
		"key":     logutil.HashPrefix(key),
		"flooded": flooded,
	}).Debug("Flooded DatabaseStore to peers")
}

// selectFloodPeers selects the closest floodfill routers for flooding, excluding ourselves.
func (fs *FloodfillServer) selectFloodPeers(key common.Hash) ([]router_info.RouterInfo, error) {
	return fs.db.SelectFloodfillRouters(key, fs.floodCount+1)
}

// floodToSelectedPeers sends the DatabaseStore message to eligible floodfill peers,
// skipping our own hash and stopping after floodCount successful sends.
// The transport parameter is captured under lock by the caller to avoid a data race
// with SetTransport or concurrent writes to fs.transport.
func (fs *FloodfillServer) floodToSelectedPeers(floodfills []router_info.RouterInfo, store i2np.Message, transport FloodfillTransport) int {
	flooded := 0
	for _, ri := range floodfills {
		if flooded >= fs.floodCount {
			break
		}
		hash, err := ri.IdentHash()
		if err != nil {
			continue
		}
		if hash == fs.ourHash {
			continue
		}
		if err := transport.SendI2NPMessage(fs.ctx, hash, store); err != nil {
			log.WithFields(logger.Fields{
				"at":   "FloodDatabaseStore",
				"peer": logutil.BytePrefix(hash[:]),
			}).WithError(err).Debug("Failed to flood to peer")
			continue
		}
		flooded++
	}
	return flooded
}

// GetFloodfillRouterInfo returns our router's RouterInfo if we are configured as floodfill.
// This can be used to advertise our floodfill capability to other routers.
func (fs *FloodfillServer) GetFloodfillRouterInfo() (*router_info.RouterInfo, error) {
	ch := fs.db.GetRouterInfo(fs.ourHash)
	if ch == nil {
		return nil, oops.Errorf("our RouterInfo not found in NetDB")
	}

	select {
	case ri, ok := <-ch:
		if !ok {
			return nil, oops.Errorf("channel closed without RouterInfo")
		}
		return &ri, nil
	case <-time.After(1 * time.Second):
		return nil, oops.Errorf("timeout getting our RouterInfo")
	}
}

// gzipCompress compresses data using gzip (used for RouterInfo in DatabaseStore).
func gzipCompress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(data); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// gzipDecompress decompresses gzip-compressed data.
// Used to decompress RouterInfo payloads in DatabaseStore messages,
// which are gzip-compressed per the I2P specification.
func gzipDecompress(data []byte) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, oops.Errorf("gzip: failed to create reader: %w", err)
	}
	defer func() { _ = r.Close() }()
	var buf bytes.Buffer
	// Limit decompressed size to 64 KiB to prevent zip-bomb attacks.
	// A valid RouterInfo is typically under 4 KiB.
	const maxDecompressedSize = 64 * 1024
	limited := io.LimitReader(r, maxDecompressedSize+1)
	if _, err := buf.ReadFrom(limited); err != nil {
		return nil, oops.Errorf("gzip: decompression failed: %w", err)
	}
	if buf.Len() > maxDecompressedSize {
		return nil, oops.Errorf("gzip: decompressed data exceeds %d bytes, possible zip bomb", maxDecompressedSize)
	}
	return buf.Bytes(), nil
}
