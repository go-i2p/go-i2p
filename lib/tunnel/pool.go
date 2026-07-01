package tunnel

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/util/logutil"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// TunnelState represents the current state of a tunnel during building
type TunnelState struct {
	ID              TunnelID
	GatewayTunnelID TunnelID         // Inbound gateway receive tunnel ID (for reply routing)
	Hops            []common.Hash    // Router hashes for each hop
	State           TunnelBuildState // Current build state
	CreatedAt       time.Time        // When tunnel building started
	ResponseCount   int              // Number of responses received
	Responses       []BuildResponse  // Responses from each hop
	IsInbound       bool             // True if this is an inbound tunnel
}

// TunnelBuildState represents different states during tunnel building
type TunnelBuildState int

const (
	// TunnelBuilding indicates that tunnel construction is currently in progress.
	TunnelBuilding TunnelBuildState = iota // Tunnel is being built
	TunnelReady                            // Tunnel is ready for use
	TunnelFailed                           // Tunnel build failed
)

const (
	// tunnelBuildTimeout is the maximum time a tunnel may remain in the
	// TunnelBuilding state before being treated as an expired in-flight build.
	// Matches the I2P spec's 90-second VTBRM deadline.
	tunnelBuildTimeout = 90 * time.Second

	// BuildTimeout is the exported form of tunnelBuildTimeout for packages
	// that need to schedule operations relative to the build deadline
	// (e.g. the startup reachability check in the router).
	BuildTimeout = tunnelBuildTimeout

	// autoFallbackThreshold is the number of consecutive exploratory build
	// timeouts that trigger the hop-reduction auto-fallback when no public
	// address is available.
	autoFallbackThreshold = 3

	defaultPeerCooldown   = 5 * time.Minute
	localFailureCooldown  = 90 * time.Second
	ambiguousFailureDecay = 3 * time.Minute
	hardFailureCooldown   = 10 * time.Minute
	minAdaptiveCooldown   = 30 * time.Second
	maxAdaptiveCooldown   = 15 * time.Minute
)

// BuildResponse represents a response from a tunnel hop
type BuildResponse struct {
	HopIndex int    // Index of the hop that responded
	Success  bool   // Whether the hop accepted the tunnel
	Reply    []byte // Raw response data
}

// PeerSelector defines interface for selecting peers for tunnel building
type PeerSelector interface {
	SelectPeers(count int, exclude []common.Hash) ([]router_info.RouterInfo, error)
}

// BuildTunnelResult contains the result of a tunnel build attempt.
// It provides the generated tunnel ID and the hashes of the peers
// that were selected for this build, enabling callers to track which
// peers participated in failed builds for exclusion on retry.
type BuildTunnelResult struct {
	TunnelID   TunnelID      // The assigned tunnel ID (0 on failure)
	PeerHashes []common.Hash // Hashes of peers selected for this build attempt
}

// BuilderInterface defines interface for building tunnels
type BuilderInterface interface {
	// BuildTunnel initiates building a new tunnel with the specified parameters.
	// Returns a BuildTunnelResult containing the tunnel ID and selected peer hashes.
	BuildTunnel(req BuildTunnelRequest) (*BuildTunnelResult, error)
}

// PoolConfig defines configuration parameters for a tunnel pool
type PoolConfig struct {
	// MinTunnels is the minimum number of tunnels to maintain
	MinTunnels int
	// MaxTunnels is the maximum number of tunnels to allow
	MaxTunnels int
	// TunnelLifetime is how long tunnels should live before expiring
	TunnelLifetime time.Duration
	// RebuildThreshold is when to start building replacement tunnels (before expiry)
	RebuildThreshold time.Duration
	// BuildRetryDelay is the initial delay before retrying failed builds
	BuildRetryDelay time.Duration
	// MaxBuildRetries is the maximum number of build retries before giving up
	MaxBuildRetries int
	// HopCount is the number of hops for tunnels in this pool
	HopCount int
	// IsInbound indicates if this pool manages inbound tunnels
	IsInbound bool
	// IsClientPool indicates this pool belongs to an I2CP client session (vs exploratory router pools).
	// When true, successful builds are counted as client tunnel successes for I2PControl stats.
	IsClientPool bool
}

// DefaultPoolConfig returns a configuration with sensible defaults
func DefaultPoolConfig() PoolConfig {
	return PoolConfig{
		MinTunnels:       4,
		MaxTunnels:       6,
		TunnelLifetime:   11 * time.Minute,
		RebuildThreshold: 90 * time.Second,
		BuildRetryDelay:  2 * time.Second, // FIX #4: Reduced initial delay (exponential backoff will increase)
		MaxBuildRetries:  3,
		HopCount:         3,
		IsInbound:        false,
	}
}

// Pool manages a collection of tunnels with automatic maintenance
type Pool struct {
	tunnels              map[TunnelID]*TunnelState
	mutex                sync.RWMutex
	peerSelector         PeerSelector
	tunnelBuilder        BuilderInterface
	config               PoolConfig
	clientSessionID      uint16        // Session ID for I2CP client pools; 0 for exploratory pools
	selectionIndex       atomic.Uint32 // Lock-free round-robin counter
	lastBuildTime        time.Time     // Track last build attempt for backoff
	buildFailures        int           // Consecutive build failures
	ctx                  context.Context
	cancel               context.CancelFunc
	maintWg              sync.WaitGroup                       // Track maintenance goroutine
	failedPeers          map[common.Hash]time.Time            // FIX #5: Track failed peer connection attempts
	failedPeerCooldown   map[common.Hash]time.Duration        // Adaptive cooldown per failed peer
	failedPeersMu        sync.RWMutex                         // FIX #5: Protect failed peers map
	peerTracker          PeerTracker                          // Optional peer reputation tracking (netdb integration)
	cachedActive         atomic.Value                         // []*TunnelState - lock-free cached sorted active tunnels
	cachedDirty          atomic.Bool                          // True when cache needs rebuild
	inFlightExpiredCount int                                  // Consecutive inbound build timeouts (no VTBRM received)
	autoFallbackFn       func() bool                          // Returns true when no public address is available
	routerHash           common.Hash                          // Our router's identity hash, used as ReplyGateway in build requests
	startupGate          <-chan struct{}                      // BUG-1: closed when pre-conditions for first build are met
	replyTunnelProvider  func() (TunnelID, common.Hash, bool) // Returns reply tunnel ID + gateway hash for reply routing (nil = direct delivery)
}

// SetStartupGate sets a channel that maintenanceLoop waits on before
// executing its first maintainPool() call. This allows the outbound pool to
// delay its initial build attempt until the inbound pool has at least one
// active tunnel ready to receive build replies (BUG-1 fix).
// The gate must be closed (not just sent to) to unblock the loop.
// A nil channel means no gate — the initial build runs immediately.
func (p *Pool) SetStartupGate(gate <-chan struct{}) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.startupGate = gate
}

// SetReplyTunnelProvider sets a function that the pool calls when building
// tunnel requests to obtain an active inbound tunnel ID to use as the
// ReplyTunnelID. When the provider returns a non-zero tunnel ID, build
// requests use TUNNEL delivery mode (wrapping the reply in a TunnelGateway
// on the existing NTCP2 session) rather than ROUTER delivery mode (direct
// type-26 to our router address, which fails behind NAT).
// A nil provider (default) leaves ReplyTunnelID=0 (ROUTER delivery).
func (p *Pool) SetReplyTunnelProvider(fn func() (TunnelID, common.Hash, bool)) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.replyTunnelProvider = fn
}

// SetRouterHash sets our router's identity hash so it can be used as the
// ReplyGateway field in outgoing tunnel build requests. This tells the last
// hop in the build chain where to send the build reply.
func (p *Pool) SetRouterHash(hash common.Hash) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.routerHash = hash
}

// PeerTracker interface for recording peer connection outcomes.
// This allows Pool to report connection results to NetDB for reputation tracking.
type PeerTracker interface {
	RecordFailure(hash common.Hash, reason string)
	RecordSuccess(hash common.Hash, responseTimeMs int64)
}

// peerScorer is an optional capability exposed by NetDB peer trackers.
// When available we use it to bias failed-peer cooldown length.
type peerScorer interface {
	ScorePeer(hash common.Hash) float64
}

// NewTunnelPool creates a new tunnel pool with the given peer selector and default configuration
func NewTunnelPool(selector PeerSelector) *Pool {
	return NewTunnelPoolWithConfig(selector, DefaultPoolConfig())
}

// NewTunnelPoolWithConfig creates a new tunnel pool with custom configuration
func NewTunnelPoolWithConfig(selector PeerSelector, config PoolConfig) *Pool {
	ctx, cancel := context.WithCancel(context.Background())
	p := &Pool{
		tunnels:            make(map[TunnelID]*TunnelState),
		peerSelector:       selector,
		config:             config,
		lastBuildTime:      time.Time{},                     // Zero time
		failedPeers:        make(map[common.Hash]time.Time), // FIX #5: Track failed connection attempts
		failedPeerCooldown: make(map[common.Hash]time.Duration),
		ctx:                ctx,
		cancel:             cancel,
		peerTracker:        nil, // Will be set via SetPeerTracker if NetDB integration is enabled
	}
	// Initialize atomic fields
	p.cachedDirty.Store(true)
	return p
}

// SetPeerTracker sets the peer tracker for NetDB integration.
// This allows the pool to report connection results for reputation tracking.
func (p *Pool) SetPeerTracker(tracker PeerTracker) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.peerTracker = tracker
	log.WithFields(logger.Fields{
		"at":     "Pool.SetPeerTracker",
		"reason": "enabling peer reputation tracking",
	}).Debug("peer tracker configured for pool")
}

// SetClientSessionID sets the I2CP session ID for this pool.
// Must be called for client pools (IsClientPool=true in config) so that
// tunnel endpoint registration can identify which session owns the tunnel.
func (p *Pool) SetClientSessionID(sessionID uint16) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.clientSessionID = sessionID
	log.WithFields(logger.Fields{
		"at":         "Pool.SetClientSessionID",
		"session_id": sessionID,
		"is_inbound": p.config.IsInbound,
		"is_client":  p.config.IsClientPool,
	}).Debug("client session ID configured for pool")
}

// SetTunnelBuilder sets the tunnel builder for this pool.
// Must be called before starting pool maintenance.
func (p *Pool) SetTunnelBuilder(builder BuilderInterface) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.tunnelBuilder = builder
}

// SetAutoFallbackCheck registers a callback that the pool calls when
// autoFallbackThreshold consecutive inbound build timeouts have occurred.
// The callback should return true when the router has no publicly-reachable
// address, which is the condition under which 0-hop inbound tunnels make
// sense. Passing nil disables auto-fallback.
func (p *Pool) SetAutoFallbackCheck(fn func() bool) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.autoFallbackFn = fn
}

// RecordInboundBuildTimeout is called by TunnelManager whenever an inbound
// tunnel build times out. It increments the in-flight expired counter and
// triggers checkAutoFallback when the threshold is reached. This is the
// authoritative notification path: pool.cleanupExpiredTunnelsLocked cannot
// reliably observe TunnelFailed state because TunnelManager removes those
// tunnels from the pool within ~1 s of marking them failed — well inside the
// 30-second pool-maintenance interval.
// No-op for client pools: client tunnel hop counts are application-specified
// and must never be reduced by the auto-fallback mechanism.
func (p *Pool) RecordInboundBuildTimeout() {
	p.recordBuildTimeout(true)
}

// RecordOutboundBuildTimeout is called by TunnelManager whenever an outbound
// tunnel build times out. After autoFallbackThreshold consecutive timeouts with
// no public address, the pool falls back to 1-hop outbound tunnels so that the
// single OBEP (which we just dialled) can reply via the existing session.
// No-op for client pools: client tunnel hop counts are application-specified
// and must never be reduced by the auto-fallback mechanism.
func (p *Pool) RecordOutboundBuildTimeout() {
	p.recordBuildTimeout(false)
}

// checkAutoFallback switches this pool to reduced-hop tunnels when the

// recordBuildTimeout is the shared implementation of RecordInboundBuildTimeout
// and RecordOutboundBuildTimeout.  It is a no-op when the pool direction or
// client-pool flag do not match expectIsInbound.
func (p *Pool) recordBuildTimeout(expectIsInbound bool) {
	if p.config.IsInbound != expectIsInbound || p.config.IsClientPool {
		return
	}
	p.mutex.Lock()
	p.inFlightExpiredCount++
	count := p.inFlightExpiredCount
	p.mutex.Unlock()

	if count >= autoFallbackThreshold {
		p.checkAutoFallback()
	}
}

// registered callback confirms no public address is available.
//   - Inbound pool: falls back to 0-hop (we are our own IBGW/IBEP).
//   - Outbound pool: falls back to 1-hop (the single OBEP we dialled can reply
//     via the already-open session, bypassing the need for inbound reachability).
//
// It is a no-op for client pools (hop count is application-specified), if the
// hop-count is already at the fallback minimum, or if no callback was registered.

// autoFallbackConfig holds the configuration needed for auto-fallback checks.

// getAutoFallbackConfig retrieves the configuration for auto-fallback checks.

// shouldSkipAutoFallback determines if auto-fallback should be skipped.

// performAutoFallback reduces hop count for inbound or outbound pools when needed.

// fallbackInbound reduces inbound pool to zero-hop tunnels if needed.

// fallbackOutbound reduces outbound pool to one-hop tunnels if needed.

// TriggerAutoFallbackCheck immediately evaluates the auto-fallback condition
// against the registered callback (e.g. "do we have a public address?"). Unlike
// the counter-based paths (RecordInboundBuildTimeout / RecordOutboundBuildTimeout),
// this bypasses the threshold check and fires unconditionally. It is intended for
// use by the router's startup goroutine so that a firewalled router can switch to
// reduced hops after one build-timeout period rather than waiting for
// autoFallbackThreshold consecutive failures.
// No-op for client pools (their hop count is application-specified).

// RunMaintenanceNow triggers an immediate pool maintenance cycle outside the
// normal 30-second ticker interval. It is intended for use by startup logic
// that needs tunnels to be built without waiting for the next scheduled tick,
// for example after switching to zero-hop mode via TriggerAutoFallbackCheck.
func (p *Pool) RunMaintenanceNow() {
	p.maintainPool()
}

// ResetBuildFailures clears the exponential backoff counter. This should be called
// when new tunnel resources become available (e.g., reply tunnels) so that builds
// can retry immediately instead of waiting for the backoff delay to expire.
func (p *Pool) ResetBuildFailures() {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	oldFailures := p.buildFailures

	p.buildFailures = 0
	p.lastBuildTime = time.Time{}

	log.WithFields(logger.Fields{
		"at":                "Pool.ResetBuildFailures",
		"previous_failures": oldFailures,
	}).Info("Reset exponential backoff counter for reply tunnel availability")
}

// SetHopCount overrides the configured per-tunnel hop count for this pool.
// HopCount=0 is only permitted on inbound pools, where it requests a
// zero-hop inbound tunnel (we are simultaneously gateway and endpoint).
// Returns an error if hopCount is out of range or 0 is requested on an
// outbound pool.
func (p *Pool) SetHopCount(hopCount int) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	minHops := 1
	if p.config.IsInbound {
		minHops = 0
	}
	if hopCount < minHops || hopCount > 8 {
		return oops.Errorf("hop count must be between %d and 8, got %d", minHops, hopCount)
	}
	p.config.HopCount = hopCount
	log.WithFields(logger.Fields{
		"at":         "Pool.SetHopCount",
		"hop_count":  hopCount,
		"is_inbound": p.config.IsInbound,
	}).Debug("pool hop count updated")
	return nil
}

// HopCount returns the configured hop count for this pool.
func (p *Pool) HopCount() int {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	return p.config.HopCount
}

// getTunnelBuilder returns the tunnel builder, safely read under the lock.
func (p *Pool) getTunnelBuilder() BuilderInterface {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	return p.tunnelBuilder
}

// GetTunnel retrieves a tunnel by ID
func (p *Pool) GetTunnel(id TunnelID) (*TunnelState, bool) {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	tunnel, exists := p.tunnels[id]
	return tunnel, exists
}

// AddTunnel adds a new tunnel to the pool
func (p *Pool) AddTunnel(tunnel *TunnelState) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.tunnels[tunnel.ID] = tunnel
	p.cachedDirty.Store(true)
	log.WithFields(logger.Fields{
		"at":           "(Pool) AddTunnel",
		"phase":        "tunnel_build",
		"reason":       "tunnel registered in pool",
		"tunnel_id":    tunnel.ID,
		"tunnel_state": tunnel.State,
		"hop_count":    len(tunnel.Hops),
		"pool_size":    len(p.tunnels),
	}).Debug("added tunnel to pool")
}

// ReanchorBuildStart resets the CreatedAt timestamp of a still-building tunnel
// to the current time. It is called once the build message has actually been
// sent on the wire, because the pool's build-expiry clock (tunnelBuildTimeout)
// otherwise starts when the TunnelState is first registered — before the
// potentially slow sendBuildMessage step (NetDB lookup plus transport
// handshake, up to tens of seconds). Without re-anchoring, that pre-send delay
// is silently subtracted from the 90-second reply window, prematurely expiring
// tunnels whose build replies are still legitimately in flight.
//
// It is a no-op if the tunnel is unknown or no longer in the building state, so
// it can never resurrect or extend the lifetime of an established tunnel.
func (p *Pool) ReanchorBuildStart(id TunnelID) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	tunnel, exists := p.tunnels[id]
	if !exists || tunnel.State != TunnelBuilding {
		return
	}
	tunnel.CreatedAt = time.Now()
}

// InvalidateActiveCache marks the active tunnel cache dirty so the next
// selection or active-list read rebuilds from current tunnel states.
// This must be called when tunnel readiness changes in-place without
// adding/removing entries from p.tunnels.
func (p *Pool) InvalidateActiveCache() {
	p.cachedDirty.Store(true)
}

// RemoveTunnel removes a tunnel from the pool
func (p *Pool) RemoveTunnel(id TunnelID) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	tunnel, existed := p.tunnels[id]
	delete(p.tunnels, id)
	p.cachedDirty.Store(true)
	log.WithFields(logger.Fields{
		"at":        "(Pool) RemoveTunnel",
		"phase":     "tunnel_build",
		"reason":    "tunnel removed from pool",
		"tunnel_id": id,
		"existed":   existed,
		"tunnel_state": func() string {
			if existed {
				return fmt.Sprintf("%v", tunnel.State)
			}
			return "unknown"
		}(),
		"pool_size": len(p.tunnels),
	}).Debug("removed tunnel from pool")
}

// GetActiveTunnels returns all active tunnels
func (p *Pool) GetActiveTunnels() []*TunnelState {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	var active []*TunnelState
	for _, tunnel := range p.tunnels {
		if tunnel.State == TunnelReady {
			active = append(active, tunnel)
		}
	}
	log.WithFields(logger.Fields{
		"at":           "(Pool) GetActiveTunnels",
		"phase":        "tunnel_build",
		"reason":       "filtered tunnels by ready state",
		"active_count": len(active),
		"total_count":  len(p.tunnels),
	}).Debug("retrieved active tunnels")
	return active
}

// Stop gracefully stops the pool maintenance goroutine
func (p *Pool) Stop() {
	if p.cancel != nil {
		p.cancel()
	}
	p.maintWg.Wait() // Wait for maintenance goroutine to exit
	log.WithFields(logger.Fields{
		"at":        "(Pool) Stop",
		"phase":     "tunnel_build",
		"reason":    "pool maintenance shutdown completed",
		"pool_size": len(p.tunnels),
	}).Debug("tunnel pool stopped")
}

// CleanupExpiredTunnels removes tunnels that have been building for too long
func (p *Pool) CleanupExpiredTunnels(maxAge time.Duration) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	now := time.Now()
	var expired []TunnelID

	for id, tunnel := range p.tunnels {
		if tunnel.State == TunnelBuilding && now.Sub(tunnel.CreatedAt) > maxAge {
			expired = append(expired, id)
		}
	}

	for _, id := range expired {
		delete(p.tunnels, id)
	}

	if len(expired) > 0 {
		log.WithFields(logger.Fields{
			"at":            "(Pool) cleanupExpiredTunnels",
			"phase":         "tunnel_build",
			"reason":        "expired tunnels removed from pool",
			"expired_count": len(expired),
			"max_age":       maxAge,
			"pool_size":     len(p.tunnels),
		}).Warn("cleaned up expired tunnels")
	}
}

// StartMaintenance begins the pool maintenance goroutine.
// This monitors tunnel health and builds new tunnels as needed.

// maintenanceLoop is the background goroutine that maintains the tunnel pool

// waitForStartupGate waits for the startup gate signal or context cancellation.
// Returns true if gate passed, false if context cancelled.

// runMaintenanceTicker runs the maintenance loop with periodic checks.

// logMaintenanceShutdown logs when the maintenance loop stops.

// maintainPool checks pool health and builds tunnels if needed

// rebuildTunnels handles failed-peer cleanup, backoff, and async tunnel building.

// cleanupExpiredTunnelsLocked removes expired tunnels (must hold mutex).
// It also tracks in-flight build timeouts to support the auto-fallback
// heuristic: three consecutive timeouts on an inbound pool with no public
// address will cause the pool to switch to zero-hop inbound tunnels.

// checkTunnelExpiration determines if a tunnel should be expired and logs the reason.

// isBuildTimeout checks if this is an inbound build timeout for the auto-fallback heuristic.

// removeTunnels deletes the specified tunnel IDs from the pool.

// updateFallbackCounter updates the in-flight expired counter for the auto-fallback heuristic.

// logCleanup logs the cleanup operation if any tunnels were removed.

// countTunnelsLocked counts active tunnels and those near expiry (must hold mutex)

// calculateNeededTunnels determines how many tunnels to build

// checkAndUpdateBackoff checks if a build should proceed based on exponential backoff,
// and updates the lastBuildTime if so. Must be called with p.mutex held (write lock).
// Returns true if building should proceed, false if still in backoff.

// launchAsyncBuild starts a goroutine to build tunnels.
// MUST be called WITHOUT holding p.mutex to prevent deadlock:
// the goroutine calls validateTunnelBuilder which acquires RLock.

// attemptBuildTunnelsAsync builds tunnels asynchronously and updates failure count

// attemptBuildTunnels attempts to build the specified number of tunnels
func (p *Pool) attemptBuildTunnels(count int) bool {
	if !p.validateTunnelBuilder() {
		return false
	}

	excludePeers := p.getAndLogFailedPeers()

	var successCount int
	for i := 0; i < count; i++ {
		if p.isContextCancelled(i, count) {
			return successCount > 0
		}

		req := p.prepareBuildRequest(excludePeers)
		tunnelID, err := p.executeBuildWithRetry(&req)
		if err != nil {
			continue
		}

		p.logBuildInitiated(i, tunnelID, req)
		successCount++
	}

	return successCount > 0
}

// isContextCancelled checks if the pool context has been cancelled.
// Logs the interruption with build progress details and returns true if cancelled.
func (p *Pool) isContextCancelled(completed, total int) bool {
	select {
	case <-p.ctx.Done():
		log.WithFields(logger.Fields{
			"at":        "(Pool) attemptBuildTunnels",
			"phase":     "tunnel_build",
			"reason":    "context cancelled, aborting build attempts",
			"completed": completed,
			"total":     total,
		}).Debug("tunnel build loop interrupted by context cancellation")
		return true
	default:
		return false
	}
}

// logBuildInitiated logs a successful tunnel build initiation.
func (p *Pool) logBuildInitiated(step int, tunnelID TunnelID, req BuildTunnelRequest) {
	log.WithFields(logger.Fields{
		"at":         "(Pool) attemptBuildTunnels",
		"phase":      "tunnel_build",
		"step":       step + 1,
		"reason":     "tunnel build initiated",
		"tunnel_id":  tunnelID,
		"hop_count":  req.HopCount,
		"is_inbound": req.IsInbound,
	}).Debug("initiated tunnel build")
}

// validateTunnelBuilder checks if the tunnel builder is configured.
// Returns true if builder is set, false otherwise with error logging.
func (p *Pool) validateTunnelBuilder() bool {
	p.mutex.RLock()
	builder := p.tunnelBuilder
	p.mutex.RUnlock()
	if builder == nil {
		log.WithFields(logger.Fields{
			"at":     "(Pool) attemptBuildTunnels",
			"phase":  "tunnel_build",
			"reason": "tunnel builder not configured",
		}).Error("cannot build tunnels: tunnel builder not set")
		return false
	}
	return true
}

// getAndLogFailedPeers retrieves the list of failed peers and logs if any exist.
// This prevents wasted retry attempts on peers that recently failed.
func (p *Pool) getAndLogFailedPeers() []common.Hash {
	excludePeers := p.GetFailedPeers()
	if len(excludePeers) > 0 {
		log.WithFields(logger.Fields{
			"at":            "Pool.attemptBuildTunnels",
			"phase":         "tunnel_build",
			"exclude_count": len(excludePeers),
			"reason":        "excluding recently failed peers from tunnel selection",
		}).Debug("excluding failed peers from tunnel building")
	}
	return excludePeers
}

// prepareBuildRequest creates a BuildTunnelRequest with progressive peer exclusion.
// Copies the base exclusion list to allow per-request modifications during retries.
func (p *Pool) prepareBuildRequest(excludePeers []common.Hash) BuildTunnelRequest {
	progressiveExclude := make([]common.Hash, len(excludePeers))
	copy(progressiveExclude, excludePeers)

	p.mutex.RLock()
	ourHash := p.routerHash
	provider := p.replyTunnelProvider
	sessionID := p.clientSessionID
	p.mutex.RUnlock()

	// CRITICAL VALIDATION: Ensure router identity is set
	// This prevents sending builds with zero identity that peers can't decrypt responses for
	if len(ourHash) == 0 {
		log.WithFields(logger.Fields{
			"at":         "prepareBuildRequest",
			"is_inbound": p.config.IsInbound,
			"hop_count":  p.config.HopCount,
		}).Warn("Router identity not yet initialized; using zero hash for now (this may cause decryption failures)")
	}

	replyTunnelID := TunnelID(0)
	replyGateway := ourHash
	// Inbound tunnels must terminate at this router (IBEP -> us). If we inject a
	// non-zero ReplyTunnelID here, the built tunnel endpoint forwards onward into
	// another tunnel instead of delivering locally, which can blackhole return
	// traffic such as DeliveryStatus ACKs.
	if !p.config.IsInbound && provider != nil {
		if id, gw, ok := provider(); ok {
			replyTunnelID = id
			if gw != (common.Hash{}) {
				replyGateway = gw
			}
		}
	}

	return BuildTunnelRequest{
		HopCount:                  p.config.HopCount,
		IsInbound:                 p.config.IsInbound,
		IsClientTunnel:            p.config.IsClientPool,
		ClientSessionID:           sessionID,
		UseShortBuild:             true, // Use modern STBM by default
		ExcludePeers:              progressiveExclude,
		RequireDirectConnectivity: true,          // FIX: Only select directly-contactable peers
		OurIdentity:               ourHash,       // Our router hash for reply routing
		ReplyGateway:              replyGateway,  // Last hop sends reply to inbound tunnel gateway (IBGW)
		ReplyTunnelID:             replyTunnelID, // Non-zero = TUNNEL delivery via existing session (NAT-safe)
	}
}

// executeBuildWithRetry attempts to build a tunnel with progressive peer exclusion on retries.
// Each retry excludes peers from previous failed attempts to improve diversity.
// Returns the tunnel ID on success or an error after all retries exhausted.
func (p *Pool) executeBuildWithRetry(req *BuildTunnelRequest) (TunnelID, error) {
	const maxRetries = 3
	var lastBuildPeers []common.Hash

	for retry := 0; retry < maxRetries; retry++ {
		if err := p.checkRetryContext(); err != nil {
			return 0, err
		}

		p.excludePreviouslyFailedPeers(req, retry, lastBuildPeers)

		builder := p.getTunnelBuilder()
		if builder == nil {
			return 0, oops.Errorf("tunnel builder not set")
		}
		result, err := builder.BuildTunnel(*req)
		if err != nil {
			p.logBuildFailure(err, retry, maxRetries, req)
			reason := classifyTunnelBuildFailureReason(err)
			lastBuildPeers = p.extractAndMarkFailedPeersWithReason(result, reason)
			continue
		}

		// BuildTunnelFromRequest already adds the tunnel to the pool,
		// so return immediately on success.
		return result.TunnelID, nil
	}

	return 0, oops.Errorf("tunnel build failed after %d retries", maxRetries)
}

// checkRetryContext verifies the pool context is still active before a retry attempt.
func (p *Pool) checkRetryContext() error {
	select {
	case <-p.ctx.Done():
		return oops.Errorf("tunnel build cancelled: context done")
	default:
		return nil
	}
}

// excludePreviouslyFailedPeers appends peers from the last failed build attempt
// to the exclusion list on retry, improving peer diversity.
func (p *Pool) excludePreviouslyFailedPeers(req *BuildTunnelRequest, retry int, lastBuildPeers []common.Hash) {
	if retry > 0 && len(lastBuildPeers) > 0 {
		req.ExcludePeers = append(req.ExcludePeers, lastBuildPeers...)
		log.WithFields(logger.Fields{
			"at":                  "Pool.executeBuildWithRetry",
			"phase":               "tunnel_build",
			"retry":               retry + 1,
			"excluded_from_retry": len(lastBuildPeers),
			"total_excluded":      len(req.ExcludePeers),
		}).Debug("excluding peers from previous failed attempt")
	}
}

// logBuildFailure logs detailed information about a tunnel build failure.
// Failures are typically caused by session establishment failures.
func (p *Pool) logBuildFailure(err error, retry, maxRetries int, req *BuildTunnelRequest) {
	log.WithFields(logger.Fields{
		"at":             "Pool.attemptBuildTunnels",
		"phase":          "tunnel_build",
		"operation":      "build_tunnel",
		"reason":         "tunnel build request failed",
		"error":          err.Error(),
		"retry":          retry + 1,
		"max_retries":    maxRetries,
		"hop_count":      req.HopCount,
		"is_inbound":     req.IsInbound,
		"pool_size":      len(p.tunnels),
		"excluded_peers": len(req.ExcludePeers),
	}).Warn("failed to build tunnel")
}

// SelectTunnel selects a tunnel from the pool using round-robin strategy.
// Returns nil if no active tunnels are available.
// SelectTunnel returns an active tunnel using lock-free round-robin selection.
// Returns nil if no active tunnels are available.
// This is a hot-path function called on every message send.
func (p *Pool) SelectTunnel() *TunnelState {
	// Lock-free read of cached active tunnels
	active := p.getActiveTunnels()
	if len(active) == 0 {
		log.WithFields(logger.Fields{
			"at":          "(Pool) SelectTunnel",
			"phase":       "tunnel_build",
			"reason":      "no active tunnels available for selection",
			"pool_size":   p.getTunnelCount(),
			"min_tunnels": p.config.MinTunnels,
			"impact":      "traffic cannot be routed until tunnels are built",
		}).Warn("no active tunnels available")
		return nil
	}

	// Lock-free round-robin selection using atomic increment
	index := p.selectionIndex.Add(1) - 1
	selected := active[index%uint32(len(active))]
	return selected
}

// getActiveTunnels returns the cached active tunnel slice with lock-free read.
// If the cache is dirty, it rebuilds the cache under a write lock.
func (p *Pool) getActiveTunnels() []*TunnelState {
	// Fast path: lock-free read of cached value
	if !p.cachedDirty.Load() {
		if cached := p.cachedActive.Load(); cached != nil {
			return cached.([]*TunnelState)
		}
	}

	// Slow path: rebuild cache under write lock
	p.mutex.Lock()
	defer p.mutex.Unlock()
	return p.rebuildActiveCacheLocked()
}

// rebuildActiveCacheLocked rebuilds the active tunnel cache (must hold write lock).
func (p *Pool) rebuildActiveCacheLocked() []*TunnelState {
	// Check again after acquiring lock (another goroutine may have rebuilt it)
	if !p.cachedDirty.Load() {
		if cached := p.cachedActive.Load(); cached != nil {
			return cached.([]*TunnelState)
		}
	}

	var active []*TunnelState
	for _, tunnel := range p.tunnels {
		if tunnel.State == TunnelReady {
			active = append(active, tunnel)
		}
	}
	sort.Slice(active, func(i, j int) bool {
		return active[i].ID < active[j].ID
	})

	// Atomic store of new cache
	p.cachedActive.Store(active)
	p.cachedDirty.Store(false)
	return active
}

// getTunnelCount returns the number of tunnels in the pool (lock-free read).
func (p *Pool) getTunnelCount() int {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	return len(p.tunnels)
}

// getActiveTunnelsLocked returns active tunnels sorted by ID for deterministic order (must hold mutex)
// DEPRECATED: Use getActiveTunnels() for lock-free access. This function remains for legacy callers.
func (p *Pool) getActiveTunnelsLocked() []*TunnelState {
	return p.rebuildActiveCacheLocked()
}

// GetPoolStats returns statistics about the pool
func (p *Pool) GetPoolStats() PoolStats {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	var stats PoolStats
	now := time.Now()

	for _, tunnel := range p.tunnels {
		switch tunnel.State {
		case TunnelBuilding:
			stats.Building++
		case TunnelReady:
			stats.Active++
			age := now.Sub(tunnel.CreatedAt)
			if age > p.config.TunnelLifetime-p.config.RebuildThreshold {
				stats.NearExpiry++
			}
		case TunnelFailed:
			stats.Failed++
		}
	}

	stats.Total = len(p.tunnels)
	return stats
}

// PoolStats contains statistics about a tunnel pool
type PoolStats struct {
	Total      int // Total tunnels in pool
	Active     int // Ready for use
	Building   int // Currently building
	Failed     int // Failed builds
	NearExpiry int // Active but near expiration
}

// RetryTunnelBuild retries building a tunnel that previously timed out.
// This method is called by the ReplyProcessor when a tunnel build times out
// and automatic retry is configured.
//
// Parameters:
//   - tunnelID: The ID of the tunnel that timed out (for logging correlation)
//   - isInbound: Direction of the tunnel (true=inbound, false=outbound)
//   - hopCount: Number of hops for the tunnel
//
// Returns error if the tunnel cannot be built (e.g., peer selection fails).
func (p *Pool) RetryTunnelBuild(tunnelID TunnelID, isInbound bool, hopCount int) error {
	log.WithFields(logger.Fields{
		"at":         "Pool.RetryTunnelBuild",
		"tunnel_id":  tunnelID,
		"is_inbound": isInbound,
		"hop_count":  hopCount,
	}).Info("retrying tunnel build after timeout")

	builder := p.getTunnelBuilder()
	if builder == nil {
		return oops.Errorf("tunnel builder not set; cannot retry tunnel build for tunnel %d", tunnelID)
	}

	p.mutex.RLock()
	routerHash := p.routerHash
	provider := p.replyTunnelProvider
	p.mutex.RUnlock()

	replyTunnelID := TunnelID(0)
	replyGateway := routerHash
	if provider != nil {
		if id, gw, ok := provider(); ok {
			replyTunnelID = id
			if gw != (common.Hash{}) {
				replyGateway = gw
			}
		}
	}

	req := BuildTunnelRequest{
		IsInbound:                 isInbound,
		IsClientTunnel:            p.config.IsClientPool,
		HopCount:                  hopCount,
		UseShortBuild:             true, // Modern STBM (type 25); legacy VTB (type 21) is rejected by current peers
		ExcludePeers:              p.GetFailedPeers(),
		RequireDirectConnectivity: true,
		OurIdentity:               routerHash,
		ReplyGateway:              replyGateway,
		ReplyTunnelID:             replyTunnelID, // Non-zero = TUNNEL delivery via existing session (NAT-safe)
	}

	result, err := builder.BuildTunnel(req)
	if err != nil {
		reason := classifyTunnelBuildFailureReason(err)
		p.extractAndMarkFailedPeersWithReason(result, reason)
		p.logRetryFailure(tunnelID, isInbound, hopCount, err)
		return err
	}

	log.WithFields(logger.Fields{
		"at":          "Pool.RetryTunnelBuild",
		"original_id": tunnelID,
		"new_id":      result.TunnelID,
		"is_inbound":  isInbound,
	}).Info("tunnel retry build initiated")

	return nil
}

// logRetryFailure logs a tunnel build retry failure, downgrading to Warn for transport unavailability.
func (p *Pool) logRetryFailure(tunnelID TunnelID, isInbound bool, hopCount int, err error) {
	fields := logger.Fields{
		"at":          "Pool.RetryTunnelBuild",
		"original_id": tunnelID,
		"is_inbound":  isInbound,
		"hop_count":   hopCount,
	}
	if strings.Contains(err.Error(), "no transports available") {
		log.WithError(err).WithFields(fields).Warn("tunnel build retry failed (no transports available)")
	} else {
		log.WithError(err).WithFields(fields).Error("failed to retry tunnel build after timeout")
	}
}

// extractAndMarkFailedPeers extracts peer hashes from a build result and marks
// each peer as failed. Returns the peer hashes for progressive exclusion on retry.
// Safe to call with a nil result (returns nil).
func (p *Pool) extractAndMarkFailedPeers(result *BuildTunnelResult) []common.Hash {
	return p.extractAndMarkFailedPeersWithReason(result, "tunnel_build_failed")
}

// extractAndMarkFailedPeersWithReason marks each failed peer with a classified
// reason so cooldown and tracker penalties can distinguish local/transient
// failures from hard peer-attributable failures.
func (p *Pool) extractAndMarkFailedPeersWithReason(result *BuildTunnelResult, reason string) []common.Hash {
	if result == nil || len(result.PeerHashes) == 0 {
		return nil
	}

	for _, peerHash := range result.PeerHashes {
		p.MarkPeerFailedWithReason(peerHash, reason)
	}

	log.WithFields(logger.Fields{
		"at":             "Pool.extractAndMarkFailedPeers",
		"phase":          "tunnel_build",
		"peer_count":     len(result.PeerHashes),
		"reason":         "marked peers from failed build for cooldown exclusion",
		"failure_reason": reason,
	}).Debug("extracted and marked failed peers from build result")

	return result.PeerHashes
}

// MarkPeerFailed records that a peer failed to establish a connection.
// This peer will be avoided for a cooldown period to prevent wasted retry attempts.
// If a PeerTracker is configured, the failure is also reported for reputation tracking.
func (p *Pool) MarkPeerFailed(peerHash common.Hash) {
	p.MarkPeerFailedWithReason(peerHash, "tunnel_build_failed")
}

// MarkPeerFailedWithReason records that a peer failed to establish a connection.
// This peer will be avoided for a reason-aware cooldown period.
// If a PeerTracker is configured, the failure is also reported for reputation tracking.
func (p *Pool) MarkPeerFailedWithReason(peerHash common.Hash, reason string) {
	cooldown := p.computePeerCooldown(peerHash, reason)

	p.failedPeersMu.Lock()
	p.failedPeers[peerHash] = time.Now()
	p.failedPeerCooldown[peerHash] = cooldown
	p.failedPeersMu.Unlock()

	// Read peerTracker under p.mutex (same lock used by SetPeerTracker)
	// to prevent a data race between MarkPeerFailed and SetPeerTracker.
	p.mutex.RLock()
	tracker := p.peerTracker
	p.mutex.RUnlock()

	// Report to NetDB peer tracker if configured (outside lock to avoid deadlock)
	if tracker != nil {
		tracker.RecordFailure(peerHash, reason)
	}

	log.WithFields(logger.Fields{
		"at":             "Pool.MarkPeerFailed",
		"phase":          "tunnel_build",
		"peer_hash":      logutil.HashPrefix(peerHash),
		"reason":         "peer connection failed, marking for cooldown",
		"failure_reason": reason,
		"cooldown":       cooldown,
		"impact":         "peer will be excluded from tunnel building temporarily",
		"tracked":        tracker != nil,
	}).Debug("marked peer as failed")
}

func (p *Pool) computePeerCooldown(peerHash common.Hash, reason string) time.Duration {
	base := baseCooldownForFailureReason(reason)

	p.mutex.RLock()
	tracker := p.peerTracker
	p.mutex.RUnlock()

	scorer, ok := tracker.(peerScorer)
	if !ok {
		return base
	}

	score := scorer.ScorePeer(peerHash)
	cooldown := base
	if score >= 0.75 {
		cooldown = time.Duration(float64(base) * 0.6)
	} else if score <= 0.25 {
		cooldown = time.Duration(float64(base) * 1.4)
	}

	if cooldown < minAdaptiveCooldown {
		cooldown = minAdaptiveCooldown
	}
	if cooldown > maxAdaptiveCooldown {
		cooldown = maxAdaptiveCooldown
	}

	return cooldown
}

func baseCooldownForFailureReason(reason string) time.Duration {
	r := strings.ToLower(reason)

	if containsAnySubstring(r,
		"local",
		"transport_not_ready",
		"no transports available",
		"context cancelled",
		"context canceled",
		"startup",
		"reply tunnel unavailable",
	) {
		return localFailureCooldown
	}

	if containsAnySubstring(r,
		"permanent",
		"incompatible",
		"invalid_routerinfo",
		"no valid address",
		"banned",
	) {
		return hardFailureCooldown
	}

	return ambiguousFailureDecay
}

func classifyTunnelBuildFailureReason(err error) string {
	if err == nil {
		return "tunnel_build_failed"
	}

	errText := strings.ToLower(err.Error())
	if containsAnySubstring(errText,
		"no transports available",
		"transport unavailable",
		"context cancelled",
		"context canceled",
		"reply tunnel unavailable",
		"router identity not yet initialized",
	) {
		return "tunnel_build_failed_local"
	}

	if containsAnySubstring(errText,
		"incompatible",
		"invalid routerinfo",
		"no valid address",
		"banned",
		"permanent",
	) {
		return "tunnel_build_failed_permanent"
	}

	return "tunnel_build_failed_ambiguous"
}

func containsAnySubstring(s string, terms ...string) bool {
	for _, term := range terms {
		if strings.Contains(s, term) {
			return true
		}
	}
	return false
}

// IsPeerFailed checks if a peer is currently in the failed state.
// Returns true if the peer failed recently and is still in cooldown.
func (p *Pool) IsPeerFailed(peerHash common.Hash) bool {
	p.failedPeersMu.RLock()
	defer p.failedPeersMu.RUnlock()
	failTime, exists := p.failedPeers[peerHash]
	if !exists {
		return false
	}
	cooldownPeriod := defaultPeerCooldown
	if custom, ok := p.failedPeerCooldown[peerHash]; ok && custom > 0 {
		cooldownPeriod = custom
	}
	return time.Since(failTime) < cooldownPeriod
}

// CleanupFailedPeers removes failed peer entries that have exceeded the cooldown period.
// Should be called periodically as part of pool maintenance.
func (p *Pool) CleanupFailedPeers() {
	p.failedPeersMu.Lock()
	defer p.failedPeersMu.Unlock()

	now := time.Now()
	var cleaned []common.Hash

	for hash, failTime := range p.failedPeers {
		cooldownPeriod := defaultPeerCooldown
		if custom, ok := p.failedPeerCooldown[hash]; ok && custom > 0 {
			cooldownPeriod = custom
		}
		if now.Sub(failTime) > cooldownPeriod {
			cleaned = append(cleaned, hash)
			delete(p.failedPeers, hash)
			delete(p.failedPeerCooldown, hash)
		}
	}

	if len(cleaned) > 0 {
		log.WithFields(logger.Fields{
			"at":            "Pool.CleanupFailedPeers",
			"phase":         "tunnel_build",
			"cleaned_count": len(cleaned),
			"remaining":     len(p.failedPeers),
			"cooldown":      "adaptive",
		}).Debug("cleaned up expired failed peer entries")
	}
}

// GetFailedPeers returns a list of peer hashes currently marked as failed.
// This is used to exclude failed peers from tunnel building attempts.
func (p *Pool) GetFailedPeers() []common.Hash {
	p.failedPeersMu.RLock()
	defer p.failedPeersMu.RUnlock()

	if len(p.failedPeers) == 0 {
		return nil
	}

	// Create slice with only peers still in cooldown
	now := time.Now()
	failed := make([]common.Hash, 0, len(p.failedPeers))

	for hash, failTime := range p.failedPeers {
		cooldownPeriod := defaultPeerCooldown
		if custom, ok := p.failedPeerCooldown[hash]; ok && custom > 0 {
			cooldownPeriod = custom
		}
		if now.Sub(failTime) < cooldownPeriod {
			failed = append(failed, hash)
		}
	}

	return failed
}
