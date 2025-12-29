package tunnel

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/logger"
)

// TunnelState represents the current state of a tunnel during building
type TunnelState struct {
	ID            TunnelID
	Hops          []common.Hash    // Router hashes for each hop
	State         TunnelBuildState // Current build state
	CreatedAt     time.Time        // When tunnel building started
	ResponseCount int              // Number of responses received
	Responses     []BuildResponse  // Responses from each hop
	IsInbound     bool             // True if this is an inbound tunnel
}

// TunnelBuildState represents different states during tunnel building
type TunnelBuildState int

const (
	TunnelBuilding TunnelBuildState = iota // Tunnel is being built
	TunnelReady                            // Tunnel is ready for use
	TunnelFailed                           // Tunnel build failed
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

// BuilderInterface defines interface for building tunnels
type BuilderInterface interface {
	// BuildTunnel initiates building a new tunnel with the specified parameters
	BuildTunnel(req BuildTunnelRequest) (TunnelID, error)
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
}

// DefaultPoolConfig returns a configuration with sensible defaults
func DefaultPoolConfig() PoolConfig {
	return PoolConfig{
		MinTunnels:       4,
		MaxTunnels:       6,
		TunnelLifetime:   10 * time.Minute,
		RebuildThreshold: 2 * time.Minute,
		BuildRetryDelay:  2 * time.Second, // BUG FIX #4: Reduced initial delay (exponential backoff will increase)
		MaxBuildRetries:  3,
		HopCount:         3,
		IsInbound:        false,
	}
}

// Pool manages a collection of tunnels with automatic maintenance
type Pool struct {
	tunnels        map[TunnelID]*TunnelState
	mutex          sync.RWMutex
	peerSelector   PeerSelector
	tunnelBuilder  BuilderInterface
	config         PoolConfig
	selectionIndex int       // For round-robin selection
	lastBuildTime  time.Time // Track last build attempt for backoff
	buildFailures  int       // Consecutive build failures
	ctx            context.Context
	cancel         context.CancelFunc
	maintWg        sync.WaitGroup            // Track maintenance goroutine
	failedPeers    map[common.Hash]time.Time // BUG FIX #5: Track failed peer connection attempts
	failedPeersMu  sync.RWMutex              // BUG FIX #5: Protect failed peers map
	peerTracker    PeerTracker               // Optional peer reputation tracking (netdb integration)
}

// PeerTracker interface for recording peer connection outcomes.
// This allows Pool to report connection results to NetDB for reputation tracking.
type PeerTracker interface {
	RecordFailure(hash common.Hash, reason string)
	RecordSuccess(hash common.Hash, responseTimeMs int64)
}

// NewTunnelPool creates a new tunnel pool with the given peer selector and default configuration
func NewTunnelPool(selector PeerSelector) *Pool {
	return NewTunnelPoolWithConfig(selector, DefaultPoolConfig())
}

// NewTunnelPoolWithConfig creates a new tunnel pool with custom configuration
func NewTunnelPoolWithConfig(selector PeerSelector, config PoolConfig) *Pool {
	ctx, cancel := context.WithCancel(context.Background())
	return &Pool{
		tunnels:       make(map[TunnelID]*TunnelState),
		peerSelector:  selector,
		config:        config,
		lastBuildTime: time.Time{},                     // Zero time
		failedPeers:   make(map[common.Hash]time.Time), // BUG FIX #5: Track failed connection attempts
		ctx:           ctx,
		cancel:        cancel,
		peerTracker:   nil, // Will be set via SetPeerTracker if NetDB integration is enabled
	}
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

// SetTunnelBuilder sets the tunnel builder for this pool.
// Must be called before starting pool maintenance.
func (p *Pool) SetTunnelBuilder(builder BuilderInterface) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.tunnelBuilder = builder
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

// RemoveTunnel removes a tunnel from the pool
func (p *Pool) RemoveTunnel(id TunnelID) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	tunnel, existed := p.tunnels[id]
	delete(p.tunnels, id)
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
func (p *Pool) StartMaintenance() error {
	if p.tunnelBuilder == nil {
		log.WithFields(logger.Fields{
			"at":     "(Pool) StartMaintenance",
			"phase":  "tunnel_build",
			"reason": "tunnel builder not configured",
		}).Error("tunnel builder not set")
		return fmt.Errorf("tunnel builder not set")
	}

	p.maintWg.Add(1)
	go p.maintenanceLoop()
	log.WithFields(logger.Fields{
		"at":          "(Pool) StartMaintenance",
		"phase":       "tunnel_build",
		"step":        1,
		"reason":      "pool maintenance goroutine started",
		"min_tunnels": p.config.MinTunnels,
		"max_tunnels": p.config.MaxTunnels,
		"hop_count":   p.config.HopCount,
		"is_inbound":  p.config.IsInbound,
	}).Info("started tunnel pool maintenance")
	return nil
}

// maintenanceLoop is the background goroutine that maintains the tunnel pool
func (p *Pool) maintenanceLoop() {
	defer p.maintWg.Done()

	// Check pool health every 30 seconds
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	// Perform initial check immediately
	p.maintainPool()

	for {
		select {
		case <-p.ctx.Done():
			log.WithFields(logger.Fields{
				"at":     "(Pool) maintenanceLoop",
				"phase":  "tunnel_build",
				"reason": "received shutdown signal",
			}).Debug("pool maintenance loop stopped")
			return
		case <-ticker.C:
			p.maintainPool()
		}
	}
}

// maintainPool checks pool health and builds tunnels if needed
func (p *Pool) maintainPool() {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	// Clean up expired tunnels
	p.cleanupExpiredTunnelsLocked()

	// Count active and near-expiry tunnels
	activeCount, nearExpiry := p.countTunnelsLocked()

	// Determine how many new tunnels to build
	needed := p.calculateNeededTunnels(activeCount, nearExpiry)

	if needed > 0 {
		// BUG FIX #5: Clean up expired failed peer entries
		p.CleanupFailedPeers()

		// Enhanced logging for tunnel pool health - Issue #4 from AUDIT.md
		log.WithFields(logger.Fields{
			"at":                   "Pool.maintainPool",
			"phase":                "tunnel_build",
			"step":                 "determine_needs",
			"operation":            "check_pool_health",
			"reason":               "tunnel pool below threshold",
			"active":               activeCount,
			"near_expiry":          nearExpiry,
			"needed":               needed,
			"min_tunnels":          p.config.MinTunnels,
			"max_tunnels":          p.config.MaxTunnels,
			"is_inbound":           p.config.IsInbound,
			"consecutive_failures": p.buildFailures,
		}).Warn("tunnel pool below minimum, building replacement tunnels")

		// Build tunnels with exponential backoff on failures
		p.buildTunnelsWithBackoff(needed)

		// Log completion of build attempt
		log.WithFields(logger.Fields{
			"at":         "Pool.maintainPool",
			"phase":      "tunnel_build",
			"operation":  "build_complete",
			"requested":  needed,
			"is_inbound": p.config.IsInbound,
		}).Debug("tunnel build attempt completed")
	}
}

// cleanupExpiredTunnelsLocked removes expired tunnels (must hold mutex)
func (p *Pool) cleanupExpiredTunnelsLocked() {
	now := time.Now()
	var expired []TunnelID

	for id, tunnel := range p.tunnels {
		age := now.Sub(tunnel.CreatedAt)

		// Remove tunnels that exceeded lifetime
		if tunnel.State == TunnelReady && age > p.config.TunnelLifetime {
			expired = append(expired, id)
			log.WithFields(logger.Fields{
				"at":           "(Pool) cleanupExpiredTunnelsLocked",
				"phase":        "tunnel_build",
				"reason":       "tunnel exceeded lifetime",
				"tunnel_id":    id,
				"age":          age,
				"max_lifetime": p.config.TunnelLifetime,
			}).Debug("tunnel expired")
		}

		// Remove failed tunnels
		if tunnel.State == TunnelFailed {
			expired = append(expired, id)
		}
	}

	for _, id := range expired {
		delete(p.tunnels, id)
	}

	if len(expired) > 0 {
		log.WithFields(logger.Fields{
			"at":        "(Pool) cleanupExpiredAndFailedTunnels",
			"phase":     "tunnel_build",
			"reason":    "removed expired and failed tunnels",
			"count":     len(expired),
			"pool_size": len(p.tunnels),
		}).Debug("cleaned up expired/failed tunnels")
	}
}

// countTunnelsLocked counts active tunnels and those near expiry (must hold mutex)
func (p *Pool) countTunnelsLocked() (active, nearExpiry int) {
	now := time.Now()
	expiryThreshold := p.config.TunnelLifetime - p.config.RebuildThreshold

	for _, tunnel := range p.tunnels {
		if tunnel.State == TunnelReady {
			active++
			age := now.Sub(tunnel.CreatedAt)
			if age > expiryThreshold {
				nearExpiry++
			}
		}
	}
	return active, nearExpiry
}

// calculateNeededTunnels determines how many tunnels to build
func (p *Pool) calculateNeededTunnels(activeCount, nearExpiry int) int {
	// Account for tunnels that will soon expire
	usableCount := activeCount - nearExpiry

	// Build to reach minimum, but don't exceed maximum
	needed := p.config.MinTunnels - usableCount
	if needed < 0 {
		needed = 0
	}

	// Don't build more than would exceed maximum including currently building
	// Note: activeCount includes only ready tunnels, not building ones
	totalAfterBuild := activeCount + needed
	if totalAfterBuild > p.config.MaxTunnels {
		needed = p.config.MaxTunnels - activeCount
		if needed < 0 {
			needed = 0
		}
	}

	return needed
}

// buildTunnelsWithBackoff builds tunnels with exponential backoff on failures
func (p *Pool) buildTunnelsWithBackoff(count int) {
	now := time.Now()

	// Calculate backoff delay based on consecutive failures
	backoffDelay := p.config.BuildRetryDelay * time.Duration(1<<uint(p.buildFailures))
	if backoffDelay > 5*time.Minute {
		backoffDelay = 5 * time.Minute // Cap at 5 minutes
	}

	// Check if we need to wait due to backoff
	if !p.lastBuildTime.IsZero() && now.Sub(p.lastBuildTime) < backoffDelay {
		remaining := backoffDelay - now.Sub(p.lastBuildTime)
		log.WithFields(logger.Fields{
			"at":              "(Pool) buildTunnelsWithBackoff",
			"phase":           "tunnel_build",
			"reason":          "skipping build due to backoff delay",
			"backoff_delay":   backoffDelay,
			"backoff_delay_s": backoffDelay.Seconds(),
			"failures":        p.buildFailures,
			"time_remaining":  remaining,
			"next_attempt_in": remaining.Round(time.Second),
		}).Warn("delaying tunnel build due to previous failures (exponential backoff)")
		return
	}

	p.lastBuildTime = now

	// Attempt to build tunnels in separate goroutine to avoid blocking with lock held
	go p.attemptBuildTunnelsAsync(count)
}

// attemptBuildTunnelsAsync builds tunnels asynchronously and updates failure count
func (p *Pool) attemptBuildTunnelsAsync(count int) {
	success := p.attemptBuildTunnels(count)

	// Update failure count with lock
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if success {
		p.buildFailures = 0 // Reset on success
	} else {
		p.buildFailures++
		if p.buildFailures > p.config.MaxBuildRetries {
			log.WithFields(logger.Fields{
				"at":          "(Pool) attemptBuildTunnelsAsync",
				"phase":       "tunnel_build",
				"reason":      "consecutive build failures exceeded threshold",
				"failures":    p.buildFailures,
				"max_retries": p.config.MaxBuildRetries,
			}).Warn("max build retries exceeded")
			p.buildFailures = p.config.MaxBuildRetries // Cap failures
		}
	}
}

// attemptBuildTunnels attempts to build the specified number of tunnels
func (p *Pool) attemptBuildTunnels(count int) bool {
	if !p.validateTunnelBuilder() {
		return false
	}

	excludePeers := p.getAndLogFailedPeers()

	var successCount int
	for i := 0; i < count; i++ {
		req := p.prepareBuildRequest(excludePeers)
		tunnelID, err := p.executeBuildWithRetry(&req)
		if err != nil {
			continue
		}

		log.WithFields(logger.Fields{
			"at":         "(Pool) attemptBuildTunnels",
			"phase":      "tunnel_build",
			"step":       i + 1,
			"reason":     "tunnel build initiated",
			"tunnel_id":  tunnelID,
			"hop_count":  req.HopCount,
			"is_inbound": req.IsInbound,
		}).Debug("initiated tunnel build")
		successCount++
	}

	return successCount > 0
}

// validateTunnelBuilder checks if the tunnel builder is configured.
// Returns true if builder is set, false otherwise with error logging.
func (p *Pool) validateTunnelBuilder() bool {
	if p.tunnelBuilder == nil {
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

	return BuildTunnelRequest{
		HopCount:                  p.config.HopCount,
		IsInbound:                 p.config.IsInbound,
		UseShortBuild:             true, // Use modern STBM by default
		ExcludePeers:              progressiveExclude,
		RequireDirectConnectivity: true, // BUG FIX: Only select directly-contactable peers
	}
}

// executeBuildWithRetry attempts to build a tunnel with progressive peer exclusion on retries.
// Each retry excludes peers from previous failed attempts to improve diversity.
// Returns the tunnel ID on success or an error after all retries exhausted.
func (p *Pool) executeBuildWithRetry(req *BuildTunnelRequest) (TunnelID, error) {
	const maxRetries = 3
	var lastBuildPeers []common.Hash // Track peers from last build attempt

	for retry := 0; retry < maxRetries; retry++ {
		if retry > 0 && len(lastBuildPeers) > 0 {
			req.ExcludePeers = append(req.ExcludePeers, lastBuildPeers...)
			log.WithFields(logger.Fields{
				"at":                  "Pool.attemptBuildTunnels",
				"phase":               "tunnel_build",
				"retry":               retry + 1,
				"excluded_from_retry": len(lastBuildPeers),
				"total_excluded":      len(req.ExcludePeers),
			}).Debug("excluding peers from previous failed attempt")
		}

		tunnelID, err := p.tunnelBuilder.BuildTunnel(*req)
		if err != nil {
			p.logBuildFailure(err, retry, maxRetries, req)
			// TODO: Extract peer hashes from build result for next retry
			continue
		}

		if !p.checkTunnelCollision(tunnelID, retry, maxRetries) {
			return tunnelID, nil
		}

		// Last retry with collision
		if retry == maxRetries-1 {
			return 0, fmt.Errorf("tunnel ID collision after %d retries", maxRetries)
		}
	}

	return 0, fmt.Errorf("tunnel build failed after %d retries", maxRetries)
}

// logBuildFailure logs detailed information about a tunnel build failure.
// Enhanced logging for Issue #3 from AUDIT.md - failures typically caused by session establishment failures.
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

// checkTunnelCollision checks if a tunnel ID already exists in the pool.
// Returns true if collision detected (extremely rare), false if ID is available.
func (p *Pool) checkTunnelCollision(tunnelID TunnelID, retry, maxRetries int) bool {
	p.mutex.RLock()
	_, exists := p.tunnels[tunnelID]
	p.mutex.RUnlock()

	if !exists {
		return false
	}

	log.WithFields(logger.Fields{
		"at":          "(Pool) attemptBuildTunnels",
		"phase":       "tunnel_build",
		"reason":      "tunnel ID collision detected",
		"tunnel_id":   tunnelID,
		"retry":       retry + 1,
		"max_retries": maxRetries,
		"probability": "extremely rare event",
	}).Warn("tunnel ID collision detected, retrying with new ID")

	return true
}

// SelectTunnel selects a tunnel from the pool using round-robin strategy.
// Returns nil if no active tunnels are available.
func (p *Pool) SelectTunnel() *TunnelState {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	active := p.getActiveTunnelsLocked()
	if len(active) == 0 {
		log.WithFields(logger.Fields{
			"at":          "(Pool) SelectTunnel",
			"phase":       "tunnel_build",
			"reason":      "no active tunnels available for selection",
			"pool_size":   len(p.tunnels),
			"min_tunnels": p.config.MinTunnels,
			"impact":      "traffic cannot be routed until tunnels are built",
		}).Warn("no active tunnels available")
		return nil
	}

	// Round-robin selection - select first, then increment
	selected := active[p.selectionIndex%len(active)]
	p.selectionIndex++
	return selected
}

// getActiveTunnelsLocked returns active tunnels sorted by ID for deterministic order (must hold mutex)
func (p *Pool) getActiveTunnelsLocked() []*TunnelState {
	var active []*TunnelState
	for _, tunnel := range p.tunnels {
		if tunnel.State == TunnelReady {
			active = append(active, tunnel)
		}
	}

	// Sort by tunnel ID to ensure deterministic round-robin selection
	sort.Slice(active, func(i, j int) bool {
		return active[i].ID < active[j].ID
	})

	return active
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
		"phase":      "tunnel_build",
		"operation":  "retry_timed_out_tunnel",
		"tunnel_id":  tunnelID,
		"is_inbound": isInbound,
		"hop_count":  hopCount,
		"reason":     "tunnel build timeout detected, attempting retry",
	}).Info("retrying tunnel build after timeout")

	// BUG FIX: Exclude failed peers from retry attempts
	excludePeers := p.GetFailedPeers()

	// Create build request with the same parameters
	req := BuildTunnelRequest{
		IsInbound:                 isInbound,
		HopCount:                  hopCount,
		ExcludePeers:              excludePeers, // BUG FIX: Exclude recently failed peers from retry
		RequireDirectConnectivity: true,         // BUG FIX: Only select directly-contactable peers
	}

	// Attempt to build the tunnel
	newTunnelID, err := p.tunnelBuilder.BuildTunnel(req)
	if err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"at":          "Pool.RetryTunnelBuild",
			"phase":       "tunnel_build",
			"operation":   "retry_failed",
			"original_id": tunnelID,
			"is_inbound":  isInbound,
			"hop_count":   hopCount,
			"reason":      "tunnel builder returned error",
		}).Error("failed to retry tunnel build after timeout")
		return err
	}

	log.WithFields(logger.Fields{
		"at":          "Pool.RetryTunnelBuild",
		"phase":       "tunnel_build",
		"operation":   "retry_success",
		"original_id": tunnelID,
		"new_id":      newTunnelID,
		"is_inbound":  isInbound,
		"hop_count":   hopCount,
		"reason":      "retry tunnel build initiated successfully",
	}).Info("tunnel retry build initiated")

	return nil
}

// BUG FIX #5: Failed peer tracking to avoid retry loops
// MarkPeerFailed records that a peer failed to establish a connection.
// This peer will be avoided for a cooldown period to prevent wasted retry attempts.
// If a PeerTracker is configured, the failure is also reported for reputation tracking.
func (p *Pool) MarkPeerFailed(peerHash common.Hash) {
	p.failedPeersMu.Lock()
	p.failedPeers[peerHash] = time.Now()
	tracker := p.peerTracker // Get tracker reference while holding lock
	p.failedPeersMu.Unlock()

	// Report to NetDB peer tracker if configured (outside lock to avoid deadlock)
	if tracker != nil {
		tracker.RecordFailure(peerHash, "tunnel_build_failed")
	}

	log.WithFields(logger.Fields{
		"at":        "Pool.MarkPeerFailed",
		"phase":     "tunnel_build",
		"peer_hash": fmt.Sprintf("%x", peerHash[:8]),
		"reason":    "peer connection failed, marking for cooldown",
		"impact":    "peer will be excluded from tunnel building temporarily",
		"tracked":   tracker != nil,
	}).Debug("marked peer as failed")
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
	// 5-minute cooldown period
	cooldownPeriod := 5 * time.Minute
	return time.Since(failTime) < cooldownPeriod
}

// CleanupFailedPeers removes failed peer entries that have exceeded the cooldown period.
// Should be called periodically as part of pool maintenance.
func (p *Pool) CleanupFailedPeers() {
	p.failedPeersMu.Lock()
	defer p.failedPeersMu.Unlock()

	now := time.Now()
	cooldownPeriod := 5 * time.Minute
	var cleaned []common.Hash

	for hash, failTime := range p.failedPeers {
		if now.Sub(failTime) > cooldownPeriod {
			cleaned = append(cleaned, hash)
			delete(p.failedPeers, hash)
		}
	}

	if len(cleaned) > 0 {
		log.WithFields(logger.Fields{
			"at":            "Pool.CleanupFailedPeers",
			"phase":         "tunnel_build",
			"cleaned_count": len(cleaned),
			"remaining":     len(p.failedPeers),
			"cooldown":      cooldownPeriod,
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
	cooldownPeriod := 5 * time.Minute
	failed := make([]common.Hash, 0, len(p.failedPeers))

	for hash, failTime := range p.failedPeers {
		if now.Sub(failTime) < cooldownPeriod {
			failed = append(failed, hash)
		}
	}

	return failed
}
