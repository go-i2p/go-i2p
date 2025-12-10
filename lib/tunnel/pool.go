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
		BuildRetryDelay:  5 * time.Second,
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
	maintWg        sync.WaitGroup // Track maintenance goroutine
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
		lastBuildTime: time.Time{}, // Zero time
		ctx:           ctx,
		cancel:        cancel,
	}
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
	return
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
	if p.tunnelBuilder == nil {
		log.WithFields(logger.Fields{
			"at":     "(Pool) attemptBuildTunnels",
			"phase":  "tunnel_build",
			"reason": "tunnel builder not configured",
		}).Error("cannot build tunnels: tunnel builder not set")
		return false
	}

	var successCount int
	for i := 0; i < count; i++ {
		req := BuildTunnelRequest{
			HopCount:      p.config.HopCount,
			IsInbound:     p.config.IsInbound,
			UseShortBuild: true, // Use modern STBM by default
		}

		// Try to build tunnel with collision retry
		const maxRetries = 3
		var tunnelID TunnelID
		var err error
		for retry := 0; retry < maxRetries; retry++ {
			tunnelID, err = p.tunnelBuilder.BuildTunnel(req)
			if err != nil {
				// Enhanced logging for tunnel build failures - Issue #3 from AUDIT.md
				// These failures are typically caused by session establishment failures (Issue #2)
				log.WithFields(logger.Fields{
					"at":          "Pool.attemptBuildTunnels",
					"phase":       "tunnel_build",
					"operation":   "build_tunnel",
					"reason":      "tunnel build request failed",
					"error":       err.Error(),
					"retry":       retry + 1,
					"max_retries": maxRetries,
					"hop_count":   req.HopCount,
					"is_inbound":  req.IsInbound,
					"pool_size":   len(p.tunnels),
				}).Warn("failed to build tunnel")
				break
			}

			// Check for tunnel ID collision
			p.mutex.RLock()
			_, exists := p.tunnels[tunnelID]
			p.mutex.RUnlock()

			if !exists {
				// No collision, success
				break
			}

			// Collision detected - extremely rare but handle it
			log.WithFields(logger.Fields{
				"at":          "(Pool) attemptBuildTunnels",
				"phase":       "tunnel_build",
				"reason":      "tunnel ID collision detected",
				"tunnel_id":   tunnelID,
				"retry":       retry + 1,
				"max_retries": maxRetries,
				"probability": "extremely rare event",
			}).Warn("tunnel ID collision detected, retrying with new ID")

			// If this was our last retry, set error
			if retry == maxRetries-1 {
				err = fmt.Errorf("tunnel ID collision after %d retries", maxRetries)
			}
		}

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

	// Create build request with the same parameters
	req := BuildTunnelRequest{
		IsInbound: isInbound,
		HopCount:  hopCount,
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
