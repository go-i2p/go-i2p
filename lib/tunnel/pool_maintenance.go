package tunnel

import (
	"fmt"
	"time"

	"github.com/go-i2p/logger"
)

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

	if !p.waitForStartupGate() {
		return // context cancelled before startup
	}

	p.runMaintenanceTicker()
}

// waitForStartupGate waits for the startup gate signal or context cancellation.
// Returns true if gate passed, false if context cancelled.
func (p *Pool) waitForStartupGate() bool {
	p.mutex.RLock()
	gate := p.startupGate
	p.mutex.RUnlock()

	if gate == nil {
		return true // no gate, proceed immediately
	}

	select {
	case <-gate:
		return true // gate signalled, proceed
	case <-p.ctx.Done():
		return false // context cancelled
	}
}

// runMaintenanceTicker runs the maintenance loop with periodic checks.
func (p *Pool) runMaintenanceTicker() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	// Perform initial check immediately
	p.maintainPool()

	for {
		select {
		case <-p.ctx.Done():
			p.logMaintenanceShutdown()
			return
		case <-ticker.C:
			p.maintainPool()
		}
	}
}

// logMaintenanceShutdown logs when the maintenance loop stops.
func (p *Pool) logMaintenanceShutdown() {
	log.WithFields(logger.Fields{
		"at":     "(Pool) maintenanceLoop",
		"phase":  "tunnel_build",
		"reason": "received shutdown signal",
	}).Debug("pool maintenance loop stopped")
}

// maintainPool checks pool health and builds tunnels if needed
func (p *Pool) maintainPool() {
	var needed int
	var expiredCount int

	// Hold mutex only for inspection and calculation
	p.mutex.Lock()
	p.cleanupExpiredTunnelsLocked()
	expiredCount = p.inFlightExpiredCount
	activeCount, nearExpiry := p.countTunnelsLocked()
	needed = p.calculateNeededTunnels(activeCount, nearExpiry)
	p.mutex.Unlock()

	// Auto-fallback: switch exploratory inbound pool to 0-hop after repeated
	// build timeouts when no public address is available. Client pools are
	// excluded — their hop count is set by the application.
	if p.config.IsInbound && !p.config.IsClientPool && expiredCount >= autoFallbackThreshold {
		p.checkAutoFallback()
	}

	if needed > 0 {
		p.rebuildTunnels(needed)
	}
}

// rebuildTunnels handles failed-peer cleanup, backoff, and async tunnel building.
func (p *Pool) rebuildTunnels(needed int) {
	p.CleanupFailedPeers()

	log.WithFields(logger.Fields{
		"at":          "Pool.maintainPool",
		"phase":       "tunnel_build",
		"needed":      needed,
		"min_tunnels": p.config.MinTunnels,
		"max_tunnels": p.config.MaxTunnels,
		"is_inbound":  p.config.IsInbound,
	}).Warn("tunnel pool below minimum, building replacement tunnels")

	// Re-acquire mutex for backoff bookkeeping
	p.mutex.Lock()
	activeCount, nearExpiry := p.countTunnelsLocked()
	needed = p.calculateNeededTunnels(activeCount, nearExpiry)
	var shouldBuild bool
	if needed > 0 {
		shouldBuild = p.checkAndUpdateBackoff()
	}
	p.mutex.Unlock()

	if shouldBuild {
		p.launchAsyncBuild(needed)
	}

	log.WithFields(logger.Fields{
		"at":         "Pool.maintainPool",
		"phase":      "tunnel_build",
		"operation":  "build_complete",
		"requested":  needed,
		"is_inbound": p.config.IsInbound,
	}).Debug("tunnel build attempt completed")
}

// cleanupExpiredTunnelsLocked removes expired tunnels (must hold mutex).
// It also tracks in-flight build timeouts to support the auto-fallback
// heuristic: three consecutive timeouts on an inbound pool with no public
// address will cause the pool to switch to zero-hop inbound tunnels.
func (p *Pool) cleanupExpiredTunnelsLocked() {
	now := time.Now()
	var expired []TunnelID
	var hasActiveTunnel bool
	var buildTimeouts int

	for id, tunnel := range p.tunnels {
		age := now.Sub(tunnel.CreatedAt)

		if shouldExpireTunnel := p.checkTunnelExpiration(tunnel, age, id); shouldExpireTunnel {
			expired = append(expired, id)
			if p.isBuildTimeout(tunnel, age) {
				buildTimeouts++
			}
		} else if tunnel.State == TunnelReady {
			hasActiveTunnel = true
		}
	}

	p.removeTunnels(expired)
	p.updateFallbackCounter(hasActiveTunnel, buildTimeouts)
	p.logCleanup(expired)
}

// checkTunnelExpiration determines if a tunnel should be expired and logs the reason.
func (p *Pool) checkTunnelExpiration(tunnel *TunnelState, age time.Duration, id TunnelID) bool {
	// Remove tunnels that exceeded lifetime
	if tunnel.State == TunnelReady && age > p.config.TunnelLifetime {
		log.WithFields(logger.Fields{
			"at":           "(Pool) cleanupExpiredTunnelsLocked",
			"phase":        "tunnel_build",
			"reason":       "tunnel exceeded lifetime",
			"tunnel_id":    id,
			"age":          age,
			"max_lifetime": p.config.TunnelLifetime,
		}).Debug("tunnel expired")
		return true
	}

	// Remove failed tunnels
	if tunnel.State == TunnelFailed {
		return true
	}

	// Remove in-flight builds that exceeded the 90-second VTBRM deadline
	if tunnel.State == TunnelBuilding && age > tunnelBuildTimeout {
		return true
	}

	return false
}

// isBuildTimeout checks if this is an inbound build timeout for the auto-fallback heuristic.
func (p *Pool) isBuildTimeout(tunnel *TunnelState, age time.Duration) bool {
	if !p.config.IsInbound {
		return false
	}
	if tunnel.State == TunnelFailed && age >= tunnelBuildTimeout {
		return true
	}
	if tunnel.State == TunnelBuilding && age > tunnelBuildTimeout {
		return true
	}
	return false
}

// removeTunnels deletes the specified tunnel IDs from the pool.
func (p *Pool) removeTunnels(expired []TunnelID) {
	for _, id := range expired {
		delete(p.tunnels, id)
	}
}

// updateFallbackCounter updates the in-flight expired counter for the auto-fallback heuristic.
func (p *Pool) updateFallbackCounter(hasActiveTunnel bool, buildTimeouts int) {
	if hasActiveTunnel {
		p.inFlightExpiredCount = 0
	} else if buildTimeouts > 0 {
		p.inFlightExpiredCount += buildTimeouts
	}
}

// logCleanup logs the cleanup operation if any tunnels were removed.
func (p *Pool) logCleanup(expired []TunnelID) {
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

// checkAndUpdateBackoff checks if a build should proceed based on exponential backoff,
// and updates the lastBuildTime if so. Must be called with p.mutex held (write lock).
// Returns true if building should proceed, false if still in backoff.
func (p *Pool) checkAndUpdateBackoff() bool {
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
			"at":              "(Pool) checkAndUpdateBackoff",
			"phase":           "tunnel_build",
			"reason":          "skipping build due to backoff delay",
			"backoff_delay":   backoffDelay,
			"backoff_delay_s": backoffDelay.Seconds(),
			"failures":        p.buildFailures,
			"time_remaining":  remaining,
			"next_attempt_in": remaining.Round(time.Second),
		}).Warn("delaying tunnel build due to previous failures (exponential backoff)")
		return false
	}

	p.lastBuildTime = now
	return true
}

// launchAsyncBuild starts a goroutine to build tunnels.
// MUST be called WITHOUT holding p.mutex to prevent deadlock:
// the goroutine calls validateTunnelBuilder which acquires RLock.
func (p *Pool) launchAsyncBuild(count int) {
	p.maintWg.Add(1)
	go func() {
		defer p.maintWg.Done()
		p.attemptBuildTunnelsAsync(count)
	}()
}

// attemptBuildTunnelsAsync builds tunnels asynchronously and updates failure count
func (p *Pool) attemptBuildTunnelsAsync(count int) {
	// Check if context is cancelled before starting
	select {
	case <-p.ctx.Done():
		return
	default:
	}

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
