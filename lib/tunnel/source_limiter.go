package tunnel

import (
	"sync"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/go-i2p/logger"
)

// SourceLimiter tracks tunnel build request rates per source router.
// It uses a token bucket algorithm with per-source tracking and automatic cleanup
// to protect against single-source tunnel flooding attacks.
//
// Design decisions:
// - Token bucket allows short bursts while limiting sustained rates
// - Automatic banning for sources that exceed limits excessively
// - Background cleanup prevents memory exhaustion from tracking
// - Thread-safe for concurrent access from multiple goroutines
type SourceLimiter struct {
	mu      sync.RWMutex
	sources map[common.Hash]*sourceState

	// Configuration
	maxRequestsPerMinute int           // Max requests per source per minute
	burstSize            int           // Burst allowance (max tokens)
	banDuration          time.Duration // How long to ban excessive requesters
	cleanupInterval      time.Duration // How often to clean stale entries

	// Statistics (protected by mu)
	totalRequests   uint64
	totalRejections uint64

	stopChan chan struct{}
	wg       sync.WaitGroup
}

// sourceState tracks the rate limiting state for a single source router.
type sourceState struct {
	tokens       float64   // Current token count
	lastUpdate   time.Time // Last token update time
	requestCount uint64    // Total requests from this source
	rejectCount  uint64    // Total rejections for this source
	bannedUntil  time.Time // If set, reject until this time
}

// NewSourceLimiter creates a new per-source rate limiter with default configuration.
// For custom configuration, use NewSourceLimiterWithConfig.
func NewSourceLimiter() *SourceLimiter {
	return NewSourceLimiterWithConfig(config.Defaults().Tunnel)
}

// NewSourceLimiterWithConfig creates a new per-source rate limiter with the specified configuration.
//
// Parameters:
// - cfg: TunnelDefaults containing rate limit configuration
//
// The limiter will start a background cleanup goroutine automatically.
func NewSourceLimiterWithConfig(cfg config.TunnelDefaults) *SourceLimiter {
	sl := &SourceLimiter{
		sources:              make(map[common.Hash]*sourceState),
		maxRequestsPerMinute: cfg.MaxBuildRequestsPerMinute,
		burstSize:            cfg.BuildRequestBurstSize,
		banDuration:          cfg.SourceBanDuration,
		cleanupInterval:      5 * time.Minute,
		stopChan:             make(chan struct{}),
	}

	sl.wg.Add(1)
	go sl.cleanupLoop()

	log.WithFields(logger.Fields{
		"at":                   "NewSourceLimiterWithConfig",
		"phase":                "tunnel_build",
		"reason":               "source limiter initialized",
		"max_requests_per_min": sl.maxRequestsPerMinute,
		"burst_size":           sl.burstSize,
		"ban_duration":         sl.banDuration,
	}).Info("source limiter started")

	return sl
}

// AllowRequest checks if a tunnel build request from the given source should be allowed.
// Uses token bucket algorithm: tokens replenish over time, each request consumes one token.
//
// Parameters:
// - sourceHash: The router hash of the tunnel build requester
//
// Returns:
// - allowed: true if the request should be accepted
// - reason: human-readable reason if rejected (empty string if accepted)
//
// Side effects:
// - Creates tracking entry for new sources
// - Updates token counts and timestamps
// - May auto-ban sources with excessive rejections (>10 rejections)
func (sl *SourceLimiter) AllowRequest(sourceHash common.Hash) (bool, string) {
	sl.mu.Lock()
	defer sl.mu.Unlock()

	now := time.Now()
	sl.totalRequests++

	state, exists := sl.sources[sourceHash]
	if !exists {
		state = &sourceState{
			tokens:     float64(sl.burstSize),
			lastUpdate: now,
		}
		sl.sources[sourceHash] = state
	}

	state.requestCount++

	// Check ban status first
	if now.Before(state.bannedUntil) {
		state.rejectCount++
		sl.totalRejections++
		log.WithFields(logger.Fields{
			"at":           "SourceLimiter.AllowRequest",
			"phase":        "tunnel_build",
			"reason":       "source_banned",
			"source":       truncateHash(sourceHash),
			"banned_until": state.bannedUntil.Format(time.RFC3339),
		}).Debug("rejecting request from banned source")
		return false, "source_banned"
	}

	// Replenish tokens based on elapsed time
	elapsed := now.Sub(state.lastUpdate)
	tokensToAdd := elapsed.Minutes() * float64(sl.maxRequestsPerMinute)
	state.tokens += tokensToAdd
	if state.tokens > float64(sl.burstSize) {
		state.tokens = float64(sl.burstSize)
	}
	state.lastUpdate = now

	// Check if request is allowed (need at least 1 token)
	if state.tokens >= 1.0 {
		state.tokens -= 1.0
		return true, ""
	}

	// Rate exceeded - increment reject count and potentially ban
	state.rejectCount++
	sl.totalRejections++

	// Auto-ban if excessive rejections (more than 10 rejections)
	if state.rejectCount > 10 {
		state.bannedUntil = now.Add(sl.banDuration)
		log.WithFields(logger.Fields{
			"at":           "SourceLimiter.AllowRequest",
			"phase":        "tunnel_build",
			"reason":       "source_auto_banned",
			"source":       truncateHash(sourceHash),
			"reject_count": state.rejectCount,
			"ban_duration": sl.banDuration,
		}).Warn("auto-banning source due to excessive rate limit violations")
		return false, "source_auto_banned"
	}

	log.WithFields(logger.Fields{
		"at":           "SourceLimiter.AllowRequest",
		"phase":        "tunnel_build",
		"reason":       "rate_limit_exceeded",
		"source":       truncateHash(sourceHash),
		"tokens":       state.tokens,
		"reject_count": state.rejectCount,
	}).Debug("rejecting request due to rate limit")
	return false, "rate_limit_exceeded"
}

// IsBanned checks if a source is currently banned.
// This is a read-only check that doesn't modify state.
func (sl *SourceLimiter) IsBanned(sourceHash common.Hash) bool {
	sl.mu.RLock()
	defer sl.mu.RUnlock()

	state, exists := sl.sources[sourceHash]
	if !exists {
		return false
	}
	return time.Now().Before(state.bannedUntil)
}

// cleanupLoop runs in a background goroutine and periodically
// removes stale source entries to prevent memory exhaustion.
func (sl *SourceLimiter) cleanupLoop() {
	defer sl.wg.Done()

	ticker := time.NewTicker(sl.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-sl.stopChan:
			log.WithFields(logger.Fields{
				"at":     "SourceLimiter.cleanupLoop",
				"reason": "shutdown_signal",
			}).Debug("source limiter cleanup loop stopping")
			return
		case <-ticker.C:
			sl.cleanup()
		}
	}
}

// cleanup removes entries that haven't been seen recently and aren't banned.
// Entries are removed if:
// - Last update was more than 10 minutes ago, AND
// - Source is not currently banned
func (sl *SourceLimiter) cleanup() {
	sl.mu.Lock()
	defer sl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-10 * time.Minute)
	removed := 0

	for hash, state := range sl.sources {
		// Remove entries not seen in 10 minutes and not currently banned
		if state.lastUpdate.Before(cutoff) && now.After(state.bannedUntil) {
			delete(sl.sources, hash)
			removed++
		}
	}

	if removed > 0 {
		log.WithFields(logger.Fields{
			"at":        "SourceLimiter.cleanup",
			"phase":     "tunnel_build",
			"reason":    "stale_entry_cleanup",
			"removed":   removed,
			"remaining": len(sl.sources),
		}).Debug("cleaned up stale source limiter entries")
	}
}

// SourceLimiterStats contains statistics about the source limiter.
type SourceLimiterStats struct {
	TrackedSources  int    // Number of sources currently being tracked
	BannedSources   int    // Number of sources currently banned
	TotalRequests   uint64 // Total requests processed
	TotalRejections uint64 // Total requests rejected
}

// GetStats returns statistics about source limiting.
// This is useful for monitoring and debugging.
func (sl *SourceLimiter) GetStats() SourceLimiterStats {
	sl.mu.RLock()
	defer sl.mu.RUnlock()

	stats := SourceLimiterStats{
		TrackedSources:  len(sl.sources),
		TotalRequests:   sl.totalRequests,
		TotalRejections: sl.totalRejections,
	}

	now := time.Now()
	for _, state := range sl.sources {
		if now.Before(state.bannedUntil) {
			stats.BannedSources++
		}
	}

	return stats
}

// GetSourceStats returns statistics for a specific source.
// Returns nil if the source is not being tracked.
func (sl *SourceLimiter) GetSourceStats(sourceHash common.Hash) *SourceStats {
	sl.mu.RLock()
	defer sl.mu.RUnlock()

	state, exists := sl.sources[sourceHash]
	if !exists {
		return nil
	}

	now := time.Now()
	return &SourceStats{
		RequestCount: state.requestCount,
		RejectCount:  state.rejectCount,
		Tokens:       state.tokens,
		IsBanned:     now.Before(state.bannedUntil),
		BannedUntil:  state.bannedUntil,
		LastUpdate:   state.lastUpdate,
	}
}

// SourceStats contains statistics for a specific source.
type SourceStats struct {
	RequestCount uint64    // Total requests from this source
	RejectCount  uint64    // Total rejections for this source
	Tokens       float64   // Current token count
	IsBanned     bool      // Whether the source is currently banned
	BannedUntil  time.Time // When the ban expires (zero if not banned)
	LastUpdate   time.Time // Last time this source was seen
}

// Stop gracefully stops the source limiter.
// Waits for background goroutines to finish.
func (sl *SourceLimiter) Stop() {
	log.WithFields(logger.Fields{
		"at":     "SourceLimiter.Stop",
		"reason": "shutdown_requested",
	}).Info("stopping source limiter")
	close(sl.stopChan)
	sl.wg.Wait()

	sl.mu.Lock()
	stats := SourceLimiterStats{
		TrackedSources:  len(sl.sources),
		TotalRequests:   sl.totalRequests,
		TotalRejections: sl.totalRejections,
	}
	sl.sources = make(map[common.Hash]*sourceState)
	sl.mu.Unlock()

	log.WithFields(logger.Fields{
		"at":               "SourceLimiter.Stop",
		"reason":           "shutdown_complete",
		"tracked_sources":  stats.TrackedSources,
		"total_requests":   stats.TotalRequests,
		"total_rejections": stats.TotalRejections,
	}).Info("source limiter stopped")
}

// truncateHash returns a truncated string representation of a hash for logging.
// Only shows first 16 characters to protect privacy while still being useful.
func truncateHash(h common.Hash) string {
	s := h.String()
	if len(s) > 16 {
		return s[:16]
	}
	return s
}
