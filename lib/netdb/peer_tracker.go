package netdb

import (
	"sync"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/logger"
)

// PeerStats tracks connection success/failure statistics for a peer.
// HIGH PRIORITY FIX #3: Stale peer detection through connection tracking.
type PeerStats struct {
	Hash              common.Hash
	SuccessCount      int
	FailureCount      int
	LastSuccess       time.Time
	LastFailure       time.Time
	LastAttempt       time.Time
	ConsecutiveFails  int
	TotalAttempts     int
	AvgResponseTimeMs int64
}

// PeerTracker maintains reputation/connectivity statistics for peers.
// Helps identify stale peers and prioritize reliable ones for tunnel building.
// HIGH PRIORITY FIX #3: Infrastructure for peer reputation scoring.
type PeerTracker struct {
	stats map[common.Hash]*PeerStats
	mu    sync.RWMutex
}

// NewPeerTracker creates a new peer tracking system.
func NewPeerTracker() *PeerTracker {
	log.WithFields(logger.Fields{
		"at":     "NewPeerTracker",
		"reason": "initialization",
	}).Debug("Creating peer tracker for connection statistics")

	return &PeerTracker{
		stats: make(map[common.Hash]*PeerStats),
	}
}

// RecordAttempt records a connection attempt to a peer.
func (pt *PeerTracker) RecordAttempt(hash common.Hash) {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	stats, exists := pt.stats[hash]
	if !exists {
		stats = &PeerStats{
			Hash: hash,
		}
		pt.stats[hash] = stats
	}

	stats.LastAttempt = time.Now()
	stats.TotalAttempts++

	log.WithFields(logger.Fields{
		"peer_hash":      hash.String()[:16],
		"total_attempts": stats.TotalAttempts,
	}).Debug("Recorded connection attempt")
}

// RecordSuccess records a successful connection to a peer.
func (pt *PeerTracker) RecordSuccess(hash common.Hash, responseTimeMs int64) {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	stats, exists := pt.stats[hash]
	if !exists {
		stats = &PeerStats{
			Hash: hash,
		}
		pt.stats[hash] = stats
	}

	stats.SuccessCount++
	stats.LastSuccess = time.Now()
	stats.ConsecutiveFails = 0 // Reset consecutive failure counter

	// Update average response time (simple moving average)
	if stats.AvgResponseTimeMs == 0 {
		stats.AvgResponseTimeMs = responseTimeMs
	} else {
		stats.AvgResponseTimeMs = (stats.AvgResponseTimeMs + responseTimeMs) / 2
	}

	log.WithFields(logger.Fields{
		"peer_hash":        hash.String()[:16],
		"success_count":    stats.SuccessCount,
		"response_time_ms": responseTimeMs,
	}).Debug("Recorded successful connection")
}

// RecordFailure records a failed connection attempt to a peer.
func (pt *PeerTracker) RecordFailure(hash common.Hash, reason string) {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	stats, exists := pt.stats[hash]
	if !exists {
		stats = &PeerStats{
			Hash: hash,
		}
		pt.stats[hash] = stats
	}

	stats.FailureCount++
	stats.LastFailure = time.Now()
	stats.ConsecutiveFails++

	log.WithFields(logger.Fields{
		"peer_hash":         hash.String()[:16],
		"failure_count":     stats.FailureCount,
		"consecutive_fails": stats.ConsecutiveFails,
		"reason":            reason,
	}).Debug("Recorded connection failure")
}

// GetStats retrieves statistics for a peer.
func (pt *PeerTracker) GetStats(hash common.Hash) *PeerStats {
	pt.mu.RLock()
	defer pt.mu.RUnlock()

	if stats, exists := pt.stats[hash]; exists {
		// Return a copy to prevent external modification
		statsCopy := *stats
		return &statsCopy
	}
	return nil
}

// GetSuccessRate calculates the connection success rate for a peer.
// Returns a value between 0.0 and 1.0, or -1.0 if no attempts recorded.
func (pt *PeerTracker) GetSuccessRate(hash common.Hash) float64 {
	pt.mu.RLock()
	defer pt.mu.RUnlock()

	stats, exists := pt.stats[hash]
	if !exists || stats.TotalAttempts == 0 {
		return -1.0 // Unknown/no data
	}

	return float64(stats.SuccessCount) / float64(stats.TotalAttempts)
}

// IsLikelyStale determines if a peer is likely offline/stale based on failure patterns.
// A peer is considered stale if:
// - It has 3+ consecutive failures, OR
// - Success rate < 25% with at least 5 attempts, OR
// - No successful connection in last hour with recent failures
func (pt *PeerTracker) IsLikelyStale(hash common.Hash) bool {
	pt.mu.RLock()
	defer pt.mu.RUnlock()

	stats, exists := pt.stats[hash]
	if !exists {
		return false // No data - assume peer is fine
	}

	if pt.hasExcessiveConsecutiveFailures(stats, hash) {
		return true
	}

	if pt.hasLowSuccessRate(stats, hash) {
		return true
	}

	if pt.hasRecentFailuresWithoutSuccess(stats, hash) {
		return true
	}

	return false
}

// hasExcessiveConsecutiveFailures checks if the peer has too many consecutive failures.
// Returns true if consecutive failures meet or exceed the threshold of 3.
func (pt *PeerTracker) hasExcessiveConsecutiveFailures(stats *PeerStats, hash common.Hash) bool {
	if stats.ConsecutiveFails >= 3 {
		log.WithFields(logger.Fields{
			"peer_hash":         hash.String()[:16],
			"consecutive_fails": stats.ConsecutiveFails,
			"reason":            "high_consecutive_failures",
		}).Debug("Peer marked as likely stale")
		return true
	}
	return false
}

// hasLowSuccessRate checks if the peer's overall success rate is below acceptable threshold.
// Returns true if success rate is below 25% with at least 5 attempts.
func (pt *PeerTracker) hasLowSuccessRate(stats *PeerStats, hash common.Hash) bool {
	if stats.TotalAttempts >= 5 {
		successRate := float64(stats.SuccessCount) / float64(stats.TotalAttempts)
		if successRate < 0.25 {
			log.WithFields(logger.Fields{
				"peer_hash":    hash.String()[:16],
				"success_rate": successRate,
				"reason":       "low_success_rate",
			}).Debug("Peer marked as likely stale")
			return true
		}
	}
	return false
}

// hasRecentFailuresWithoutSuccess checks if the peer has recent failures with no recent successes.
// Returns true if peer has consecutive failures in the last hour but no success in that period.
func (pt *PeerTracker) hasRecentFailuresWithoutSuccess(stats *PeerStats, hash common.Hash) bool {
	hourAgo := time.Now().Add(-1 * time.Hour)
	if stats.ConsecutiveFails >= 3 && !stats.LastFailure.IsZero() && stats.LastFailure.After(hourAgo) {
		if stats.LastSuccess.IsZero() || stats.LastSuccess.Before(hourAgo) {
			log.WithFields(logger.Fields{
				"peer_hash":    hash.String()[:16],
				"last_success": stats.LastSuccess,
				"last_failure": stats.LastFailure,
				"reason":       "no_recent_success_with_failures",
			}).Debug("Peer marked as likely stale")
			return true
		}
	}
	return false
}

// GetReliablePeers returns a list of peer hashes that are considered reliable.
// Reliable peers have: success rate >= 75%, or recent successful connections.
func (pt *PeerTracker) GetReliablePeers(minAttempts int) []common.Hash {
	pt.mu.RLock()
	defer pt.mu.RUnlock()

	var reliable []common.Hash

	for hash, stats := range pt.stats {
		// Require minimum attempts for statistical significance
		if stats.TotalAttempts < minAttempts {
			continue
		}

		// Check success rate
		successRate := float64(stats.SuccessCount) / float64(stats.TotalAttempts)
		if successRate >= 0.75 {
			reliable = append(reliable, hash)
		}
	}

	log.WithFields(logger.Fields{
		"reliable_count": len(reliable),
		"total_tracked":  len(pt.stats),
		"min_attempts":   minAttempts,
	}).Debug("Retrieved reliable peers")

	return reliable
}

// PruneOldEntries removes tracking data for peers not seen recently.
// Helps prevent unbounded memory growth.
func (pt *PeerTracker) PruneOldEntries(maxAge time.Duration) int {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	cutoff := time.Now().Add(-maxAge)
	pruned := 0

	for hash, stats := range pt.stats {
		// Remove if no recent activity
		if stats.LastAttempt.Before(cutoff) {
			delete(pt.stats, hash)
			pruned++
		}
	}

	if pruned > 0 {
		log.WithFields(logger.Fields{
			"pruned_count": pruned,
			"max_age":      maxAge.String(),
			"remaining":    len(pt.stats),
		}).Info("Pruned old peer tracking entries")
	}

	return pruned
}

// GetSummary returns overall tracking statistics.
func (pt *PeerTracker) GetSummary() map[string]interface{} {
	pt.mu.RLock()
	defer pt.mu.RUnlock()

	totalPeers := len(pt.stats)
	totalAttempts := 0
	totalSuccesses := 0
	staleCount := 0

	for _, stats := range pt.stats {
		totalAttempts += stats.TotalAttempts
		totalSuccesses += stats.SuccessCount

		// Inline staleness check to avoid releasing the lock mid-iteration.
		// This mirrors the logic in IsLikelyStale/hasExcessiveConsecutiveFailures/
		// hasLowSuccessRate/hasRecentFailuresWithoutSuccess without acquiring a
		// separate RLock that would require us to drop our own.
		if isStaleUnlocked(stats) {
			staleCount++
		}
	}

	overallSuccessRate := 0.0
	if totalAttempts > 0 {
		overallSuccessRate = float64(totalSuccesses) / float64(totalAttempts)
	}

	return map[string]interface{}{
		"total_tracked_peers":  totalPeers,
		"total_attempts":       totalAttempts,
		"total_successes":      totalSuccesses,
		"overall_success_rate": overallSuccessRate,
		"likely_stale_peers":   staleCount,
	}
}

// isStaleUnlocked performs the staleness check without acquiring any locks.
// Caller must hold at least pt.mu.RLock.
func isStaleUnlocked(stats *PeerStats) bool {
	// Excessive consecutive failures (threshold: 3)
	if stats.ConsecutiveFails >= 3 {
		return true
	}
	// Low success rate with enough attempts
	if stats.TotalAttempts >= 5 {
		successRate := float64(stats.SuccessCount) / float64(stats.TotalAttempts)
		if successRate < 0.25 {
			return true
		}
	}
	// Recent failures without recent success
	hourAgo := time.Now().Add(-1 * time.Hour)
	if stats.ConsecutiveFails >= 3 && !stats.LastFailure.IsZero() && stats.LastFailure.After(hourAgo) {
		if stats.LastSuccess.IsZero() || stats.LastSuccess.Before(hourAgo) {
			return true
		}
	}
	return false
}
