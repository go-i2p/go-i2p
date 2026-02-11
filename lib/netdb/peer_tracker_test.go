package netdb

import (
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper function to create a test hash
func testHash(suffix byte) common.Hash {
	var hash common.Hash
	for i := range hash {
		hash[i] = suffix
	}
	return hash
}

func TestNewPeerTracker(t *testing.T) {
	pt := NewPeerTracker()
	require.NotNil(t, pt)
	assert.NotNil(t, pt.stats)
}

func TestRecordAttempt(t *testing.T) {
	pt := NewPeerTracker()
	hash := testHash(1)

	// Record first attempt
	pt.RecordAttempt(hash)
	stats := pt.GetStats(hash)
	require.NotNil(t, stats)
	assert.Equal(t, 1, stats.TotalAttempts)
	assert.False(t, stats.LastAttempt.IsZero())

	// Record second attempt
	pt.RecordAttempt(hash)
	stats = pt.GetStats(hash)
	assert.Equal(t, 2, stats.TotalAttempts)
}

func TestRecordSuccess(t *testing.T) {
	pt := NewPeerTracker()
	hash := testHash(2)

	pt.RecordSuccess(hash, 100)
	stats := pt.GetStats(hash)
	require.NotNil(t, stats)
	assert.Equal(t, 1, stats.SuccessCount)
	assert.Equal(t, 0, stats.ConsecutiveFails)
	assert.Equal(t, int64(100), stats.AvgResponseTimeMs)
	assert.False(t, stats.LastSuccess.IsZero())
}

func TestRecordFailure(t *testing.T) {
	pt := NewPeerTracker()
	hash := testHash(3)

	pt.RecordFailure(hash, "timeout")
	stats := pt.GetStats(hash)
	require.NotNil(t, stats)
	assert.Equal(t, 1, stats.FailureCount)
	assert.Equal(t, 1, stats.ConsecutiveFails)
	assert.False(t, stats.LastFailure.IsZero())
}

func TestConsecutiveFailures(t *testing.T) {
	pt := NewPeerTracker()
	hash := testHash(4)

	// Record 3 failures
	for i := 0; i < 3; i++ {
		pt.RecordFailure(hash, "connection refused")
	}

	stats := pt.GetStats(hash)
	assert.Equal(t, 3, stats.ConsecutiveFails)
	assert.Equal(t, 3, stats.FailureCount)

	// Success resets consecutive failures
	pt.RecordSuccess(hash, 50)
	stats = pt.GetStats(hash)
	assert.Equal(t, 0, stats.ConsecutiveFails)
	assert.Equal(t, 1, stats.SuccessCount)
}

func TestGetSuccessRate(t *testing.T) {
	pt := NewPeerTracker()
	hash := testHash(5)

	// No data - should return -1.0
	rate := pt.GetSuccessRate(hash)
	assert.Equal(t, -1.0, rate)

	// 3 successes, 1 failure = 75% success rate
	pt.RecordAttempt(hash)
	pt.RecordSuccess(hash, 50)
	pt.RecordAttempt(hash)
	pt.RecordSuccess(hash, 60)
	pt.RecordAttempt(hash)
	pt.RecordSuccess(hash, 70)
	pt.RecordAttempt(hash)
	pt.RecordFailure(hash, "timeout")

	rate = pt.GetSuccessRate(hash)
	assert.InDelta(t, 0.75, rate, 0.01)
}

func TestIsLikelyStale_ConsecutiveFailures(t *testing.T) {
	pt := NewPeerTracker()
	hash := testHash(6)

	// Not stale with 2 failures
	pt.RecordFailure(hash, "timeout")
	pt.RecordFailure(hash, "timeout")
	assert.False(t, pt.IsLikelyStale(hash))

	// Stale with 3+ consecutive failures
	pt.RecordFailure(hash, "timeout")
	assert.True(t, pt.IsLikelyStale(hash))
}

func TestIsLikelyStale_LowSuccessRate(t *testing.T) {
	pt := NewPeerTracker()
	hash := testHash(7)

	// Record 5 attempts with 1 success (20% success rate)
	pt.RecordAttempt(hash)
	pt.RecordSuccess(hash, 100)
	for i := 0; i < 4; i++ {
		pt.RecordAttempt(hash)
		pt.RecordFailure(hash, "connection refused")
	}

	// Should be marked as stale (success rate < 25%)
	assert.True(t, pt.IsLikelyStale(hash))
}

func TestIsLikelyStale_NoRecentSuccess(t *testing.T) {
	pt := NewPeerTracker()
	hash := testHash(8)

	// Old success, then 3 recent failures
	pt.RecordSuccess(hash, 100)
	stats := pt.GetStats(hash)
	stats.LastSuccess = time.Now().Add(-2 * time.Hour) // Modify to simulate old success
	pt.mu.Lock()
	pt.stats[hash] = stats
	pt.mu.Unlock()

	// 3 consecutive failures should mark it as stale
	pt.RecordFailure(hash, "timeout")
	pt.RecordFailure(hash, "timeout")
	pt.RecordFailure(hash, "timeout")

	assert.True(t, pt.IsLikelyStale(hash))
}

func TestGetReliablePeers(t *testing.T) {
	pt := NewPeerTracker()
	hash1 := testHash(10)
	hash2 := testHash(11)
	hash3 := testHash(12)

	// Peer 1: High success rate (4/5 = 80%)
	for i := 0; i < 4; i++ {
		pt.RecordAttempt(hash1)
		pt.RecordSuccess(hash1, 50)
	}
	pt.RecordAttempt(hash1)
	pt.RecordFailure(hash1, "timeout")

	// Peer 2: Low attempts (insufficient data)
	pt.RecordAttempt(hash2)
	pt.RecordSuccess(hash2, 50)

	// Peer 3: Low success rate (1/5 = 20%)
	pt.RecordAttempt(hash3)
	pt.RecordSuccess(hash3, 50)
	for i := 0; i < 4; i++ {
		pt.RecordAttempt(hash3)
		pt.RecordFailure(hash3, "connection refused")
	}

	reliable := pt.GetReliablePeers(3)
	assert.Len(t, reliable, 1)
	assert.Contains(t, reliable, hash1)
	assert.NotContains(t, reliable, hash2) // Insufficient attempts
	assert.NotContains(t, reliable, hash3) // Low success rate
}

func TestPruneOldEntries(t *testing.T) {
	pt := NewPeerTracker()
	hash1 := testHash(20)
	hash2 := testHash(21)

	// Record recent activity for hash1
	pt.RecordAttempt(hash1)

	// Record old activity for hash2
	pt.RecordAttempt(hash2)
	stats := pt.GetStats(hash2)
	stats.LastAttempt = time.Now().Add(-25 * time.Hour)
	pt.mu.Lock()
	pt.stats[hash2] = stats
	pt.mu.Unlock()

	// Prune entries older than 24 hours
	pruned := pt.PruneOldEntries(24 * time.Hour)
	assert.Equal(t, 1, pruned)

	// hash1 should still exist, hash2 should be gone
	assert.NotNil(t, pt.GetStats(hash1))
	assert.Nil(t, pt.GetStats(hash2))
}

func TestGetSummary(t *testing.T) {
	pt := NewPeerTracker()
	hash1 := testHash(30)
	hash2 := testHash(31)

	// Peer 1: 3 attempts — 2 successes, 1 failure
	pt.RecordAttempt(hash1)
	pt.RecordSuccess(hash1, 50)
	pt.RecordAttempt(hash1)
	pt.RecordSuccess(hash1, 60)
	pt.RecordAttempt(hash1)
	pt.RecordFailure(hash1, "timeout")

	// Peer 2: 3 attempts — 1 success, 2 failures
	pt.RecordAttempt(hash2)
	pt.RecordSuccess(hash2, 70)
	pt.RecordAttempt(hash2)
	pt.RecordFailure(hash2, "connection refused")
	pt.RecordAttempt(hash2)
	pt.RecordFailure(hash2, "connection refused")

	summary := pt.GetSummary()
	assert.Equal(t, 2, summary["total_tracked_peers"])
	assert.Equal(t, 6, summary["total_attempts"])
	assert.Equal(t, 3, summary["total_successes"])
	assert.InDelta(t, 0.5, summary["overall_success_rate"], 0.01)
}

func TestAvgResponseTime(t *testing.T) {
	pt := NewPeerTracker()
	hash := testHash(40)

	pt.RecordSuccess(hash, 100)
	stats := pt.GetStats(hash)
	assert.Equal(t, int64(100), stats.AvgResponseTimeMs)

	pt.RecordSuccess(hash, 200)
	stats = pt.GetStats(hash)
	assert.Equal(t, int64(150), stats.AvgResponseTimeMs) // (100 + 200) / 2
}

func TestGetStats_NonExistent(t *testing.T) {
	pt := NewPeerTracker()
	hash := testHash(99)

	stats := pt.GetStats(hash)
	assert.Nil(t, stats)
}

func TestConcurrentAccess(t *testing.T) {
	pt := NewPeerTracker()
	hash := testHash(50)

	// Simulate concurrent access
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			pt.RecordAttempt(hash)
			pt.RecordSuccess(hash, 100)
			pt.GetStats(hash)
			pt.IsLikelyStale(hash)
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	stats := pt.GetStats(hash)
	assert.NotNil(t, stats)
	assert.GreaterOrEqual(t, stats.TotalAttempts, 10)
}
