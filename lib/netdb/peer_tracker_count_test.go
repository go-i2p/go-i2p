package netdb

import (
	"testing"

	common "github.com/go-i2p/common/data"
	"github.com/stretchr/testify/assert"
)

// TestPeerTracker_TotalAttempts_NoDoubleCount verifies that TotalAttempts is
// only incremented by RecordAttempt, not by RecordSuccess or RecordFailure.
func TestPeerTracker_TotalAttempts_NoDoubleCount(t *testing.T) {
	pt := NewPeerTracker()
	hash := common.Hash{0x01}

	// 5 attempts: 3 successes, 2 failures
	for i := 0; i < 5; i++ {
		pt.RecordAttempt(hash)
	}

	pt.RecordSuccess(hash, 50)
	pt.RecordSuccess(hash, 40)
	pt.RecordSuccess(hash, 60)
	pt.RecordFailure(hash, "timeout")
	pt.RecordFailure(hash, "refused")

	stats := pt.GetStats(hash)
	assert.NotNil(t, stats)
	assert.Equal(t, 5, stats.TotalAttempts, "TotalAttempts should equal number of RecordAttempt calls")
	assert.Equal(t, 3, stats.SuccessCount)
	assert.Equal(t, 2, stats.FailureCount)
}

// TestPeerTracker_SuccessRate_AfterFix verifies that the success rate calculation
// produces correct values now that double-counting is fixed.
func TestPeerTracker_SuccessRate_AfterFix(t *testing.T) {
	pt := NewPeerTracker()
	hash := common.Hash{0x02}

	// 10 attempts, 8 successes, 2 failures
	for i := 0; i < 10; i++ {
		pt.RecordAttempt(hash)
	}
	for i := 0; i < 8; i++ {
		pt.RecordSuccess(hash, 30)
	}
	for i := 0; i < 2; i++ {
		pt.RecordFailure(hash, "err")
	}

	rate := pt.GetSuccessRate(hash)
	assert.InDelta(t, 0.8, rate, 0.001, "Success rate should be 8/10 = 0.8")
}

// TestPeerTracker_RecordSuccessWithoutAttempt verifies behavior when
// RecordSuccess is called without a prior RecordAttempt (edge case).
func TestPeerTracker_RecordSuccessWithoutAttempt(t *testing.T) {
	pt := NewPeerTracker()
	hash := common.Hash{0x03}

	// Call RecordSuccess directly without RecordAttempt
	pt.RecordSuccess(hash, 100)

	stats := pt.GetStats(hash)
	assert.NotNil(t, stats)
	assert.Equal(t, 1, stats.SuccessCount)
	assert.Equal(t, 0, stats.TotalAttempts, "TotalAttempts should be 0 when only RecordSuccess was called")
}

// TestPeerTracker_RecordFailureWithoutAttempt verifies behavior when
// RecordFailure is called without a prior RecordAttempt (edge case).
func TestPeerTracker_RecordFailureWithoutAttempt(t *testing.T) {
	pt := NewPeerTracker()
	hash := common.Hash{0x04}

	// Call RecordFailure directly without RecordAttempt
	pt.RecordFailure(hash, "timeout")

	stats := pt.GetStats(hash)
	assert.NotNil(t, stats)
	assert.Equal(t, 1, stats.FailureCount)
	assert.Equal(t, 0, stats.TotalAttempts, "TotalAttempts should be 0 when only RecordFailure was called")
}
