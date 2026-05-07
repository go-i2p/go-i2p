package netdb

import (
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/stretchr/testify/assert"
)

// TestTimeBucketedCooldown_BasicOperations tests basic Store/Load/Sweep operations
func TestTimeBucketedCooldown_BasicOperations(t *testing.T) {
	cooldown := newTimeBucketedCooldown(5 * time.Minute)

	hash1 := common.Hash{1, 2, 3}
	hash2 := common.Hash{4, 5, 6}
	now := time.Now()

	// Store hash1
	cooldown.Store(hash1, now)

	// Load hash1 - should exist
	val, ok := cooldown.Load(hash1)
	assert.True(t, ok, "hash1 should exist after Store")
	ts, ok := val.(time.Time)
	assert.True(t, ok, "value should be time.Time")
	assert.Equal(t, now.Unix(), ts.Unix(), "timestamp should match")

	// Load hash2 - should not exist
	_, ok = cooldown.Load(hash2)
	assert.False(t, ok, "hash2 should not exist")

	// Store hash2
	cooldown.Store(hash2, now.Add(1*time.Minute))

	// Load hash2 - should exist
	_, ok = cooldown.Load(hash2)
	assert.True(t, ok, "hash2 should exist after Store")
}

// TestTimeBucketedCooldown_BucketRotation tests that buckets rotate correctly over time
func TestTimeBucketedCooldown_BucketRotation(t *testing.T) {
	bucketDuration := 5 * time.Minute
	cooldown := newTimeBucketedCooldown(bucketDuration)

	hash1 := common.Hash{1}
	hash2 := common.Hash{2}
	hash3 := common.Hash{3}

	now := time.Now()

	// Store hash1 in current bucket
	cooldown.Store(hash1, now)

	// Simulate moving to next bucket (6 minutes later)
	nextBucketTime := now.Add(6 * time.Minute)
	cooldown.Store(hash2, nextBucketTime)

	// hash1 should still be accessible (in previous bucket)
	_, ok := cooldown.Load(hash1)
	assert.True(t, ok, "hash1 should still be accessible in previous bucket")

	// hash2 should be in current bucket
	_, ok = cooldown.Load(hash2)
	assert.True(t, ok, "hash2 should be in current bucket")

	// Simulate moving to bucket after that (12 minutes total)
	laterTime := now.Add(12 * time.Minute)
	cooldown.Store(hash3, laterTime)

	// hash1 should be gone (older than 10 minutes, discarded)
	_, ok = cooldown.Load(hash1)
	assert.False(t, ok, "hash1 should be discarded after 2 bucket rotations")

	// hash2 should still exist (in previous bucket)
	_, ok = cooldown.Load(hash2)
	assert.True(t, ok, "hash2 should still exist in previous bucket")

	// hash3 should exist (in current bucket)
	_, ok = cooldown.Load(hash3)
	assert.True(t, ok, "hash3 should exist in current bucket")
}

// TestTimeBucketedCooldown_SweepPerformance validates that sweep operation
// completes in <10ms even with 10,000 entries
func TestTimeBucketedCooldown_SweepPerformance(t *testing.T) {
	cooldown := newTimeBucketedCooldown(5 * time.Minute)

	now := time.Now()

	// Populate with 10,000 entries in current bucket
	for i := 0; i < 10000; i++ {
		var hash common.Hash
		hash[0] = byte(i >> 24)
		hash[1] = byte(i >> 16)
		hash[2] = byte(i >> 8)
		hash[3] = byte(i)
		cooldown.Store(hash, now)
	}

	stats := cooldown.Stats()
	assert.Equal(t, 10000, stats.CurrentBucketSize, "should have 10000 entries in current bucket")

	// Simulate time passing to trigger bucket rotation (6 minutes later)
	// This will move current bucket to previous bucket
	futureTime := now.Add(6 * time.Minute)
	var testHash common.Hash
	testHash[0] = 255
	cooldown.Store(testHash, futureTime)

	stats = cooldown.Stats()
	assert.Equal(t, 10000, stats.PrevBucketSize, "should have 10000 entries in previous bucket")
	assert.Equal(t, 1, stats.CurrentBucketSize, "should have 1 entry in current bucket")

	// Now sweep to trigger cleanup - should discard nothing yet (previous bucket still valid)
	swept := cooldown.Sweep(futureTime)
	assert.Equal(t, 0, swept, "should not discard entries within cooldown period")

	// Move forward another 6 minutes (12 minutes total from original entries)
	// This should trigger discard of the 10,000 old entries
	veryFutureTime := now.Add(12 * time.Minute)

	start := time.Now()
	swept = cooldown.Sweep(veryFutureTime)
	elapsed := time.Since(start)

	assert.Equal(t, 10000, swept, "should discard 10000 old entries")
	assert.Less(t, elapsed, 10*time.Millisecond, "sweep should complete in <10ms")

	t.Logf("Swept 10,000 entries in %v (required: <10ms)", elapsed)

	stats = cooldown.Stats()
	assert.Equal(t, 1, stats.TotalEntries, "should only have 1 entry left (the test hash)")
}

// TestTimeBucketedCooldown_Stats tests the Stats method returns correct counts
func TestTimeBucketedCooldown_Stats(t *testing.T) {
	cooldown := newTimeBucketedCooldown(5 * time.Minute)

	// Initially empty
	stats := cooldown.Stats()
	assert.Equal(t, 0, stats.TotalEntries, "should start with 0 entries")

	now := time.Now()

	// Add 10 entries to current bucket
	for i := 0; i < 10; i++ {
		var hash common.Hash
		hash[0] = byte(i)
		cooldown.Store(hash, now)
	}

	stats = cooldown.Stats()
	assert.Equal(t, 10, stats.CurrentBucketSize, "should have 10 in current bucket")
	assert.Equal(t, 0, stats.PrevBucketSize, "should have 0 in previous bucket")
	assert.Equal(t, 10, stats.TotalEntries, "should have 10 total")

	// Rotate buckets by adding entry in future
	future := now.Add(6 * time.Minute)
	var hash common.Hash
	hash[0] = 255
	cooldown.Store(hash, future)

	stats = cooldown.Stats()
	assert.Equal(t, 1, stats.CurrentBucketSize, "should have 1 in current bucket")
	assert.Equal(t, 10, stats.PrevBucketSize, "should have 10 in previous bucket")
	assert.Equal(t, 11, stats.TotalEntries, "should have 11 total")
}

// TestTimeBucketedCooldown_ConcurrentAccess tests thread-safe concurrent access
func TestTimeBucketedCooldown_ConcurrentAccess(t *testing.T) {
	cooldown := newTimeBucketedCooldown(5 * time.Minute)

	now := time.Now()
	done := make(chan bool)

	// Writer goroutine
	go func() {
		for i := 0; i < 1000; i++ {
			var hash common.Hash
			hash[0] = byte(i)
			cooldown.Store(hash, now)
		}
		done <- true
	}()

	// Reader goroutine
	go func() {
		for i := 0; i < 1000; i++ {
			var hash common.Hash
			hash[0] = byte(i)
			cooldown.Load(hash)
		}
		done <- true
	}()

	// Sweeper goroutine
	go func() {
		for i := 0; i < 10; i++ {
			cooldown.Sweep(now.Add(time.Duration(i) * time.Minute))
			time.Sleep(1 * time.Millisecond)
		}
		done <- true
	}()

	// Wait for all goroutines
	<-done
	<-done
	<-done

	// Should not crash or race
	stats := cooldown.Stats()
	assert.Greater(t, stats.TotalEntries, 0, "should have some entries")
}
