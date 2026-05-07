package netdb

import (
	"sync"
	"time"

	common "github.com/go-i2p/common/data"
)

// timeBucketedCooldown is a time-bucketed cooldown tracker that avoids
// expensive iteration during cleanup by organizing entries into time buckets.
//
// Each bucket represents a fixed time window (e.g., 5 minutes). When cleanup
// runs, we simply discard entire old buckets without iteration, making cleanup
// O(1) regardless of the number of entries.
//
// The structure maintains 3 buckets:
// - current: entries added in the current time window
// - previous: entries from the previous window (still within cooldown)
// - old: entries older than cooldown duration (discarded on next sweep)
type timeBucketedCooldown struct {
	bucketDuration time.Duration

	mu            sync.RWMutex
	currentBucket map[common.Hash]time.Time
	currentStart  time.Time
	prevBucket    map[common.Hash]time.Time
	prevStart     time.Time
}

// newTimeBucketedCooldown creates a new time-bucketed cooldown tracker.
// bucketDuration should match the cooldown duration (e.g., 5 minutes).
func newTimeBucketedCooldown(bucketDuration time.Duration) *timeBucketedCooldown {
	now := time.Now()
	return &timeBucketedCooldown{
		bucketDuration: bucketDuration,
		currentBucket:  make(map[common.Hash]time.Time),
		currentStart:   now,
		prevBucket:     make(map[common.Hash]time.Time),
		prevStart:      now.Add(-bucketDuration),
	}
}

// Store adds a hash with the given timestamp to the appropriate time bucket.
func (t *timeBucketedCooldown) Store(hash common.Hash, timestamp time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Rotate buckets if needed
	t.rotateBucketsIfNeeded(timestamp)

	// Store in current bucket
	t.currentBucket[hash] = timestamp
}

// Load retrieves the timestamp for a hash, checking all active buckets.
// Returns (timestamp, true) if found, (zero time, false) if not found.
func (t *timeBucketedCooldown) Load(hash common.Hash) (interface{}, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	// Check current bucket first (most likely)
	if ts, ok := t.currentBucket[hash]; ok {
		return ts, true
	}

	// Check previous bucket
	if ts, ok := t.prevBucket[hash]; ok {
		return ts, true
	}

	return time.Time{}, false
}

// Sweep discards entries older than the cooldown duration by rotating buckets.
// This is O(1) as it simply discards old bucket references without iteration.
//
// Returns the number of entries discarded (for logging/metrics).
func (t *timeBucketedCooldown) Sweep(now time.Time) int {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Rotate buckets if needed
	swept := t.rotateBucketsIfNeeded(now)
	return swept
}

// rotateBucketsIfNeeded checks if the current time has moved into a new bucket
// window and rotates buckets accordingly. Must be called with mu held.
//
// Returns the number of entries discarded.
func (t *timeBucketedCooldown) rotateBucketsIfNeeded(now time.Time) int {
	swept := 0

	// Calculate how many bucket rotations are needed
	elapsed := now.Sub(t.currentStart)
	bucketsToRotate := int(elapsed / t.bucketDuration)

	if bucketsToRotate == 0 {
		return 0 // Still in current bucket
	}

	if bucketsToRotate == 1 {
		// Normal case: move to next bucket
		// Discard old previous bucket, current becomes previous
		swept = len(t.prevBucket)
		t.prevBucket = t.currentBucket
		t.prevStart = t.currentStart
		t.currentBucket = make(map[common.Hash]time.Time)
		t.currentStart = t.currentStart.Add(t.bucketDuration)
	} else {
		// Multiple buckets elapsed (e.g., after long inactivity)
		// Discard everything and start fresh
		swept = len(t.currentBucket) + len(t.prevBucket)
		t.prevBucket = make(map[common.Hash]time.Time)
		t.currentBucket = make(map[common.Hash]time.Time)
		t.currentStart = now
		t.prevStart = now.Add(-t.bucketDuration)
	}

	return swept
}

// Stats returns statistics about the cooldown tracker for monitoring.
type cooldownStats struct {
	CurrentBucketSize int
	PrevBucketSize    int
	TotalEntries      int
	CurrentBucketAge  time.Duration
}

// Stats returns current statistics for monitoring/debugging.
func (t *timeBucketedCooldown) Stats() cooldownStats {
	t.mu.RLock()
	defer t.mu.RUnlock()

	now := time.Now()
	return cooldownStats{
		CurrentBucketSize: len(t.currentBucket),
		PrevBucketSize:    len(t.prevBucket),
		TotalEntries:      len(t.currentBucket) + len(t.prevBucket),
		CurrentBucketAge:  now.Sub(t.currentStart),
	}
}
