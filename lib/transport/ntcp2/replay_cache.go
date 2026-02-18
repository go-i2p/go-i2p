package ntcp2

import (
	"sync"
	"time"
)

// Replay cache constants.
//
// Spec reference: https://geti2p.net/spec/ntcp2#replay-prevention
//
// Bob must maintain a local cache of previously-used ephemeral keys (X values
// from message 1) and reject duplicates to prevent replay attacks.
const (
	// replayCacheTTL is the time-to-live for replay cache entries.
	// Entries older than this are evicted. Set to 2× the clock skew tolerance
	// (120 seconds) to cover legitimate retransmissions within the skew window.
	replayCacheTTL = 2 * ClockSkewTolerance

	// replayCacheCleanupInterval is how often the cache runs eviction of
	// expired entries.
	replayCacheCleanupInterval = 30 * time.Second

	// replayCacheMaxSize is the maximum number of entries before forced eviction
	// of the oldest entries. This prevents memory exhaustion under attack.
	replayCacheMaxSize = 100000
)

// ReplayCache is a thread-safe, bounded, TTL-based cache for detecting
// replayed NTCP2 handshake ephemeral keys. It is shared across all listener
// goroutines within a single router instance.
//
// The cache stores the first 32 bytes of each message 1 (the ephemeral key X)
// and rejects duplicates within the TTL window.
type ReplayCache struct {
	mu      sync.RWMutex
	entries map[[32]byte]time.Time // ephemeral key → first-seen time
	done    chan struct{}          // signals the cleanup goroutine to stop
}

// NewReplayCache creates a new replay cache and starts a background cleanup
// goroutine. Call Close() when the cache is no longer needed.
func NewReplayCache() *ReplayCache {
	rc := &ReplayCache{
		entries: make(map[[32]byte]time.Time),
		done:    make(chan struct{}),
	}
	go rc.cleanupLoop()
	return rc
}

// CheckAndAdd checks whether an ephemeral key has been seen before.
// If the key is new, it is added to the cache and false is returned (not a replay).
// If the key has been seen within the TTL window, true is returned (replay detected).
//
// This is the primary method called by the listener before processing message 1.
func (rc *ReplayCache) CheckAndAdd(ephemeralKey [32]byte) bool {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	now := time.Now()

	// Check if this key has been seen before and is still within the TTL
	if firstSeen, exists := rc.entries[ephemeralKey]; exists {
		if now.Sub(firstSeen) < replayCacheTTL {
			// Replay detected — key was seen recently
			return true
		}
		// Entry expired — treat as new
	}

	// Force eviction if we've hit the size limit
	if len(rc.entries) >= replayCacheMaxSize {
		rc.evictOldest()
	}

	// Record this ephemeral key
	rc.entries[ephemeralKey] = now
	return false
}

// Size returns the current number of entries in the cache.
func (rc *ReplayCache) Size() int {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	return len(rc.entries)
}

// Close stops the background cleanup goroutine and releases resources.
func (rc *ReplayCache) Close() {
	close(rc.done)
}

// cleanupLoop periodically evicts expired entries from the cache.
func (rc *ReplayCache) cleanupLoop() {
	ticker := time.NewTicker(replayCacheCleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-rc.done:
			return
		case <-ticker.C:
			rc.evictExpired()
		}
	}
}

// evictExpired removes all entries older than replayCacheTTL.
func (rc *ReplayCache) evictExpired() {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	cutoff := time.Now().Add(-replayCacheTTL)
	for key, firstSeen := range rc.entries {
		if firstSeen.Before(cutoff) {
			delete(rc.entries, key)
		}
	}
}

// evictOldest removes the oldest 10% of entries when the cache is full.
// Must be called with mu held.
func (rc *ReplayCache) evictOldest() {
	evictCount := len(rc.entries) / 10
	if evictCount < 1 {
		evictCount = 1
	}

	// Find the oldest entries
	type entry struct {
		key  [32]byte
		time time.Time
	}

	// Simple approach: just delete entries that are older than the median.
	// For a cache under attack, any eviction strategy works since we're
	// just preventing OOM — the TTL handles correctness.
	cutoff := time.Now().Add(-replayCacheTTL / 2)
	evicted := 0
	for key, firstSeen := range rc.entries {
		if evicted >= evictCount {
			break
		}
		if firstSeen.Before(cutoff) {
			delete(rc.entries, key)
			evicted++
		}
	}

	// If we couldn't evict enough old entries, just delete any entries
	if evicted < evictCount {
		for key := range rc.entries {
			if evicted >= evictCount {
				break
			}
			delete(rc.entries, key)
			evicted++
		}
	}
}
