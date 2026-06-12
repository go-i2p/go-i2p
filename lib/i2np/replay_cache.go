package i2np

import (
	"sync"
	"time"
)

// msgReplayEntry records when a message ID was first seen.
type msgReplayEntry struct {
	seenAt time.Time
}

// messageReplayCache is a bounded, TTL-based cache of recently seen I2NP message IDs.
// It prevents the same message from being processed more than once within its
// validity window, blocking replay attacks (traffic amplification, build-reply
// corruption, spurious delivery-status callbacks).
//
// Design:
//   - Fixed-capacity circular structure implemented as a map with an LRU eviction ring.
//   - maxEntries prevents unbounded growth from attacker-controlled message ID streams.
//   - TTL == ExpirationValidator tolerance (default 5 min): entries older than the TTL
//     are considered stale regardless of map size.
//   - Cleanup runs on every insertion rather than in a background goroutine so the
//     cache never needs its own goroutine lifecycle.
type messageReplayCache struct {
	mu          sync.Mutex
	entries     map[int]msgReplayEntry // messageID → first-seen time
	insertOrder []int                  // FIFO ring for eviction when capacity is reached
	maxEntries  int
	ttl         time.Duration
}

// newMessageReplayCache creates a replay cache with the given capacity and TTL.
// A capacity of 10_000 and TTL of 5 minutes matches the default I2NP expiry window.
func newMessageReplayCache(maxEntries int, ttl time.Duration) *messageReplayCache {
	return &messageReplayCache{
		entries:     make(map[int]msgReplayEntry, maxEntries),
		insertOrder: make([]int, 0, maxEntries),
		maxEntries:  maxEntries,
		ttl:         ttl,
	}
}

// Seen returns true if the given message ID was seen within the TTL window.
// This is a read-only check; call Mark to record the ID.
func (c *messageReplayCache) Seen(msgID int) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[msgID]
	if !ok {
		return false
	}
	if time.Since(entry.seenAt) > c.ttl {
		// Entry is stale; treat as unseen and let Mark re-insert it.
		delete(c.entries, msgID)
		return false
	}
	return true
}

// Mark records a message ID as seen.  If the ID is already present (non-stale)
// this is a no-op.  When the cache is full, the oldest entry is evicted.
func (c *messageReplayCache) Mark(msgID int) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()

	// Evict stale entries from the front of the ring before checking capacity.
	c.evictStale(now)

	if _, exists := c.entries[msgID]; exists {
		return // already recorded
	}

	// Enforce capacity: evict the oldest entry if we're at the limit.
	if len(c.entries) >= c.maxEntries && len(c.insertOrder) > 0 {
		oldest := c.insertOrder[0]
		c.insertOrder = c.insertOrder[1:]
		delete(c.entries, oldest)
	}

	c.entries[msgID] = msgReplayEntry{seenAt: now}
	c.insertOrder = append(c.insertOrder, msgID)
}

// evictStale removes entries from the front of insertOrder that are older than TTL.
// Must be called with c.mu held.
func (c *messageReplayCache) evictStale(now time.Time) {
	for len(c.insertOrder) > 0 {
		id := c.insertOrder[0]
		entry, ok := c.entries[id]
		if !ok || now.Sub(entry.seenAt) > c.ttl {
			c.insertOrder = c.insertOrder[1:]
			delete(c.entries, id)
			continue
		}
		break // front is fresh; remaining entries are at least as fresh
	}
}
