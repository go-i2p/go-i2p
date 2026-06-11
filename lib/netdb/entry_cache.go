package netdb

import (
	"sync"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/samber/oops"
)

// entryCache is a generic cache for both RouterInfos and LeaseSets.
// It bundles the map, RWMutex, capacity, admission controller, and expiry tracking.
type entryCache struct {
	// Map stores the actual cache entries
	entries map[common.Hash]Entry

	// mu protects the entries map
	mu sync.RWMutex

	// capacity is the maximum number of entries allowed
	capacity int

	// admission controller enforces rate limits when under pressure
	admission *admissionController

	// expiry maps each key to its expiration time
	expiry map[common.Hash]time.Time
}

// newEntryCache creates a new generic cache with the given capacity and admission config.
func newEntryCache(capacity int, config admissionConfig) *entryCache {
	return &entryCache{
		entries:   make(map[common.Hash]Entry),
		capacity:  capacity,
		admission: newAdmissionController(capacity, config),
		expiry:    make(map[common.Hash]time.Time),
	}
}

// get retrieves an entry from the cache (read-only).
func (ec *entryCache) get(key common.Hash) (Entry, bool) {
	ec.mu.RLock()
	defer ec.mu.RUnlock()
	entry, exists := ec.entries[key]
	return entry, exists
}

// getCacheState returns cache state for admission checks: (exists, currentCount, maxCapacity).
func (ec *entryCache) getCacheState(key common.Hash) (exists bool, current, max int) {
	ec.mu.RLock()
	_, exists = ec.entries[key]
	current = len(ec.entries)
	max = ec.capacity
	ec.mu.RUnlock()
	return exists, current, max
}

// put stores an entry in the cache.
func (ec *entryCache) put(key common.Hash, entry Entry) {
	ec.mu.Lock()
	ec.entries[key] = entry
	ec.mu.Unlock()
}

// delete removes an entry from the cache.
func (ec *entryCache) delete(key common.Hash) {
	ec.mu.Lock()
	delete(ec.entries, key)
	ec.mu.Unlock()
}

// count returns the number of entries currently in the cache.
func (ec *entryCache) count() int {
	ec.mu.RLock()
	defer ec.mu.RUnlock()
	return len(ec.entries)
}

// getCapacity returns the max capacity.
func (ec *entryCache) getCapacity() int {
	ec.mu.RLock()
	defer ec.mu.RUnlock()
	return ec.capacity
}

// setCapacity updates the max capacity.
func (ec *entryCache) setCapacity(max int) {
	if max <= 0 {
		return
	}
	ec.mu.Lock()
	ec.capacity = max
	ec.mu.Unlock()
	if ec.admission != nil {
		ec.admission.SetCapacity(max)
	}
}

// setExpiry records the expiration time for an entry.
func (ec *entryCache) setExpiry(key common.Hash, expiry time.Time) {
	ec.mu.Lock()
	defer ec.mu.Unlock()
	ec._setExpiryLocked(key, expiry)
}

// _setExpiryLocked records the expiration time without acquiring the lock.
// Must be called while the lock is already held.
func (ec *entryCache) _setExpiryLocked(key common.Hash, expiry time.Time) {
	ec.expiry[key] = expiry
}

// getExpiry retrieves the expiration time for an entry.
func (ec *entryCache) getExpiry(key common.Hash) (time.Time, bool) {
	ec.mu.RLock()
	defer ec.mu.RUnlock()
	expiry, exists := ec.expiry[key]
	return expiry, exists
}

// deleteExpiry removes an expiration entry.
func (ec *entryCache) deleteExpiry(key common.Hash) {
	ec.mu.Lock()
	defer ec.mu.Unlock()
	delete(ec.expiry, key)
}

// isExpired checks if an entry has expired.
func (ec *entryCache) isExpired(key common.Hash, now time.Time) bool {
	expiry, exists := ec.getExpiry(key)
	return exists && now.After(expiry)
}

// checkCapacity checks if cache is at capacity.
func (ec *entryCache) checkCapacity(current int) error {
	if ec.capacity > 0 && current >= ec.capacity {
		return oops.Errorf("cache capacity reached (%d)", ec.capacity)
	}
	return nil
}

// checkAdmissionLimits checks if an introduction should be accepted.
func (ec *entryCache) checkAdmissionLimits(key common.Hash, source *common.Hash, current int) bool {
	if ec.admission == nil {
		return true
	}
	return ec.admission.AllowIntroduction(source, key, current)
}

// evictSoonestExpiring removes the entry with the earliest expiration time.
// Evicts even non-expired entries to enforce capacity limits.
// Returns the evicted key if successful, or zero key if nothing was evicted.
func (ec *entryCache) evictSoonestExpiring() common.Hash {
	// Take read lock to scan the expiry map safely
	ec.mu.RLock()
	var soonestKey common.Hash
	var soonestTime time.Time

	// Find the earliest expiration (even if in the future)
	for key, expiry := range ec.expiry {
		if soonestTime.IsZero() || expiry.Before(soonestTime) {
			soonestKey = key
			soonestTime = expiry
		}
	}
	ec.mu.RUnlock()

	// If nothing found with an expiry time, can't evict
	if soonestTime.IsZero() {
		return common.Hash{}
	}

	// Now acquire write lock to delete
	ec.mu.Lock()
	defer ec.mu.Unlock()

	// Double-check the entry still exists before deleting
	if _, exists := ec.entries[soonestKey]; !exists {
		return common.Hash{}
	}

	delete(ec.entries, soonestKey)
	delete(ec.expiry, soonestKey)

	return soonestKey
}
