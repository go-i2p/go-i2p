// Package netdb provides network database functionality for I2P.
package netdb

import (
	"sync"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/go-i2p/logger"
)

// CongestionStats contains network-wide congestion statistics.
// Used by PROP_170 for PoW activation decisions based on network health.
type CongestionStats struct {
	// TotalPeers is the total number of peers with known RouterInfo
	TotalPeers int
	// DFlagCount is the number of peers advertising medium congestion (D flag)
	DFlagCount int
	// EFlagCount is the number of peers advertising high congestion (E flag)
	EFlagCount int
	// GFlagCount is the number of peers rejecting all tunnels (G flag)
	GFlagCount int
	// CongestedRatio is the ratio of congested peers to total: (D+E+G)/Total
	CongestedRatio float64
}

// PeerCongestionInfo provides congestion information about remote peers.
// This interface enables congestion-aware tunnel building decisions.
type PeerCongestionInfo interface {
	// GetPeerCongestionFlag returns the congestion flag for a specific peer.
	// Returns CongestionFlagNone if peer is not found or has no congestion flag.
	GetPeerCongestionFlag(hash common.Hash) config.CongestionFlag

	// GetCongestionStats returns network-wide congestion statistics.
	// Statistics are calculated on-demand from the current RouterInfo cache.
	GetCongestionStats() CongestionStats

	// CountCongestedPeers returns counts of peers by congestion level.
	// Returns (dCount, eCount, gCount, totalCount).
	CountCongestedPeers() (dCount, eCount, gCount, totalCount int)
}

// CongestionCache caches parsed congestion flags to avoid repeated parsing.
// The cache is invalidated when RouterInfo is updated.
// It enforces a maximum size and TTL to prevent unbounded memory growth.
type CongestionCache struct {
	mu      sync.RWMutex
	flags   map[common.Hash]cachedFlag
	maxSize int           // maximum entries; 0 means unlimited (for backward compat)
	ttl     time.Duration // entries older than this are evicted on access; 0 means no TTL
}

// cachedFlag stores a parsed congestion flag with its parse timestamp.
type cachedFlag struct {
	flag     config.CongestionFlag
	parsedAt time.Time
	riAge    time.Time // RouterInfo published time for staleness check
}

// NewCongestionCache creates a new congestion flag cache with default limits.
// Default: max 2048 entries, 30-minute TTL.
func NewCongestionCache() *CongestionCache {
	return &CongestionCache{
		flags:   make(map[common.Hash]cachedFlag),
		maxSize: 2048,
		ttl:     30 * time.Minute,
	}
}

// Get retrieves a cached congestion flag for a peer.
// Returns the flag and true if found and not expired, or CongestionFlagNone and false otherwise.
func (c *CongestionCache) Get(hash common.Hash) (config.CongestionFlag, time.Time, bool) {
	// First try with a read lock for the common (non-expired) path
	c.mu.RLock()
	cached, ok := c.flags[hash]
	c.mu.RUnlock()

	if !ok {
		return config.CongestionFlagNone, time.Time{}, false
	}

	// Check TTL if configured
	if c.ttl > 0 && time.Since(cached.parsedAt) > c.ttl {
		// Evict the expired entry under a write lock
		c.mu.Lock()
		// Re-check under write lock (another goroutine may have already evicted)
		if current, stillExists := c.flags[hash]; stillExists {
			if c.ttl > 0 && time.Since(current.parsedAt) > c.ttl {
				delete(c.flags, hash)
			}
		}
		c.mu.Unlock()
		return config.CongestionFlagNone, time.Time{}, false
	}

	return cached.flag, cached.riAge, true
}

// Set stores a congestion flag in the cache.
// If the cache exceeds its maximum size, the oldest entry is evicted.
func (c *CongestionCache) Set(hash common.Hash, flag config.CongestionFlag, riAge time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Evict before inserting if at capacity, to avoid evicting the new entry
	if c.maxSize > 0 && len(c.flags) >= c.maxSize {
		// Don't evict the entry we're about to set if it already exists
		c.evictEntry(hash)
	}

	c.flags[hash] = cachedFlag{
		flag:     flag,
		parsedAt: time.Now(),
		riAge:    riAge,
	}
}

// evictEntry removes a random entry from the cache, skipping the given hash.
// Uses O(1) random eviction by leveraging Go's randomized map iteration order.
// Must be called with c.mu held.
func (c *CongestionCache) evictEntry(skipHash common.Hash) {
	for h := range c.flags {
		if h != skipHash {
			delete(c.flags, h)
			return
		}
	}
}

// Delete removes a cached flag (called when RouterInfo is updated).
func (c *CongestionCache) Delete(hash common.Hash) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.flags, hash)
}

// Clear removes all cached flags.
func (c *CongestionCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.flags = make(map[common.Hash]cachedFlag)
}

// Size returns the number of cached flags.
func (c *CongestionCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return len(c.flags)
}

// NetDBCongestionTracker implements PeerCongestionInfo for StdNetDB.
// It provides congestion flag parsing and caching for remote peers.
type NetDBCongestionTracker struct {
	db    *StdNetDB
	cache *CongestionCache
	cfg   config.CongestionDefaults
}

// NewNetDBCongestionTracker creates a congestion tracker for the given NetDB.
func NewNetDBCongestionTracker(db *StdNetDB, cfg config.CongestionDefaults) *NetDBCongestionTracker {
	log.WithFields(logger.Fields{
		"at":     "NewNetDBCongestionTracker",
		"reason": "initialization",
	}).Debug("Creating NetDB congestion tracker")

	return &NetDBCongestionTracker{
		db:    db,
		cache: NewCongestionCache(),
		cfg:   cfg,
	}
}

// GetPeerCongestionFlag returns the congestion flag for a specific peer.
// Uses caching to avoid repeated parsing of RouterInfo caps.
func (t *NetDBCongestionTracker) GetPeerCongestionFlag(hash common.Hash) config.CongestionFlag {
	// Check cache first
	if flag, _, found := t.cache.Get(hash); found {
		return flag
	}

	// Load RouterInfo from database
	riChan := t.db.GetRouterInfo(hash)
	if riChan == nil {
		return config.CongestionFlagNone
	}

	ri, ok := <-riChan
	if !ok {
		return config.CongestionFlagNone
	}

	// Parse and cache the congestion flag
	flag := t.parseAndCacheCongestionFlag(hash, &ri)
	return flag
}

// parseAndCacheCongestionFlag parses the congestion flag from RouterInfo and caches it.
func (t *NetDBCongestionTracker) parseAndCacheCongestionFlag(hash common.Hash, ri *router_info.RouterInfo) config.CongestionFlag {
	caps := ri.RouterCapabilities()
	flag := config.ParseCongestionFlag(caps)

	// Get RouterInfo age for staleness tracking
	var riAge time.Time
	if published := ri.Published(); published != nil {
		riAge = published.Time()
	}

	t.cache.Set(hash, flag, riAge)

	log.WithFields(logger.Fields{
		"at":     "NetDBCongestionTracker.parseAndCacheCongestionFlag",
		"hash":   hash.String()[:16],
		"caps":   caps,
		"flag":   flag.String(),
		"reason": "parsed congestion flag from RouterInfo",
	}).Debug("cached peer congestion flag")

	return flag
}

// GetCongestionStats returns network-wide congestion statistics.
// Iterates through all known RouterInfos to calculate current statistics.
func (t *NetDBCongestionTracker) GetCongestionStats() CongestionStats {
	dCount, eCount, gCount, total := t.CountCongestedPeers()

	var ratio float64
	if total > 0 {
		ratio = float64(dCount+eCount+gCount) / float64(total)
	}

	stats := CongestionStats{
		TotalPeers:     total,
		DFlagCount:     dCount,
		EFlagCount:     eCount,
		GFlagCount:     gCount,
		CongestedRatio: ratio,
	}

	log.WithFields(logger.Fields{
		"at":              "NetDBCongestionTracker.GetCongestionStats",
		"total_peers":     stats.TotalPeers,
		"d_flag_count":    stats.DFlagCount,
		"e_flag_count":    stats.EFlagCount,
		"g_flag_count":    stats.GFlagCount,
		"congested_ratio": stats.CongestedRatio,
		"reason":          "calculated network congestion statistics",
	}).Debug("congestion stats calculated")

	return stats
}

// CountCongestedPeers returns counts of peers by congestion level.
func (t *NetDBCongestionTracker) CountCongestedPeers() (dCount, eCount, gCount, totalCount int) {
	allRIs := t.db.GetAllRouterInfos()
	totalCount = len(allRIs)

	for _, ri := range allRIs {
		hash, err := ri.IdentHash()
		if err != nil {
			continue
		}

		flag := t.GetPeerCongestionFlagFromRI(&ri, hash)
		switch flag {
		case config.CongestionFlagD:
			dCount++
		case config.CongestionFlagE:
			eCount++
		case config.CongestionFlagG:
			gCount++
		}
	}

	return dCount, eCount, gCount, totalCount
}

// GetPeerCongestionFlagFromRI parses congestion flag directly from RouterInfo.
// This is useful when RouterInfo is already loaded.
func (t *NetDBCongestionTracker) GetPeerCongestionFlagFromRI(ri *router_info.RouterInfo, hash common.Hash) config.CongestionFlag {
	// Check cache first
	if flag, _, found := t.cache.Get(hash); found {
		return flag
	}

	// Parse and cache
	return t.parseAndCacheCongestionFlag(hash, ri)
}

// InvalidatePeerCache invalidates the cache for a specific peer.
// Should be called when a peer's RouterInfo is updated.
func (t *NetDBCongestionTracker) InvalidatePeerCache(hash common.Hash) {
	t.cache.Delete(hash)

	log.WithFields(logger.Fields{
		"at":     "NetDBCongestionTracker.InvalidatePeerCache",
		"hash":   hash.String()[:16],
		"reason": "RouterInfo updated, cache invalidated",
	}).Debug("invalidated congestion cache for peer")
}

// ClearCache clears the entire congestion flag cache.
func (t *NetDBCongestionTracker) ClearCache() {
	t.cache.Clear()

	log.WithFields(logger.Fields{
		"at":     "NetDBCongestionTracker.ClearCache",
		"reason": "full cache clear requested",
	}).Debug("cleared congestion cache")
}

// GetCacheSize returns the number of cached congestion flags.
func (t *NetDBCongestionTracker) GetCacheSize() int {
	return t.cache.Size()
}

// IsStaleEFlag checks if a peer's E flag should be treated as D due to stale RouterInfo.
// Per PROP_162: if RouterInfo is older than EFlagAgeThreshold (15 min), treat E as D.
func (t *NetDBCongestionTracker) IsStaleEFlag(hash common.Hash) bool {
	_, riAge, found := t.cache.Get(hash)
	if !found {
		return false
	}

	if riAge.IsZero() {
		return false
	}

	age := time.Since(riAge)
	return age > t.cfg.EFlagAgeThreshold
}

// GetEffectiveCongestionFlag returns the effective congestion flag for peer selection.
// Handles stale E flag → D downgrade per PROP_162 spec.
func (t *NetDBCongestionTracker) GetEffectiveCongestionFlag(hash common.Hash) config.CongestionFlag {
	flag := t.GetPeerCongestionFlag(hash)

	// Per spec: E flag with stale RouterInfo is treated as D
	if flag == config.CongestionFlagE && t.IsStaleEFlag(hash) {
		log.WithFields(logger.Fields{
			"at":     "NetDBCongestionTracker.GetEffectiveCongestionFlag",
			"hash":   hash.String()[:16],
			"reason": "E flag with stale RouterInfo, treating as D",
		}).Debug("downgraded stale E flag to D")
		return config.CongestionFlagD
	}

	return flag
}

// Compile-time interface check
var _ PeerCongestionInfo = (*NetDBCongestionTracker)(nil)
