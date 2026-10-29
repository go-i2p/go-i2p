package bootstrap

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// Peer cache on-disk format constants.
//
// The cache is a self-contained binary file (no gob, consistent with the
// codebase's existing compact binary conventions). Layout:
//
//	[4 bytes magic "PCAC"][1 byte version][4 bytes BE entry count]
//	per entry:
//	  [32 bytes ident hash][8 bytes BE last-activity unix seconds]
//	  [4 bytes BE router-info length][N bytes router-info]
const (
	peerCacheMagic0 byte = 'P'
	peerCacheMagic1 byte = 'C'
	peerCacheMagic2 byte = 'A'
	peerCacheMagic3 byte = 'C'

	peerCacheVersion byte = 1

	// peerCacheHeaderSize is the fixed-size header before the first entry.
	peerCacheHeaderSize = 4 + 1 + 4

	// peerCacheEntryFixedSize is the per-entry fixed overhead:
	// 32-byte hash + 8-byte timestamp + 4-byte length.
	peerCacheEntryFixedSize = 32 + 8 + 4

	// peerCacheMaxAge is the maximum age of a cached RouterInfo before it is
	// considered stale and dropped. Mirrors the 48h RouterInfoMaxAge used by
	// the netDb reseed path.
	peerCacheMaxAge = 48 * time.Hour

	// peerCacheMaxClockSkew tolerates small clock differences between the
	// machine that wrote the cache and the one reading it.
	peerCacheMaxClockSkew = 10 * time.Minute

	// peerCacheDefaultMaxSize is the default cap on cached peers.
	peerCacheDefaultMaxSize = 500
)

// cachedPeer is a single entry in the peer cache.
type cachedPeer struct {
	// hash is the router's ident hash, used as the map key and for dedup.
	hash common.Hash
	// lastActivity is the last time this peer was seen/recorded. Used for
	// LRU eviction and freshness ordering.
	lastActivity time.Time
	// routerInfo is the serialized RouterInfo bytes.
	routerInfo []byte
}

// PeerCache is a bounded, on-disk cache of recently discovered peer
// RouterInfos. It is self-contained (does not import lib/netdb) so it can
// live in the bootstrap package without an import cycle.
//
// The cache is loaded once at startup and consulted as the fastest local
// bootstrap source. Fresh, valid peers are returned immediately, avoiding a
// network reseed on repeat startups. Newly discovered peers are recorded back
// to the cache with a last-activity timestamp; entries are evicted by
// last-activity (LRU) once the size limit is exceeded.
type PeerCache struct {
	// path is the on-disk cache file location.
	path string
	// maxSize is the maximum number of cached peers.
	maxSize int
	// mu guards peers.
	mu sync.RWMutex
	// peers maps ident hash to cached peer.
	peers map[common.Hash]*cachedPeer
	// loaded indicates the cache has been read from disk.
	loaded bool
}

// NewPeerCache creates a peer cache backed by the file at path. If maxSize is
// <= 0, peerCacheDefaultMaxSize is used. The cache is not loaded until Load is
// called.
func NewPeerCache(path string, maxSize int) *PeerCache {
	if maxSize <= 0 {
		maxSize = peerCacheDefaultMaxSize
	}
	return &PeerCache{
		path:    path,
		maxSize: maxSize,
		peers:   make(map[common.Hash]*cachedPeer),
	}
}

// Load reads the cache file from disk into memory, validating each entry's
// signature and freshness. Missing or corrupt files are not fatal: the cache
// simply starts empty.
func (pc *PeerCache) Load(ctx context.Context) error {
	if pc.path == "" {
		return nil
	}

	if ctx.Err() != nil {
		return oops.Wrapf(ctx.Err(), "peer cache load canceled")
	}

	data, err := os.ReadFile(pc.path)
	if err != nil {
		if os.IsNotExist(err) {
			// No cache yet — start empty.
			pc.loaded = true
			return nil
		}
		return oops.Wrapf(err, "failed to read peer cache file")
	}

	entries, err := parsePeerCache(data)
	if err != nil {
		// A corrupt cache should not block bootstrap; log and start empty.
		log.WithError(err).WithFields(logger.Fields{
			"at":      "(PeerCache) Load",
			"phase":   "bootstrap",
			"reason":  "corrupt_cache",
			"file":    pc.path,
		}).Warn("peer cache file is corrupt, starting with empty cache")
		pc.loaded = true
		return nil
	}

	now := time.Now()
	valid := 0
	pc.mu.Lock()
	for _, e := range entries {
		ri, _, err := router_info.ReadRouterInfo(e.routerInfo)
		if err != nil {
			continue
		}
		// Re-validate signature and freshness on load so stale or tampered
		// entries are dropped.
		if err := VerifyRouterInfoSignature(ri); err != nil {
			continue
		}
		if err := validateRouterInfoFreshness(ri); err != nil {
			continue
		}
		hash, err := ri.IdentHash()
		if err != nil {
			continue
		}
		lastActivity := e.lastActivity
		if lastActivity.After(now) {
			lastActivity = now
		}
		pc.peers[hash] = &cachedPeer{
			hash:         hash,
			lastActivity: lastActivity,
			routerInfo:   e.routerInfo,
		}
		valid++
	}
	pc.loaded = true
	pc.mu.Unlock()

	// Enforce the size cap after loading (a hand-edited or older cache may
	// exceed the current limit).
	pc.evictIfNeeded()

	log.WithFields(logger.Fields{
		"at":         "(PeerCache) Load",
		"phase":      "bootstrap",
		"step":       "complete",
		"file":       pc.path,
		"total":      len(entries),
		"valid":      valid,
		"max_size":   pc.maxSize,
	}).Info("peer cache loaded")

	return nil
}

// GetPeers implements the Bootstrap interface. It returns up to n fresh,
// valid cached peers ordered by most-recently-active first. If n <= 0, all
// cached peers are returned. Returns an error if no usable peers are cached.
func (pc *PeerCache) GetPeers(ctx context.Context, n int) ([]router_info.RouterInfo, error) {
	if ctx.Err() != nil {
		return nil, oops.Wrapf(ctx.Err(), "peer cache read canceled")
	}

	pc.mu.RLock()
	peers := make([]router_info.RouterInfo, 0, len(pc.peers))
	for _, cp := range pc.peers {
		ri, _, err := router_info.ReadRouterInfo(cp.routerInfo)
		if err != nil {
			continue
		}
		peers = append(peers, ri)
	}
	pc.mu.RUnlock()

	if len(peers) == 0 {
		return nil, oops.Errorf("no peers in cache")
	}

	// Order by most-recently-active first so the freshest peers are preferred.
	sort.Slice(peers, func(i, j int) bool {
		hi, ei := peers[i].IdentHash()
		hj, ej := peers[j].IdentHash()
		if ei != nil || ej != nil {
			return false
		}
		return pc.activity(hi).After(pc.activity(hj))
	})

	if n > 0 && len(peers) > n {
		peers = peers[:n]
	}

	log.WithFields(logger.Fields{
		"at":           "(PeerCache) GetPeers",
		"phase":        "bootstrap",
		"step":         "complete",
		"router_count": len(peers),
	}).Info("loaded peers from cache")

	return peers, nil
}

// activity returns the last-activity time for a hash (zero if unknown).
func (pc *PeerCache) activity(hash common.Hash) time.Time {
	pc.mu.RLock()
	defer pc.mu.RUnlock()
	if cp, ok := pc.peers[hash]; ok {
		return cp.lastActivity
	}
	return time.Time{}
}

// Record adds or updates the given peers in the cache, stamping them with the
// current time as their last-activity, then persists the cache to disk.
// Peers that fail signature validation are skipped.
func (pc *PeerCache) Record(peers []router_info.RouterInfo) error {
	if pc.path == "" || len(peers) == 0 {
		return nil
	}

	now := time.Now()
	added := 0
	pc.mu.Lock()
	for i := range peers {
		ri := peers[i]
		if err := VerifyRouterInfoSignature(ri); err != nil {
			continue
		}
		hash, err := ri.IdentHash()
		if err != nil {
			continue
		}
		b, err := ri.Bytes()
		if err != nil {
			continue
		}
		pc.peers[hash] = &cachedPeer{
			hash:         hash,
			lastActivity: now,
			routerInfo:   b,
		}
		added++
	}
	pc.mu.Unlock()

	if added > 0 {
		pc.evictIfNeeded()
		if err := pc.Save(); err != nil {
			return err
		}
		log.WithFields(logger.Fields{
			"at":         "(PeerCache) Record",
			"phase":      "bootstrap",
			"step":       "complete",
			"recorded":   added,
			"total":      pc.Size(),
			"max_size":   pc.maxSize,
		}).Info("recorded peers to cache")
	}

	return nil
}

// Size returns the number of cached peers.
func (pc *PeerCache) Size() int {
	pc.mu.RLock()
	defer pc.mu.RUnlock()
	return len(pc.peers)
}

// evictIfNeeded drops the least-recently-active entries until the cache is at
// or below maxSize. Callers must not hold the lock.
func (pc *PeerCache) evictIfNeeded() {
	pc.mu.Lock()
	defer pc.mu.Unlock()

	if len(pc.peers) <= pc.maxSize {
		return
	}

	// Sort by last-activity ascending so the oldest are evicted first.
	entries := make([]*cachedPeer, 0, len(pc.peers))
	for _, cp := range pc.peers {
		entries = append(entries, cp)
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].lastActivity.Before(entries[j].lastActivity)
	})

	toEvict := len(pc.peers) - pc.maxSize
	for i := 0; i < toEvict; i++ {
		delete(pc.peers, entries[i].hash)
	}
}

// Save persists the current cache to disk atomically (write to temp file,
// then rename).
func (pc *PeerCache) Save() error {
	if pc.path == "" {
		return nil
	}

	pc.mu.RLock()
	entries := make([]cachedPeer, 0, len(pc.peers))
	for _, cp := range pc.peers {
		entries = append(entries, *cp)
	}
	pc.mu.RUnlock()

	// Order by last-activity descending so the most-recently-active peers are
	// written first (they survive any future truncation).
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].lastActivity.After(entries[j].lastActivity)
	})

	buf := make([]byte, 0, peerCacheHeaderSize+len(entries)*peerCacheEntryFixedSize)
	buf = append(buf, peerCacheMagic0, peerCacheMagic1, peerCacheMagic2, peerCacheMagic3)
	buf = append(buf, peerCacheVersion)
	var count [4]byte
	binary.BigEndian.PutUint32(count[:], uint32(len(entries)))
	buf = append(buf, count[:]...)

	for _, e := range entries {
		var ts [8]byte
		binary.BigEndian.PutUint64(ts[:], uint64(e.lastActivity.Unix()))
		buf = append(buf, e.hash[:]...)
		buf = append(buf, ts[:]...)
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(e.routerInfo)))
		buf = append(buf, length[:]...)
		buf = append(buf, e.routerInfo...)
	}

	if err := os.MkdirAll(filepath.Dir(pc.path), 0o700); err != nil {
		return oops.Wrapf(err, "failed to create peer cache directory")
	}

	tmp := pc.path + ".tmp"
	if err := os.WriteFile(tmp, buf, 0o600); err != nil {
		return oops.Wrapf(err, "failed to write peer cache temp file")
	}
	if err := os.Rename(tmp, pc.path); err != nil {
		os.Remove(tmp)
		return oops.Wrapf(err, "failed to rename peer cache file")
	}

	return nil
}

// parsePeerCache decodes the on-disk cache format into raw entries. It bounds
// each RouterInfo read to i2np.MaxRouterInfoSize to prevent OOM from a
// maliciously crafted cache file.
func parsePeerCache(data []byte) ([]cachedPeer, error) {
	if len(data) < peerCacheHeaderSize {
		return nil, oops.Errorf("peer cache too small: %d bytes", len(data))
	}
	if data[0] != peerCacheMagic0 || data[1] != peerCacheMagic1 ||
		data[2] != peerCacheMagic2 || data[3] != peerCacheMagic3 {
		return nil, oops.Errorf("peer cache bad magic")
	}
	if data[4] != peerCacheVersion {
		return nil, oops.Errorf("peer cache unsupported version %d", data[4])
	}

	count := binary.BigEndian.Uint32(data[5:9])
	if count == 0 {
		return nil, nil
	}

	entries := make([]cachedPeer, 0, count)
	off := peerCacheHeaderSize
	for i := uint32(0); i < count; i++ {
		if off+peerCacheEntryFixedSize > len(data) {
			return nil, oops.Errorf("peer cache truncated at entry %d", i)
		}
		hash := data[off : off+32]
		lastActivity := int64(binary.BigEndian.Uint64(data[off+32 : off+40]))
		length := binary.BigEndian.Uint32(data[off+40 : off+44])
		off += peerCacheEntryFixedSize

		if length > i2np.MaxRouterInfoSize {
			return nil, oops.Errorf("peer cache entry %d too large: %d bytes", i, length)
		}
		if off+int(length) > len(data) {
			return nil, oops.Errorf("peer cache truncated at entry %d payload", i)
		}
		riBytes := make([]byte, length)
		copy(riBytes, data[off:off+int(length)])
		off += int(length)

		var h common.Hash
		copy(h[:], hash)
		entries = append(entries, cachedPeer{
			hash:         h,
			lastActivity: time.Unix(lastActivity, 0),
			routerInfo:   riBytes,
		})
	}

	return entries, nil
}