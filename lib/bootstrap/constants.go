package bootstrap

import (
	"time"

	"github.com/go-i2p/go-i2p/lib/config"
)

// ──────────────────────────────────────────────────────────────────────────────
// Peer cache on-disk format
// ──────────────────────────────────────────────────────────────────────────────

// The cache file is a fixed header followed by variable-length entries:
//
//	[4 bytes magic "PCAC"][1 byte version][4 bytes BE entry count]
//	per entry:
//	  [32 bytes ident hash][8 bytes BE last-activity unix seconds]
//	  [4 bytes BE router-info length][N bytes router-info]
//
// Moved from: peer_cache.go
const (
	peerCacheMagic0 byte = 'P'
	peerCacheMagic1 byte = 'C'
	peerCacheMagic2 byte = 'A'
	peerCacheMagic3 byte = 'C'

	peerCacheVersion byte = 1

	// peerCacheMagicSize is how many bytes spell the format tag.
	peerCacheMagicSize = 4

	// peerCacheVersionSize is the single byte carrying the format version.
	peerCacheVersionSize = 1

	// peerCacheCountFieldSize is the big-endian uint32 entry count.
	peerCacheCountFieldSize = 4

	// peerCacheHeaderSize is the fixed-size header before the first entry.
	peerCacheHeaderSize = peerCacheMagicSize + peerCacheVersionSize +
		peerCacheCountFieldSize // 9

	// peerCacheHashSize is the width of a cached RouterInfo identity hash.
	peerCacheHashSize = 32

	// peerCacheTimestampSize is the big-endian uint64 of last-activity seconds.
	peerCacheTimestampSize = 8

	// peerCacheLengthFieldSize is the big-endian uint32 router-info length.
	peerCacheLengthFieldSize = 4

	// peerCacheEntryFixedSize is the per-entry fixed overhead ahead of the
	// variable-length RouterInfo body.
	peerCacheEntryFixedSize = peerCacheHashSize + peerCacheTimestampSize +
		peerCacheLengthFieldSize // 44
)

// ──────────────────────────────────────────────────────────────────────────────
// RouterInfo freshness
// ──────────────────────────────────────────────────────────────────────────────

// Both the peer cache and the local netDb bootstrap reject a RouterInfo whose
// published date is older than the netDb's own expiry, and both tolerate a small
// clock difference between the machine that wrote the record and the one reading
// it. Sharing the values keeps a cache written today from being judged stale by a
// different rule than the netDb uses.
//
// Moved from: peer_cache.go, local_netdb_bootstrap.go
const (
	// routerInfoMaxAge is the maximum age of a cached RouterInfo before it is
	// considered stale and dropped. Mirrors the netDb reseed path.
	routerInfoMaxAge = 48 * time.Hour

	// maxClockSkew tolerates small clock differences between the machine that
	// wrote a record and the one reading it.
	maxClockSkew = 10 * time.Minute

	// peerCacheDefaultMaxSize is the default cap on cached peers.
	peerCacheDefaultMaxSize = config.DefaultPeerCacheMaxSize
)

// ──────────────────────────────────────────────────────────────────────────────
// Filesystem permissions
// ──────────────────────────────────────────────────────────────────────────────

// The peer cache holds RouterInfos for the peers we talk to, so it is written
// owner-only: another local account reading it would learn our peer set and its
// arrival order. The directory gets the execute bit it needs to be traversed but
// nothing more.
//
// Moved from: peer_cache.go
const (
	// peerCacheDirMode is the permission for the cache directory.
	peerCacheDirMode = 0o700

	// peerCacheFileMode is the permission for the cache file.
	peerCacheFileMode = 0o600
)

// ──────────────────────────────────────────────────────────────────────────────
// Reseed thresholds
// ──────────────────────────────────────────────────────────────────────────────

// Moved from: reseed_bootstrap.go, file_bootstrap.go, reseed_multi.go
const (
	// reseedRequestTimeout bounds the HTTP request to one reseed server, so an
	// unresponsive server cannot hang the whole bootstrap.
	reseedRequestTimeout = 30 * time.Second

	// slowReseedThreshold is the elapsed time past which a single server's reseed
	// is logged as slow. It is set to the request timeout, so a slow log means the
	// fetch used nearly all of the time it was given.
	slowReseedThreshold = 30 * time.Second

	// minValidRoutersAfterReseed is how many valid RouterInfos one server should
	// yield for the fetch to count as healthy. Below it the operator is warned the
	// server may need company, since a thin reply leaves the netDb short. Aliased
	// from lib/config so the threshold and the configured default agree.
	minValidRoutersAfterReseed = config.DefaultMinimumReseedPeers

	// minReseedFileSizeBytes is the smallest file that can be a real reseed
	// archive. A valid SU3 carries a signature block and at least one signed
	// RouterInfo, so anything near this size is a truncated download or an empty
	// placeholder rather than a reseed file.
	minReseedFileSizeBytes = 100

	// maxConcurrentReseedServers is how many reseed servers are contacted at once.
	// The cap keeps a bootstrap with many configured servers from flooding the
	// network — and from revealing the full server list in one burst — while still
	// finishing promptly.
	maxConcurrentReseedServers = 3
)

// ──────────────────────────────────────────────────────────────────────────────
// Local fallback and preflight timeouts
// ──────────────────────────────────────────────────────────────────────────────

// A bootstrap path that touches only the local filesystem or the resolver still
// needs a deadline, because a hung DNS lookup or a stalled disk read would
// otherwise block startup forever. These budgets are short by design: the work is
// local, so taking longer than a few seconds already indicates a problem.
//
// Moved from: composite_bootstrap.go, preflight.go
const (
	// localFallbackBudget is the fresh deadline given to filesystem bootstrap when
	// the caller's context has already expired.
	localFallbackBudget = 5 * time.Second

	// dnsPreflightTimeout bounds one resolver lookup during preflight.
	dnsPreflightTimeout = 5 * time.Second
)

// ──────────────────────────────────────────────────────────────────────────────
// Bootstrap method accounting
// ──────────────────────────────────────────────────────────────────────────────

// Moved from: composite_bootstrap.go
const (
	// bootstrapMethodCount is how many independent sources the composite
	// bootstrap tries — peer cache, reseed file, reseed servers, local netDb — and
	// therefore the count reported when all of them fail.
	bootstrapMethodCount = 4

	// requestLimitOverfetchFactor is how the file bootstrap inflates a caller's
	// requested peer count before reading. A reseed file contains entries that
	// fail validation, so asking for exactly the number wanted would come up
	// short.
	requestLimitOverfetchFactor = 2
)

// ──────────────────────────────────────────────────────────────────────────────
// Display helpers
// ──────────────────────────────────────────────────────────────────────────────

// Moved from: validation.go
const (
	// percentBase converts a ratio into a percentage for the validity-rate and
	// success-rate figures the bootstrap reports.
	percentBase = 100.0

	// hashLogPrefixBytes is how many leading bytes of an identity hash are printed
	// when a full hash would only bloat the log line.
	hashLogPrefixBytes = 8
)
