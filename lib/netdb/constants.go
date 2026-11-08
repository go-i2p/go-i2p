package netdb

import (
	"time"

	"github.com/go-i2p/go-i2p/lib/i2np"
)

// ──────────────────────────────────────────────────────────────────────────────
// Peer reliability threshold constants
// ──────────────────────────────────────────────────────────────────────────────

// LowSuccessRateThreshold is the success rate below which a peer is
// considered stale. Used by PeerTracker.IsLikelyStale.
const LowSuccessRateThreshold = 0.25

// HighSuccessRateThreshold is the success rate above which a peer is
// considered reliable. Used by PeerTracker.GetReliablePeers.
const HighSuccessRateThreshold = 0.75

// MinAttemptsForStats is the minimum number of connection attempts
// before a peer's success rate is considered statistically meaningful.
const MinAttemptsForStats = 5

// ConsecutiveFailThreshold is the number of consecutive failures that
// triggers automatic staleness classification.
const ConsecutiveFailThreshold = 3

// EMAAlpha is the exponential moving average smoothing factor used
// for response time tracking. A value of 0.2 gives new samples 20%
// weight, providing a stable average that smoothly adapts to changing
// network conditions without being overly reactive to outliers.
const EMAAlpha = 0.2

// StalenessCheckWindow is the lookback window for the "recent failures
// without recent success" staleness check in PeerTracker.
const StalenessCheckWindow = 1 * time.Hour

// ──────────────────────────────────────────────────────────────────────────────
// Floodfill rate limiter tuning
// ──────────────────────────────────────────────────────────────────────────────

// The floodfill server runs two token buckets per peer: a per-peer bucket that
// bounds one identity and an aggregate global bucket that bounds the total load
// across every identity. Both are expressed as requests-per-minute plus a burst
// ceiling, and both are converted to a per-second refill rate by dividing by the
// number of seconds in a minute.
//
// Moved from: floodfill_server.go
const (
	// defaultFloodfillGlobalRequestsPerMinute is the aggregate lookup budget
	// shared by all peers when a caller uses NewFloodfillRateLimiter. It exists
	// so many distinct (or spoofed) identities cannot collectively flood the
	// server even while each stays inside its own per-peer allowance.
	defaultFloodfillGlobalRequestsPerMinute = 2000

	// defaultFloodfillGlobalBurst is the global bucket's ceiling: how many
	// aggregate lookups may be served instantly before the per-second refill
	// takes over. Sized at a quarter of the minute budget so a burst is
	// absorbed but a sustained flood is shed.
	defaultFloodfillGlobalBurst = 500

	// defaultFloodfillLookupRequestsPerMinute is the per-peer DatabaseLookup
	// budget for a floodfill server. 60/min is one request per second per peer,
	// comfortably above honest periodic lookup traffic yet low enough that a
	// single misbehaving router cannot exhaust the NetDB's CPU.
	defaultFloodfillLookupRequestsPerMinute = 60

	// defaultFloodfillLookupBurst is the per-peer bucket's ceiling, allowing a
	// short spike (e.g. a router recovering from a restart and re-lookups up
	// several keys at once) before throttling engages.
	defaultFloodfillLookupBurst = 10

	// secondsPerMinute converts a requests-per-minute figure into the bucket's
	// per-second refill rate.
	secondsPerMinute = 60.0

	// tokensPerRequest is what one admitted request costs from a token bucket,
	// and (as a refund) what a request rejected by the peer bucket gives back
	// to the global bucket.
	tokensPerRequest = 1.0

	// floodfillLimiterCleanupInterval is how often the rate limiter sweeps
	// idle peers so its per-peer map cannot grow without bound.
	floodfillLimiterCleanupInterval = 5 * time.Minute

	// floodfillLimiterStalePeerAge is how long a peer must be silent before the
	// sweep drops its bucket. Set below the refill horizon so a dropped peer
	// would simply have a full bucket again on its next request.
	floodfillLimiterStalePeerAge = 2 * time.Minute

	// floodfillSelfRouterInfoTimeout bounds the wait for our own RouterInfo
	// when advertising floodfill capability. It is a local channel read, so a
	// second is already generous; beyond that the caller has a NetDB problem,
	// not a slow network.
	floodfillSelfRouterInfoTimeout = 1 * time.Second
)

// ──────────────────────────────────────────────────────────────────────────────
// Floodfill replication fan-out
// ──────────────────────────────────────────────────────────────────────────────

// defaultFloodfillPeers is how many of the closest floodfill routers a RouterInfo
// or LeaseSet is published to, and (symmetrically) how many peers a stored entry
// is flooded to. The publisher, the floodfill server's default config, and its
// fallback when configured with a non-positive count all want the same number.
// Four matches Java I2P's floodfill replication factor and gives the entry a
// reasonable chance of surviving a floodfill restart without writing it to every
// floodfill on the network.
//
// Moved from: floodfill_server.go, publisher.go
const defaultFloodfillPeers = 4

// ──────────────────────────────────────────────────────────────────────────────
// Peer sampling for exploratory lookups
// ──────────────────────────────────────────────────────────────────────────────

// explorationExcludedPeerSampleSize caps how many already-known peer hashes are
// placed in an exploratory DatabaseLookup's exclude list. The list travels in the
// message body, so an unbounded exclude set would grow the lookup past the 2-byte
// I2NP payload limit. 100 is enough to suppress re-suggestions on a normally
// sized NetDB while keeping the message small; i2pd likewise sends a bounded
// subset rather than its whole routing table.
//
// Moved from: kad.go
const explorationExcludedPeerSampleSize = 100

// ──────────────────────────────────────────────────────────────────────────────
// DatabaseStore RouterInfo payload framing
// ──────────────────────────────────────────────────────────────────────────────

// databaseStoreLengthFieldSize is the width of the big-endian Integer that
// prefixes a type-0 (RouterInfo) DatabaseStore payload with the length of the
// gzip bytes that follow. The payload is therefore
// [databaseStoreLengthFieldSize] + compressedLen bytes.
//
// Spec: i2np.rst §"Database Store Message" ("data is a 2-byte Integer specifying
// the number of bytes that follow")
// Moved from: floodfill_server.go, kad.go, publisher.go
const databaseStoreLengthFieldSize = 2

// ──────────────────────────────────────────────────────────────────────────────
// Identity / key sizes and log redaction
// ──────────────────────────────────────────────────────────────────────────────

const (
	// hashLogPrefixBytes is how many leading bytes of an identity hash are
	// included in error and log messages. It matches the prefix
	// logutil.HashPrefix truncates to: enough to correlate one peer across a
	// log file while withholding the full identity, which is an
	// anonymity-sensitive value.
	// Moved from: destination_resolver.go, floodfill_server.go, kad.go, publisher.go
	hashLogPrefixBytes = 8

	// hashLogPrefixHexChars is the same prefix expressed in hex characters,
	// derived from the byte count so the two cannot disagree. Used where the
	// hash is already a hex string rather than raw bytes.
	// Moved from: congestion.go, peer_tracker.go, publisher.go
	hashLogPrefixHexChars = hashLogPrefixBytes * 2 // 16

	// x25519EncryptionKeySize is the width in bytes of the X25519 encryption
	// public key a LeaseSet2 carries. A LeaseSet2 whose EncryptionKey field is
	// any other length cannot hold a usable key and is rejected rather than
	// truncated.
	// Moved from: destination_resolver.go
	x25519EncryptionKeySize = 32
)

// ──────────────────────────────────────────────────────────────────────────────
// NetDB entry file framing
// ──────────────────────────────────────────────────────────────────────────────

// The on-disk skiplist entry is: 1-byte type indicator, 2-byte big-endian data
// length, then the serialized payload.
//
// Moved from: entry.go
const (
	// entryDataLengthFieldSize is the width of the entry header's length field.
	entryDataLengthFieldSize = 2

	// entryDataMaxLength is the largest payload that length field can name.
	// Exceeding it would silently truncate the value in the uint16 write, so
	// serialization fails instead.
	entryDataMaxLength = (1 << (entryDataLengthFieldSize * bitsPerByte)) - 1 // 65535
)

// ──────────────────────────────────────────────────────────────────────────────
// Congestion flag cache
// ──────────────────────────────────────────────────────────────────────────────

// Moved from: congestion.go
const (
	// congestionCacheMaxEntries bounds the congestion-flag cache so a router
	// with a very large NetDB cannot be made to cache one parsed flag per peer
	// indefinitely. 2048 comfortably covers the peers a single tunnel-build
	// pass consults.
	congestionCacheMaxEntries = 2048

	// congestionCacheTTL is how long a cached congestion flag stays usable.
	// Congestion flags are published in RouterInfo caps and refreshed on the
	// 30-minute RouterInfo republish cycle, so the TTL matches that cycle: an
	// entry older than a full republish window is no evidence of current state.
	congestionCacheTTL = 30 * time.Minute
)

// ──────────────────────────────────────────────────────────────────────────────
// Database explorer defaults
// ──────────────────────────────────────────────────────────────────────────────

// DefaultExplorerConfig values. The explorer performs periodic DHT lookups to
// grow the NetDB beyond the floodfills, so its cadence is deliberately slow:
// growth is a background concern and every lookup costs bandwidth on a peer.
//
// Moved from: exploration.go
const (
	// defaultExplorerInterval is the steady-state delay between exploration
	// rounds.
	defaultExplorerInterval = 5 * time.Minute

	// defaultExplorerMinInterval is the floor the adaptive strategy may
	// back-off to when the NetDB is sparse.
	defaultExplorerMinInterval = 1 * time.Minute

	// defaultExplorerMaxInterval is the ceiling the adaptive strategy may
	// relax to when the NetDB looks healthy.
	defaultExplorerMaxInterval = 15 * time.Minute

	// defaultExplorerConcurrency is how many exploration lookups run in
	// parallel per round, matching the DHT alpha-style parallelism that
	// saturates a round without hammering any one peer.
	defaultExplorerConcurrency = 3

	// defaultLookupTimeout bounds a single RouterInfo lookup. 30s is long
	// enough to cover multi-hop tunnel round-trips plus a peer's own remote
	// lookup, and short enough that an unreachable peer is abandoned rather
	// than stalling the caller's budget.
	defaultLookupTimeout = 30 * time.Second

	// defaultStatsUpdateInterval is how often the explorer refreshes the
	// adaptive strategy's bucket statistics from the NetDB.
	defaultStatsUpdateInterval = 1 * time.Minute
)

// ──────────────────────────────────────────────────────────────────────────────
// Adaptive exploration strategy thresholds
// ──────────────────────────────────────────────────────────────────────────────

// Moved from: exploration_strategy.go
const (
	// defaultMinNetDBSize is the router count below which the adaptive strategy
	// considers the NetDB undersized and explores more aggressively. A router
	// needs a few hundred peers to pick diverse tunnel hops with reasonable
	// latency and bandwidth characteristics.
	defaultMinNetDBSize = 500

	// defaultMinFloodfillsTotal is the floodfill count below which exploration
	// is triggered regardless of total size, because a NetDB with too few
	// floodfills cannot answer DHT lookups reliably.
	defaultMinFloodfillsTotal = 50

	// netDBHealthySizeMultiplier is how far above the minimum size the NetDB
	// must climb before the strategy treats it as healthy and relaxes to the
	// maximum exploration interval.
	netDBHealthySizeMultiplier = 2
)

// ──────────────────────────────────────────────────────────────────────────────
// Peer reliability scoring
// ──────────────────────────────────────────────────────────────────────────────

// Scores produced by PeerTracker.ScorePeer and PeerTracker.GetSuccessRate are
// floats in [0,1] used to order peers for tunnel building and publish fallback.
// These are the fixed reference points of that scale.
//
// Moved from: peer_tracker.go, publisher.go
const (
	// unknownSuccessRate is GetSuccessRate's sentinel for "no data at all",
	// distinct from a measured 0.0 rate. Negative is safe because a real rate
	// is never below zero.
	unknownSuccessRate = -1.0

	// neutralPeerScore is the score for a peer we have no usable history on.
	// Mid-scale keeps unknown peers ordered between proven-good and
	// proven-bad ones instead of starving them of the chance to be measured.
	neutralPeerScore = 0.5

	// consecutiveFailPenaltyPerFailure is the per-consecutive-failure
	// deduction applied to a peer's success rate when scoring, so a peer that
	// just went bad sinks faster than its lifetime average implies.
	consecutiveFailPenaltyPerFailure = 0.1

	// maxConsecutiveFailPenalty caps that deduction so a long outage cannot
	// drive the score below the range the sorters expect.
	maxConsecutiveFailPenalty = 0.3
)

// ──────────────────────────────────────────────────────────────────────────────
// Publisher timing
// ──────────────────────────────────────────────────────────────────────────────

// Republish intervals match the I2P convention that a RouterInfo is refreshed
// well inside its own lifetime so it never expires in the DHT, while LeaseSets
// rotate on the much shorter lease clock.
//
// Moved from: publisher.go
const (
	// defaultRouterInfoPublishInterval is how often our RouterInfo is
	// republished to floodfills. RouterInfo lifetime is 90 minutes in Java I2P,
	// so 30 minutes refreshes it three times per lifetime.
	defaultRouterInfoPublishInterval = 30 * time.Minute

	// defaultLeaseSetPublishInterval is how often LeaseSets are republished,
	// tracking the ~10-minute lease period so advertised tunnels are replaced
	// before they expire.
	defaultLeaseSetPublishInterval = 5 * time.Minute

	// publisherVerifyTimeout bounds the pre-publish verification of the data
	// being handed to the DHT.
	publisherVerifyTimeout = 15 * time.Second

	// publisherSendAttemptTimeout bounds one DatabaseStore send attempt to a
	// floodfill, including obtaining a session to it.
	publisherSendAttemptTimeout = 20 * time.Second

	// publisherAckTimeout bounds the wait for the floodfill's DeliveryStatus
	// acknowledgement of a stored entry.
	publisherAckTimeout = 20 * time.Second

	// replyTokenMaxAge is how long a DatabaseStore reply token may stay pending
	// before the stale-token sweep retires it. Set above the publish interval
	// so an ack that arrives after a slow retry is still attributable, but well
	// below RouterInfo lifetime so tokens cannot accumulate forever.
	replyTokenMaxAge = 45 * time.Minute

	// publishAckPollInterval is how often the ack waiter re-checks its pending
	// reply tokens. Short enough to notice an ack promptly, long enough that
	// waiting for an ack costs no meaningful CPU.
	publishAckPollInterval = 250 * time.Millisecond

	// replyTokenGenerationAttempts is how many times generateReplyToken re-draws
	// random bytes before giving up. The all-zero token is reserved (floodfills
	// read it as "do not flood"), so the retry covers a repeated RNG failure;
	// three attempts make the odds of that effectively zero.
	replyTokenGenerationAttempts = 3
)

// ──────────────────────────────────────────────────────────────────────────────
// RouterInfo / LeaseSet expiration tolerance
// ──────────────────────────────────────────────────────────────────────────────

// Moved from: std.go, std_leaseset.go
const (
	// routerInfoFuturePublishTolerance is how far in the future a RouterInfo's
	// published timestamp may sit and still be accepted. Peer clocks skew, but
	// a timestamp beyond one hour ahead is not skew - it is a forged lifetime
	// or a broken clock, and accepting it would keep a router in the NetDB far
	// longer than its signature was valid for.
	// The matching backward bound is RouterInfoMaxAge in
	// routerinfo_expiration.go, which this check also applies.
	routerInfoFuturePublishTolerance = 1 * time.Hour

	// defaultLeaseSetExpiryFallback is the expiration assumed for a LeaseSet
	// whose newest lease expiration cannot be read, so the entry is still
	// eventually cleaned instead of living forever. 10 minutes matches the
	// standard lease period.
	defaultLeaseSetExpiryFallback = 10 * time.Minute

	// leaseSetCleanupInterval is how often the expiration cleaner sweeps
	// LeaseSets. Leases are short-lived, so the sweep runs at the lease
	// timescale rather than the RouterInfo timescale.
	leaseSetCleanupInterval = 1 * time.Minute

	// routerInfoCleanupTickDivisor is how many LeaseSet cleanup ticks must pass
	// before the slower RouterInfo/peer-tracker maintenance runs, i.e. RouterInfo
	// cleanup runs every 10 minutes off the 1-minute lease sweep.
	routerInfoCleanupTickDivisor = 10
)

// ──────────────────────────────────────────────────────────────────────────────
// NetDB on-disk permissions
// ──────────────────────────────────────────────────────────────────────────────

// The NetDB directory and its files hold other peers' RouterInfos and our own
// LeaseSets, which reveal our tunnel schedule and the peers we talk to. They are
// owner-only so other local accounts cannot read the routing table or the
// arrival order of entries.
//
// Moved from: std.go, std_leaseset.go
const (
	// netDBFileMode is the permission for NetDB entry files.
	netDBFileMode = 0o600

	// netDBDirMode is the permission for NetDB directories.
	netDBDirMode = 0o700
)

// ──────────────────────────────────────────────────────────────────────────────
// Peer diversity address families
// ──────────────────────────────────────────────────────────────────────────────

// routerAddressPrefix tags each peer address with the IP family its dedup
// prefix belongs to, so two peers in the same /16 (v4) or /48 (v6) - typically
// the same host or the same provider's block - count as one for diversity
// purposes. The tags are the IP protocol version numbers, which is how the
// values read everywhere else in the stack.
//
// Moved from: std_peer_selection.go
const (
	// ipv4AddressFamily selects the IPv4 prefix bucket.
	ipv4AddressFamily = 4

	// ipv6AddressFamily selects the IPv6 prefix bucket.
	ipv6AddressFamily = 6
)

// ──────────────────────────────────────────────────────────────────────────────
// Bit indexing
// ──────────────────────────────────────────────────────────────────────────────

// Kademlia-style distance work treats a 256-bit hash as a bit string, and the
// buckets are numbered from the most significant bit. A byte index and a bit
// index therefore have to be converted between each other, and the bit order
// inside a byte is inverted relative to the bucket order — bit 7 of byte 0 is
// bucket 0.
const (
	// bitsPerByte converts a byte count into a bit count.
	bitsPerByte = 8

	// highestBitIndex is the index of a byte's most significant bit, and also the
	// offset that inverts bucket order into bit order.
	highestBitIndex = bitsPerByte - 1 // 7
)

// ──────────────────────────────────────────────────────────────────────────────
// Percentage arithmetic
// ──────────────────────────────────────────────────────────────────────────────

// percentWhole is the denominator for the occupancy thresholds expressed as
// percentages, so a threshold and its comparison cannot use different bases.
//
// Moved from: admission_controller.go
const percentWhole = 100

// ──────────────────────────────────────────────────────────────────────────────
// Floodfill lookup flag decoding
// ──────────────────────────────────────────────────────────────────────────────

// A floodfill reads the reply routing and record type straight out of the
// DatabaseLookup flags byte. The field positions are defined by i2np, which owns
// the message; these are the values a field takes once extracted.
//
// Spec: https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/database.rst
// Moved from: floodfill_server.go
const (
	// floodfillTunnelReplyValue is the delivery field (bit 0) set to 1: send the
	// reply through the tunnel named by ReplyTunnelID rather than directly to the
	// requesting router.
	floodfillTunnelReplyValue = 1

	// floodfillLookupTypeShift and floodfillLookupTypeMask locate the 2-bit lookup
	// type field at bits 3-2.
	floodfillLookupTypeShift = 2
	floodfillLookupTypeMask  = 0x03

	// The lookup type values below are the i2np flag constants shifted down out of
	// bits 3-2, so the floodfill's decoding agrees with the requester's encoding
	// by construction rather than by two lists of literals matching.
	floodfillLookupTypeAny         = i2np.DatabaseLookupFlagTypeNormal >> floodfillLookupTypeShift
	floodfillLookupTypeLeaseSet    = i2np.DatabaseLookupFlagTypeLS >> floodfillLookupTypeShift
	floodfillLookupTypeRouterInfo  = i2np.DatabaseLookupFlagTypeRI >> floodfillLookupTypeShift
	floodfillLookupTypeExploration = i2np.DatabaseLookupFlagTypeExploration >> floodfillLookupTypeShift
)
