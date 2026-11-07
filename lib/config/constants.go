package config

import "time"

// ──────────────────────────────────────────────────────────────────────────────
// Bandwidth class boundaries (Proposal 162)
// ──────────────────────────────────────────────────────────────────────────────

// BytesPerKiB is the divisor converting bytes/second into the KBps unit the
// bandwidth classes and the I2CP BandwidthLimits message are expressed in.
// Moved from: caps.go, router.go
const BytesPerKiB = 1024

// Bandwidth class thresholds, in KBps, as advertised in the RouterInfo caps
// string. The I2P spec allows either 2000 or 2048 KBps as the P/X boundary
// (implementor's choice); this implementation uses 2000.
//
// Spec: https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/common-structures.rst
// Moved from: caps.go
const (
	// BandwidthClassLMinKBps is the lower bound of the "L" class; below it a
	// router is class "K".
	BandwidthClassLMinKBps = 12
	// BandwidthClassMMinKBps is the lower bound of the "M" class.
	BandwidthClassMMinKBps = 48
	// BandwidthClassNMinKBps is the lower bound of the "N" class.
	BandwidthClassNMinKBps = 64
	// BandwidthClassOMinKBps is the lower bound of the "O" class.
	BandwidthClassOMinKBps = 128
	// BandwidthClassPMinKBps is the lower bound of the "P" class.
	BandwidthClassPMinKBps = 256
	// BandwidthClassXMinKBps is the lower bound of the "X" class.
	BandwidthClassXMinKBps = 2000
)

// ──────────────────────────────────────────────────────────────────────────────
// Network address constants
// ──────────────────────────────────────────────────────────────────────────────

const (
	// LoopbackIPv4Prefix is the address prefix identifying an IPv4 loopback
	// bind. Used to decide whether a cleartext control interface is reachable
	// off-machine.
	// Moved from: defaults.go
	LoopbackIPv4Prefix = "127.0.0.1:"

	// LoopbackIPv6Prefix is the address prefix identifying an IPv6 loopback
	// bind, in the bracketed host form net.JoinHostPort produces.
	// Moved from: defaults.go
	LoopbackIPv6Prefix = "[::1]:"

	// LocalhostPrefix is the hostname prefix identifying a localhost bind.
	// Moved from: defaults.go
	LocalhostPrefix = "localhost:"

	// MaxPort is the largest valid TCP/UDP port number. A port of 0 is legal
	// and means "let the OS assign one".
	// Moved from: defaults.go
	MaxPort = 65535
)

// DefaultI2PControlPassword is the standard default password defined by the
// I2PControl specification. It is unsafe for any non-loopback bind; the
// validation in defaults.go rejects it there and security.go warns about it.
// Moved from: defaults.go, i2pcontrol.go, security.go
const DefaultI2PControlPassword = "itoopie"

// ──────────────────────────────────────────────────────────────────────────────
// Security constants
// ──────────────────────────────────────────────────────────────────────────────

// RandomPasswordBytes is the entropy, in bytes, drawn for a generated
// I2PControl password. Encoded as URL-safe base64 it yields a 32-character
// string.
// Moved from: security.go
const RandomPasswordBytes = 24

// ──────────────────────────────────────────────────────────────────────────────
// Validation bounds
// ──────────────────────────────────────────────────────────────────────────────

// These are the floors and ceilings Validate enforces on operator-supplied
// configuration. They are separate from the defaults below: a default is a
// starting value, a bound is a refusal.
// Moved from: defaults.go

const (
	// MinRouterInfos is the smallest NetDB router-info cache that can still
	// hold a usable view of the network.
	MinRouterInfos = 10

	// MinAdmissionPressurePct and MaxAdmissionPressurePct bound the admission
	// pressure threshold, which is a percentage.
	MinAdmissionPressurePct = 1
	MaxAdmissionPressurePct = 99

	// MinMaxMessageSizeBytes is the smallest transport message size that can
	// carry a full tunnel-data frame plus its framing overhead.
	MinMaxMessageSizeBytes = 1024

	// MinParticipatingTunnels is the smallest participating-tunnel pool that
	// is worth enabling the limit for; below it a router cannot serve enough
	// peers to be a useful network participant.
	MinParticipatingTunnels = 100
)

// ──────────────────────────────────────────────────────────────────────────────
// Default tuning values
// ──────────────────────────────────────────────────────────────────────────────

// NetDB defaults. Moved from: netdb.go, defaults.go
const (
	// DefaultMaxRouterInfos is the size of the in-memory router-info cache.
	DefaultMaxRouterInfos = 5000
	// DefaultMaxLeaseSets is the size of the in-memory lease-set cache.
	DefaultMaxLeaseSets = 1000
	// DefaultRouterInfoAdmissionPressurePct is the cache-pressure percentage
	// at which per-source admission limits start to apply.
	DefaultRouterInfoAdmissionPressurePct = 80
)

// Bootstrap defaults. Moved from: bootstrap.go, defaults.go
const (
	// DefaultLowPeerThreshold is the peer count under which the router
	// considers itself short of peers and re-seeds.
	DefaultLowPeerThreshold = 10
	// DefaultMinimumReseedPeers is the number of peers a reseed must yield to
	// count as successful.
	DefaultMinimumReseedPeers = 50
	// DefaultPeerCacheMaxSize is the number of peers retained in the on-disk
	// peer cache; least-recently-active peers are evicted past it.
	// Moved from: bootstrap.go, defaults.go
	DefaultPeerCacheMaxSize = 500
)

// I2CP server defaults. Moved from: router.go, defaults.go
const (
	// DefaultI2CPMaxSessions is the default concurrent I2CP client session
	// cap. The hard ceiling is MaxI2CPSessions.
	DefaultI2CPMaxSessions = 100
	// DefaultI2CPMessageQueueSize is the per-session outbound message queue depth.
	DefaultI2CPMessageQueueSize = 64
)

// Router defaults. Moved from: router.go, config.go, defaults.go
const (
	// DefaultMaxBandwidthBytesPerSec is the shared bandwidth limit for a
	// router with no configured tier: 1 MB/s, which lands in bandwidth class
	// "N" (64-128 KBps) once the outbound share is taken into account.
	DefaultMaxBandwidthBytesPerSec = 1024 * BytesPerKiB
	// DefaultRouterMaxConnections is the router-wide peer connection cap.
	DefaultRouterMaxConnections = 200
	// DefaultMaxConcurrentSessions is the number of concurrent client sessions
	// the router allows.
	DefaultMaxConcurrentSessions = 200
	// DefaultNTCP2MaxConnections is the NTCP2 transport's own connection cap,
	// distinct from the router-wide limit above.
	DefaultNTCP2MaxConnections = 200
)

// Tunnel defaults. Moved from: defaults.go
const (
	// DefaultMaxParticipatingTunnels bounds how many tunnels this router
	// agrees to host, as resource-exhaustion protection.
	DefaultMaxParticipatingTunnels = 15000
	// DefaultMaxBuildRequestsPerMinute is the per-source tunnel-build rate limit.
	DefaultMaxBuildRequestsPerMinute = 10
)

// Transport defaults. Moved from: defaults.go
const (
	// DefaultTransportMaxMessageSizeBytes is the largest message the transport
	// will carry: 32 KiB.
	DefaultTransportMaxMessageSizeBytes = 32768
)

// Performance defaults. Moved from: defaults.go
const (
	// DefaultPerformanceMessageQueueSize is the router-wide inbound queue depth.
	DefaultPerformanceMessageQueueSize = 256
	// DefaultGarlicEncryptionCacheSize is the number of garlic encryption
	// contexts retained before eviction.
	DefaultGarlicEncryptionCacheSize = 1000
	// DefaultFragmentCacheSize is the number of reassembly fragment buffers
	// retained before eviction.
	DefaultFragmentCacheSize = 500
)

// ──────────────────────────────────────────────────────────────────────────────
// Default durations
// ──────────────────────────────────────────────────────────────────────────────

// Moved from: defaults.go, bootstrap.go, congestion.go
const (
	// DefaultRouterInfoRefreshInterval is how often the router re-publishes
	// its own RouterInfo.
	DefaultRouterInfoRefreshInterval = 30 * time.Minute

	// DefaultMessageExpirationTime is how long an I2NP message stays
	// deliverable before it is dropped as stale.
	DefaultMessageExpirationTime = 60 * time.Second

	// DefaultReseedTimeout bounds a single reseed attempt.
	DefaultReseedTimeout = 60 * time.Second

	// DefaultReseedRetryInterval is the wait between reseed attempts.
	DefaultReseedRetryInterval = 5 * time.Minute

	// DefaultSessionTimeout is how long an idle I2CP session is retained.
	DefaultSessionTimeout = 30 * time.Minute

	// DefaultI2CPReadTimeout bounds a blocking read from an I2CP client.
	DefaultI2CPReadTimeout = 60 * time.Second

	// DefaultI2CPWriteTimeout bounds a write to an I2CP client.
	DefaultI2CPWriteTimeout = 30 * time.Second

	// DefaultI2PControlTokenExpiration is how long an authentication token
	// stays valid before the client must re-authenticate.
	DefaultI2PControlTokenExpiration = 10 * time.Minute

	// DefaultTunnelLifetime is the age at which a tunnel is replaced.
	DefaultTunnelLifetime = 10 * time.Minute

	// DefaultTunnelTestInterval is how often a tunnel is liveness-tested.
	DefaultTunnelTestInterval = 60 * time.Second

	// DefaultTunnelBuildTimeout bounds a single tunnel build attempt.
	DefaultTunnelBuildTimeout = 90 * time.Second

	// DefaultTunnelMaintenanceInterval is the tunnel pool maintenance period.
	DefaultTunnelMaintenanceInterval = 30 * time.Second

	// DefaultTransportConnectionTimeout bounds transport connection setup.
	DefaultTransportConnectionTimeout = 30 * time.Second

	// DefaultTransportIdleTimeout is how long an idle transport connection is
	// kept before being closed.
	DefaultTransportIdleTimeout = 5 * time.Minute

	// DefaultPerformanceCleanupInterval is the expired-entry sweep period.
	DefaultPerformanceCleanupInterval = 5 * time.Minute

	// DefaultNetDBExpirationCheckInterval is how often the NetDB scans for
	// expired entries.
	DefaultNetDBExpirationCheckInterval = 1 * time.Minute

	// DefaultNetDBLeaseSetRefreshThreshold is the remaining lease lifetime at
	// which a lease set is refreshed.
	DefaultNetDBLeaseSetRefreshThreshold = 2 * time.Minute

	// DefaultNetDBExplorationInterval is the NetDB exploration period.
	DefaultNetDBExplorationInterval = 5 * time.Minute

	// DefaultTunnelReplaceBeforeExpiration is how early a tunnel is rebuilt
	// ahead of its expiry.
	DefaultTunnelReplaceBeforeExpiration = 2 * time.Minute

	// DefaultTunnelTestTimeout bounds a single tunnel test.
	DefaultTunnelTestTimeout = 5 * time.Second

	// DefaultSourceBanDuration is how long a rate-limit offender is refused.
	DefaultSourceBanDuration = 5 * time.Minute
)

// ──────────────────────────────────────────────────────────────────────────────
// Congestion advertisement thresholds (Proposal 162)
// ──────────────────────────────────────────────────────────────────────────────

// These are fractions of a capacity limit, not percentages. The clear
// thresholds sit below the advertisement thresholds so a router does not
// oscillate a caps flag when it hovers at a boundary.
// Moved from: congestion.go
const (
	// DefaultDFlagThreshold is the utilisation that advertises medium congestion.
	DefaultDFlagThreshold = 0.70
	// DefaultEFlagThreshold is the utilisation that advertises high congestion.
	DefaultEFlagThreshold = 0.85
	// DefaultGFlagThreshold is the utilisation that advertises tunnel rejection.
	DefaultGFlagThreshold = 1.00

	// DefaultClearDFlagThreshold is the utilisation that clears the D flag.
	DefaultClearDFlagThreshold = 0.60
	// DefaultClearEFlagThreshold is the utilisation that clears the E flag.
	DefaultClearEFlagThreshold = 0.75
	// DefaultClearGFlagThreshold is the utilisation that clears the G flag.
	DefaultClearGFlagThreshold = 0.95

	// DefaultDFlagCapacityMultiplier is the derating applied to a peer's advertised
	// capacity when it carries the D flag.
	DefaultDFlagCapacityMultiplier = 0.5
	// DefaultEFlagCapacityMultiplier is the derating applied to a peer's advertised
	// capacity when it carries the E flag.
	DefaultEFlagCapacityMultiplier = 0.1
	// DefaultStaleEFlagCapacityMultiplier is the derating applied instead of
	// DefaultEFlagCapacityMultiplier when the peer's RouterInfo is older than
	// DefaultCongestionEFlagAgeThreshold, on the reasoning that a stale
	// congestion sample overstates how busy the peer still is.
	DefaultStaleEFlagCapacityMultiplier = 0.5

	// DefaultCongestionAveragingWindow is the smoothing window for utilisation
	// samples (implementation convention).
	DefaultCongestionAveragingWindow = 5 * time.Minute

	// DefaultCongestionEFlagAgeThreshold is the RouterInfo age past which an E flag
	// is treated as a D flag (implementation convention).
	DefaultCongestionEFlagAgeThreshold = 15 * time.Minute
)
