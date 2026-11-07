package router

import (
	"time"

	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/go-i2p/go-i2p/lib/i2pcontrol"
	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/go-i2p/go-i2p/lib/tunnel"
)

// ──────────────────────────────────────────────────────────────────────────────
// Network status codes
// ──────────────────────────────────────────────────────────────────────────────

// GetNetworkStatus returns one of these integers as i2p.router.status. They are
// the I2PControl protocol's codes, so they are owned by lib/i2pcontrol and
// aliased here rather than restated: the package that defines the wire meaning
// and the package that produces the value cannot then disagree.
//
// Moved from: router_status.go
const (
	// statusOK is the router running and directly reachable.
	statusOK = i2pcontrol.NetworkStatusOK

	// statusTesting is a router with no active peers yet.
	statusTesting = i2pcontrol.NetworkStatusTesting

	// statusFirewalled is a router whose inbound connections are blocked.
	statusFirewalled = i2pcontrol.NetworkStatusFirewalled

	// statusHidden is a router configured to stay hidden from lookups.
	statusHidden = i2pcontrol.NetworkStatusHidden

	// statusErrorI2CP is a router whose I2CP server is not running.
	statusErrorI2CP = i2pcontrol.NetworkStatusErrorI2CP

	// statusErrorSymmetricNAT is a router reachable only via introducers because
	// its NAT is symmetric.
	statusErrorSymmetricNAT = i2pcontrol.NetworkStatusErrorSymmetricNAT
)

// ──────────────────────────────────────────────────────────────────────────────
// Tunnel data block sizes
// ──────────────────────────────────────────────────────────────────────────────

// A TunnelData message carries exactly one tunnel block, and a block has two
// sizes depending on whether the hop has decrypted its layer: the encrypted form
// is the 4-byte tunnel ID plus a 1024-byte payload, and the decrypted form is the
// 1028-byte block the next hop reads. Both are owned by the packages that define
// the format, so the inbound handler checks against them rather than repeating
// the numbers.
//
// Moved from: inbound.go
const (
	// tunnelDataPayloadSize is the encrypted block a TunnelData message carries.
	tunnelDataPayloadSize = i2np.TunnelDataPayloadSize // 1024

	// tunnelMessageSize is the whole tunnel block, tunnel ID included, which is
	// also the size of a decrypted layer at a transit hop.
	tunnelMessageSize = tunnel.TunnelMessageSize // 1028
)

// ──────────────────────────────────────────────────────────────────────────────
// Diagnostics bounds
// ──────────────────────────────────────────────────────────────────────────────

// Moved from: inbound.go, router_tunnel_wiring.go
const (
	// maxLoggedTunnelIDs caps how many registered tunnel IDs are listed when an
	// unregistered one arrives. The full list is only useful for spotting a
	// systemic mismatch, and a router with many tunnels would otherwise emit an
	// unbounded log line per stray message.
	maxLoggedTunnelIDs = 8

	// maxLoggedHashChars caps the identity hash prefix printed in tunnel
	// diagnostics.
	maxLoggedHashChars = 16
)

// ──────────────────────────────────────────────────────────────────────────────
// Sampling windows
// ──────────────────────────────────────────────────────────────────────────────

// The congestion monitor and the bandwidth tracker both sample once a second and
// keep a fixed number of samples. The floors below keep the window usable when a
// configured averaging period is shorter than one sample would cover.
//
// Moved from: congestion.go, bandwidth.go
const (
	// congestionSampleInterval is how often the congestion monitor samples, and
	// the divisor that turns an averaging window into a sample count.
	congestionSampleInterval = time.Second

	// minCongestionSamples is the smallest window the congestion monitor will
	// average over; fewer samples than this cannot distinguish a transient spike
	// from real congestion.
	minCongestionSamples = 10

	// startupGraceSeconds is how long after boot the congestion monitor reports no
	// flags. A router that has just started has not yet had traffic to judge, and
	// raising a flag on that empty evidence would spread a false signal. Held as
	// whole seconds because the monitor compares it as an int count.
	startupGraceSeconds = 60

	// bandwidthSampleInterval is how often the bandwidth tracker samples.
	bandwidthSampleInterval = time.Second

	// bandwidthSampleWindow is how many samples the bandwidth tracker retains,
	// giving a 15-second average at one-second sampling.
	bandwidthSampleWindow = 15
)

// ──────────────────────────────────────────────────────────────────────────────
// Router metric fallbacks
// ──────────────────────────────────────────────────────────────────────────────

// The metrics collector reports the router's live limits. Where a subsystem is
// absent — a participant manager that was never constructed, a config that was
// never loaded — the collector falls back to these, which mirror the defaults in
// lib/config so the fallback and the configured value agree.
//
// Moved from: congestion.go, router_congestion_adapter.go
const (
	// fallbackMaxParticipants is the participating-tunnel ceiling reported when no
	// participant manager exists.
	fallbackMaxParticipants = config.DefaultMaxParticipatingTunnels

	// fallbackUnconfiguredMaxParticipants is the ceiling used by the metrics
	// collector's own default when no accessor is supplied. It is deliberately a
	// tenth of the router-wide cap: a collector with no wiring should understate
	// capacity rather than claim the whole router's allowance.
	fallbackUnconfiguredMaxParticipants = 1000

	// fallbackMaxBandwidthBytesPerSec is the bandwidth ceiling reported when the
	// router has no configured limit.
	fallbackMaxBandwidthBytesPerSec = config.DefaultMaxBandwidthBytesPerSec

	// fallbackMaxConnections is the transport connection ceiling reported when the
	// router has no configured limit.
	fallbackMaxConnections = config.DefaultRouterMaxConnections
)

// ──────────────────────────────────────────────────────────────────────────────
// Reseed and NAT detection
// ──────────────────────────────────────────────────────────────────────────────

// Moved from: router_bootstrap.go, router_ssu2.go
const (
	// defaultReseedCooldown is how long the router waits between reseed attempts
	// when no retry interval is configured.
	defaultReseedCooldown = config.DefaultReseedRetryInterval

	// minPeersForPeerTest is how many SSU2 peers a router needs before a PeerTest
	// can meaningfully determine its NAT type: the test sends to one peer and
	// reflects from another.
	minPeersForPeerTest = 2
)

// ──────────────────────────────────────────────────────────────────────────────
// Read-warning limiter bookkeeping
// ──────────────────────────────────────────────────────────────────────────────

// The per-peer read-warning map is bounded; the warning threshold below says when
// churn is high enough that eviction is about to start dropping useful state, and
// it is expressed as a fraction of the cap so the two cannot drift.
//
// Moved from: router_message_dispatch.go
const (
	// readWarnHighWaterMarkNum and readWarnHighWaterMarkDen are the 9/10 fraction
	// of readWarnMaxMapSize past which the map is considered near capacity.
	readWarnHighWaterMarkNum = 9
	readWarnHighWaterMarkDen = 10
)

// ──────────────────────────────────────────────────────────────────────────────
// Tunnel wiring defaults
// ──────────────────────────────────────────────────────────────────────────────

// Moved from: router_tunnel_wiring.go
const (
	// tunnelReplyMaxRetries is how many times a tunnel build reply is retried.
	tunnelReplyMaxRetries = 3

	// tunnelReplyDefaultTimeout bounds a single reply wait.
	tunnelReplyDefaultTimeout = 30 * time.Second

	// replyTimeoutMultiplier is how the per-build timeout is derived from the
	// configured build timeout: twice it, so a reply that arrives late but within
	// the router's own patience is still counted.
	replyTimeoutMultiplier = 2
)

// ──────────────────────────────────────────────────────────────────────────────
// Bandwidth tier promotion
// ──────────────────────────────────────────────────────────────────────────────

// A router may advertise a higher bandwidth class than its rate alone justifies
// when its connection limits show it can actually carry the traffic. The
// thresholds below are session counts, and the letters name the class each one
// unlocks. The rate-derived class itself comes from config.BandwidthClassFromRate
// so both paths share one set of boundaries.
//
// Moved from: router_bandwidth_tier.go
const (
	// sessionLimitXThreshold promotes a router to class X.
	sessionLimitXThreshold = 4096
	// sessionLimitPThreshold promotes a router to class P.
	sessionLimitPThreshold = 1024
	// sessionLimitOThreshold promotes a router to class O.
	sessionLimitOThreshold = 512
)
