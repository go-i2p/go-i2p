package tunnel

import (
	"time"

	"github.com/go-i2p/crypto/tunnel"
)

// ──────────────────────────────────────────────────────────────────────────────
// Tunnel message framing
// ──────────────────────────────────────────────────────────────────────────────

// Every tunnel message on the wire is exactly one block. The encrypted form is
// TunnelID | IV | encrypted data; once a hop decrypts its layer the same block
// is read as TunnelID | IV | checksum | padding | 0x00 | instructions | message.
// The offsets below describe the decrypted view, which is what this package
// parses. The encrypted view is owned by the go-i2p/crypto/tunnel package and
// is reused from there rather than restated here.
//
// Spec: https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/tunnel-message.rst
// Moved from: endpoint.go, gateway.go, message.go, participant.go
const (
	// TunnelMessageSize is the fixed size of a tunnel message block, in both
	// its encrypted and decrypted forms.
	TunnelMessageSize = tunnel.TunnelMessageSize // 1028

	// TunnelIVSize is the size of the initialization vector written after the
	// tunnel ID. A fresh IV per message stops identical payloads producing
	// identical ciphertext.
	TunnelIVSize = tunnel.TunnelIVSize // 16

	// TunnelIDOffset is where the cleartext tunnel ID begins — the head of the
	// block. It is the only field a hop can route on before decrypting.
	TunnelIDOffset = 0

	// TunnelIVOffset is where the IV begins, immediately after the tunnel ID.
	TunnelIVOffset = tunnel.TunnelIVOffset // 4

	// TunnelEncryptedDataOffset is where the encrypted payload region begins in
	// the on-wire block. Reused from the crypto package that performs the
	// encryption so the two cannot disagree about where the cipher starts.
	TunnelEncryptedDataOffset = tunnel.TunnelPayloadOffset // 20

	// TunnelChecksumSize is the size of the truncated SHA-256 that follows the
	// IV once the layer is decrypted.
	TunnelChecksumSize = 4

	// TunnelChecksumOffset is where the checksum begins: immediately after the
	// cleartext tunnel ID and the IV.
	TunnelChecksumOffset = TunnelIDSize + TunnelIVSize // 20

	// TunnelHeaderSize is the length of the fixed header — tunnel ID, IV and
	// checksum — and therefore the offset at which the random padding begins.
	TunnelHeaderSize = TunnelChecksumOffset + TunnelChecksumSize // 24

	// TunnelZeroSeparatorSize is the single 0x00 byte that terminates the
	// padding and marks the start of the delivery instructions.
	TunnelZeroSeparatorSize = 1
)

// ──────────────────────────────────────────────────────────────────────────────
// Fragment numbering
// ──────────────────────────────────────────────────────────────────────────────

// The follow-on fragment flag byte carries the fragment number in bits 6-1, a
// 6-bit field whose usable range is 1 through 63.
//
// Spec: tunnel-message.rst §"Follow-on Fragment" ("bits 6-1: nnnnnn is the 6
// bit fragment number from 1 to 63").
// Moved from: endpoint.go, gateway.go
const (
	// MaxFollowOnFragments is the highest fragment number a message may carry.
	// Exceeding it means the message cannot be expressed in the 6-bit field.
	MaxFollowOnFragments = 63

	// fragmentNumberFieldBits is the width of the fragment number bitfield.
	fragmentNumberFieldBits = 6

	// fragmentNumberValues is how many distinct values that field encodes, used
	// as the exclusive upper bound when validating a raw number.
	fragmentNumberValues = 1 << fragmentNumberFieldBits // 64
)

// ──────────────────────────────────────────────────────────────────────────────
// Fragment reassembly
// ──────────────────────────────────────────────────────────────────────────────

// Moved from: endpoint.go, delivery.go
const (
	// fragmentCleanupInterval is how often the endpoint sweeps assemblies that
	// have stalled — fragments that never completed and are now too old to be
	// worth waiting on.
	fragmentCleanupInterval = 30 * time.Second

	// deliveryInstructionsInitialCapacity is the capacity hint for a serialised
	// delivery instruction, sized to a typical first-fragment encoding so the
	// common case allocates once.
	deliveryInstructionsInitialCapacity = 128
)

// ──────────────────────────────────────────────────────────────────────────────
// Participant and pool lifetimes
// ──────────────────────────────────────────────────────────────────────────────

// Moved from: participant.go, tunnel_tester.go, pool.go, pool_maintenance.go
const (
	// defaultParticipantLifetime is how long a participant keeps a tunnel
	// before rotating it. Ten minutes is the standard I2P tunnel lifetime and
	// matches buildrecord.DefaultExpirationSeconds.
	defaultParticipantLifetime = 10 * time.Minute

	// tunnelTestStaleAfter is the age past which a tunnel that has not passed a
	// test is treated as broken rather than merely slow. It sits just inside
	// defaultParticipantLifetime so a failing tunnel is replaced before expiry.
	tunnelTestStaleAfter = 9 * time.Minute

	// tunnelTestPollInterval is how long the tester waits between checks for a
	// test result to land.
	tunnelTestPollInterval = 10 * time.Millisecond

	// poolTunnelLifetime is the lifetime a pool requests when it builds
	// tunnels, set just above defaultParticipantLifetime so a tunnel is
	// replaced ahead of expiry instead of dropping at the boundary.
	poolTunnelLifetime = 11 * time.Minute

	// poolRebuildThreshold is how long before expiry a pool tunnel is replaced.
	poolRebuildThreshold = 90 * time.Second

	// poolMaintenanceInterval is how often the pool checks for tunnels needing
	// replacement.
	poolMaintenanceInterval = 30 * time.Second
)

// ──────────────────────────────────────────────────────────────────────────────
// Manager bookkeeping
// ──────────────────────────────────────────────────────────────────────────────

// Moved from: manager.go
const (
	// managerCleanupInterval is how often the tunnel manager sweeps stale
	// state. The startup log line reports it from this same constant so the
	// message cannot drift from the ticker.
	managerCleanupInterval = 60 * time.Second

	// bytesPerKiB converts the KBps bandwidth figures carried in build records
	// into the bytes-per-second the local accounting uses.
	bytesPerKiB = 1024
)

// ──────────────────────────────────────────────────────────────────────────────
// Per-source build request limiting
// ──────────────────────────────────────────────────────────────────────────────

// Moved from: source_limiter.go
const (
	// banRejectCountThreshold is how many rejects one source may accumulate
	// within rejectCountWindow before it is banned outright.
	banRejectCountThreshold = 10

	// rejectCountWindow is how far back rejects are counted when deciding
	// whether to ban a source.
	rejectCountWindow = 10 * time.Minute
)

// ──────────────────────────────────────────────────────────────────────────────
// Display and logging helpers
// ──────────────────────────────────────────────────────────────────────────────

// Moved from: endpoint.go, filtering_selector.go, congestion_selector.go,
// source_limiter.go, peer_selector.go
const (
	// percentCompleteFull is the completeness value, as a percentage, reported
	// for an assembly that has received every expected fragment.
	percentCompleteFull = 100

	// logHashPrefixLen is how many characters of an identity hash are included
	// in a log line. A full base32 hash makes logs hard to scan and carries
	// more precision than a log message needs.
	logHashPrefixLen = 16

	// percentScale converts a ratio into a percentage for display.
	percentScale = 100
)
