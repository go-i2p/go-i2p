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

	// TunnelZeroSeparator is the byte value that terminates the padding. A hop
	// scans for it to find where the delivery instructions begin.
	TunnelZeroSeparator = 0x00
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

// ──────────────────────────────────────────────────────────────────────────────
// Delivery instruction flag bits
// ──────────────────────────────────────────────────────────────────────────────

// The single flag byte that opens every delivery instruction is packed by
// fragment type: a follow-on fragment uses bit 7 as a marker with the fragment
// number in bits 6-1 and the last-fragment bit in bit 0, while a first fragment
// uses bit 7 as 0 and spends bits 6-5 on the delivery type plus one bit each for
// delay, fragmentation and extended options. The two layouts share the same byte
// and are distinguished only by bit 7.
//
// Spec: https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/tunnel-message.rst
// Moved from: delivery.go
const (
	// followOnFragmentMarker is bit 7: set on a follow-on fragment, clear on a
	// first fragment.
	followOnFragmentMarker = 0x80

	// followOnFragmentNumberMask selects bits 6-1, the 6-bit fragment number.
	followOnFragmentNumberMask = 0x7E

	// fragmentNumberValueMask bounds a fragment number once shifted down to the
	// low 6 bits, used when writing the field back out.
	fragmentNumberValueMask = 0x3F

	// followOnFragmentNumberShift is how far the fragment number sits above the
	// last-fragment bit.
	followOnFragmentNumberShift = 1

	// lastFragmentMarker is bit 0 of a follow-on fragment: the sequence ends
	// with this fragment.
	lastFragmentMarker = 0x01

	// firstFragmentTypeMask selects the 2-bit delivery type in bits 6-5.
	firstFragmentTypeMask = 0x60

	// firstFragmentTypeShift is the delivery type's bit position.
	firstFragmentTypeShift = 5

	// firstFragmentDelayMask is bit 4: a delay field follows.
	firstFragmentDelayMask = 0x10

	// firstFragmentFragmentedMask is bit 3: the message is fragmented, so a
	// message ID follows.
	firstFragmentFragmentedMask = 0x08

	// firstFragmentExtOptionsMask is bit 2: extended options follow.
	firstFragmentExtOptionsMask = 0x04

	// deliveryTypeValueMask bounds the delivery type after shifting it down.
	deliveryTypeValueMask = 0x03

	// followOnInstructionSize is the full follow-on fragment instruction: flag(1)
	// + message ID(4) + size(2), which the spec states as a total length of 7.
	followOnInstructionSize = FlagSize + MessageIDSize + SizeFieldSize // 7
)

// ──────────────────────────────────────────────────────────────────────────────
// Hop count bounds
// ──────────────────────────────────────────────────────────────────────────────

// An outbound tunnel must have at least one hop to be a tunnel at all; an
// inbound tunnel may have zero, which is how a router terminates a tunnel on
// itself. The ceiling is the largest variable-length build the wire format
// carries.
//
// Moved from: builder.go, pool.go
const (
	minOutboundHops = 1
	minInboundHops  = 0
	maxHops         = 8
)

// ──────────────────────────────────────────────────────────────────────────────
// Pool defaults
// ──────────────────────────────────────────────────────────────────────────────

// Moved from: pool.go
const (
	// defaultPoolMinTunnels is how many ready tunnels a pool keeps at steady
	// state.
	defaultPoolMinTunnels = 4

	// defaultPoolMaxTunnels is the ceiling a pool may grow to while replacing.
	defaultPoolMaxTunnels = 6

	// defaultPoolHopCount is the tunnel length the spec recommends for both
	// directions.
	defaultPoolHopCount = 3

	// defaultPoolBuildRetryDelay is the first retry delay for a failed build;
	// exponential backoff grows it from there.
	defaultPoolBuildRetryDelay = 2 * time.Second

	// defaultPoolMaxBuildRetries caps how many times one build is retried.
	defaultPoolMaxBuildRetries = 3

	// maxBuildBackoff caps how long exponential backoff may grow the retry delay,
	// so a persistently failing pool still retries rather than stalling.
	maxBuildBackoff = 5 * time.Minute
)

// ──────────────────────────────────────────────────────────────────────────────
// Peer selection
// ──────────────────────────────────────────────────────────────────────────────

// Moved from: congestion_selector.go, scoring_selector.go, filtering_selector.go
const (
	// defaultSelectorMaxRetries is how many candidate sets a selector tries
	// before giving up on a build.
	defaultSelectorMaxRetries = 3

	// candidateOversampleDivisor is how the candidate request is padded beyond
	// the number of hops actually wanted: half again as many, so that peers
	// rejected by a filter still leave enough to choose from.
	candidateOversampleDivisor = 2

	// candidateOversampleFloor is the extra candidate requested on top of the
	// oversample, so a request for a single hop still asks for more than one.
	candidateOversampleFloor = 1
)

// ──────────────────────────────────────────────────────────────────────────────
// Score-adaptive build cooldown
// ──────────────────────────────────────────────────────────────────────────────

// A peer that scores well is worth trying again soon; one that scores badly
// should be left alone longer. The multipliers below scale the base cooldown by
// the peer's score, and the thresholds decide which side of the split a score
// falls on.
//
// Moved from: pool.go
const (
	// highPeerScoreThreshold is the score at or above which a peer is considered
	// healthy enough to retry sooner.
	highPeerScoreThreshold = 0.75

	// lowPeerScoreThreshold is the score at or below which a peer is considered
	// unreliable and held off longer.
	lowPeerScoreThreshold = 0.25

	// highScoreCooldownFactor shortens the cooldown for a well-scored peer.
	highScoreCooldownFactor = 0.6

	// lowScoreCooldownFactor lengthens the cooldown for a poorly-scored peer.
	lowScoreCooldownFactor = 1.4
)

// ──────────────────────────────────────────────────────────────────────────────
// Participant manager limits
// ──────────────────────────────────────────────────────────────────────────────

// Moved from: manager.go
const (
	// softLimitDivisor halves the participant ceiling to give the soft limit at
	// which probabilistic rejection begins, so the manager backs off gradually
	// instead of refusing everything at the hard cap.
	softLimitDivisor = 2
)

// ──────────────────────────────────────────────────────────────────────────────
// Fragment and test timing
// ──────────────────────────────────────────────────────────────────────────────

// Moved from: endpoint.go, source_limiter.go, tunnel_tester.go
const (
	// defaultFragmentTimeout is how long an incomplete fragment assembly is kept
	// before it is discarded. It matches i2pd's I2NP_MESSAGE_EXPIRATION_TIMEOUT
	// so a stalled assembly is dropped on the same schedule the message that
	// started it would expire.
	defaultFragmentTimeout = 8 * time.Second

	// sourceLimiterCleanupInterval is how often the limiter sweeps per-source
	// state that has gone quiet.
	sourceLimiterCleanupInterval = 5 * time.Minute

	// tunnelTestTimeout bounds a single tunnel test round trip.
	tunnelTestTimeout = 5 * time.Second
)

// ──────────────────────────────────────────────────────────────────────────────
// Delivery instruction field presence
// ──────────────────────────────────────────────────────────────────────────────

// A DTLocal first-fragment instruction is only a flag byte plus the 2-byte
// message size, and it has to fit in the payload alongside the message it
// describes — so the budget for the message is the payload limit minus the
// instruction that carries it.
//
// Moved from: gateway.go
const localDeliveryInstructionSize = FlagSize + SizeFieldSize // 3
