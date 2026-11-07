package ntcp2

import (
	"time"

	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/go-i2p/go-noise/ntcp2"
)

// ──────────────────────────────────────────────────────────────────────────────
// Key sizes
// ──────────────────────────────────────────────────────────────────────────────

// staticKeySize is the width of the NTCP2 X25519 static key, which doubles as
// the width of the Curve25519 u-coordinate published in a peer's "s=" address
// option: both are 2^255-19 field elements serialised into 32 bytes (RFC 7748
// §5). It is aliased from the handshake library that consumes it so the router's
// length checks and the library's key schedule cannot disagree about what a
// valid static key is.
//
// Spec: ntcp2.rst:298 (static key validation), :1842 ("s :: 32 bytes").
// Moved from: transport.go, peer_key.go, addr_options.go, router_address.go,
// curve_validation.go
const staticKeySize = ntcp2.StaticKeySize // 32

// ──────────────────────────────────────────────────────────────────────────────
// Block framing field layout
// ──────────────────────────────────────────────────────────────────────────────

// Every NTCP2 block — in the handshake and in the data phase alike — begins with
// a three-byte header: a one-byte type followed by a two-byte big-endian data
// length. The header width itself is blockHeaderSize in blocks.go; the offsets
// below name the fields inside it so the encoders and the parsers index the same
// bytes rather than each spelling out 1, 3 and 4.
//
// Spec: ntcp2.rst:1438-1450 ("Unencrypted data").
// Reference: i2pd libi2pd/NTCP2.cpp writeBlock / handleBlock.
// Moved from: blocks.go
const (
	// blockSizeFieldOffset is where the two-byte data-length field begins,
	// immediately after the one-byte block type.
	blockSizeFieldOffset = 1

	// blockSizeFieldSize is the width of the data-length field. Being two bytes
	// is what bounds a block's data at MaxBlockDataSize.
	blockSizeFieldSize = 2

	// blockSizeFieldEnd is one past the last byte of the header. It must equal
	// blockHeaderSize, which the assertions at the bottom of this file enforce.
	blockSizeFieldEnd = blockSizeFieldOffset + blockSizeFieldSize // 3
)

// dateTimeFieldSize is the width of a DateTime block's payload: the sender's
// clock as a big-endian Integer, which the spec fixes at four bytes. A DateTime
// block of any other length is malformed rather than merely short.
//
// Spec: ntcp2.rst:1487-1491 ("time :: 4 bytes; Implementations must round to the
// nearest second").
// Reference: i2pd libi2pd/NTCP2.cpp handleDateTimeBlock.
// Moved from: blocks.go
const dateTimeFieldSize = 4

// A RouterInfo block's data is a one-byte flag followed by the serialised
// RouterInfo. Bit 0 of the flag is the flood request
// (RouterInfoFlagFloodRequest in blocks.go); bits 1-7 must be zero.
//
// Spec: ntcp2.rst:1575-1577.
// Moved from: blocks.go, session.go
const (
	// routerInfoFlagSize is the width of the flag byte that precedes the
	// RouterInfo payload.
	routerInfoFlagSize = 1

	// minRouterInfoBlockDataSize is the shortest RouterInfo block data that can
	// be interpreted: the flag plus at least one byte of RouterInfo.
	minRouterInfoBlockDataSize = routerInfoFlagSize + 1 // 2
)

// ──────────────────────────────────────────────────────────────────────────────
// Options block field layout
// ──────────────────────────────────────────────────────────────────────────────

// The Options block's mandatory data is four fixed-point ratio bytes followed by
// four big-endian uint16 fields. ntcp2.rst:1515 calls the whole region "12 bytes
// minimum" — that total is optionsDataMinSize in blocks.go — and the offsets
// below name each field's position so the parser reads the bytes in the order
// the spec lays them out instead of indexing with bare numbers.
//
// Spec: ntcp2.rst:1493-1542.
// Reference: i2pd libi2pd/NTCP2.cpp handleOptionsBlock.
// Moved from: blocks.go
const (
	// optionsRatioFieldSize is the width of one transmit/receive padding-ratio
	// byte, expressed in 4.4 fixed point.
	optionsRatioFieldSize = 1

	// optionsRatioFieldCount is the number of ratio bytes at the head of the
	// block: transmit min, transmit max, receive min, receive max.
	optionsRatioFieldCount = 4

	// optionsUInt16Size is the width of each of the four uint16 option fields
	// that follow the ratios.
	optionsUInt16Size = 2

	// optionsDummyTransmitOffset is where transmitDummy begins, one past the
	// four ratio bytes.
	optionsDummyTransmitOffset = optionsRatioFieldSize * optionsRatioFieldCount // 4

	// optionsDummyReceiveOffset is where receiveDummy begins.
	optionsDummyReceiveOffset = optionsDummyTransmitOffset + optionsUInt16Size // 6

	// optionsDelayTransmitOffset is where transmitDelay begins.
	optionsDelayTransmitOffset = optionsDummyReceiveOffset + optionsUInt16Size // 8

	// optionsDelayReceiveOffset is where receiveDelay begins.
	optionsDelayReceiveOffset = optionsDelayTransmitOffset + optionsUInt16Size // 10

	// optionsMandatorySize is one past the last byte of the mandatory region;
	// anything beyond it is the optional "more options" tail. It is the same
	// value as optionsDataMinSize, restated from the field widths, and asserted
	// against it below.
	optionsMandatorySize = optionsDelayReceiveOffset + optionsUInt16Size // 12
)

// ──────────────────────────────────────────────────────────────────────────────
// Termination block field layout
// ──────────────────────────────────────────────────────────────────────────────

// terminationFramesReceivedSize is the width of the valid-data-frames-received
// counter that a Termination block carries ahead of its one-byte reason. The
// spec fixes the block's data at 9 bytes minimum, which is this counter plus the
// reason byte, so the two must always sum to terminationBlockPayloadSize.
//
// Spec: ntcp2.rst:1660-1664 ("valid frames received :: 8 bytes",
// "reason :: 1 byte").
// Reference: i2pd libi2pd/NTCP2.cpp SendTermination (writes size 9).
// Moved from: termination.go
const terminationFramesReceivedSize = 8

// ──────────────────────────────────────────────────────────────────────────────
// Data-phase block ordering rules
// ──────────────────────────────────────────────────────────────────────────────

// maxPaddingBlocksPerFrame is how many Padding blocks one AEAD frame may carry.
// The spec allows at most one, and it must be the frame's last block; a frame
// with two is a protocol violation the receiver terminates on.
//
// Spec: ntcp2.rst:1467 ("no more than one padding block per frame").
// Moved from: block_validation.go
const maxPaddingBlocksPerFrame = 1

// ──────────────────────────────────────────────────────────────────────────────
// Address options and protocol version
// ──────────────────────────────────────────────────────────────────────────────

// ntcp2ProtocolVersion is the value of the "v=" RouterAddress option, the NTCP2
// wire-protocol revision this router speaks. Only version 2 has ever been
// defined; the option is mandatory in a published NTCP2 address, so a router
// that omits it is not dialable over NTCP2. It is also the sole entry of the
// supported-version list that inbound address validation matches against.
//
// Spec: ntcp2.rst:1853 ("v :: 2 - NTCP2 version"), :1861-1862 (options are
// mandatory).
// Moved from: addr_options.go
const ntcp2ProtocolVersion = 2

// ntcp2VersionString is the same version as it appears on the wire: the
// "v=" option is an I2PString holding the decimal digits, so publishing it
// requires the string form. It must always agree with ntcp2ProtocolVersion.
//
// Spec: ntcp2.rst:1853.
// Moved from: router_address.go
const ntcp2VersionString = "2"

// ──────────────────────────────────────────────────────────────────────────────
// RouterAddress cost values
// ──────────────────────────────────────────────────────────────────────────────

// The cost byte advertised on a RouterAddress is how tunnel builders rank
// candidate hops: lower is cheaper, so directly reachable routers are preferred.
// The spec assigns no numbers; these are the values Java I2P and i2pd use, and
// matching them keeps go-i2p's tunnel selection comparable with the rest of the
// network instead of quietly biasing peer choice.
//
// Reference: Java RouterAddress.java COST_* constants; i2pd RouterInfo.cpp.
// Moved from: router_address.go
const (
	// costNTCP2Published is the cost of an address carrying a "host=" option,
	// i.e. one a peer can connect to directly.
	costNTCP2Published = 3

	// costNTCP2NonPublished is the cost of a caps-only address: reachable only
	// through an already-established session, so it is deliberately priced above
	// every directly reachable address.
	costNTCP2NonPublished = 14
)

// ──────────────────────────────────────────────────────────────────────────────
// Peer hash marker
// ──────────────────────────────────────────────────────────────────────────────

// peerHashMarkerByte overwrites the first byte of the fallback peer hash that
// transport.DeriveConnectionHash builds from a socket address, used when a
// connection has no router hash yet. It keeps address-derived session keys from
// colliding with a real router hash whose leading byte happens to match, and it
// must stay distinct from SSU2's marker (0xFE) so the two transports cannot
// claim each other's sessions.
//
// Moved from: transport.go
const peerHashMarkerByte = 0xFF

// ──────────────────────────────────────────────────────────────────────────────
// Inbound accept loop and handshake plumbing
// ──────────────────────────────────────────────────────────────────────────────

// These bound the inbound path, which runs before a peer has proven anything.
// None are protocol values: they are the router's own resource limits, chosen so
// that a slow or hostile peer costs a bounded amount of memory and a bounded
// amount of time.
//
// Moved from: transport.go, config.go
const (
	// pendingConnsQueueSize is the depth of the queue of connections whose
	// responder handshake has finished, waiting to be handed to Accept(). It
	// matches the SSU2 transport's queue so both transports absorb the same
	// burst of simultaneous establishments before back-pressure kicks in.
	pendingConnsQueueSize = 64

	// defaultPendingConnQueueTimeout bounds how long a finished handshake worker
	// waits to deliver its connection to Accept(). A consumer that stops
	// draining Accept() must not pin a session slot and a goroutine forever, so
	// the worker closes the connection and releases the slot once this expires.
	// It is the Config default and remains overridable per router.
	defaultPendingConnQueueTimeout = 5 * time.Second

	// listenerSwapPollInterval is how long the accept loop waits before
	// re-checking for a listener when the current one is nil. A nil listener
	// while the transport is still running means SetIdentity is swapping it,
	// which is brief; polling rather than blocking lets the loop notice a
	// shutdown without waiting on a signal only Close() sends.
	listenerSwapPollInterval = 50 * time.Millisecond

	// transientAcceptBackoff is the pause after a transient accept error
	// (EMFILE, or a listener closed mid-swap) before retrying. Short enough that
	// a recovered listener resumes promptly, long enough that a permanently
	// erroring listener does not spin hot.
	transientAcceptBackoff = 10 * time.Millisecond

	// tcpDialTimeout bounds the TCP connect phase of an outbound handshake.
	// Reduced from 30 s (P0.2): a reachable peer completes the SYN/ACK far inside
	// this, and the shorter window stops a host that silently drops SYNs from
	// holding a goroutine for half a minute.
	tcpDialTimeout = 10 * time.Second
)

// ──────────────────────────────────────────────────────────────────────────────
// Session sizing and pacing
// ──────────────────────────────────────────────────────────────────────────────

// Moved from: session.go, framing.go
const (
	// recvBackpressureTimeout is how long the receive worker waits for space in
	// the application's receive channel before dropping the message. Dropping
	// rather than blocking keeps one slow consumer from stalling decryption of
	// every later frame on the connection.
	recvBackpressureTimeout = 500 * time.Millisecond

	// metaJitterDivisor splits the DateTime metadata interval into its jitter
	// band: metadata is emitted at a uniform random point in
	// [ntcp2MetaFrequency/2, ntcp2MetaFrequency), so routers that started
	// together do not synchronise their clock blocks into a recognisable traffic
	// pattern.
	metaJitterDivisor = 2

	// maxFrameReadBufferSize is the buffer handed to the connection per read. It
	// is sized to the largest frame the wire format can carry, so one Read() can
	// return a whole frame and a frame is never silently truncated by a buffer
	// that is too small.
	maxFrameReadBufferSize = ntcp2SpecMaxFrameSize + 1 // 65536
)

// ──────────────────────────────────────────────────────────────────────────────
// Capacity accounting
// ──────────────────────────────────────────────────────────────────────────────

// Moved from: transport.go
const (
	// percentBase is the denominator of the percentage values haveCapacity
	// compares session occupancy against.
	percentBase = 100

	// capacityThresholdPercent is the occupancy level, as a percentage of
	// MaxSessions, below which the router still has room for new peers. The
	// idle-expiry window widens while there is room and narrows once usage
	// passes this point. It sits just above a third so a router at exactly one
	// third of capacity is already treated as full, biasing the window towards
	// closing idle sessions before the pool is exhausted rather than after.
	capacityThresholdPercent = 33
)

// ──────────────────────────────────────────────────────────────────────────────
// Probing resistance
// ──────────────────────────────────────────────────────────────────────────────

// probingResistanceJunkReadGrace is the extra time added to the read deadline
// used while draining junk bytes for probing resistance. The random delay
// already applied is the timing signal the prober sees; this grace only ensures
// the local read does not time out before the delay it is paired with has
// elapsed, so the observable close time stays governed by the delay and not by
// the read.
//
// Spec basis: ntcp2.rst §"DoS Mitigation" ("set a random timeout and then read a
// random number of bytes before closing the socket").
// Moved from: probing_resistance.go
const probingResistanceJunkReadGrace = 500 * time.Millisecond

// ──────────────────────────────────────────────────────────────────────────────
// Diagnostic log prefixes
// ──────────────────────────────────────────────────────────────────────────────

// When a handshake fails the transport logs a slice of the offending bytes so an
// operator can tell a truncated frame from a garbled one without dumping a whole
// RouterInfo into the log. The lengths are observability choices, not protocol
// values, but they are repeated at several call sites and must stay consistent
// for log parsers.
//
// Moved from: transport.go, peer_key.go
const (
	// logRouterInfoPrefixBytes is how many leading (and trailing) RouterInfo
	// bytes are hex-logged on a parse failure.
	logRouterInfoPrefixBytes = 16

	// logKeyPrefixBytes is how many leading bytes of a key or hash are logged.
	// Enough to match against a peer's b32 address, short enough that the log
	// line does not leak the whole secret.
	logKeyPrefixBytes = 8
)

// Layout assertions. These are compile-time checks, not runtime ones: if a field
// width above is edited without the corresponding total, or one of the existing
// block-layout constants is edited without these, the package stops building
// rather than silently mis-framing every message.
const (
	_ = uint(blockSizeFieldEnd - blockHeaderSize)
	_ = uint(optionsMandatorySize - optionsDataMinSize)
	_ = uint(terminationFramesReceivedSize - (terminationBlockPayloadSize - 1))
)

// ──────────────────────────────────────────────────────────────────────────────
// On-disk file permissions
// ──────────────────────────────────────────────────────────────────────────────

// secureFilePermissions is the mode used for every file this transport writes
// that contains key material: owner read/write only. Aliased from lib/config,
// which owns the router-wide policy, so the transport cannot write a key file
// with a looser mode than the rest of the router.
//
// Moved from: persistent_config.go
const secureFilePermissions = config.SecureFilePermissions
