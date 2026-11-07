package i2np

import (
	"errors"
	"time"

	i2ptunnel "github.com/go-i2p/crypto/tunnel"
	"github.com/go-i2p/go-i2p/lib/tunnel/buildrecord"
)

// I2NP Message Type Constants
// These are the type bytes in the I2NP message header that identify the
// message kind. See [I2P Spec: I2NP](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/i2np.rst) for the full list.
// Moved from: header.go
const (
	// I2NPMessageTypeDatabaseStore is the type for DatabaseStore messages.
	I2NPMessageTypeDatabaseStore = 1
	// I2NPMessageTypeDatabaseLookup is the type for DatabaseLookup messages.
	I2NPMessageTypeDatabaseLookup = 2
	// I2NPMessageTypeDatabaseSearchReply is the type for DatabaseSearchReply messages.
	I2NPMessageTypeDatabaseSearchReply = 3
	// I2NPMessageTypeDeliveryStatus is the type for DeliveryStatus messages.
	I2NPMessageTypeDeliveryStatus = 10
	// I2NPMessageTypeGarlic is the type for Garlic messages.
	I2NPMessageTypeGarlic = 11
	// I2NPMessageTypeTunnelData is the type for TunnelData messages.
	I2NPMessageTypeTunnelData = 18
	// I2NPMessageTypeTunnelGateway is the type for TunnelGateway messages.
	I2NPMessageTypeTunnelGateway = 19
	// I2NPMessageTypeData is the type for Data messages.
	I2NPMessageTypeData = 20
	// I2NPMessageTypeTunnelBuild is the type for TunnelBuild messages.
	// Declared so the router can recognise the message and drop it with an
	// accurate log instead of reporting a defined type as "unknown"; the
	// 528-byte records it carries are not implemented (see the "Tunnel build
	// message coverage (known gap)" section of doc.go and the dispatch note in
	// processor.go). i2np.rst:691 lists the type, and :1581-1583 states it "has
	// not been deprecated. Routers must implement."
	I2NPMessageTypeTunnelBuild = 21
	// I2NPMessageTypeTunnelBuildReply is the type for TunnelBuildReply
	// messages, the reply counterpart of I2NPMessageTypeTunnelBuild. Declared
	// for the same reason; i2np.rst:1607-1609 carries the same "Routers must
	// implement." sentence.
	I2NPMessageTypeTunnelBuildReply = 22
	// I2NPMessageTypeVariableTunnelBuild is the type for VariableTunnelBuild messages.
	I2NPMessageTypeVariableTunnelBuild = 23
	// I2NPMessageTypeVariableTunnelBuildReply is the type for VariableTunnelBuildReply messages.
	I2NPMessageTypeVariableTunnelBuildReply = 24
	// I2NPMessageTypeShortTunnelBuild is the type for ShortTunnelBuild messages.
	I2NPMessageTypeShortTunnelBuild = 25
	// I2NPMessageTypeOutboundTunnelBuildReply is the type for
	// OutboundTunnelBuildReply messages — the reply that travels back over the
	// outbound tunnel. This is the specification name (i2np.rst:696, :1721).
	// The earlier name for this constant,
	// I2NPMessageTypeShortTunnelBuildReply, was removed rather than kept as an
	// alias: no "ShortTunnelBuildReply" exists in the I2P specification, and
	// tunnel-creation-ecies.rst:537 describes the pair as "Short Tunnel Build
	// Message (type 25) and Outbound Tunnel Build Reply Message (type 26)".
	// The outbound direction is the semantic distinction, so the non-spec name
	// actively misleads a reader into looking for a "short" reply variant.
	I2NPMessageTypeOutboundTunnelBuildReply = 26
)

// I2NP Error Constants
// These use errors.New (not oops.Errorf) so callers can match them with errors.Is().
// Moved from: header.go, build_request_record.go, build_response_record.go, database_lookup.go
var (
	// ErrI2NPNotEnoughData is returned when a message buffer is too short to
	// contain a valid I2NP header.
	ErrI2NPNotEnoughData = errors.New("not enough i2np header data")
	// ErrBuildRequestRecordNotEnoughData is returned when a build request
	// record buffer is too short to parse.
	ErrBuildRequestRecordNotEnoughData = buildrecord.ErrNotEnoughData
	// ErrBuildResponseRecordNotEnoughData is returned when a build response
	// record buffer is too short to parse.
	ErrBuildResponseRecordNotEnoughData = buildrecord.ErrBuildResponseRecordNotEnoughData
	// ErrDatabaseLookupNotEnoughData is returned when a DatabaseLookup payload
	// is too short to parse.
	ErrDatabaseLookupNotEnoughData = errors.New("not enough i2np database lookup data")
	// ErrDatabaseSearchReplyNotEnoughData is returned when a DatabaseSearchReply
	// payload is too short to parse.
	ErrDatabaseSearchReplyNotEnoughData = errors.New("not enough i2np database search reply data")
	// ErrDatabaseLookupInvalidSize is returned when a DatabaseLookup's excluded
	// peers list exceeds the protocol limit.
	ErrDatabaseLookupInvalidSize = errors.New("database lookup excluded peers size exceeds protocol limit")
	// ErrI2NPMessageExpired is returned when a message's expiration is in the
	// past.
	ErrI2NPMessageExpired = errors.New("i2np message has expired")
)

// Build record size constants per the I2P specification.
// The 528-byte long records (ElGamal and ECIES long form) are deprecated by the
// specification - "DEPRECATED, only used in the current network when a tunnel
// contains an ElGamal router" and "NOTE: Deprecated, obsolete. Use the Short
// Record format specified below" - and go-i2p no longer builds or parses them.
// The constants are retained only to document the historical sizes.
// Short (ECIES) records are 218 bytes on the wire (added in 0.9.51).
const (
	// StandardBuildRecordSize is the deprecated 528-byte on-wire long-record
	// size. Retained for documentation only; the long-record path is removed.
	StandardBuildRecordSize         = 528
	ShortBuildRecordSize            = buildrecord.ShortRecordSize          // 218
	StandardBuildRecordCleartextLen = buildrecord.StandardCleartextLen     // 222 (deprecated long record)
	ShortBuildRecordCleartextLen    = buildrecord.ShortCleartextLen        // 154
	ShortRecordHeaderSize           = 64                                   // toPeer(16) + ephemeralKey(32) + MAC(16)
	DefaultExpirationSeconds        = buildrecord.DefaultExpirationSeconds // 600, the only spec-supported value
)

// DefaultExpirationTolerance is the default expiration tolerance for clock skew (5 minutes into the past).
// This allows for reasonable clock differences between I2P routers while
// still rejecting clearly expired messages.
const DefaultExpirationTolerance = 5 * 60 // 5 minutes in seconds

// ──────────────────────────────────────────────────────────────────────────────
// I2NP header field layout
// ──────────────────────────────────────────────────────────────────────────────

// I2NP messages travel with one of two headers. The standard header carries a
// payload size and checksum and is required for tunnel-delivered messages; the
// short header omits both because the transport already frames the payload and
// authenticates it. Field offsets are identical in the two forms up to the
// expiration, which is an 8-byte millisecond Date in the standard header and a
// 4-byte seconds-since-epoch Integer in the short one.
//
// Spec: https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/i2np.rst
// Moved from: i2np.go, utils.go
const (
	// I2NPTypeSize is the width of the leading message type byte.
	I2NPTypeSize = 1

	// I2NPMessageIDOffset is where the 4-byte message ID begins, immediately
	// after the type byte.
	I2NPMessageIDOffset = I2NPTypeSize // 1
	// I2NPMessageIDSize is the width of the message ID field.
	I2NPMessageIDSize = 4

	// I2NPExpirationOffset is where the expiration field begins in both header
	// forms.
	I2NPExpirationOffset = I2NPMessageIDOffset + I2NPMessageIDSize // 5

	// I2NPExpirationSize is the width of the standard header's expiration, an
	// 8-byte Date in milliseconds since the epoch.
	I2NPExpirationSize = 8

	// I2NPShortExpirationSize is the width of the short header's expiration, a
	// 4-byte Integer in seconds since the epoch.
	I2NPShortExpirationSize = 4

	// I2NPSizeFieldOffset is where the 2-byte payload length begins in the
	// standard header, after the 8-byte expiration.
	I2NPSizeFieldOffset = I2NPExpirationOffset + I2NPExpirationSize // 13
	// I2NPSizeFieldSize is the width of the payload length field. Because it is
	// two bytes, MaxI2NPStandardPayload is the largest payload it can name.
	I2NPSizeFieldSize = 2

	// I2NPChecksumOffset is where the 1-byte payload checksum begins, after the
	// size field. It is the first byte of the payload's SHA-256.
	I2NPChecksumOffset = I2NPSizeFieldOffset + I2NPSizeFieldSize // 15
	// I2NPChecksumSize is the width of the checksum field.
	I2NPChecksumSize = 1

	// I2NPShortHeaderSize is the full short (NTCP2/SSU2) header length: type +
	// message ID + short expiration. It is the same value as the exported
	// ShortI2NPHeaderSize, restated from its field widths; the assertions below
	// fail the build if the two ever disagree.
	I2NPShortHeaderSize = I2NPTypeSize + I2NPMessageIDSize + I2NPShortExpirationSize // 9

	// I2NPStandardHeaderSize is the full standard header length: type + message
	// ID + expiration + size + checksum, again restated from field widths and
	// asserted against StandardI2NPHeaderSize.
	I2NPStandardHeaderSize = I2NPShortHeaderSize + I2NPSizeFieldSize + I2NPChecksumSize // 16

	// I2NPSizeFieldShift is the bit position of the size field's high byte,
	// used when reading the two-byte length without a binary helper.
	I2NPSizeFieldShift = 8

	// I2NPMessageIDShift32/24/16/8 are the byte bit positions used to assemble
	// a big-endian message ID from four individual bytes.
	I2NPMessageIDShift24 = 24
	I2NPMessageIDShift16 = 16
	I2NPMessageIDShift8  = 8
)

// ──────────────────────────────────────────────────────────────────────────────
// I2NP message type ranges
// ──────────────────────────────────────────────────────────────────────────────

// The type byte is one byte, so 0-255 are addressable, but only some of them
// are assigned. These ranges are what ReadI2NPType uses to decide whether an
// unfamiliar type is merely unassigned (log quietly, it may be specified later)
// or something a router should not be sending (log loudly).
//
// Spec: i2np.rst §"Message Types"
// Moved from: utils.go
const (
	// unassignedTypeRangeStart and unassignedTypeRangeEnd bound the first block
	// of types the spec does not use (4-9).
	unassignedTypeRangeStart = 4
	unassignedTypeRangeEnd   = 9

	// unassignedTypeRange2Start and unassignedTypeRange2End bound the second
	// unused block (12-17).
	unassignedTypeRange2Start = 12
	unassignedTypeRange2End   = 17

	// experimentalTypeRangeStart and experimentalTypeRangeEnd bound the
	// implementation-defined range (224-254) that routers may use for their own
	// protocols. Receiving one is not an error but is worth a warning, since it
	// means a peer is speaking something outside the spec.
	experimentalTypeRangeStart = 224
	experimentalTypeRangeEnd   = 254

	// reservedType is the single type held back entirely (255).
	reservedType = 255
)

// ──────────────────────────────────────────────────────────────────────────────
// Identity hash sizes
// ──────────────────────────────────────────────────────────────────────────────

// HashSize is the width, in bytes, of the SHA-256 identity hashes that appear
// throughout the I2NP payload types: the DatabaseLookup key, the excluded-peer
// list entries, the reply key, and the DatabaseSearchReply peer hashes. It
// matches common.Hash, which is the type these fields are declared as.
// Moved from: database_lookup.go, database_search_reply.go, database_store.go
const HashSize = 32

// ──────────────────────────────────────────────────────────────────────────────
// TunnelData message framing
// ──────────────────────────────────────────────────────────────────────────────

// A TunnelData message's payload is a 4-byte tunnel ID followed by a fixed
// 1024-byte encrypted block — one AES-CBC block chain, no length field — for
// 1028 bytes total. The size is fixed by the tunnel layer, not by the payload.
//
// Spec: tunnel-message.rst; i2np.rst §"Tunnel Data Message"
// Moved from: tunnel_data.go, tunnel_data_message.go, i2np.go
const (
	// TunnelDataPayloadSize is the encrypted tunnel payload that follows the
	// tunnel ID in a TunnelData message.
	TunnelDataPayloadSize = 1024

	// TunnelDataSize is the whole TunnelData payload: tunnel ID plus encrypted
	// data. Equal to tunnel.TunnelMessageSize, which the crypto package uses to
	// size the same block.
	TunnelDataSize = i2ptunnel.TunnelMessageSize // 1028
)

// ──────────────────────────────────────────────────────────────────────────────
// DeliveryStatus message framing
// ──────────────────────────────────────────────────────────────────────────────

// The DeliveryStatus replay cache key is SHA-256 over the 4-byte message ID
// concatenated with the 8-byte delivery timestamp, so the preimage is exactly
// 12 bytes.
//
// Spec: i2np.rst §"Delivery Status Message"
// Moved from: delivery_status_message.go
const (
	// DeliveryStatusKeySize is the length of the message ID + timestamp buffer
	// that is hashed to form a replay-cache key.
	DeliveryStatusKeySize = I2NPMessageIDSize + I2NPExpirationSize // 12

	// DeliveryStatusTimestampSize is the width of the delivery timestamp, an
	// 8-byte Date in milliseconds.
	DeliveryStatusTimestampSize = I2NPExpirationSize // 8

	// DeliveryStatusMaxAge is how far in the past a DeliveryStatus may be
	// dated and still be accepted. A status older than this is stale: the
	// message it refers to has long since expired, so recording it in the
	// replay cache would only consume space.
	DeliveryStatusMaxAge = 24 * time.Hour
)

// ──────────────────────────────────────────────────────────────────────────────
// Garlic message limits
// ──────────────────────────────────────────────────────────────────────────────

const (
	// garlicCloveWireLimit is the ceiling the wire format imposes on cloves in
	// one garlic message. The clove count is written as a single byte, so 255 is
	// the most a message can declare. The builder's own, tighter cap is
	// MaxGarlicCloves.
	// Moved from: garlic_builder.go
	garlicCloveWireLimit = 255

	// garlicBuilderInitialCapacity is the capacity hint for a serialised garlic
	// message, sized to a typical small clove set to avoid regrowth.
	// Moved from: garlic_builder.go
	garlicBuilderInitialCapacity = 128

	// garlicDeliveryInstructionInitialCapacity is the capacity hint for one
	// serialised delivery instruction.
	// Moved from: garlic_builder.go
	garlicDeliveryInstructionInitialCapacity = 37

	// garlicCloveHeaderSize is the size of the per-clove header written ahead of
	// each clove's I2NP message.
	// Moved from: garlic_builder.go
	garlicCloveHeaderSize = 9

	// garlicMessageTTL is how long a built garlic message stays deliverable.
	// Kept short because a garlic message is a burst of cloves for one
	// destination and a stale one is better dropped than retried.
	// Moved from: garlic_builder.go, garlic_session.go
	garlicMessageTTL = 10 * time.Second

	// maxOneTimeGarlicKeys bounds how many one-time garlic keys the session
	// manager retains. Each is registered by a peer, so an unbounded map would
	// let a remote peer grow router memory without limit.
	// Moved from: garlic_session.go
	maxOneTimeGarlicKeys = 10_000
)

// ──────────────────────────────────────────────────────────────────────────────
// RouterInfo / LeaseSet size limits
// ──────────────────────────────────────────────────────────────────────────────

// Upper bounds applied when accepting a DatabaseStore payload. The compressed
// and decompressed limits are deliberately generous: they exist to stop a
// decompression bomb and a truncated stream, not to police honest routers.
// Moved from: database_store.go, database_manager.go
const (
	// KiB is the multiplier for the kilobyte units used by the size limits
	// below.
	KiB = 1024

	// MaxRouterInfoCompressedSize is the largest accepted compressed RouterInfo.
	MaxRouterInfoCompressedSize = 20 * KiB

	// MaxRouterInfoUncompressedSize is the largest a RouterInfo may expand to.
	// The ratio between this and the compressed limit is what catches a bomb.
	MaxRouterInfoUncompressedSize = 100 * KiB

	// MaxDecompressionRatio is how much a payload may grow during
	// decompression before it is treated as a bomb rather than as compression
	// doing its job.
	MaxDecompressionRatio = 100

	// databaseStoreReplyTokenSize is the width of the reply token field in a
	// DatabaseStore payload. When it is zero the optional reply tunnel ID and
	// gateway that follow it are absent.
	databaseStoreReplyTokenSize = I2NPMessageIDSize // 4

	// databaseStoreMinSize is the smallest valid DatabaseStore payload:
	// key + type + reply token.
	databaseStoreMinSize = HashSize + I2NPTypeSize + databaseStoreReplyTokenSize // 37

	// databaseSearchReplyMinSize is the smallest valid DatabaseSearchReply:
	// the requested key plus the peer count byte.
	databaseSearchReplyMinSize = HashSize + I2NPTypeSize // 33

)

// ──────────────────────────────────────────────────────────────────────────────
// NetDB query rate limiting
// ──────────────────────────────────────────────────────────────────────────────

// Moved from: database_manager.go
const (
	// routerInfoDumpDateLayout is the Go reference layout for the date suffix
	// on periodic RouterInfo dump filenames.
	// Moved from: database_manager.go
	routerInfoDumpDateLayout = "20060102"
)

// ──────────────────────────────────────────────────────────────────────────────
// Short build record ECIES sizes
// ──────────────────────────────────────────────────────────────────────────────

// The sizes of the short (ECIES) build record are owned by
// lib/tunnel/buildrecord, which defines the record; these alias them so the
// encryption code and the serialisation code cannot drift apart.
const (
	// x25519KeySize is the width of an X25519 private key or public key, the
	// key agreement used by the short build record.
	// Moved from: build_record_crypto_short.go
	x25519KeySize = 32

	// shortRecordAESKeySize is the width of the chaining key and Noise
	// transcript hash produced by the short record's ECIES handshake.
	// Moved from: build_record_crypto_short.go
	shortRecordAESKeySize = 32
)

// Header layout assertions. These are compile-time checks, not runtime ones: if
// a field width above is edited without the corresponding header total, or the
// existing ShortI2NPHeaderSize / StandardI2NPHeaderSize constants are edited
// without these, the package stops building rather than silently mis-framing
// every message.
const (
	_ = uint(ShortI2NPHeaderSize - I2NPShortHeaderSize)
	_ = uint(StandardI2NPHeaderSize - I2NPStandardHeaderSize)
)
