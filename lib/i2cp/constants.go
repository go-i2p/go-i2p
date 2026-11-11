package i2cp

import (
	"time"

	"github.com/go-i2p/go-i2p/lib/i2np"
)

// ──────────────────────────────────────────────────────────────────────────────
// I2CP message framing
// ──────────────────────────────────────────────────────────────────────────────

// Every I2CP message on the wire is length(4) + type(1) + payload(variable).
// The session ID is not part of that framing — ReadMessage extracts it from the
// payload of the message types that carry it, so the payload parsers below all
// measure from the start of the payload, not the start of the message.
//
// Spec: https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/i2cp.rst
// Moved from: protocol.go
const (
	// messageLengthFieldSize is the big-endian uint32 that prefixes every
	// message and declares the payload length.
	messageLengthFieldSize = 4

	// messageTypeFieldSize is the single byte after the length that names the
	// message type.
	messageTypeFieldSize = 1

	// messageHeaderSize is the fixed framing ahead of the payload: length plus
	// type.
	messageHeaderSize = messageLengthFieldSize + messageTypeFieldSize // 5

	// sessionIDFieldSize is the big-endian uint16 session ID that opens the
	// payload of the messages listed in extractSessionIDFromPayload.
	sessionIDFieldSize = 2
)

// ──────────────────────────────────────────────────────────────────────────────
// Payload struct field sizes
// ──────────────────────────────────────────────────────────────────────────────

// The SendMessage, MessagePayload, HostLookup, HostReply and BlindingInfo
// payloads are all hand-decoded from big-endian fields. The sizes below name
// each field so the minimum-length guards and the offset arithmetic in
// payload.go read as the struct they describe.
//
// Moved from: payload.go
const (
	// payloadLengthFieldSize is the in-payload big-endian uint32 that gives the
	// length of an embedded message body. Distinct from messageLengthFieldSize,
	// which frames the I2CP message itself.
	payloadLengthFieldSize = 4

	// nonceFieldSize is the SendMessage nonce, echoed back in MessageStatus so a
	// client can correlate a delivery result with the message it sent.
	nonceFieldSize = 4

	// flagsFieldSize is the SendMessageExpires flags field.
	flagsFieldSize = 2

	// expirationFieldSize is the SendMessageExpires deadline: a 48-bit
	// milliseconds-since-epoch integer, six bytes rather than the usual eight.
	expirationFieldSize = 6

	// messageIDFieldSize is the MessagePayload router-assigned message ID.
	messageIDFieldSize = 4

	// requestIDFieldSize is the HostLookup/HostReply client-chosen request ID.
	requestIDFieldSize = 4

	// timeoutMSFieldSize is the HostLookup client-supplied timeout in
	// milliseconds.
	timeoutMSFieldSize = 4

	// lookupTypeFieldSize is the HostLookup single-byte lookup type selector.
	lookupTypeFieldSize = 1

	// resultCodeFieldSize is the HostReply single-byte result code.
	resultCodeFieldSize = 1

	// blindingFlagsFieldSize is the BlindingInfo single-byte flag field.
	blindingFlagsFieldSize = 1

	// blindingEndpointTypeFieldSize is the single byte naming the endpoint
	// encoding that follows.
	blindingEndpointTypeFieldSize = 1

	// blindingExpirationFieldSize is the big-endian uint32 blinding expiration.
	blindingExpirationFieldSize = 4

	// sigTypeFieldSize is the big-endian uint16 signature type, both in the
	// BlindingInfo prefix and in the sig-type endpoint encoding.
	sigTypeFieldSize = 2
)

// Fixed-size payload headers, composed from the field sizes above. Each is the
// smallest buffer its parser can accept.
//
// Moved from: payload.go
const (
	// sendMessageMinTrailingSize is what must follow a SendMessage Destination:
	// payload length plus nonce.
	sendMessageMinTrailingSize = payloadLengthFieldSize + nonceFieldSize // 8

	// sendMessageExpiresMinTrailingSize is what must follow a
	// SendMessageExpires Destination: payload length, nonce, flags and
	// expiration.
	sendMessageExpiresMinTrailingSize = payloadLengthFieldSize + nonceFieldSize +
		flagsFieldSize + expirationFieldSize // 16

	// messagePayloadHeaderSize is the MessagePayload header: session ID, message
	// ID and payload length.
	messagePayloadHeaderSize = sessionIDFieldSize + messageIDFieldSize +
		payloadLengthFieldSize // 10

	// hostLookupHeaderSize is the HostLookup header: session ID, request ID,
	// timeout and lookup type. Everything after it depends on the lookup type.
	hostLookupHeaderSize = sessionIDFieldSize + requestIDFieldSize +
		timeoutMSFieldSize + lookupTypeFieldSize // 11

	// hostReplyHeaderSize is the HostReply header: session ID, request ID and
	// result code. A Destination may follow.
	hostReplyHeaderSize = sessionIDFieldSize + requestIDFieldSize +
		resultCodeFieldSize // 7

	// blindingInfoMinSize is the fixed BlindingInfo prefix: session ID, flags,
	// endpoint type, signature type and expiration.
	blindingInfoMinSize = sessionIDFieldSize + blindingFlagsFieldSize +
		blindingEndpointTypeFieldSize + sigTypeFieldSize +
		blindingExpirationFieldSize // 10

	// leaseSet2HeaderSize is the CreateLeaseSet2 header: session ID plus the
	// single byte naming the LeaseSet structure that follows.
	leaseSet2HeaderSize = sessionIDFieldSize + messageTypeFieldSize // 3

	// sessionIDPrefixSize is the SessionID that ReadMessage leaves at the front
	// of msg.Payload; the payload parsers expect it stripped.
	sessionIDPrefixSize = sessionIDFieldSize
)

// ──────────────────────────────────────────────────────────────────────────────
// Identity and key sizes
// ──────────────────────────────────────────────────────────────────────────────

// hashSize is the width of the destination and gateway SHA-256 hashes that
// appear in HostLookup queries, HostReply destinations and lease entries. It is
// aliased from i2np rather than restated so the two packages cannot disagree
// about the size of the same identity hash.
//
// Moved from: payload.go, server_dispatch.go
const hashSize = i2np.HashSize // 32

// hashHexLen is the length of a lowercase hex-encoded destination hash, which is
// how a HostLookup hash query arrives when it is not given as raw bytes.
//
// Moved from: payload.go
const hashHexLen = hashSize * 2 // 64

// x25519KeySize is the width of the X25519 key material a session uses for
// message encryption: the client-supplied encryption key and the keystore's own
// encryption private key are both exactly this wide.
//
// Moved from: session.go
const x25519KeySize = 32

// ──────────────────────────────────────────────────────────────────────────────
// LeaseSet and destination sizes
// ──────────────────────────────────────────────────────────────────────────────

// destinationMinSize is the smallest possible I2P Destination: 387 bytes of
// NULL-certificate ElGamal/DSA key material. A Destination with a key
// certificate is larger, so this is a floor for validation, not an expected
// length. It is the first field of a type-1 LeaseSet, which is why a LeaseSet
// shorter than this cannot hold a Destination at all.
//
// Moved from: server_dispatch.go
const destinationMinSize = 387

// ──────────────────────────────────────────────────────────────────────────────
// RequestVariableLeaseSet payload layout
// ──────────────────────────────────────────────────────────────────────────────

// The reply is 2-byte session ID, 1-byte lease count, then count fixed 44-byte
// lease entries (32-byte gateway hash + 4-byte tunnel ID + 8-byte end date).
//
// Moved from: server_tunnels.go
const (
	// leaseSetCountFieldSize is the single byte that carries the number of lease
	// entries following the session ID.
	leaseSetCountFieldSize = 1

	// leaseEntryTunnelIDSize is the big-endian uint32 tunnel ID in a lease
	// entry.
	leaseEntryTunnelIDSize = 4

	// leaseEntryEndDateSize is the big-endian uint64 millisecond end date in a
	// lease entry.
	leaseEntryEndDateSize = 8

	// leaseEntrySize is the full fixed-size lease entry.
	leaseEntrySize = hashSize + leaseEntryTunnelIDSize + leaseEntryEndDateSize // 44
)

// ──────────────────────────────────────────────────────────────────────────────
// BandwidthLimits payload
// ──────────────────────────────────────────────────────────────────────────────

// BandwidthLimits is specified as 16 uint32 values, of which this
// implementation populates the inbound and outbound limits and zero-fills the
// rest.
//
// Moved from: server_dispatch.go
const (
	// bandwidthLimitsValueCount is the number of uint32 fields in a
	// BandwidthLimits payload.
	bandwidthLimitsValueCount = 16

	// bandwidthLimitsPayloadSize is the wire size of a BandwidthLimits payload.
	bandwidthLimitsPayloadSize = bandwidthLimitsValueCount * payloadLengthFieldSize // 64

	// defaultBandwidthLimitBytesPerSec is the 1 MB/s limit reported when no
	// bandwidth provider is configured: a conservative standing default rather
	// than a measured rate.
	defaultBandwidthLimitBytesPerSec = i2cpKiB * i2cpKiB
)

// ──────────────────────────────────────────────────────────────────────────────
// Session config defaults
// ──────────────────────────────────────────────────────────────────────────────

// DefaultSessionConfig mirrors the defaults the reference implementations use,
// so a client that requests no options gets the same tunnel shape it would from
// a Java or C++ router. The I2CP spec calls out the 3-hop / 5-tunnel shape and
// the 10-minute tunnel lifetime explicitly.
//
// Moved from: session.go
const (
	// defaultTunnelLength is the hop count for both tunnel directions.
	defaultTunnelLength = 3

	// defaultTunnelCount is the number of tunnels built in each direction.
	defaultTunnelCount = 5

	// defaultSessionTunnelLifetime is how long a session tunnel lives before it
	// is rebuilt.
	defaultSessionTunnelLifetime = 10 * time.Minute

	// defaultMessageTimeout is how long a message may wait for delivery.
	defaultMessageTimeout = 60 * time.Second

	// defaultMessageQueueSize is the per-session inbound/outbound message queue
	// depth.
	defaultMessageQueueSize = 100

	// defaultMessageRateLimit is the sustained messages-per-second allowed per
	// session.
	defaultMessageRateLimit = 100

	// defaultMessageRateBurst is how many messages a session may send
	// instantaneously before the sustained rate applies.
	defaultMessageRateBurst = 200

	// defaultLeaseSetExpirationSeconds is the LeaseSet lifetime the router
	// advertises for a session: 600 seconds, i.e. the same 10 minutes as the
	// tunnels underneath it.
	defaultLeaseSetExpirationSeconds = 600
)

// Moved from: session.go
const (
	// rateLimiterBurstMultiplier derives a burst size from the sustained rate
	// when a client sets a rate but no burst, so a full second of traffic can be
	// sent without throttling.
	rateLimiterBurstMultiplier = 2

	// leaseValidityMinFloor is the least remaining lifetime a tunnel lease may
	// have when a LeaseSet is built from it.
	leaseValidityMinFloor = 30 * time.Second

	// leaseValidityLifetimeDivisor turns the configured tunnel lifetime into a
	// proportional minimum — one tenth of a tunnel's life — so short-lived test
	// tunnels are not rejected by the absolute floor alone.
	leaseValidityLifetimeDivisor = 10
)

// ──────────────────────────────────────────────────────────────────────────────
// Session config validation bounds
// ──────────────────────────────────────────────────────────────────────────────

// A client may ask for any tunnel shape, but the router has to refuse the ones it
// cannot serve: a hop count it cannot build, or a count that would exhaust its
// transit capacity. The bounds below encode those limits, and the error messages
// quote them so a client learns the accepted range.
//
// Moved from: session_config_parser.go
const (
	// minTunnelLength and maxTunnelLength bound the hop count for either
	// direction. Zero is allowed (a destination-local tunnel); the ceiling of 7
	// matches the reference implementation's maximum.
	minTunnelLength = 0
	maxTunnelLength = 7

	// minTunnelCount and maxTunnelCount bound the number of tunnels per
	// direction. At least one is required to carry traffic; 16 is the most a
	// single session may claim.
	minTunnelCount = 1
	maxTunnelCount = 16

	// minTunnelLifetime and maxTunnelLifetime bound the configured rebuild
	// interval: under a minute churns tunnels needlessly, over an hour keeps
	// stale tunnels in the network too long.
	minTunnelLifetime = 1 * time.Minute
	maxTunnelLifetime = 60 * time.Minute

	// minMessageQueueSize is the smallest queue a client may request; a zero or
	// negative depth could not hold a message at all.
	minMessageQueueSize = 1
)

// ──────────────────────────────────────────────────────────────────────────────
// Session config wire layout
// ──────────────────────────────────────────────────────────────────────────────

// The signed CreateSession/ReconfigureSession body is options-size(2) +
// options mapping + date(8) + signature. The date is an 8-byte
// milliseconds-since-epoch integer, and the spec rejects a session whose date is
// more than +/- 30 seconds from the router's clock.
//
// Moved from: session_config_parser.go
const (
	// optionsSizeFieldSize is the big-endian uint16 that prefixes the options
	// mapping in a signed session body.
	optionsSizeFieldSize = 2

	// sessionDateFieldSize is the 8-byte milliseconds-since-epoch Date field.
	sessionDateFieldSize = 8

	// minMappingSize is the smallest buffer that can be a valid I2P Mapping:
	// anything shorter is treated as an empty option set rather than a parse
	// failure.
	minMappingSize = 3

	// mappingPairLength is how many values a well-formed Mapping key/value pair
	// holds.
	mappingPairLength = 2

	// mappingSizeFieldSize is the big-endian uint16 length header that precedes
	// mapping data in the auth and session-config encodings.
	mappingSizeFieldSize = 2
)

// ──────────────────────────────────────────────────────────────────────────────
// Server defaults
// ──────────────────────────────────────────────────────────────────────────────

// Moved from: server.go, server_connection.go
const (
	// defaultServerReadTimeout bounds the idle gap between messages (the
	// header wait). Zero means no idle timeout is enforced: idle clients are
	// never disconnected for inactivity. The previous 60-second default
	// killed normal long-lived I2CP client connections that sit idle after
	// the GetDate/Setdate exchange (issue #54).
	//
	// The per-message byte read is bounded separately by MessageReadTimeout
	// (30s) to prevent slow-send attacks.
	defaultServerReadTimeout = 0

	// defaultServerWriteTimeout bounds a single write to a client connection, so
	// a client that stops reading cannot pin a writer goroutine indefinitely.
	defaultServerWriteTimeout = 30 * time.Second

	// defaultServerSessionTimeout is how long a session may go unused before the
	// server reaps it.
	defaultServerSessionTimeout = 30 * time.Minute

	// connectionLimitMultiplier scales MaxSessions into the raw connection
	// ceiling. A client connects before it creates a session, so the socket limit
	// has to sit above the session limit or a burst of connecting clients would
	// be rejected before any of them could authenticate.
	connectionLimitMultiplier = 2
)

// ──────────────────────────────────────────────────────────────────────────────
// Session tunnel pool defaults
// ──────────────────────────────────────────────────────────────────────────────

// I2CP client pools are built with the same shape the router uses for its own
// tunnels, plus a headroom of backup tunnels that rebuild ahead of expiry.
//
// Moved from: server_tunnels.go
const (
	// defaultBackupTunnelQuantity is the number of backup tunnels a session pool
	// keeps when the client does not ask for a specific quantity.
	defaultBackupTunnelQuantity = 2

	// poolTunnelLifetime is how long a client-pool tunnel lives.
	poolTunnelLifetime = 10 * time.Minute

	// poolRebuildThreshold is how before expiry a tunnel is replaced, so a
	// replacement is ready when the old one dies.
	poolRebuildThreshold = 2 * time.Minute

	// poolBuildRetryDelay is the first retry delay for a failed tunnel build;
	// exponential backoff grows it from there.
	poolBuildRetryDelay = 2 * time.Second

	// poolMaxBuildRetries caps how many times a single build attempt is retried.
	poolMaxBuildRetries = 3

	// maxTunnelsPerLeaseSet caps the lease entries reported for one session. A
	// client asking for more tunnels than this is misconfigured, and an
	// unbounded count would let one session inflate the reply payload.
	maxTunnelsPerLeaseSet = 16
)

// ──────────────────────────────────────────────────────────────────────────────
// Private key tuple layout
// ──────────────────────────────────────────────────────────────────────────────

// A session's key store hands back its private keys as an untyped slice, so the
// position of each entry is the only thing identifying it. extractPrivateKeys
// reads them by index; the log field that reports whether a session is usable
// counts the same entries.
//
// Moved from: session.go
const (
	// minPrivateKeysForSession is how many entries a session's private key slice
	// must hold before the session can sign and decrypt at all: the signing key
	// at index 0 and the encryption key at index 1.
	minPrivateKeysForSession = 2

	// privateKeysWithIdentityPadding is the slice length at which a third entry,
	// the identity padding, is present. Keystores that predate blinding supply
	// only the two keys.
	privateKeysWithIdentityPadding = 3
)

// ──────────────────────────────────────────────────────────────────────────────
// LeaseSet maintenance intervals
// ──────────────────────────────────────────────────────────────────────────────

// Moved from: session_maintenance.go
const (
	// maintenanceIntervalDivisor is how the maintenance tick is derived from the
	// tunnel lifetime: checking four times per lifetime is often enough to catch
	// a LeaseSet approaching expiry without waking the session needlessly.
	maintenanceIntervalDivisor = 4

	// defaultMaintenanceInterval is the tick used when a configured lifetime is
	// too short to divide into a usable interval.
	defaultMaintenanceInterval = 15 * time.Second

	// leaseSetRegenerationDivisor is how the regeneration threshold is derived
	// from the tunnel lifetime: a LeaseSet older than half the lifetime is
	// replaced so it is still fresh when the tunnels under it expire.
	leaseSetRegenerationDivisor = 2

	// defaultLeaseSetRegenerationThreshold is the threshold used when a
	// configured lifetime is too short to divide into a usable one.
	defaultLeaseSetRegenerationThreshold = 5 * time.Minute
)

// ──────────────────────────────────────────────────────────────────────────────
// Session ID generation
// ──────────────────────────────────────────────────────────────────────────────

// ──────────────────────────────────────────────────────────────────────────────
// Session ID generation
// ──────────────────────────────────────────────────────────────────────────────

// Moved from: session_manager.go
const (
	// sessionIDByteSize is how many random bytes are drawn to build a session
	// ID, which is a uint16.
	sessionIDByteSize = 2

	// bitsPerByte is the shift step for assembling a big-endian integer from
	// bytes.
	bitsPerByte = 8
)

// ──────────────────────────────────────────────────────────────────────────────
// Payload safety budget
// ──────────────────────────────────────────────────────────────────────────────

// Moved from: server_dispatch.go
const (
	// encryptionOverheadBudget is the headroom held back from MaxPayloadSize on
	// the SendMessage paths. A payload accepted at the full spec limit leaves no
	// room for the garlic wrapping and encryption the router adds before the
	// message goes on the wire, so the effective ceiling is lower than the
	// protocol's.
	encryptionOverheadBudget = 2048

	// maxSafeSendPayloadSize is the largest client payload this router will
	// accept for a SendMessage-like message: the spec limit minus the encryption
	// overhead budget.
	maxSafeSendPayloadSize = MaxPayloadSize - encryptionOverheadBudget
)
