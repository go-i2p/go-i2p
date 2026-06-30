# ntcp2
--
    import "github.com/go-i2p/go-i2p/lib/transport/ntcp2"

![ntcp2.svg](ntcp2.svg)

Package ntcp2 implements the NTCP2 transport protocol for the I2P network. NTCP2
is a TCP-based transport that uses the Noise protocol framework (XK pattern) for
authenticated key agreement, providing forward secrecy and identity hiding.

# Implementation Notes

## NAT Traversal

As of 2026-06, NAT traversal logic (UPnP/NAT-PMP, loopback detection,
SO_REUSEADDR socket options, and TOCTOU retry handling) has been extracted to
the shared lib/nat package. The bindOSAssignedPort and bindWithNATTraversal
functions in this package are now thin wrappers around
nat.ProbeAndBindWithNATTraversal and nat.BindWithNATTraversal respectively.

Future enhancements to NAT handling should be implemented in lib/nat, not here.
This ensures consistent behavior across all transports (NTCP2, SSU2, and any
future transport implementations).

See lib/nat/doc.go for details on the NAT traversal implementation.

## Usage

```go
const (
	// BlockTypeDateTime is a DateTime block (type 0).
	// Payload: 4 bytes, unsigned big-endian Unix epoch seconds.
	BlockTypeDateTime byte = 0

	// BlockTypeOptions is an Options block (type 1).
	// Payload: variable length, contains padding/traffic negotiation params.
	BlockTypeOptions byte = 1

	// BlockTypeRouterInfo is a RouterInfo block (type 2).
	// Payload: 1-byte flag + raw RouterInfo (never gzip-compressed in NTCP2).
	// Flag byte: bit 0 = 0 (local store) or 1 (flood request); bits 1-7 unused.
	// Spec: ntcp2.rst §1575-1577.
	BlockTypeRouterInfo byte = 2

	// BlockTypeI2NP is an I2NP message block (type 3).
	// Payload: 9-byte short I2NP header + message body.
	BlockTypeI2NP byte = 3

	// BlockTypeTermination is a Termination block (type 4).
	// Payload: version(4) + networkID(1) + time(4) + reason(1) = 10 bytes.
	BlockTypeTermination byte = 4

	// BlockTypePadding is a Padding block (type 254).
	// Payload: arbitrary bytes, ignored by the receiver.
	BlockTypePadding byte = 254
)
```
NTCP2 data-phase block types per the specification.

Spec reference: https://geti2p.net/spec/ntcp2#data-phase

After the Noise XK handshake completes, both peers exchange AEAD-encrypted
frames. Each decrypted frame payload consists of one or more concatenated
blocks. Every block begins with a 3-byte header: [type:1][size:2].

```go
const (
	// RouterInfoFlagLocalStore indicates the peer should store the RouterInfo locally only.
	RouterInfoFlagLocalStore byte = 0x00
	// RouterInfoFlagFloodRequest indicates the peer should flood the RouterInfo to the netdb.
	RouterInfoFlagFloodRequest byte = 0x01
)
```
NTCP2 RouterInfo block flag byte constants (ntcp2.rst §1575-1577). Bit 0: 0 =
local store, 1 = flood request. Bits 1-7: unused, must be 0. NOTE: RouterInfo in
NTCP2 blocks is NEVER gzip-compressed (unlike DatabaseStore).

```go
const (
	// TerminationNormalClose indicates a graceful session shutdown.
	TerminationNormalClose byte = 0

	// TerminationOppositeDirectionTerminated indicates a Termination block was
	// received from the peer; this router is responding with its own termination.
	TerminationOppositeDirectionTerminated byte = 1

	// TerminationIdleTimeout indicates the session was terminated due to inactivity.
	TerminationIdleTimeout byte = 2

	// TerminationRouterShutdown indicates the router is shutting down.
	TerminationRouterShutdown byte = 3

	// TerminationAEADFailure indicates an AEAD decryption failure in the data phase.
	// When this is the reason, the termination block MUST NOT be sent if the cipher
	// state may be corrupted — only probing-resistance junk-read should be performed.
	TerminationAEADFailure byte = 4

	// TerminationIncompatibleOptions indicates an error in the session options negotiation
	// (version, network ID, or option values are incompatible).
	TerminationIncompatibleOptions byte = 5

	// TerminationIncompatibleSignatureType indicates the peer uses a signature type
	// that this router does not support.
	TerminationIncompatibleSignatureType byte = 6

	// TerminationClockSkew indicates the peer's timestamp is too far from local time.
	TerminationClockSkew byte = 7

	// TerminationPaddingViolation indicates padding rules were violated.
	TerminationPaddingViolation byte = 8

	// TerminationAEADFramingError indicates an AEAD framing error (e.g. wrong frame length).
	TerminationAEADFramingError byte = 9

	// TerminationPayloadFormatError indicates the payload format was invalid.
	TerminationPayloadFormatError byte = 10

	// TerminationMsg1DecryptionFailure indicates message 1 (handshake) decryption failed.
	TerminationMsg1DecryptionFailure byte = 11

	// TerminationMsg2DecryptionFailure indicates message 2 (handshake) decryption failed.
	TerminationMsg2DecryptionFailure byte = 12

	// TerminationMsg3Error indicates an error processing message 3 of the handshake
	// (decryption failure or invalid contents). Matches i2pd eNTCP2Message3Error.
	TerminationMsg3Error byte = 13

	// TerminationIntraFrameReadTimeout indicates a timeout while reading a frame
	// during the data phase. Matches i2pd eNTCP2IntraFrameReadTimeout.
	TerminationIntraFrameReadTimeout byte = 14

	// TerminationRouterInfoSignatureVerificationFail indicates the peer's RouterInfo
	// signature verification failed. Matches i2pd eNTCP2RouterInfoSignatureVerificationFail.
	TerminationRouterInfoSignatureVerificationFail byte = 15

	// TerminationIncorrectSParameter indicates the static key (the Noise "s" parameter)
	// is incorrect — e.g. it does not match the encryption key published in the peer's
	// RouterInfo. Matches i2pd eNTCP2IncorrectSParameter.
	TerminationIncorrectSParameter byte = 16

	// TerminationBanned indicates the peer is banned. Matches i2pd eNTCP2Banned.
	TerminationBanned byte = 17
)
```
Termination reason codes per the NTCP2 specification. These are used in the
termination block (block type 0x04) to indicate why the session is being closed.

Spec reference: https://geti2p.net/spec/ntcp2#termination

```go
const ClockSkewTolerance = transport.ClockSkewTolerance
```
ClockSkewTolerance is re-exported from the shared transport package. Per the
NTCP2 spec, connections with a clock skew exceeding this value should be
terminated with reason code 6.

We intentionally use 30 s (half the go-noise default of 60 s) to narrow the
post-restart replay window: a captured handshake msg1 is only replayable for up
to 30 s rather than 60 s after a router restart that flushes the in-memory
replay cache. This is a security trade-off; operators with loose NTP discipline
should consider tightening NTP synchronisation rather than widening this value.

```go
const DefaultMaxSessions = 512
```
DefaultMaxSessions is the default maximum number of concurrent NTCP2 sessions.
This prevents resource exhaustion under heavy load.

```go
const RekeyThreshold uint64 = 65535
```
RekeyThreshold is the number of messages (sent + received) after which a session
should be rekeyed for forward secrecy. Per the NTCP2 specification, rekeying
should occur periodically. 65535 messages is a conservative threshold (just
under 2^16) that balances forward secrecy with performance.

```go
var (
	// ErrNTCP2NotSupported indicates that a peer/router does not advertise NTCP2 support.
	ErrNTCP2NotSupported      = oops.New("router does not support NTCP2")
	ErrSessionClosed          = oops.New("NTCP2 session is closed")
	ErrHandshakeFailed        = oops.New("NTCP2 handshake failed")
	ErrInvalidRouterInfo      = oops.New("invalid router info for NTCP2")
	ErrConnectionPoolFull     = oops.New("NTCP2 connection pool full")
	ErrFramingError           = oops.New("I2NP message framing error")
	ErrInvalidListenerAddress = oops.New("invalid listener address for NTCP2")
	ErrInvalidConfig          = oops.New("invalid NTCP2 configuration")
	ErrUnexpectedConnType     = oops.New("accepted connection is not *ntcp2.Conn")
)
```

#### func  BlockTypeString

```go
func BlockTypeString(blockType byte) string
```
BlockTypeString returns a human-readable name for a block type.

#### func  BuildTerminationBlock

```go
func BuildTerminationBlock(reason byte) []byte
```
BuildTerminationBlock constructs a termination block payload suitable for
sending through NTCP2Conn.Write, which will encrypt it with the session's Noise
cipher state and apply SipHash length obfuscation.

The termination block format per NTCP2 spec is:

    [type:1=0x04][size:2=0x0009][sessionDuration:8][reason:1]

Total: 12 bytes (3 header + 9 payload). sessionDuration is elapsed seconds since
the session was established; zero is acceptable when the caller does not track
session start time.

#### func  ConfigureDialConfig

```go
func ConfigureDialConfig(config *ntcp2.Config, peerInfo router_info.RouterInfo) error
```
ConfigureDialConfig sets the peer's static key and obfuscation IV on a Config
for outbound connections. This is required for the Noise XK handshake pattern
where the initiator must know the responder's static key.

Spec reference: https://geti2p.net/spec/ntcp2 — Noise XK pattern requires the
initiator to pre-know the responder's static public key.

#### func  ConvertToRouterAddress

```go
func ConvertToRouterAddress(transport *NTCP2Transport) (*router_address.RouterAddress, error)
```
ConvertToRouterAddress converts an NTCP2Transport's listening address to a
RouterAddress suitable for publishing in RouterInfo. This enables other routers
to connect to this transport.

The function extracts: - Host IP address from the transport's listener - Port
number from the transport's listener - Static public key from the NTCP2
configuration - Initialization vector (IV) for AES obfuscation

Returns a RouterAddress with transport style "NTCP2" and all required options,
or an error if address extraction or conversion fails.

#### func  ExtractNTCP2Addr

```go
func ExtractNTCP2Addr(routerInfo router_info.RouterInfo) (net.Addr, error)
```
ExtractNTCP2Addr extracts the NTCP2 network address from a RouterInfo structure.
It validates NTCP2 support and returns a properly wrapped NTCP2 address with
router hash metadata.

#### func  ExtractPeerIV

```go
func ExtractPeerIV(routerInfo router_info.RouterInfo) ([]byte, error)
```
ExtractPeerIV extracts the NTCP2 AES obfuscation IV ("i=" option) from a peer's
RouterInfo. This IV is used for AES-CBC obfuscation of the ephemeral key in
message 1.

Returns the 16-byte IV or an error if not found.

#### func  ExtractPeerStaticKey

```go
func ExtractPeerStaticKey(routerInfo router_info.RouterInfo) ([]byte, error)
```
ExtractPeerStaticKey extracts the NTCP2 static public key ("s=" option) from a
peer's RouterInfo. This key is required by the Noise XK pattern because the
initiator must know the responder's static key before the handshake begins.

The static key is published in the peer's RouterInfo as a base64-encoded 32-byte
Curve25519 public key in the "s=" option of the NTCP2 address.

Returns the 32-byte static key or an error if:

    - The RouterInfo has no NTCP2 addresses
    - No NTCP2 address has a valid "s=" option
    - The "s=" value cannot be decoded or is not 32 bytes

#### func  FrameI2NPMessageAsBlock

```go
func FrameI2NPMessageAsBlock(msg i2np.Message) ([]byte, error)
```
FrameI2NPMessageAsBlock frames an I2NP message using NTCP2 block format. The
message is serialized with a 9-byte short header and wrapped in a type-3 (I2NP)
block. The result can be combined with other blocks via SerializeBlocks.

The 9-byte short header is mandatory for every NTCP2 data-phase I2NP block,
regardless of the concrete message type. i2pd reconstructs the full 16-byte
header by reading the 9-byte short header and adding 7 bytes (NTCP2.cpp
FromNTCP2); sending a 16-byte standard header here would shift the payload by 7
bytes and corrupt every message. The 16-byte standard header is only used for
tunnel-delivered messages (inside TunnelGateway/TunnelData), never here.

Spec reference: https://geti2p.net/spec/ntcp2#data-phase

#### func  GetStaticKeyFromRouter

```go
func GetStaticKeyFromRouter(encryptionKey types.PrivateEncryptionKey) []byte
```
GetStaticKeyFromRouter extracts the X25519 encryption private key from the
router keystore. This key serves as the NTCP2 static key, ensuring consistent
peer identification across router restarts. The key is already persisted by the
RouterInfoKeystore.

Parameters:

    - encryptionKey: The router's X25519 encryption private key

Returns:

    - 32-byte static key suitable for NTCP2 configuration

#### func  HasDialableNTCP2Address

```go
func HasDialableNTCP2Address(routerInfo *router_info.RouterInfo) bool
```
HasDialableNTCP2Address checks if a RouterInfo has at least one directly
dialable NTCP2 address (i.e., an NTCP2 address with both host and port).
Introducer-only addresses are not dialable and will return false.

#### func  HasDirectConnectivity

```go
func HasDirectConnectivity(addr *router_address.RouterAddress) bool
```
HasDirectConnectivity checks if a RouterAddress has direct NTCP2 connectivity.
Returns true if the address has both host and port keys (directly dialable).
Returns false if the address is introducer-only (requires NAT traversal).

#### func  IsAEADFailureReason

```go
func IsAEADFailureReason(reason byte) bool
```
IsAEADFailureReason returns true if the given reason code indicates an AEAD
decryption failure, in which case the cipher state may be corrupted and the
termination block MUST NOT be sent encrypted (only junk-read for probing
resistance).

#### func  MeasureClockSkew

```go
func MeasureClockSkew(peerTime uint32) time.Duration
```
MeasureClockSkew returns the observed clock skew between a peer's timestamp and
the local time. Positive skew means the peer's clock is ahead of ours. This can
be used for diagnostic logging without enforcing the tolerance.

#### func  ParseDateTimeBlock

```go
func ParseDateTimeBlock(data []byte) (time.Time, error)
```
ParseDateTimeBlock extracts the Unix epoch timestamp from a DateTime block's
data. Returns an error if the data is not exactly 4 bytes.

#### func  SerializeBlocks

```go
func SerializeBlocks(blocks ...Block) []byte
```
SerializeBlocks serializes one or more blocks into a single data-phase frame
payload suitable for writing via NTCP2Conn.Write().

#### func  SupportsDirectNTCP2

```go
func SupportsDirectNTCP2(routerInfo *router_info.RouterInfo) bool
```
SupportsDirectNTCP2 checks if a RouterInfo has at least one directly dialable
NTCP2 address. Convenience function for peer selection; filters out
introducer-only routers.

#### func  SupportsNTCP2

```go
func SupportsNTCP2(routerInfo *router_info.RouterInfo) bool
```
SupportsNTCP2 checks if RouterInfo has an NTCP2 transport address.

#### func  TerminationReasonString

```go
func TerminationReasonString(reason byte) string
```
TerminationReasonString returns a human-readable string for a termination reason
code received from a peer. The descriptions match i2pd's definitions.

#### func  UnframeI2NPMessage

```go
func UnframeI2NPMessage(conn net.Conn) (i2np.Message, error)
```
UnframeI2NPMessage unframes I2NP messages from an internal test/pipe stream.

M-4 WARNING: This function reads a NON-STANDARD 4-byte big-endian length prefix.
It is NOT compliant with the NTCP2 spec, which uses a 2-byte SipHash-obfuscated
length field handled by the NTCP2Conn.Read layer. Do NOT call this function on a
real NTCP2 connection — use BlockUnframer (which parses spec-compliant NTCP2
block frames) instead. This function is retained for internal benchmark/test
helpers that use pre-decoded I2NP wire format over net.Pipe.

#### func  ValidateTimestamp

```go
func ValidateTimestamp(peerTime uint32) error
```
ValidateTimestamp checks whether a peer's timestamp is within the allowed clock
skew tolerance relative to the current time.

Returns nil if the timestamp is acceptable, or a *ClockSkewError if the skew
exceeds ClockSkewTolerance.

A peerTime of 0 is treated as "timestamp not provided" and is accepted without
validation, since some peers may not include timestamps during early protocol
negotiation.

#### func  VerifyStaticKeyConsistency

```go
func VerifyStaticKeyConsistency(transport *NTCP2Transport, identity router_info.RouterInfo) error
```
VerifyStaticKeyConsistency checks that the Noise static private key stored in
the transport config produces the same public key that was published in the
NTCP2 RouterInfo "s=" option.

A mismatch means every remote peer will reject our Noise message 1 immediately
after verifying our static key, causing 100% outbound NTCP2 handshake failures
and making us unreachable to all NTCP2 peers.

Should be called once at startup after the RouterInfo has been built and signed.
Returns a descriptive error (with both keys base64-encoded) if a mismatch is
found.

#### func  WrapNTCP2Addr

```go
func WrapNTCP2Addr(addr net.Addr, routerHash data.Hash) (*ntcp2.Addr, error)
```
WrapNTCP2Addr converts a net.Addr to ntcp2.Addr.

#### func  WrapNTCP2Error

```go
func WrapNTCP2Error(err error, operation string) error
```
WrapNTCP2Error wraps an error with NTCP2 operation context. Uses oops.Wrapf
which preserves the original error in the chain.

#### type Block

```go
type Block struct {
	// Type is the block type identifier (0–4, 254).
	Type byte

	// Data is the block payload (excluding the 3-byte header).
	Data []byte
}
```

Block represents a single parsed NTCP2 data-phase block.

#### func  NewDateTimeBlock

```go
func NewDateTimeBlock() Block
```
NewDateTimeBlock creates a DateTime block (type 0) containing the current Unix
epoch timestamp as 4 big-endian bytes.

#### func  NewI2NPBlock

```go
func NewI2NPBlock(i2npData []byte) Block
```
NewI2NPBlock creates an I2NP message block (type 3) from raw I2NP message bytes.
The caller is responsible for providing the short I2NP header + message body.

#### func  NewOptionsBlock

```go
func NewOptionsBlock(opts *Options) Block
```
NewOptionsBlock creates an Options block (type 1) from an Options struct.

#### func  NewPaddingBlock

```go
func NewPaddingBlock(size int) Block
```
NewPaddingBlock creates a Padding block (type 254) filled with cryptographically
random bytes. The NTCP2 spec requires random padding; zero padding is
distinguishable from Java I2P's output and fingerprintable (M-3 / G-9 fix). If
the CSPRNG fails (should never happen in practice), the padding falls back to a
zero-filled slice rather than panicking.

#### func  NewRouterInfoBlock

```go
func NewRouterInfoBlock(routerInfoBytes []byte, flag byte) Block
```
NewRouterInfoBlock creates a RouterInfo block (type 2) with a flag byte
prepended. Per ntcp2.rst §1575-1577, the flag byte encodes:

    bit 0: 0 = local store (RouterInfoFlagLocalStore), 1 = flood request (RouterInfoFlagFloodRequest)
    bits 1-7: unused, must be 0

IMPORTANT: RouterInfo in NTCP2 blocks is NEVER gzip-compressed. Use
RouterInfoFlagLocalStore (0x00) or RouterInfoFlagFloodRequest (0x01).

#### func  ParseBlocks

```go
func ParseBlocks(payload []byte) ([]Block, error)
```
ParseBlocks parses a decrypted data-phase frame payload into individual blocks.
The payload consists of zero or more concatenated [type:1][size:2][data:size]
blocks. Unknown block types are preserved (returned with their raw data) so the
caller can decide how to handle them. Returns an error if the payload is
truncated.

#### type BlockUnframer

```go
type BlockUnframer struct {

	// BlockCallback is called for non-I2NP blocks (DateTime, Options, etc.)
	BlockCallback func(block Block)
}
```

BlockUnframer reads NTCP2 block-framed data from a connection and extracts I2NP
messages. It handles all block types per the NTCP2 spec.

#### func  NewBlockUnframer

```go
func NewBlockUnframer(conn net.Conn) *BlockUnframer
```
NewBlockUnframer creates an unframer for NTCP2 block-based protocol.

#### func (*BlockUnframer) BytesRead

```go
func (u *BlockUnframer) BytesRead() int
```
BytesRead returns the number of bytes read during the last ReadNextMessage call.

#### func (*BlockUnframer) ReadNextMessage

```go
func (u *BlockUnframer) ReadNextMessage() (i2np.Message, error)
```
ReadNextMessage reads and parses NTCP2 frames until an I2NP message is found or
the connection is closed. Non-I2NP blocks are passed to BlockCallback. Multiple
I2NP messages in a single frame are buffered for subsequent calls.

Uses an iterative loop rather than recursion so that a peer sending an unbounded
stream of non-I2NP (e.g. padding-only) frames cannot cause a goroutine stack
overflow.

#### type ClockSkewError

```go
type ClockSkewError struct {
	// PeerTime is the peer's reported Unix timestamp.
	PeerTime uint32
	// LocalTime is the local Unix timestamp at the time of validation.
	LocalTime uint32
	// Skew is the observed clock difference (peer - local).
	Skew time.Duration
}
```

ClockSkewError is returned when a peer's timestamp exceeds the allowed skew.

#### func (*ClockSkewError) Error

```go
func (e *ClockSkewError) Error() string
```
Error returns a human-readable description of the clock skew violation,
including the peer and local timestamps, observed skew, and tolerance.

#### type Config

```go
type Config struct {
	ListenerAddress string // Address to listen on, e.g., ":42069"
	WorkingDir      string // Working directory for persistent storage (e.g., ~/.go-i2p/config)
	MaxSessions     int    // Maximum number of concurrent sessions (0 = use DefaultMaxSessions)
	*ntcp2.Config
}
```

Config holds the configuration parameters for an NTCP2 transport instance,
including listener address, working directory, and session limits.

#### func  NewConfig

```go
func NewConfig(listenerAddress string) (*Config, error)
```
NewConfig creates a new Config with the specified listener address and default
values for other fields.

#### func (*Config) GetMaxSessions

```go
func (c *Config) GetMaxSessions() int
```
GetMaxSessions returns the effective maximum session limit. Returns
DefaultMaxSessions if MaxSessions is not set (0 or negative).

#### func (*Config) Validate

```go
func (c *Config) Validate() error
```
Validate checks the Config for required fields and returns an error if the
configuration is invalid.

#### type DefaultHandler

```go
type DefaultHandler struct {
	*transport.BaseHandler
}
```

DefaultHandler implements NTCP2Handler using the existing functions in this
package. It is wired into the NTCP2Transport at construction time. The replay
cache is managed by the embedded BaseHandler.

#### func  NewDefaultHandler

```go
func NewDefaultHandler() *DefaultHandler
```
NewDefaultHandler creates a new DefaultHandler with a fresh replay cache. Call
Close() on the handler when it is no longer needed to stop the background cache
cleanup goroutine.

#### func (*DefaultHandler) OnHandshakeError

```go
func (h *DefaultHandler) OnHandshakeError(rawConn net.Conn, err error)
```
OnHandshakeError applies probing resistance (random delay + junk read) on the
raw TCP connection. This makes handshake failures indistinguishable from a
random TCP service to an active prober.

#### func (*DefaultHandler) SendTermination

```go
func (h *DefaultHandler) SendTermination(conn *gonoise.Conn, reason byte) error
```
SendTermination constructs and sends an encrypted termination block through the
NTCP2 connection's Noise cipher. The block is written via conn.Write, which
applies AEAD encryption and SipHash length obfuscation.

#### func (*DefaultHandler) ValidateTimestamp

```go
func (h *DefaultHandler) ValidateTimestamp(peerTime uint32) error
```
ValidateTimestamp checks whether a peer's timestamp is within ±60 seconds of the
local clock. Returns a *ClockSkewError if the skew is excessive.

#### type I2NPUnframer

```go
type I2NPUnframer struct {
}
```

I2NPUnframer provides stream-based unframing for test/pipe use only.

M-4 WARNING: I2NPUnframer reads a NON-STANDARD 4-byte big-endian length prefix
that does NOT appear in the NTCP2 specification. Real NTCP2 connections use a
2-byte SipHash-obfuscated length field, handled transparently by NTCP2Conn.Read.
Use BlockUnframer for spec-compliant NTCP2 data-phase parsing. I2NPUnframer
exists only to support tests and benchmarks that write raw I2NP frames over a
net.Pipe.

#### func  NewI2NPUnframer

```go
func NewI2NPUnframer(conn net.Conn) *I2NPUnframer
```
NewI2NPUnframer creates a new I2NPUnframer that reads length-prefixed I2NP
messages from the given connection.

#### func (*I2NPUnframer) BytesRead

```go
func (u *I2NPUnframer) BytesRead() int
```
BytesRead returns the number of bytes read during the last ReadNextMessage call

#### func (*I2NPUnframer) ReadNextMessage

```go
func (u *I2NPUnframer) ReadNextMessage() (i2np.Message, error)
```
ReadNextMessage reads the next length-prefixed I2NP message from the underlying
connection and returns the parsed message.

#### type KeystoreProvider

```go
type KeystoreProvider interface {
	GetEncryptionPrivateKey() types.PrivateEncryptionKey
}
```

KeystoreProvider is the interface that supplies the X25519 encryption private
key required for NTCP2 handshake negotiation.

#### type NTCP2Handler

```go
type NTCP2Handler interface {
	// OnHandshakeError is called when a Noise XK handshake fails (either as
	// initiator or responder). The implementation should apply probing
	// resistance (random delay + junk read) on the raw TCP connection before
	// the connection is closed.
	//
	// rawConn is the underlying TCP connection; it may be nil if extraction
	// failed. The error is the original handshake failure reason.
	OnHandshakeError(rawConn net.Conn, err error)

	// CheckReplay checks whether an ephemeral key (the first 32 bytes of
	// message 1) has been seen before. Returns true if the key is a replay
	// and the connection should be rejected.
	//
	// The replay cache must be shared across all listener goroutines within
	// a single router instance.
	CheckReplay(ephemeralKey [32]byte) bool

	// ValidateTimestamp checks whether a peer's timestamp (Unix epoch seconds)
	// is within the allowed clock skew tolerance. Returns a non-nil error if
	// the skew exceeds the tolerance.
	ValidateTimestamp(peerTime uint32) error

	// SendTermination sends an encrypted termination block through the NTCP2
	// connection's Noise cipher state. The block is encrypted and framed by
	// conn.Write, ensuring no plaintext termination data appears on the wire.
	//
	// For AEAD failure reasons (reason 4), this must NOT be called because
	// the cipher state may be corrupted. Use OnHandshakeError instead.
	SendTermination(conn *gonoise.Conn, reason byte) error
}
```

NTCP2Handler defines callback hooks for injecting I2P-specific behaviour into
the NTCP2 transport layer. The go-noise library handles the low-level Noise
protocol mechanics; this interface allows the router transport to add
higher-level concerns: probing resistance, replay detection, timestamp
validation, and encrypted termination.

Implementations must be safe for concurrent use across multiple goroutines.

#### type NTCP2Session

```go
type NTCP2Session struct {
	// Shared session core fields: queues, bandwidth tracking, lifecycle, and callbacks.
	// This embeds *SessionCore, so callers can call QueueSendI2NP, ReadNextI2NP, etc. directly.
	*transport.SessionCore
}
```

NTCP2Session represents an active NTCP2 connection session with a remote peer,
managing message queues, bandwidth tracking, and rekeying state.

#### func  NewNTCP2Session

```go
func NewNTCP2Session(conn net.Conn, ctx context.Context, logger *logger.Entry) *NTCP2Session
```
NewNTCP2Session creates a new NTCP2 session and immediately starts background
send/receive workers. Use NewNTCP2SessionDeferred + StartWorkers for cases where
worker startup should be delayed (e.g., dedup via LoadOrStore).

#### func  NewNTCP2SessionDeferred

```go
func NewNTCP2SessionDeferred(conn net.Conn, ctx context.Context, logger *logger.Entry) *NTCP2Session
```
NewNTCP2SessionDeferred creates a new NTCP2 session without starting background
workers. Call StartWorkers() after confirming the session will be used (e.g.,
after winning a LoadOrStore race). This prevents spawning goroutines for
sessions that will be immediately discarded.

#### func (*NTCP2Session) Close

```go
func (s *NTCP2Session) Close() error
```
Close closes the session cleanly. It first waits briefly for the send queue to
drain before sending an encrypted termination block (reason 0 = normal close)
and closing the connection. This gives queued messages a chance to be
transmitted rather than being silently dropped.

#### func (*NTCP2Session) CloseWithReason

```go
func (s *NTCP2Session) CloseWithReason(reason byte) error
```
CloseWithReason closes the session with the specified termination reason code.
If the reason is an AEAD failure (reason 4), the termination block is NOT sent
because the cipher state may be corrupted — instead, only probing-resistance
junk-read is performed on the underlying connection.

For all other reasons, an encrypted termination block is sent through the NTCP2
connection's Noise cipher state (via conn.Write), which ensures it is encrypted
and has a SipHash-obfuscated length prefix like any other data-phase frame. No
plaintext termination blocks are ever sent.

Spec reference: https://geti2p.net/spec/ntcp2#termination

#### func (*NTCP2Session) DetachConn

```go
func (s *NTCP2Session) DetachConn()
```
DetachConn clears the session's reference to the underlying connection,
preventing Close() from closing the socket. This is used when a session loses a
promotion race — the winner owns the socket, so the loser must not close it.
Workers will still stop cleanly when Close() cancels the session context (SM-2
fix).

#### func (*NTCP2Session) GetRekeyStats

```go
func (s *NTCP2Session) GetRekeyStats() (messagesSinceRekey, rekeyCount uint64)
```
GetRekeyStats returns rekeying statistics for this session: messagesSinceRekey
is the count of messages since the last rekey (or session start), rekeyCount is
the total number of successful rekeys performed.

#### func (*NTCP2Session) ReadNextI2NP

```go
func (s *NTCP2Session) ReadNextI2NP() (i2np.Message, error)
```
ReadNextI2NP blocking reads the next fully received I2NP message from this
session. If a critical error occurred during receive processing, it is returned
instead of waiting for more messages.

#### func (*NTCP2Session) SetRouterInfoCallback

```go
func (s *NTCP2Session) SetRouterInfoCallback(cb func([]byte))
```
SetRouterInfoCallback sets a callback for RouterInfo blocks received from the
peer. The callback receives the raw (decompressed) RouterInfo bytes.

#### func (*NTCP2Session) StartWorkers

```go
func (s *NTCP2Session) StartWorkers()
```
StartWorkers launches the background send and receive goroutines. Must be called
exactly once after the session is confirmed as the active session.

#### type NTCP2Transport

```go
type NTCP2Transport struct {
}
```

NTCP2Transport implements the I2P NTCP2 transport protocol, managing listener
setup, session lifecycle, and peer connections.

#### func  NewNTCP2Transport

```go
func NewNTCP2Transport(identity router_info.RouterInfo, config *Config, keystore KeystoreProvider) (*NTCP2Transport, error)
```
NewNTCP2Transport creates and initializes a new NTCP2Transport with the given
router identity, configuration, and keystore provider.

#### func (*NTCP2Transport) Accept

```go
func (t *NTCP2Transport) Accept() (net.Conn, error)
```
Accept accepts an incoming session. The accepted connection is tracked in the
transport's session map so that GetSessionCount() and checkSessionLimit()
accurately reflect both inbound and outbound sessions. A cleanup callback is
registered to remove the tracking entry when the connection is closed.

Handshakes run in per-connection goroutines so that one slow or malicious peer
cannot block the accept loop. The background runner is started lazily on the
first call to Accept().

Spec reference: https://geti2p.net/spec/ntcp2#probing-resistance

#### func (*NTCP2Transport) AcceptedConnPromotionAttempts

```go
func (t *NTCP2Transport) AcceptedConnPromotionAttempts() int32
```
AcceptedConnPromotionAttempts returns the number of times
promoteInboundConnection refused to promote an acceptedConn (X-1 bug detection
metric). This counter should remain at 0 in a correct implementation. A non-zero
value indicates findExistingSession bypassed the acceptedConn guard and
attempted dual socket ownership.

#### func (*NTCP2Transport) Addr

```go
func (t *NTCP2Transport) Addr() net.Addr
```
Addr returns the network address the transport is bound to (plain IP:port). This
returns the unwrapped TCP address for consistency with config.ListenerAddress.
If callers need the wrapped NTCP2 address with router hash metadata, they should
use ExtractNTCP2Addr on the transport's identity instead.

#### func (*NTCP2Transport) Close

```go
func (t *NTCP2Transport) Close() error
```
Close closes the transport cleanly.

#### func (*NTCP2Transport) Compatible

```go
func (t *NTCP2Transport) Compatible(routerInfo router_info.RouterInfo) bool
```
Compatible returns true if a routerInfo is compatible with this transport. It
checks that the RouterInfo has at least one directly dialable NTCP2 address
(i.e., one with a valid host and port), not just any NTCP2 address listing.

#### func (*NTCP2Transport) GetRouterInfoParseFailures

```go
func (t *NTCP2Transport) GetRouterInfoParseFailures() int
```
GetRouterInfoParseFailures returns the total count of RouterInfo parse failures
since transport startup. Incremented each time ReadRouterInfo fails on inbound
msg3. EH-1 fix: Exposes peer RouterInfo quality for monitoring and alerting.
High count indicates peer misconfiguration, network corruption, or attack
attempts.

#### func (*NTCP2Transport) GetRouterInfoStoreFailures

```go
func (t *NTCP2Transport) GetRouterInfoStoreFailures() int
```
GetRouterInfoStoreFailures returns the total count of RouterInfo storage
failures since transport startup. Incremented each time storeRouterInfoInNetDB
fails. E-3 fix: Exposes NetDB health for monitoring and alerting. High count
indicates NetDB unavailability or I/O errors that break OBEP reply routing.

#### func (*NTCP2Transport) GetSession

```go
func (t *NTCP2Transport) GetSession(routerInfo router_info.RouterInfo) (transport.TransportSession, error)
```
GetSession obtains a transport session with a router given its RouterInfo.

#### func (*NTCP2Transport) GetSessionCount

```go
func (t *NTCP2Transport) GetSessionCount() int32
```
GetSessionCount returns the number of active sessions managed by this transport.
Uses an atomic counter for O(1) performance instead of iterating the session
map.

#### func (*NTCP2Transport) GetTotalBandwidth

```go
func (t *NTCP2Transport) GetTotalBandwidth() (totalBytesSent, totalBytesReceived uint64)
```
GetTotalBandwidth returns the total bytes sent and received across all active
sessions. This aggregates bandwidth statistics from all sessions managed by this
transport.

#### func (*NTCP2Transport) GetTransportMetrics

```go
func (t *NTCP2Transport) GetTransportMetrics() TransportMetricsSnapshot
```
GetTransportMetrics returns a point-in-time snapshot of all transport metric
counters for monitoring and diagnostics.

#### func (*NTCP2Transport) Name

```go
func (t *NTCP2Transport) Name() string
```
Name returns the name of this transport.

#### func (*NTCP2Transport) SetIdentity

```go
func (t *NTCP2Transport) SetIdentity(ident router_info.RouterInfo) error
```
SetIdentity sets the router identity for this transport. Protected by identityMu
to prevent races with GetSession/Accept/Compatible.

#### func (*NTCP2Transport) SetPeerConnNotifier

```go
func (t *NTCP2Transport) SetPeerConnNotifier(n transport.PeerConnNotifier)
```
SetPeerConnNotifier wires a connection-outcome notifier into the transport. Call
this after construction to enable PeerTracker feedback. Safe to call
concurrently; the field is only read under t.identityMu or from the goroutine
that dials (no hot-path lock needed because the pointer is set once before any
sessions are created).

#### func (*NTCP2Transport) SetRouterInfoRefresher

```go
func (t *NTCP2Transport) SetRouterInfoRefresher(r transport.RouterInfoRefresher)
```
SetRouterInfoRefresher wires a RouterInfo cache-eviction notifier so that stale
entries are removed from NetDB after a handshake EOF failure.

#### func (*NTCP2Transport) SetRouterInfoStorer

```go
func (t *NTCP2Transport) SetRouterInfoStorer(s transport.RouterInfoStorer)
```
SetRouterInfoStorer wires a NetDB store so that RouterInfos received from
inbound peers during the NTCP2 handshake are persisted locally. This is required
for tunnel-build reply routing to work: the OBEP looks up the originator's
RouterInfo in the NetDB when delivering a ShortTunnelBuildReply.

#### func (*NTCP2Transport) UpdateLocalRouterInfo

```go
func (t *NTCP2Transport) UpdateLocalRouterInfo(ri router_info.RouterInfo)
```
UpdateLocalRouterInfo replaces the stored local RouterInfo with a re-signed
version that includes the transport's address. Safe to call during transport
initialization (before the router starts accepting connections). Unlike
SetIdentity, this does NOT recreate the listener.

#### func (*NTCP2Transport) ValidateSessionCountingInvariant

```go
func (t *NTCP2Transport) ValidateSessionCountingInvariant() int
```
ValidateSessionCountingInvariant checks that sessionCount matches the number of
entries in the sessions map (A-1 fix for SA-2). This invariant must hold:
sessionCount == number of (net.Conn + acceptedConn + *NTCP2Session) entries
Returns the mismatch count (0 = healthy, >0 = accounting bug detected). SA-2
FIX: Added explicit invariant validation to detect session counting leaks.

#### type Options

```go
type Options struct {
	// Version is the NTCP2 protocol version. Currently 0.
	Version uint8

	// PaddingMin is the minimum padding length for data-phase frames.
	// Encoded as a 4.4 fixed-point ratio of the frame payload size.
	PaddingMin float64

	// PaddingMax is the maximum padding length for data-phase frames.
	// Encoded as a 4.4 fixed-point ratio of the frame payload size.
	PaddingMax float64

	// DummyMin is the minimum interval (in seconds) between dummy traffic frames.
	// 0 means no dummy traffic.
	DummyMin uint16

	// DummyMax is the maximum interval (in seconds) between dummy traffic frames.
	// 0 means no dummy traffic.
	DummyMax uint16

	// DelayMin is the minimum intra-message delay (in milliseconds).
	// 0 means no artificial delay.
	DelayMin uint16

	// DelayMax is the maximum intra-message delay (in milliseconds).
	// 0 means no artificial delay.
	DelayMax uint16
}
```

Options represents the NTCP2 options block parameters used for negotiating
padding and traffic shaping between peers.

Spec reference: https://geti2p.net/spec/ntcp2#options-block

The options block is sent in message 3 part 2 (first post-handshake payload from
the initiator) and can be resent during the data phase to renegotiate
parameters.

#### func  DefaultOptions

```go
func DefaultOptions() *Options
```
DefaultOptions returns the default NTCP2 options.

PaddingMax is set to 0.06 (up to 6 % of the frame payload size), matching i2pd's
NTCP2_MAX_PADDING_RATIO (6 %, see i2pd NTCP2.h / NTCP2.cpp CreatePaddingBlock).
PaddingMin remains 0 so that frames with small payloads are not forced to carry
unnecessary overhead, while a non-zero PaddingMax still prevents fingerprinting
via the absence of padding. Padding bytes are generated from crypto/rand by
NewPaddingBlock.

Spec reference: https://geti2p.net/spec/ntcp2#options-block

#### func  ParseOptions

```go
func ParseOptions(data []byte) (*Options, error)
```
ParseOptions parses an options block payload (the data portion, without the
3-byte block header) into an Options struct.

#### func (*Options) Serialize

```go
func (o *Options) Serialize() []byte
```
Serialize encodes the Options into a byte slice suitable for use as the data
portion of an Options block (type 1).

#### type PersistentConfig

```go
type PersistentConfig struct {
}
```

PersistentConfig manages persistent NTCP2 configuration data. It handles loading
and storing the obfuscation IV which must remain consistent across router
restarts to maintain session continuity.

#### func  NewPersistentConfig

```go
func NewPersistentConfig(workingDir string) *PersistentConfig
```
NewPersistentConfig creates a new persistent configuration manager. workingDir
is the router's working directory (typically ~/.go-i2p/config).

#### func (*PersistentConfig) LoadOrGenerateObfuscationIV

```go
func (pc *PersistentConfig) LoadOrGenerateObfuscationIV() ([]byte, error)
```
LoadOrGenerateObfuscationIV loads the obfuscation IV from persistent storage. If
the file doesn't exist, generates a new random IV and saves it. Returns an error
if the file exists but contains invalid data. Returns the 16-byte obfuscation IV
or an error if loading/generation fails.

#### type Rekeyer

```go
type Rekeyer interface {
	// Rekey replaces the session's encryption key using the Noise protocol's
	// rekeying mechanism (encrypt 32 zero bytes with nonce 2^64-1, use first
	// 32 bytes as new key). Both send and receive cipher states should be rekeyed.
	Rekey() error
}
```

Rekeyer is an interface for connections that support cryptographic rekeying. The
go-noise library's NTCP2Conn and NoiseConn both implement this interface (since
go-noise v0.1.4), so rekeying is fully functional for NTCP2 sessions.

Implementations must be safe for concurrent use.

#### type TransportMetricsSnapshot

```go
type TransportMetricsSnapshot struct {
	// StaleSessionsReconciled is the number of times Close() found non-zero
	// stale sessions during final reconciliation. This should always be 0
	// when session accounting is correct (A-3 fix). Non-zero indicates
	// accounting drift bugs (typically from A-1, A-2, X-2, X-3 issues).
	StaleSessionsReconciled uint64

	// QueueSendTimeouts is the number of inbound handshakes that timed out
	// trying to send their connection to the pendingConns queue (TE-2 metric).
	// High values indicate Accept() consumer is slow or blocked.
	QueueSendTimeouts uint64

	// MaxPendingConnsQueueDepth is the maximum observed length of the
	// pendingConns channel (0-64). Used for capacity planning and detecting
	// sustained queue pressure under load.
	MaxPendingConnsQueueDepth uint64

	// PendingConnsQueueFullEvents is the number of times an inbound handshake
	// attempted to send to a full queue (len=64). High values indicate queue
	// capacity should be increased or Accept() throughput optimized.
	PendingConnsQueueFullEvents uint64
}
```

TransportMetricsSnapshot is a point-in-time copy of all transport metric
counters.



ntcp2 

github.com/go-i2p/go-i2p/lib/transport/ntcp2

[go-i2p template file](template.md)
