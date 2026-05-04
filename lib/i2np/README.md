# i2np
--
    import "github.com/go-i2p/go-i2p/lib/i2np"

![i2np.svg](i2np.svg)

Package i2np implements the I2P Network Protocol (I2NP) for router-to-router
communication.

# Message Types

I2NP defines message types for:

    - Network database operations (DatabaseStore, DatabaseLookup)
    - Tunnel building (ShortTunnelBuild, VariableTunnelBuild)
    - Data delivery (TunnelData, Data, DeliveryStatus)
    - Garlic encryption (end-to-end encrypted message bundles)

# Message Structure

All I2NP messages consist of:

    - Header: type, ID, expiration, size, checksum
    - Payload: type-specific data

# Cryptography

I2NP uses modern cryptography:

    - ECIES-X25519-AEAD-Ratchet for garlic encryption
    - ChaCha20-Poly1305 for tunnel build records
    - ElGamal/AES (legacy, compatibility only)

See github.com/go-i2p/crypto for cryptographic primitives.

# Usage Example

    // Create DatabaseStore message
    ds := i2np.NewDatabaseStore(hash, data, i2np.DatabaseStoreTypeRouterInfo)

    // Serialize for transmission
    payload, err := ds.MarshalBinary()
    if err != nil {
        log.Printf("Failed to serialize message: %v", err)
    }

# Database Operations

DatabaseStore supports RouterInfo, LeaseSet, and LeaseSet2:

    - Type field bits 3-0 specify entry type
    - Validation ensures hash matches content
    - Replies are sent via DeliveryStatus messages

DatabaseLookup queries the network database:

    - Supports iterative and recursive lookups
    - Returns DatabaseStore or DatabaseSearchReply
    - Floodfill routers handle lookup requests

# Tunnel Building

Tunnel build messages are encrypted per-hop:

    - Build request records encrypted to each hop
    - Build reply records return encrypted status
    - Short format for 1-8 hop tunnels
    - Variable format for longer tunnels (deprecated)

See lib/tunnel for tunnel management and building.

## Usage

```go
const (
	I2NPMessageTypeDatabaseStore            = 1
	I2NPMessageTypeDatabaseLookup           = 2
	I2NPMessageTypeDatabaseSearchReply      = 3
	I2NPMessageTypeDeliveryStatus           = 10
	I2NPMessageTypeGarlic                   = 11
	I2NPMessageTypeTunnelData               = 18
	I2NPMessageTypeTunnelGateway            = 19
	I2NPMessageTypeData                     = 20
	I2NPMessageTypeTunnelBuild              = 21
	I2NPMessageTypeTunnelBuildReply         = 22
	I2NPMessageTypeVariableTunnelBuild      = 23
	I2NPMessageTypeVariableTunnelBuildReply = 24
	I2NPMessageTypeShortTunnelBuild         = 25
	I2NPMessageTypeShortTunnelBuildReply    = 26
)
```
I2NP Message Type Constants Moved from: header.go

```go
const (
	StandardBuildRecordSize          = 528 // Encrypted on-wire size for standard/variable tunnel build records
	ShortBuildRecordSize             = 218 // Encrypted on-wire size for short tunnel build records (ECIES)
	StandardBuildRecordCleartextLen  = 222 // Cleartext length for standard ElGamal build request records
	ElGamalBuildRecordCleartextLen   = 222 // Cleartext length for ElGamal build request records (same as StandardBuildRecordCleartextLen)
	ECIESLongBuildRecordCleartextLen = 464 // Cleartext length for ECIES-X25519 long-form build request records
	ShortBuildRecordCleartextLen     = 154 // Cleartext length for short ECIES build request records (218 - 64)
	ShortRecordHeaderSize            = 64  // toPeer(16) + ephemeralKey(32) + MAC(16)
	DefaultExpirationSeconds         = 480 // Default tunnel expiration: 8 minutes
)
```
Build record size constants per the I2P specification. Standard (ElGamal)
records are 528 bytes on the wire; cleartext is 222 bytes. ECIES-X25519
long-form records are also 528 bytes on the wire; cleartext is 464 bytes. Short
(ECIES) records are 218 bytes on the wire (added in 0.9.49). Standard cleartext
(before encryption) is 222 bytes. Short cleartext (ECIES short) is 154 bytes
(218 - 16 toPeer - 32 ephKey - 16 MAC).

```go
const (
	// DatabaseLookupFlagDirect means send reply directly (bit 0 = 0)
	DatabaseLookupFlagDirect byte = 0x00
	// DatabaseLookupFlagTunnel means send reply to a tunnel (bit 0 = 1)
	DatabaseLookupFlagTunnel byte = 0x01
	// DatabaseLookupFlagEncryption means encrypt reply (bit 1 = 1)
	DatabaseLookupFlagEncryption byte = 0x02
	// DatabaseLookupFlagTypeNormal is a normal lookup (bits 3-2 = 00)
	DatabaseLookupFlagTypeNormal byte = 0x00
	// DatabaseLookupFlagTypeLS is a LeaseSet lookup (bits 3-2 = 01)
	DatabaseLookupFlagTypeLS byte = 0x04
	// DatabaseLookupFlagTypeRI is a RouterInfo lookup (bits 3-2 = 10)
	DatabaseLookupFlagTypeRI byte = 0x08
	// DatabaseLookupFlagTypeExploration is an exploration lookup (bits 3-2 = 11)
	DatabaseLookupFlagTypeExploration byte = 0x0C
	// DatabaseLookupFlagECIES means use ECIES encryption for reply (bit 4 = 1)
	DatabaseLookupFlagECIES byte = 0x10
)
```
DatabaseLookup flag constants for constructing lookup messages

```go
const (
	// DatabaseStoreTypeRouterInfo indicates a RouterInfo entry
	DatabaseStoreTypeRouterInfo = 0
	// DatabaseStoreTypeLeaseSet indicates original LeaseSet (deprecated)
	DatabaseStoreTypeLeaseSet = 1
	// DatabaseStoreTypeLeaseSet2 indicates LeaseSet2 (standard as of 0.9.38+)
	DatabaseStoreTypeLeaseSet2 = 3
	// DatabaseStoreTypeEncryptedLeaseSet indicates EncryptedLeaseSet (0.9.39+), handled by lib/netdb
	DatabaseStoreTypeEncryptedLeaseSet = 5
	// DatabaseStoreTypeMetaLeaseSet indicates MetaLeaseSet (0.9.40+), handled by lib/netdb
	DatabaseStoreTypeMetaLeaseSet = 7
)
```
DatabaseStore type constants (bits 3-0 of type field)

```go
const (
	// MaxRouterInfoSize is the maximum size for a RouterInfo (gzip-compressed)
	// Real RouterInfos are typically 2-6KB; 64KB provides large safety margin
	MaxRouterInfoSize = 65536 // 64KB

	// MaxLeaseSetSize is the maximum size for any LeaseSet type
	// LeaseSets are typically <2KB; 32KB provides large safety margin
	MaxLeaseSetSize = 32768 // 32KB
)
```
Size limits for DatabaseStore data payloads

```go
const (
	ExploratoryReplyStageInboundI2NPReceived    = "inbound_i2np_received"
	ExploratoryReplyStageTunnelGatewayParsed    = "tunnel_gateway_inner_parsed"
	ExploratoryReplyStageGarlicDecryptAttempt   = "garlic_decrypt_attempted"
	ExploratoryReplyStageGarlicDecryptSuccess   = "garlic_decrypt_succeeded"
	ExploratoryReplyStageShortReplyDispatched   = "short_build_reply_dispatched"
	ExploratoryReplyStageShortReplyCorrelated   = "short_build_reply_correlated"
	ExploratoryReplyStageShortReplyUncorrelated = "short_build_reply_uncorrelated"
)
```

```go
const (
	TunnelBuildReplySuccess   = 0x00 // Tunnel hop accepted the request
	TunnelBuildReplyReject    = 0x01 // General rejection
	TunnelBuildReplyOverload  = 0x02 // Router is overloaded
	TunnelBuildReplyBandwidth = 0x03 // Insufficient bandwidth
	TunnelBuildReplyInvalid   = 0x04 // Invalid request data
	TunnelBuildReplyExpired   = 0x05 // Request has expired
)
```
TunnelBuildReply constants for processing responses

```go
const DefaultExpirationTolerance = 5 * 60 // 5 minutes in seconds

```
DefaultExpirationTolerance is the default expiration tolerance for clock skew (5
minutes into the past). This allows for reasonable clock differences between I2P
routers while still rejecting clearly expired messages.

```go
const MaxI2NPStandardPayload = 65535
```
MaxI2NPStandardPayload is the maximum payload size for I2NP messages using the
standard 16-byte header. The size field is 2 bytes (uint16), so the maximum
representable value is 65535.

```go
const ShortI2NPHeaderSize = 9
```
ShortI2NPHeaderSize is the size of the short I2NP header used in NTCP2 blocks.
Format: type(1) + msgID(4) + shortExpiration(4) = 9 bytes

```go
var (
	ErrI2NPNotEnoughData                = errors.New("not enough i2np header data")
	ErrBuildRequestRecordNotEnoughData  = errors.New("not enough i2np build request record data")
	ErrBuildResponseRecordNotEnoughData = errors.New("not enough i2np build response record data")
	ErrDatabaseLookupNotEnoughData      = errors.New("not enough i2np database lookup data")
	ErrDatabaseSearchReplyNotEnoughData = errors.New("not enough i2np database search reply data")
	ErrDatabaseLookupInvalidSize        = errors.New("database lookup excluded peers size exceeds protocol limit")
	ErrI2NPMessageExpired               = errors.New("i2np message has expired")
)
```
I2NP Error Constants These use errors.New (not oops.Errorf) so callers can match
them with errors.Is(). Moved from: header.go, build_request_record.go,
build_response_record.go, database_lookup.go

#### func  CheckMessageExpiration

```go
func CheckMessageExpiration(msg I2NPMessage) error
```
CheckMessageExpiration is a convenience function that validates message
expiration using the default validator settings (5 minute tolerance).

#### func  DecryptSTBMRecordReturningChainingKey

```go
func DecryptSTBMRecordReturningChainingKey(encrypted [218]byte, privateKey []byte) ([32]byte, error)
```
DecryptSTBMRecordReturningChainingKey performs the same Noise_N AEAD-decrypt as
DecryptShortBuildRequestRecordNoise but returns the post-decrypt Noise chaining
key instead of the cleartext record. This chaining key is what the hop needs to
derive its replyKey (via DeriveSTBMReplyKey) so it can:

    1. Peel its own layer off all subsequent records via ChaCha20 stream.
    2. AEAD-decrypt the build response record addressed to it.

Used by the test harness to validate the sender-side chained ChaCha20 layer
obfuscation, and intended for use by the real receive path once we wire up
inbound STBM handling.

#### func  DecryptSTBMRecordReturningChainingKeyAndHash

```go
func DecryptSTBMRecordReturningChainingKeyAndHash(encrypted [218]byte, privateKey []byte) ([32]byte, [32]byte, error)
```
DecryptSTBMRecordReturningChainingKeyAndHash performs the same Noise_N
AEAD-decrypt as DecryptSTBMRecordReturningChainingKey but also returns the
post-decrypt Noise handshake hash (m_H). The transit hop needs m_H as AEAD
associated data when constructing its ShortTunnelBuildReply record.

#### func  DeriveSTBMGarlicKey

```go
func DeriveSTBMGarlicKey(noiseHash [32]byte) ([32]byte, [8]byte, error)
```
DeriveSTBMGarlicKey derives the one-time symmetric garlic key used by the OBEP
to wrap a ShortTunnelBuildReply in a garlic message (type 11).

The key material is derived from the STBM Noise transcript hash using:

    HKDF(noiseHash, "", "AttachLayerEncryption") -> 32 bytes

Slicing follows the one-time garlic decryptor contract in go-noise:

    - key = keyMaterial[0:32]
    - tag = keyMaterial[24:32]

#### func  DeriveSTBMGarlicKeyFromChainingKey

```go
func DeriveSTBMGarlicKeyFromChainingKey(chainingKey [32]byte) ([32]byte, [8]byte, error)
```
DeriveSTBMGarlicKeyFromChainingKey derives the one-time symmetric garlic key/tag
from the post-reply HKDF chaining key as a compatibility fallback.

Some implementations derive the attach-layer key from the Noise transcript hash,
while others derive it from the evolving HKDF chaining key used for
SMTunnelReplyKey and subsequent per-hop keys. Registering both derivations
allows inbound decrypt to match either sender behavior.

#### func  DeriveSTBMLegacyGarlicKeyFromChainingKey

```go
func DeriveSTBMLegacyGarlicKeyFromChainingKey(chainingKey [32]byte) ([32]byte, [8]byte, error)
```
DeriveSTBMLegacyGarlicKeyFromChainingKey is retained for compatibility. It wraps
DeriveSTBMOBEPGarlicKeyAndTag with the old name.

Deprecated: use DeriveSTBMOBEPGarlicKeyAndTag directly.

#### func  DeriveSTBMOBEPGarlicKeyAndTag

```go
func DeriveSTBMOBEPGarlicKeyAndTag(postReplyCK [32]byte) ([32]byte, [8]byte, error)
```
DeriveSTBMOBEPGarlicKeyAndTag derives the one-time garlic key and tag that the
OBEP uses to wrap its ShortTunnelBuildReply, matching i2pd exactly.

Input: postReplyCK — the Noise chaining key after "SMTunnelReplyKey" HKDF step.

Derivation (from TransitTunnel.cpp::HandleShortTransitTunnelBuildMsg):

    HKDF64(postReplyCK, "SMTunnelLayerKey") -> ck1 || layerKey
    HKDF64(ck1, "TunnelLayerIVKey")         -> ck2 || ivKey
    HKDF64(ck2, "RGarlicKeyAndTag")          -> ck3 || garlicEncKey
      TAG = ck3[0:8]         (first 8 bytes of new chaining key)
      KEY = garlicEncKey     (output key, 32 bytes)

#### func  DeriveSTBMReplyKey

```go
func DeriveSTBMReplyKey(chainingKey [32]byte) ([32]byte, [32]byte, error)
```
DeriveSTBMReplyKey derives the per-hop ChaCha20 reply key from a hop's
post-encryption Noise chaining key. This key is used both for the chained
stream-cipher layer obfuscation that the sender applies to records following
this hop, and for AEAD-decrypting that hop's build response record.

The derivation matches i2pd:

    HKDF-SHA256(salt=ck, ikm="", info="SMTunnelReplyKey", out=64)
    -> new_ck (bytes 0:32) || replyKey (bytes 32:64)

Returns both the replyKey and the new chaining key so callers can continue the
HKDF chain (e.g. for layer/IV/garlic key derivation).

#### func  EncryptBuildRequestRecord

```go
func EncryptBuildRequestRecord(record BuildRequestRecord, recipientRouterInfo router_info.RouterInfo) ([528]byte, error)
```
EncryptBuildRequestRecord encrypts a BuildRequestRecord using ECIES-X25519-AEAD.

This adapter extracts the recipient's public key and identity hash from
RouterInfo, serializes the BuildRequestRecord, then delegates ECIES encryption
to go-noise/ratchet.

#### func  EncryptGarlicWithBuilder

```go
func EncryptGarlicWithBuilder(
	sm *GarlicSessionManager,
	builder *GarlicBuilder,
	destinationHash common.Hash,
	destinationPubKey [32]byte,
) ([]byte, error)
```
EncryptGarlicWithBuilder is a convenience function that builds and encrypts a
garlic message. This combines GarlicBuilder.BuildAndSerialize with
GarlicSessionManager.EncryptGarlicMessage.

#### func  EncryptShortBuildRequestRecord

```go
func EncryptShortBuildRequestRecord(record BuildRequestRecord, recipientRouterInfo router_info.RouterInfo) ([218]byte, error)
```
EncryptShortBuildRequestRecord encrypts a BuildRequestRecord into the 218-byte
STBM (Short Tunnel Build Message) wire format defined by the I2P
tunnel-creation-ECIES specification (proposal 152).

Wire layout (218 bytes):

    [  0: 16] toPeer        - first 16 bytes of recipient identity hash
    [ 16: 48] ephemeralKey  - sender's ephemeral X25519 public key
    [ 48:202] ciphertext    - ChaCha20-Poly1305(key=k, nonce=0, AD=h)
    [202:218] poly1305 tag  - included in the ciphertext output above

The crypto follows the Noise_N_25519_ChaChaPoly_SHA256 pattern with the sender
as the initiator and the hop's static key as the responder static. Per i2pd's
CreateBuildRequestRecord / RouterContext::DecryptECIESTunnelBuildRecord the
per-record transcript is:

    state = InitNoiseN(recipient_static_pub)
    MixHash(eph_pub)
    MixKey(X25519(eph_priv, recipient_static))
    ciphertext = AEAD_ChaCha20Poly1305(key=ck[32:64], nonce=0, ad=h, plaintext)
    MixHash(ciphertext)

#### func  EncryptShortBuildRequestRecordWithChain

```go
func EncryptShortBuildRequestRecordWithChain(record BuildRequestRecord, recipientRouterInfo router_info.RouterInfo) ([218]byte, [32]byte, [32]byte, error)
```
EncryptShortBuildRequestRecordWithChain is the same as
EncryptShortBuildRequestRecord but also returns the post-encryption Noise
chaining key (32 bytes). The caller needs this chaining key to derive the
per-hop reply/layer/IV keys via i2p HKDF (info="SMTunnelReplyKey" etc.) — the
reply key in particular is required to apply the chained ChaCha20 stream-cipher
layer obfuscation that the I2P tunnel build protocol mandates over records
following each hop.

See i2pd ShortECIESTunnelHopConfig::CreateBuildRequestRecord for the full
per-hop key derivation chain. Also returns the Noise transcript hash (m_H) after
EncryptAndHash, which the initiator stores and later uses as AEAD associated
data when decrypting each hop's ShortTunnelBuildReply record.

#### func  ExtractIdentityHashPrefix

```go
func ExtractIdentityHashPrefix(encrypted [528]byte) common.Hash
```
ExtractIdentityHashPrefix returns the first 16 bytes of an encrypted record as a
common.Hash (remaining bytes zero).

#### func  IsMessageExpired

```go
func IsMessageExpired(msg I2NPMessage) bool
```
IsMessageExpired is a convenience function that checks if a message is expired
using the default validator settings (5 minute tolerance).

#### func  MarshalSecondGenTransportHeader

```go
func MarshalSecondGenTransportHeader(header I2NPSecondGenTransportHeader) ([]byte, error)
```
MarshalSecondGenTransportHeader serializes an I2NP NTCP2/SSU2 header into a
9-byte buffer: type (1 byte) + msg_id (4 bytes, big-endian) + short_expiration
(4 bytes, seconds since epoch, big-endian). This is the inverse of
ReadI2NPSecondGenTransportHeader.

#### func  ReadI2NPNTCPData

```go
func ReadI2NPNTCPData(data []byte, size int) ([]byte, error)
```
ReadI2NPNTCPData reads the message data from NTCP payload

#### func  ReadI2NPNTCPMessageChecksum

```go
func ReadI2NPNTCPMessageChecksum(data []byte) (int, error)
```
ReadI2NPNTCPMessageChecksum reads the message checksum from NTCP data

#### func  ReadI2NPNTCPMessageExpiration

```go
func ReadI2NPNTCPMessageExpiration(data []byte) (common.Date, error)
```
ReadI2NPNTCPMessageExpiration reads the expiration from NTCP data

#### func  ReadI2NPNTCPMessageID

```go
func ReadI2NPNTCPMessageID(data []byte) (int, error)
```
ReadI2NPNTCPMessageID reads the message ID from NTCP data

#### func  ReadI2NPNTCPMessageSize

```go
func ReadI2NPNTCPMessageSize(data []byte) (int, error)
```
ReadI2NPNTCPMessageSize reads the message size from NTCP data

#### func  ReadI2NPSSUMessageExpiration

```go
func ReadI2NPSSUMessageExpiration(data []byte) (common.Date, error)
```
ReadI2NPSSUMessageExpiration reads the expiration from SSU data Note: Short
expiration is a 4-byte unsigned integer that will wrap around on February 7,
2106. As of that date, an offset must be added to get the correct time. See I2NP
specification for details.

#### func  ReadI2NPType

```go
func ReadI2NPType(data []byte) (int, error)
```
ReadI2NPType reads the I2NP message type from data

#### func  RecordExploratoryReplyStage

```go
func RecordExploratoryReplyStage(stage string)
```
RecordExploratoryReplyStage increments a stage counter used to audit the
exploratory reply funnel from transport ingress through reply correlation.

#### func  ResetDefaultExpirationValidator

```go
func ResetDefaultExpirationValidator()
```
ResetDefaultExpirationValidator resets to a fresh default validator.

#### func  SetDefaultExpirationValidator

```go
func SetDefaultExpirationValidator(v *ExpirationValidator)
```
SetDefaultExpirationValidator replaces the default validator. This is primarily
useful for testing.

#### func  SnapshotExploratoryReplyStages

```go
func SnapshotExploratoryReplyStages() map[string]uint64
```
SnapshotExploratoryReplyStages returns current exploratory reply funnel
counters.

#### func  VerifyIdentityHash

```go
func VerifyIdentityHash(encrypted [528]byte, ourRouterInfo router_info.RouterInfo) bool
```
VerifyIdentityHash checks if an encrypted BuildRequestRecord is intended for us.
This adapter extracts the identity hash from RouterInfo, then delegates the byte
comparison to go-noise/ratchet.

#### type BaseI2NPMessage

```go
type BaseI2NPMessage struct {
}
```

BaseI2NPMessage provides a basic implementation of I2NPMessage

#### func  NewBaseI2NPMessage

```go
func NewBaseI2NPMessage(msgType int) *BaseI2NPMessage
```
NewBaseI2NPMessage creates a new base I2NP message. If crypto/rand fails to
generate a message ID, falls back to a time-based ID and logs a critical
warning. This avoids panicking in library code while still providing a usable
(if less random) ID.

#### func  WrapInGarlicMessage

```go
func WrapInGarlicMessage(encryptedGarlic []byte) (*BaseI2NPMessage, error)
```
WrapInGarlicMessage creates a Garlic I2NP message from encrypted garlic data.
This wraps the encrypted garlic in the proper I2NP message structure.

#### func (*BaseI2NPMessage) Expiration

```go
func (m *BaseI2NPMessage) Expiration() time.Time
```
Expiration returns the expiration time

#### func (*BaseI2NPMessage) GetData

```go
func (m *BaseI2NPMessage) GetData() []byte
```
GetData returns the message data

#### func (*BaseI2NPMessage) MarshalBinary

```go
func (m *BaseI2NPMessage) MarshalBinary() ([]byte, error)
```
MarshalBinary serializes the I2NP message according to NTCP format. Returns an
error if the payload exceeds 65535 bytes (the 2-byte size field limit).

#### func (*BaseI2NPMessage) MarshalShortI2NP

```go
func (m *BaseI2NPMessage) MarshalShortI2NP() ([]byte, error)
```
MarshalShortI2NP serializes the I2NP message using the 9-byte short header
format used in NTCP2 block type 3 (I2NP message blocks).

Short header format:

    - Type (1 byte)
    - Message ID (4 bytes, big-endian)
    - Short Expiration (4 bytes, big-endian, seconds since epoch)

The payload follows the header. No checksum is included (AEAD provides
integrity).

#### func (*BaseI2NPMessage) MessageID

```go
func (m *BaseI2NPMessage) MessageID() int
```
MessageID returns the message ID

#### func (*BaseI2NPMessage) SetData

```go
func (m *BaseI2NPMessage) SetData(data []byte)
```
SetData sets the message data

#### func (*BaseI2NPMessage) SetExpiration

```go
func (m *BaseI2NPMessage) SetExpiration(exp time.Time)
```
SetExpiration sets the expiration time

#### func (*BaseI2NPMessage) SetMessageID

```go
func (m *BaseI2NPMessage) SetMessageID(id int)
```
SetMessageID sets the message ID

#### func (*BaseI2NPMessage) Type

```go
func (m *BaseI2NPMessage) Type() int
```
Type returns the message type

#### func (*BaseI2NPMessage) UnmarshalBinary

```go
func (m *BaseI2NPMessage) UnmarshalBinary(data []byte) error
```
UnmarshalBinary deserializes the I2NP message from NTCP format

#### func (*BaseI2NPMessage) UnmarshalShortI2NP

```go
func (m *BaseI2NPMessage) UnmarshalShortI2NP(data []byte) error
```
UnmarshalShortI2NP deserializes an I2NP message from the 9-byte short header
format used in NTCP2 block type 3.

#### type BuildRecordCrypto

```go
type BuildRecordCrypto struct {
}
```

BuildRecordCrypto provides encryption/decryption for tunnel build records. This
is a thin adapter that delegates to go-noise/ratchet.BuildReplyCrypto while
handling I2P-specific type conversions (SessionKey, BuildResponseRecord,
BuildRequestRecord, RouterInfo).

#### func  NewBuildRecordCrypto

```go
func NewBuildRecordCrypto() *BuildRecordCrypto
```
NewBuildRecordCrypto creates a new build record crypto handler.

#### func (*BuildRecordCrypto) DecryptRecord

```go
func (c *BuildRecordCrypto) DecryptRecord(encrypted [528]byte, privateKey []byte) (BuildRequestRecord, error)
```
DecryptRecord decrypts an encrypted BuildRequestRecord using ECIES-X25519-AEAD.
This method satisfies the BuildRequestDecryptor interface, delegating to the
package-level DecryptBuildRequestRecord function.

#### func (*BuildRecordCrypto) DecryptReplyRecord

```go
func (c *BuildRecordCrypto) DecryptReplyRecord(
	encryptedData []byte,
	replyKey session_key.SessionKey,
	replyIV [16]byte,
) (BuildResponseRecord, error)
```
DecryptReplyRecord decrypts an encrypted BuildResponseRecord. Delegates to
go-noise/ratchet for decryption, then parses and verifies the result using
I2P-specific types.

#### func (*BuildRecordCrypto) EncryptReplyRecord

```go
func (c *BuildRecordCrypto) EncryptReplyRecord(
	record BuildResponseRecord,
	replyKey session_key.SessionKey,
	replyIV [16]byte,
) ([]byte, error)
```
EncryptReplyRecord encrypts a BuildResponseRecord using the reply key and IV.
Serializes the record to bytes, converts SessionKey to [32]byte, then delegates
to go-noise/ratchet.

#### type BuildRecordReader

```go
type BuildRecordReader interface {
	ReadBuildRequestRecord(data []byte) (BuildRequestRecord, error)
}
```

BuildRecordReader represents types that can parse build request records

#### type BuildRecordWriter

```go
type BuildRecordWriter interface {
	WriteBuildResponseRecord() ([]byte, error)
}
```

BuildRecordWriter represents types that can write build response records

#### type BuildReplyForwarder

```go
type BuildReplyForwarder interface {
	// ForwardBuildReplyToRouter forwards a build reply message directly to a router.
	// This is used when the next hop is a router that we have a direct transport connection to.
	//
	// Parameters:
	// - routerHash: The hash of the router to forward to (NextIdent from BuildRequestRecord)
	// - messageID: The I2NP message ID for the reply
	// - encryptedRecords: The complete encrypted build reply records
	// - isShortBuild: Whether this is a Short Tunnel Build Message (STBM) format
	ForwardBuildReplyToRouter(routerHash common.Hash, messageID int, encryptedRecords []byte, isShortBuild bool) error

	// ForwardBuildReplyThroughTunnel forwards a build reply message through a reply tunnel.
	// This is used when the build request specifies a reply tunnel for the response.
	//
	// Parameters:
	// - gatewayHash: The hash of the tunnel gateway router
	// - tunnelID: The tunnel ID to use for forwarding
	// - messageID: The I2NP message ID for the reply
	// - encryptedRecords: The complete encrypted build reply records
	// - isShortBuild: Whether this is a Short Tunnel Build Message (STBM) format
	ForwardBuildReplyThroughTunnel(gatewayHash common.Hash, tunnelID tunnel.TunnelID, messageID int, encryptedRecords []byte, isShortBuild bool) error
}
```

BuildReplyForwarder defines the interface for forwarding tunnel build replies.
This interface enables the MessageProcessor to send build response messages to
the next hop in the tunnel or back through the reply tunnel.

#### type BuildRequestDecryptor

```go
type BuildRequestDecryptor interface {
	// DecryptRecord decrypts a 528-byte encrypted build request record
	// using the router's static private key and returns the parsed record.
	DecryptRecord(encrypted [528]byte, privateKey []byte) (BuildRequestRecord, error)
}
```

BuildRequestDecryptor decrypts inbound tunnel build request records. When
processing build requests from the network, encrypted records destined for this
router must be decrypted before parsing. This interface abstracts the
ECIES-X25519-AEAD decryption so that test mocks can be substituted.

#### type BuildRequestRecord

```go
type BuildRequestRecord struct {
	ReceiveTunnel tunnel.TunnelID
	OurIdent      common.Hash
	NextTunnel    tunnel.TunnelID
	NextIdent     common.Hash
	LayerKey      session_key.SessionKey
	IVKey         session_key.SessionKey
	ReplyKey      session_key.SessionKey
	ReplyIV       [16]byte
	Flag          int
	RequestTime   time.Time
	SendMessageID int
	Padding       [29]byte
}
```

BuildRequestRecord represents a single record in a tunnel build request,
containing the cryptographic keys and routing information needed to construct
one hop in a tunnel.

#### func  DecryptBuildRequestRecord

```go
func DecryptBuildRequestRecord(encrypted [528]byte, privateKey []byte) (BuildRequestRecord, error)
```
DecryptBuildRequestRecord decrypts an encrypted BuildRequestRecord using
ECIES-X25519-AEAD.

This adapter delegates ECIES decryption to go-noise/ratchet, then parses the
resulting 222-byte cleartext into a BuildRequestRecord.

#### func  DecryptShortBuildRequestRecord

```go
func DecryptShortBuildRequestRecord(encrypted [218]byte, privateKey []byte) (BuildRequestRecord, error)
```
DecryptShortBuildRequestRecord decrypts a 218-byte STBM (Short Tunnel Build
Message) record using the Noise_N_25519_ChaChaPoly_SHA256 transcript specified
by I2P proposal 152. See DecryptShortBuildRequestRecordNoise in
build_record_crypto_short.go for the full transcript description.

STBM on-wire layout (218 bytes):

    - Bytes   0-15:  toPeer (first 16 bytes of recipient identity hash)
    - Bytes  16-47:  sender ephemeral X25519 public key
    - Bytes  48-201: ChaCha20-Poly1305 ciphertext (154 bytes of cleartext)
    - Bytes 202-217: Poly1305 MAC tag (16 bytes)

#### func  DecryptShortBuildRequestRecordNoise

```go
func DecryptShortBuildRequestRecordNoise(encrypted [218]byte, privateKey []byte) (BuildRequestRecord, error)
```
DecryptShortBuildRequestRecordNoise is the inverse of
EncryptShortBuildRequestRecord: it decrypts a 218-byte STBM record using the
Noise_N_25519_ChaChaPoly_SHA256 transcript described above. The caller supplies
the local router's static X25519 private key (which corresponds to the public
key the sender used as the responder static).

Returns the parsed cleartext BuildRequestRecord on success.

#### func  ReadBuildRequestRecord

```go
func ReadBuildRequestRecord(data []byte) (BuildRequestRecord, error)
```
ReadBuildRequestRecord parses a BuildRequestRecord from the provided byte slice.

#### func  ReadShortBuildRequestRecord

```go
func ReadShortBuildRequestRecord(data []byte) (BuildRequestRecord, error)
```
ReadShortBuildRequestRecord parses the 154-byte STBM cleartext payload into a
BuildRequestRecord. The STBM cleartext uses a compact layout: cryptographic keys
(LayerKey, IVKey, ReplyKey) are absent and must be derived via HKDF by the
caller.

Cleartext layout (154 bytes):

    [0:4]    receiveTunnel (4 bytes)
    [4:8]    nextTunnel    (4 bytes)
    [8:40]   next_ident     (32 bytes)
    [40]     flag           (1 byte)
    [44:48]  request_time   (4 bytes, minutes since epoch)
    [52:56]  sendMessageID (4 bytes)

#### func (*BuildRequestRecord) Bytes

```go
func (b *BuildRequestRecord) Bytes() []byte
```
Bytes serializes the BuildRequestRecord to its cleartext 222-byte
representation. The caller is responsible for encrypting this data.

#### func (*BuildRequestRecord) GetIVKey

```go
func (b *BuildRequestRecord) GetIVKey() session_key.SessionKey
```
GetIVKey returns the IV session key

#### func (*BuildRequestRecord) GetLayerKey

```go
func (b *BuildRequestRecord) GetLayerKey() session_key.SessionKey
```
GetLayerKey returns the layer session key

#### func (*BuildRequestRecord) GetNextIdent

```go
func (b *BuildRequestRecord) GetNextIdent() common.Hash
```
GetNextIdent returns the next identity hash

#### func (*BuildRequestRecord) GetNextTunnel

```go
func (b *BuildRequestRecord) GetNextTunnel() tunnel.TunnelID
```
GetNextTunnel returns the next tunnel ID

#### func (*BuildRequestRecord) GetOurIdent

```go
func (b *BuildRequestRecord) GetOurIdent() common.Hash
```
GetOurIdent returns our identity hash

#### func (*BuildRequestRecord) GetReceiveTunnel

```go
func (b *BuildRequestRecord) GetReceiveTunnel() tunnel.TunnelID
```
GetReceiveTunnel returns the receive tunnel ID

#### func (*BuildRequestRecord) GetReplyKey

```go
func (b *BuildRequestRecord) GetReplyKey() session_key.SessionKey
```
GetReplyKey returns the reply session key

#### func (*BuildRequestRecord) ShortBytes

```go
func (b *BuildRequestRecord) ShortBytes() []byte
```
ShortBytes serializes the BuildRequestRecord to the 218-byte ECIES short record
wire format as defined in the I2P specification (proposal 157, since 0.9.49).

Short build records use a more compact layout than the standard 222-byte ElGamal
cleartext. Keys (LayerKey, IVKey, ReplyKey) are derived via HKDF rather than
transmitted explicitly, saving significant space.

On-wire format (218 bytes total):

    toPeer:         16 bytes - truncated SHA-256 of peer's RouterIdentity
    ephemeral key:  32 bytes - X25519 public key (placeholder pre-encryption)
    encrypted data: 170 bytes - AEAD(cleartext 154 bytes) + 16-byte MAC

Cleartext payload layout (154 bytes):

    receiveTunnel:  4 bytes [0:4]
    nextTunnel:     4 bytes [4:8]
    next_ident:     32 bytes [8:40]
    flag:            1 byte  [40] + 2 unused bytes [41:43]
    layer_enc_type:  1 byte  [43]
    request_time:    4 bytes [44:48] (minutes since epoch)
    expiration:      4 bytes [48:52] (seconds)
    sendMessageID: 4 bytes [52:56]
    options/padding: 98 bytes [56:154]

The caller is responsible for applying ECIES encryption.

#### type BuildRequestRecordElGamal

```go
type BuildRequestRecordElGamal [528]byte
```


#### type BuildRequestRecordElGamalAES

```go
type BuildRequestRecordElGamalAES [528]byte
```


#### type BuildResponseRecord

```go
type BuildResponseRecord struct {
	Hash       common.Hash
	RandomData [495]byte
	Reply      byte
}
```

BuildResponseRecord struct contains a response to BuildRequestRecord concerning
the creation of one hop in the tunnel

BuildResponseRecord represents a single response record in a tunnel build reply,
indicating whether a hop accepted or rejected the tunnel build request.

#### func  CreateBuildResponseRecord

```go
func CreateBuildResponseRecord(reply byte, randomData [495]byte) BuildResponseRecord
```
CreateBuildResponseRecord creates a new BuildResponseRecord with proper hash.

Parameters:

    - reply: Status code (0=accept, non-zero=reject reason)
    - randomData: 495 bytes of random data (should be cryptographically random)

Returns a BuildResponseRecord with the SHA-256 hash properly computed.

#### func  ReadBuildResponseRecord

```go
func ReadBuildResponseRecord(data []byte) (BuildResponseRecord, error)
```
ReadBuildResponseRecord parses a BuildResponseRecord from the provided byte
slice.

#### type BuildResponseRecordELGamal

```go
type BuildResponseRecordELGamal [528]byte
```


#### type BuildResponseRecordELGamalAES

```go
type BuildResponseRecordELGamalAES [528]byte
```


#### type Data

```go
type Data struct {
	Length int
	Data   []byte
}
```

Data represents an I2NP Data message used to encapsulate an arbitrary payload
for delivery through a tunnel.

#### type DataCarrier

```go
type DataCarrier interface {
	GetData() []byte
}
```

DataCarrier represents messages that expose raw message data via GetData(). All
typed I2NP messages embed BaseI2NPMessage and satisfy this interface. Use this
for type-safe data extraction instead of asserting *BaseI2NPMessage directly,
which fails for typed message structs.

#### type DataMessage

```go
type DataMessage struct {
	*BaseI2NPMessage
	PayloadLength int
	Payload       []byte
}
```

DataMessage represents an I2NP Data message Moved from: messages.go

#### func  NewDataMessage

```go
func NewDataMessage(payload []byte) *DataMessage
```
NewDataMessage creates a new Data message

#### func (*DataMessage) GetPayload

```go
func (d *DataMessage) GetPayload() []byte
```
GetPayload returns the actual payload data

#### func (*DataMessage) UnmarshalBinary

```go
func (d *DataMessage) UnmarshalBinary(data []byte) error
```
UnmarshalBinary deserializes a Data message

#### type DataMessageHandler

```go
type DataMessageHandler interface {
	// HandleDataMessage processes a Data message payload.
	// The payload is the raw message bytes extracted from the I2NP Data message.
	HandleDataMessage(payload []byte) error
}
```

DataMessageHandler defines the interface for handling incoming Data messages.
Data messages carry end-to-end payloads that need to be delivered to I2CP
sessions.

#### type DatabaseLookup

```go
type DatabaseLookup struct {
	Key            common.Hash
	From           common.Hash
	Flags          byte
	ReplyTunnelID  [4]byte
	Size           int
	ExcludedPeers  []common.Hash
	ReplyKey       session_key.SessionKey
	Tags           int
	ReplyTags      []session_tag.SessionTag
	ECIESReplyTags []session_tag.ECIESSessionTag
}
```

DatabaseLookup represents an I2NP DatabaseLookup message used to query the
network database for a RouterInfo or LeaseSet.

#### func  NewDatabaseLookup

```go
func NewDatabaseLookup(key, from common.Hash, lookupType byte, excludedPeers []common.Hash) *DatabaseLookup
```
NewDatabaseLookup creates a new DatabaseLookup message for RouterInfo lookups.
This creates a simple direct-reply lookup without encryption.

Parameters:

    - key: The hash of the RouterInfo/LeaseSet to look up
    - from: The hash of our router (where to send the reply)
    - lookupType: The type of lookup (DatabaseLookupFlagTypeRI, DatabaseLookupFlagTypeLS, etc.)
    - excludedPeers: Peers to exclude from DatabaseSearchReply (can be nil)

#### func  NewDatabaseLookupWithTunnel

```go
func NewDatabaseLookupWithTunnel(key, replyGateway common.Hash, replyTunnelID [4]byte, lookupType byte, excludedPeers []common.Hash) *DatabaseLookup
```
NewDatabaseLookupWithTunnel creates a DatabaseLookup that sends replies through
a tunnel.

Parameters:

    - key: The hash of the RouterInfo/LeaseSet to look up
    - replyGateway: The hash of the tunnel gateway router
    - replyTunnelID: The tunnel ID to send the reply through
    - lookupType: The type of lookup (DatabaseLookupFlagTypeRI, DatabaseLookupFlagTypeLS, etc.)
    - excludedPeers: Peers to exclude from DatabaseSearchReply (can be nil)

#### func  ReadDatabaseLookup

```go
func ReadDatabaseLookup(data []byte) (DatabaseLookup, error)
```
ReadDatabaseLookup parses a DatabaseLookup message from the provided byte slice.

#### func (*DatabaseLookup) GetECIESReplyTags

```go
func (d *DatabaseLookup) GetECIESReplyTags() []session_tag.ECIESSessionTag
```
GetECIESReplyTags returns the ECIES reply tags (8-byte)

#### func (*DatabaseLookup) GetFlags

```go
func (d *DatabaseLookup) GetFlags() byte
```
GetFlags returns the lookup flags

#### func (*DatabaseLookup) GetFrom

```go
func (d *DatabaseLookup) GetFrom() common.Hash
```
GetFrom returns the from hash

#### func (*DatabaseLookup) GetKey

```go
func (d *DatabaseLookup) GetKey() common.Hash
```
GetKey returns the lookup key

#### func (*DatabaseLookup) GetReplyTags

```go
func (d *DatabaseLookup) GetReplyTags() []session_tag.SessionTag
```
GetReplyTags returns the reply tags

#### func (*DatabaseLookup) GetTagCount

```go
func (d *DatabaseLookup) GetTagCount() int
```
GetTagCount returns the number of tags

#### func (*DatabaseLookup) IsECIES

```go
func (d *DatabaseLookup) IsECIES() bool
```
IsECIES returns true if the ECIESFlag (bit 4) is set in the flags byte

#### func (*DatabaseLookup) MarshalBinary

```go
func (d *DatabaseLookup) MarshalBinary() ([]byte, error)
```
MarshalBinary serializes the DatabaseLookup message to binary format. The format
follows the I2NP specification for DatabaseLookup messages.

#### type DatabaseManager

```go
type DatabaseManager struct {
}
```

DatabaseManager coordinates database-related message processing and response
generation.

#### func  NewDatabaseManager

```go
func NewDatabaseManager(netdb I2NPNetDBStore) *DatabaseManager
```
NewDatabaseManager creates a new database manager with NetDB integration

#### func (*DatabaseManager) PerformLookup

```go
func (dm *DatabaseManager) PerformLookup(reader DatabaseReader) error
```
PerformLookup performs a database lookup using DatabaseReader interface and
generates appropriate responses

#### func (*DatabaseManager) SetFloodfillSelector

```go
func (dm *DatabaseManager) SetFloodfillSelector(selector FloodfillSelector)
```
SetFloodfillSelector sets the floodfill selector for selecting closest floodfill
routers

#### func (*DatabaseManager) SetOurRouterHash

```go
func (dm *DatabaseManager) SetOurRouterHash(hash common.Hash)
```
SetOurRouterHash sets our router's identity hash for use in DatabaseSearchReply
messages

#### func (*DatabaseManager) SetRetriever

```go
func (dm *DatabaseManager) SetRetriever(retriever NetDBRetriever)
```
SetRetriever sets the NetDB retriever for database operations

#### func (*DatabaseManager) SetSessionProvider

```go
func (dm *DatabaseManager) SetSessionProvider(provider SessionProvider)
```
SetSessionProvider sets the session provider for sending responses

#### func (*DatabaseManager) StoreData

```go
func (dm *DatabaseManager) StoreData(writer DatabaseWriter) error
```
StoreData stores data using DatabaseWriter interface and NetDB integration

#### func (*DatabaseManager) StoreDataFromPeer

```go
func (dm *DatabaseManager) StoreDataFromPeer(writer DatabaseWriter, source common.Hash) error
```
StoreDataFromPeer stores data with source peer context when available.

#### type DatabaseReader

```go
type DatabaseReader interface {
	GetKey() common.Hash
	GetFrom() common.Hash
	GetFlags() byte
}
```

DatabaseReader represents types that can perform database lookups

#### func  CreateDatabaseQuery

```go
func CreateDatabaseQuery(key, from common.Hash, flags byte) DatabaseReader
```
CreateDatabaseQuery creates a database lookup with interface methods

#### type DatabaseSearchReply

```go
type DatabaseSearchReply struct {
	*BaseI2NPMessage
	Key        common.Hash
	Count      int
	PeerHashes []common.Hash
	From       common.Hash
}
```

DatabaseSearchReply represents an I2NP DatabaseSearchReply message returned in
response to a failed DatabaseLookup, containing hashes of alternative peers to
query.

#### func  NewDatabaseSearchReply

```go
func NewDatabaseSearchReply(key, from common.Hash, peerHashes []common.Hash) *DatabaseSearchReply
```
NewDatabaseSearchReply creates a new DatabaseSearchReply message

#### func  ReadDatabaseSearchReply

```go
func ReadDatabaseSearchReply(data []byte) (*DatabaseSearchReply, error)
```
ReadDatabaseSearchReply reads a DatabaseSearchReply from binary data. This is a
convenience function that creates a new DatabaseSearchReply and unmarshals into
it.

#### func (*DatabaseSearchReply) MarshalBinary

```go
func (d *DatabaseSearchReply) MarshalBinary() ([]byte, error)
```
MarshalBinary serializes the DatabaseSearchReply as a complete I2NP message
including the 16-byte I2NP header (type, messageID, expiration, size, checksum).

#### func (*DatabaseSearchReply) MarshalPayload

```go
func (d *DatabaseSearchReply) MarshalPayload() ([]byte, error)
```
MarshalPayload serializes only the DatabaseSearchReply-specific payload fields
(without the I2NP header). Use MarshalBinary() for a complete I2NP message.

#### func (*DatabaseSearchReply) String

```go
func (d *DatabaseSearchReply) String() string
```
String returns a human-readable representation of the DatabaseSearchReply

#### func (*DatabaseSearchReply) UnmarshalBinary

```go
func (d *DatabaseSearchReply) UnmarshalBinary(data []byte) error
```
UnmarshalBinary deserializes the DatabaseSearchReply message from binary data.

#### type DatabaseStore

```go
type DatabaseStore struct {
	*BaseI2NPMessage
	Key           common.Hash
	StoreType     byte
	ReplyToken    [4]byte
	ReplyTunnelID [4]byte
	ReplyGateway  common.Hash
	Data          []byte
}
```

DatabaseStore represents an I2NP DatabaseStore message used to publish a
RouterInfo or LeaseSet to the network database.

#### func  NewDatabaseStore

```go
func NewDatabaseStore(key common.Hash, data []byte, dataType byte) *DatabaseStore
```
NewDatabaseStore creates a new DatabaseStore message

#### func (*DatabaseStore) GetLeaseSetType

```go
func (d *DatabaseStore) GetLeaseSetType() int
```
GetLeaseSetType returns the LeaseSet type variant from bits 3-0 of the type
field. Returns one of: DatabaseStoreTypeRouterInfo, DatabaseStoreTypeLeaseSet,
DatabaseStoreTypeLeaseSet2, DatabaseStoreTypeEncryptedLeaseSet, or
DatabaseStoreTypeMetaLeaseSet.

#### func (*DatabaseStore) GetStoreData

```go
func (d *DatabaseStore) GetStoreData() []byte
```
GetStoreData returns the store data

#### func (*DatabaseStore) GetStoreKey

```go
func (d *DatabaseStore) GetStoreKey() common.Hash
```
GetStoreKey returns the store key

#### func (*DatabaseStore) GetStoreType

```go
func (d *DatabaseStore) GetStoreType() byte
```
GetStoreType returns the store type

#### func (*DatabaseStore) IsLeaseSet

```go
func (d *DatabaseStore) IsLeaseSet() bool
```
IsLeaseSet returns true if this DatabaseStore contains any type of LeaseSet

#### func (*DatabaseStore) IsLeaseSet2

```go
func (d *DatabaseStore) IsLeaseSet2() bool
```
IsLeaseSet2 returns true if this DatabaseStore contains a LeaseSet2

#### func (*DatabaseStore) IsRouterInfo

```go
func (d *DatabaseStore) IsRouterInfo() bool
```
IsRouterInfo returns true if this DatabaseStore contains a RouterInfo

#### func (*DatabaseStore) MarshalBinary

```go
func (d *DatabaseStore) MarshalBinary() ([]byte, error)
```
MarshalBinary serializes the DatabaseStore as a complete I2NP message including
the 16-byte I2NP header (type, messageID, expiration, size, checksum).

#### func (*DatabaseStore) MarshalPayload

```go
func (d *DatabaseStore) MarshalPayload() ([]byte, error)
```
MarshalPayload serializes only the DatabaseStore-specific payload fields
(without the I2NP header). Use MarshalBinary() for a complete I2NP message.

#### func (*DatabaseStore) UnmarshalBinary

```go
func (d *DatabaseStore) UnmarshalBinary(data []byte) error
```
UnmarshalBinary deserializes the DatabaseStore message from I2NP message data

#### type DatabaseWriter

```go
type DatabaseWriter interface {
	GetStoreKey() common.Hash
	GetStoreData() []byte
	GetStoreType() byte
}
```

DatabaseWriter represents types that can store database entries

#### func  CreateDatabaseEntry

```go
func CreateDatabaseEntry(key common.Hash, data []byte, dataType byte) DatabaseWriter
```
CreateDatabaseEntry creates a database store with interface methods

#### type DeliveryStatus

```go
type DeliveryStatus struct {
	MessageID int
	Timestamp time.Time
}
```

DeliveryStatus represents an I2NP DeliveryStatus message used to confirm the
successful delivery or creation of a message.

#### type DeliveryStatusHandler

```go
type DeliveryStatusHandler interface {
	// HandleDeliveryStatus processes a delivery status notification.
	// msgID is the original message ID being confirmed, timestamp is when it was delivered.
	HandleDeliveryStatus(msgID int, timestamp time.Time) error
}
```

DeliveryStatusHandler defines the interface for handling delivery status
confirmations. When a DeliveryStatus message is received, it notifies the
original sender that their message was delivered, completing the delivery
confirmation loop.

#### type DeliveryStatusMessage

```go
type DeliveryStatusMessage struct {
	*BaseI2NPMessage
	StatusMessageID int
	Timestamp       time.Time
}
```

DeliveryStatusMessage represents an I2NP DeliveryStatus message Moved from:
messages.go

#### func  NewDeliveryStatusMessage

```go
func NewDeliveryStatusMessage(messageID int, timestamp time.Time) *DeliveryStatusMessage
```
NewDeliveryStatusMessage creates a new DeliveryStatus message

#### func (*DeliveryStatusMessage) GetStatusMessageID

```go
func (d *DeliveryStatusMessage) GetStatusMessageID() int
```
GetStatusMessageID returns the status message ID

#### func (*DeliveryStatusMessage) GetTimestamp

```go
func (d *DeliveryStatusMessage) GetTimestamp() time.Time
```
GetTimestamp returns the timestamp

#### func (*DeliveryStatusMessage) UnmarshalBinary

```go
func (d *DeliveryStatusMessage) UnmarshalBinary(data []byte) error
```
UnmarshalBinary deserializes a DeliveryStatus message

#### type ExpirationValidator

```go
type ExpirationValidator struct {
}
```

ExpirationValidator provides configurable message expiration checking. I2NP
messages have an expiration timestamp, and expired messages should be rejected
to prevent replay attacks and resource waste.

#### func  NewExpirationValidator

```go
func NewExpirationValidator() *ExpirationValidator
```
NewExpirationValidator creates a new validator with default settings. Default
tolerance is 5 minutes to allow for reasonable clock skew.

#### func (*ExpirationValidator) Disable

```go
func (v *ExpirationValidator) Disable() *ExpirationValidator
```
Disable turns off expiration checking. Returns the validator for method
chaining.

#### func (*ExpirationValidator) Enable

```go
func (v *ExpirationValidator) Enable() *ExpirationValidator
```
Enable turns on expiration checking. Returns the validator for method chaining.

#### func (*ExpirationValidator) IsEnabled

```go
func (v *ExpirationValidator) IsEnabled() bool
```
IsEnabled returns whether expiration checking is enabled.

#### func (*ExpirationValidator) IsExpired

```go
func (v *ExpirationValidator) IsExpired(expiration time.Time) bool
```
IsExpired checks if the given expiration time is in the past, accounting for the
configured tolerance.

#### func (*ExpirationValidator) ValidateExpiration

```go
func (v *ExpirationValidator) ValidateExpiration(expiration time.Time) error
```
ValidateExpiration checks if the message expiration is valid. Returns nil if
valid, or an error describing the expiration issue.

#### func (*ExpirationValidator) ValidateMessage

```go
func (v *ExpirationValidator) ValidateMessage(msg I2NPMessage) error
```
ValidateMessage checks if an I2NP message has expired. Returns nil if valid, or
an error if the message has expired.

#### func (*ExpirationValidator) WithTimeSource

```go
func (v *ExpirationValidator) WithTimeSource(source func() time.Time) *ExpirationValidator
```
WithTimeSource sets a custom time source for testing. Returns the validator for
method chaining.

#### func (*ExpirationValidator) WithTolerance

```go
func (v *ExpirationValidator) WithTolerance(seconds int64) *ExpirationValidator
```
WithTolerance sets the clock skew tolerance in seconds. Returns the validator
for method chaining.

#### type FloodfillSelector

```go
type FloodfillSelector interface {
	SelectFloodfillRouters(targetHash common.Hash, count int) ([]router_info.RouterInfo, error)
}
```

FloodfillSelector defines the interface for selecting closest floodfill routers

#### type Garlic

```go
type Garlic struct {
	Count       int
	Cloves      []GarlicClove
	Certificate certificate.Certificate
	MessageID   int
	Expiration  time.Time
}
```

Garlic represents an I2NP Garlic message containing one or more encrypted garlic
cloves for anonymous message delivery.

#### func  DeserializeGarlic

```go
func DeserializeGarlic(data []byte, nestingDepth int) (*Garlic, error)
```
DeserializeGarlic parses a decrypted garlic message from bytes with validation.
This function enforces security limits to prevent resource exhaustion attacks.

Security validations: - Maximum clove count (64) to prevent memory exhaustion -
Maximum nesting depth (3) to prevent stack overflow from recursive garlic -
Proper bounds checking for all fields

Returns the parsed Garlic structure or an error if validation fails.

#### func (*Garlic) GetCloveCount

```go
func (g *Garlic) GetCloveCount() int
```
GetCloveCount returns the number of cloves

#### func (*Garlic) GetCloves

```go
func (g *Garlic) GetCloves() []GarlicClove
```
GetCloves returns the garlic cloves

#### type GarlicBuilder

```go
type GarlicBuilder struct {
}
```

GarlicBuilder provides methods to construct encrypted garlic messages. Garlic
messages wrap I2NP messages with delivery instructions and encryption, enabling
end-to-end encrypted communication through I2P tunnels.

The builder supports: - Multiple cloves per garlic message - Various delivery
instruction types (LOCAL, DESTINATION, ROUTER, TUNNEL) - Expiration and message
ID management

#### func  NewGarlicBuilder

```go
func NewGarlicBuilder(messageID int, expiration time.Time) *GarlicBuilder
```
NewGarlicBuilder creates a new garlic message builder. messageID: Unique
identifier for this garlic message (for tracking/ACKs) expiration: Time when
this garlic message should no longer be processed

#### func  NewGarlicBuilderWithDefaults

```go
func NewGarlicBuilderWithDefaults() (*GarlicBuilder, error)
```
NewGarlicBuilderWithDefaults creates a garlic builder with sensible defaults: -
Random message ID - Expiration set to 10 seconds from now

#### func (*GarlicBuilder) AddClove

```go
func (gb *GarlicBuilder) AddClove(
	deliveryInstructions GarlicCloveDeliveryInstructions,
	message I2NPMessage,
	cloveID int,
	cloveExpiration time.Time,
) error
```
AddClove adds a garlic clove to the message. The clove wraps an I2NP message
with delivery instructions.

deliveryInstructions: How to deliver the wrapped message (LOCAL, DESTINATION,
ROUTER, TUNNEL) message: The I2NP message to wrap cloveID: Unique identifier for
this clove cloveExpiration: When this clove expires (typically same as or before
garlic message expiration)

#### func (*GarlicBuilder) AddDestinationDeliveryClove

```go
func (gb *GarlicBuilder) AddDestinationDeliveryClove(
	message I2NPMessage,
	cloveID int,
	destinationHash common.Hash,
) error
```
AddDestinationDeliveryClove adds a clove with DESTINATION delivery instructions.
The message will be delivered to the specified I2P destination.

message: The I2NP message to wrap cloveID: Unique identifier for this clove
destinationHash: SHA256 hash of the destination

#### func (*GarlicBuilder) AddLocalDeliveryClove

```go
func (gb *GarlicBuilder) AddLocalDeliveryClove(message I2NPMessage, cloveID int) error
```
AddLocalDeliveryClove adds a clove with LOCAL delivery instructions. This is the
simplest delivery type - the message is processed locally by the recipient.

message: The I2NP message to wrap cloveID: Unique identifier for this clove

#### func (*GarlicBuilder) AddRouterDeliveryClove

```go
func (gb *GarlicBuilder) AddRouterDeliveryClove(
	message I2NPMessage,
	cloveID int,
	routerHash common.Hash,
) error
```
AddRouterDeliveryClove adds a clove with ROUTER delivery instructions. The
message will be delivered to the specified router.

message: The I2NP message to wrap cloveID: Unique identifier for this clove
routerHash: SHA256 hash of the destination router

#### func (*GarlicBuilder) AddTunnelDeliveryClove

```go
func (gb *GarlicBuilder) AddTunnelDeliveryClove(
	message I2NPMessage,
	cloveID int,
	gatewayHash common.Hash,
	tunnelID tunnel.TunnelID,
) error
```
AddTunnelDeliveryClove adds a clove with TUNNEL delivery instructions. The
message will be forwarded through the specified tunnel to the gateway router.

message: The I2NP message to wrap cloveID: Unique identifier for this clove
gatewayHash: SHA256 hash of the tunnel gateway router tunnelID: Destination
tunnel ID

#### func (*GarlicBuilder) Build

```go
func (gb *GarlicBuilder) Build() (*Garlic, error)
```
Build constructs the unencrypted Garlic message structure. This produces a
Garlic object ready for encryption. The actual encryption is handled by
SessionManager (ECIES-X25519-AEAD-Ratchet).

#### func (*GarlicBuilder) BuildAndSerialize

```go
func (gb *GarlicBuilder) BuildAndSerialize() ([]byte, error)
```
BuildAndSerialize constructs the garlic message and serializes it to bytes. This
produces the plaintext garlic payload ready for encryption.

Returns the serialized plaintext garlic message (unencrypted).

#### type GarlicClove

```go
type GarlicClove struct {
	DeliveryInstructions GarlicCloveDeliveryInstructions
	I2NPMessage          I2NPMessage
	CloveID              int
	Expiration           time.Time
	Certificate          certificate.Certificate
}
```

GarlicClove represents a single clove within an I2NP Garlic message, containing
delivery instructions, an embedded I2NP message, and expiration metadata.

#### type GarlicCloveDeliveryInstructions

```go
type GarlicCloveDeliveryInstructions struct {
	Flag       byte
	SessionKey session_key.SessionKey
	Hash       common.Hash
	TunnelID   tunnel.TunnelID
	Delay      int
}
```

GarlicCloveDeliveryInstructions represents the delivery instructions for a
garlic clove, specifying how and where the enclosed I2NP message should be
delivered.

#### func  NewDestinationDeliveryInstructions

```go
func NewDestinationDeliveryInstructions(destinationHash common.Hash) GarlicCloveDeliveryInstructions
```
NewDestinationDeliveryInstructions creates delivery instructions for destination
delivery. destinationHash: SHA256 hash of the destination

#### func  NewLocalDeliveryInstructions

```go
func NewLocalDeliveryInstructions() GarlicCloveDeliveryInstructions
```
NewLocalDeliveryInstructions creates delivery instructions for local processing.

#### func  NewRouterDeliveryInstructions

```go
func NewRouterDeliveryInstructions(routerHash common.Hash) GarlicCloveDeliveryInstructions
```
NewRouterDeliveryInstructions creates delivery instructions for router delivery.
routerHash: SHA256 hash of the destination router

#### func  NewTunnelDeliveryInstructions

```go
func NewTunnelDeliveryInstructions(gatewayHash common.Hash, tunnelID tunnel.TunnelID) GarlicCloveDeliveryInstructions
```
NewTunnelDeliveryInstructions creates delivery instructions for tunnel delivery.
gatewayHash: SHA256 hash of the tunnel gateway router tunnelID: Destination
tunnel ID

#### type GarlicCloveForwarder

```go
type GarlicCloveForwarder interface {
	// ForwardToDestination forwards a message to a destination hash (delivery type 0x01).
	// The forwarder should lookup the destination's LeaseSet and route through a tunnel.
	ForwardToDestination(destHash common.Hash, msg I2NPMessage) error

	// ForwardToRouter forwards a message directly to a router hash (delivery type 0x02).
	// The forwarder should send the message via the transport layer.
	ForwardToRouter(routerHash common.Hash, msg I2NPMessage) error

	// ForwardThroughTunnel forwards a message through a tunnel to a gateway (delivery type 0x03).
	// The forwarder should wrap the message in a TunnelGateway envelope and send to the gateway.
	ForwardThroughTunnel(gatewayHash common.Hash, tunnelID tunnel.TunnelID, msg I2NPMessage) error
}
```

GarlicCloveForwarder defines the interface for forwarding garlic cloves to
different delivery targets. This interface enables the MessageProcessor to
delegate non-LOCAL delivery types to router-level components that have access to
NetDB, transport, and tunnel infrastructure.

#### type GarlicElGamal

```go
type GarlicElGamal struct {
	Length uint32
	Data   []byte
}
```

GarlicElGamal represents an ElGamal encrypted garlic message with proper
structure

#### func  NewGarlicElGamal

```go
func NewGarlicElGamal(bytes []byte) (*GarlicElGamal, error)
```
NewGarlicElGamal creates a new GarlicElGamal from raw bytes

#### func (*GarlicElGamal) Bytes

```go
func (g *GarlicElGamal) Bytes() ([]byte, error)
```
Bytes serializes the GarlicElGamal to bytes

#### type GarlicKeyRegistrar

```go
type GarlicKeyRegistrar interface {
	// RegisterOneTimeGarlicKey stores a single-use garlic key for a pending
	// ShortTunnelBuildReply. tag is garlicKeyMaterial[24:32], key is [0:32].
	RegisterOneTimeGarlicKey(tag [8]byte, key [32]byte)
}
```

GarlicKeyRegistrar allows callers to register one-time symmetric garlic keys
derived from STBM Noise transcript hashes. Implemented by *GarlicSessionManager.

#### type GarlicMessageDecryptor

```go
type GarlicMessageDecryptor interface {
	// DecryptGarlicMessage decrypts an encrypted garlic message.
	// Returns plaintext, session tag, session hash (non-nil for New Session), and error.
	DecryptGarlicMessage(encrypted []byte) (plaintext []byte, sessionTag [8]byte, sessionHash *[32]byte, err error)
}
```

GarlicMessageDecryptor provides garlic message decryption for the processor.
This interface is satisfied by both GarlicSessionManager (the concrete adapter)
and test mocks.

#### type GarlicProcessor

```go
type GarlicProcessor interface {
	GetCloves() []GarlicClove
	GetCloveCount() int
}
```

GarlicProcessor represents types that process garlic messages

#### type GarlicSessionManager

```go
type GarlicSessionManager struct {
}
```

GarlicSessionManager is a thin adapter around go-noise/ratchet.SessionManager.
It translates between the go-i2p common.Hash type used in the I2NP layer and the
[32]byte type used in the go-noise ratchet layer.

All cryptographic operations (ECIES key exchange, ratchet advancement,
encryption, and decryption) are delegated to the underlying
ratchet.SessionManager.

Session lifecycle:

    1. New Session: First message uses ephemeral-static DH (ECIES)
    2. Existing Session: Subsequent messages use ratchet for forward secrecy
    3. Session Expiry: Sessions expire after inactivity timeout

#### func  GenerateGarlicSessionManager

```go
func GenerateGarlicSessionManager() (*GarlicSessionManager, error)
```
GenerateGarlicSessionManager creates a session manager with a fresh key pair.

#### func  NewGarlicSessionManager

```go
func NewGarlicSessionManager(privateKey [32]byte) (*GarlicSessionManager, error)
```
NewGarlicSessionManager creates a new garlic session manager with the given
private key. The private key is used for decrypting New Session messages.

#### func (*GarlicSessionManager) CleanupExpiredSessions

```go
func (sm *GarlicSessionManager) CleanupExpiredSessions() int
```
CleanupExpiredSessions removes sessions that haven't been used recently.

#### func (*GarlicSessionManager) Close

```go
func (sm *GarlicSessionManager) Close() error
```
Close stops the cleanup loop, removes all sessions, and zeroes key material. It
is safe to call Close multiple times.

#### func (*GarlicSessionManager) DecryptGarlicMessage

```go
func (sm *GarlicSessionManager) DecryptGarlicMessage(encryptedGarlic []byte) ([]byte, [8]byte, *[32]byte, error)
```
DecryptGarlicMessage decrypts an encrypted garlic message. Handles both New
Session and Existing Session message types.

Returns:

    - plaintext: the decrypted garlic payload
    - sessionTag: the 8-byte tag used to identify the session (zero for NS and NSR)
    - sessionHash: SHA-256(initiatorStaticPub) for New Session messages; nil otherwise.
      Callers that need to send a New Session Reply must pass the dereferenced
      value to EncryptNewSessionReply.

#### func (*GarlicSessionManager) EncryptGarlicMessage

```go
func (sm *GarlicSessionManager) EncryptGarlicMessage(
	destinationHash common.Hash,
	destinationPubKey [32]byte,
	plaintextGarlic []byte,
) ([]byte, error)
```
EncryptGarlicMessage encrypts a plaintext garlic message for the given
destination. This translates the common.Hash destinationHash to [32]byte and
delegates to the underlying ratchet.SessionManager.

The raw garlic bytes are automatically wrapped in the ECIES-X25519-AEAD-Ratchet
payload format (DateTime + GarlicClove blocks) required by the go-noise library.

Parameters:

    - destinationHash: Hash of the destination's public key (common.Hash)
    - destinationPubKey: The destination's X25519 public key (32 bytes)
    - plaintextGarlic: Serialized garlic message (from GarlicBuilder.BuildAndSerialize)

Returns encrypted garlic message ready to send via I2NP.

#### func (*GarlicSessionManager) EncryptNewSessionReply

```go
func (sm *GarlicSessionManager) EncryptNewSessionReply(sessionHash [32]byte, payload []byte) ([]byte, error)
```
EncryptNewSessionReply constructs a New Session Reply (NSR) for a session
established by a received New Session message. The responder calls this to
complete the Noise IK handshake and transition to Existing Session encryption.

sessionHash is the [32]byte value returned by DecryptGarlicMessage (dereference
the *[32]byte). payload is the reply plaintext.

#### func (*GarlicSessionManager) GetPublicKey

```go
func (sm *GarlicSessionManager) GetPublicKey() [32]byte
```
GetPublicKey returns this session manager's X25519 public key.

#### func (*GarlicSessionManager) GetSessionCount

```go
func (sm *GarlicSessionManager) GetSessionCount() int
```
GetSessionCount returns the number of active sessions.

#### func (*GarlicSessionManager) ProcessIncomingDHRatchet

```go
func (sm *GarlicSessionManager) ProcessIncomingDHRatchet(sessionTag [8]byte, newRemotePubKey [32]byte) error
```
ProcessIncomingDHRatchet processes a DH ratchet key received from a peer. The
session is found by tag lookup using the sessionTag parameter.

#### func (*GarlicSessionManager) RegisterOneTimeGarlicKey

```go
func (sm *GarlicSessionManager) RegisterOneTimeGarlicKey(tag [8]byte, key [32]byte)
```
RegisterOneTimeGarlicKey registers a one-time symmetric garlic key derived from
a STBM Noise transcript hash via HKDF("AttachLayerEncryption"). The OBEP uses
this key to wrap the ShortTunnelBuildReply garlic; it is consumed on first use
and never reused.

tag is garlicKeyMaterial[24:32], key is garlicKeyMaterial[0:32].

#### func (*GarlicSessionManager) StartCleanupLoop

```go
func (sm *GarlicSessionManager) StartCleanupLoop(ctx context.Context)
```
StartCleanupLoop starts periodic cleanup of expired sessions.

#### type HashProvider

```go
type HashProvider interface {
	GetOurIdent() common.Hash
	GetNextIdent() common.Hash
}
```

HashProvider represents types that provide hash identification

#### type I2NPMessage

```go
type I2NPMessage interface {
	MessageSerializer
	MessageIdentifier
	MessageExpiration
}
```

I2NPMessage interface represents any I2NP message that can be
marshaled/unmarshaled This is the primary interface that combines all core
message behaviors

#### func  NewI2NPMessage

```go
func NewI2NPMessage(msgType int) I2NPMessage
```
NewI2NPMessage creates a new base I2NP message and returns it as I2NPMessage
interface

#### type I2NPMessageDispatcher

```go
type I2NPMessageDispatcher struct {
}
```

I2NPMessageDispatcher demonstrates advanced interface-based routing

#### func  NewI2NPMessageDispatcher

```go
func NewI2NPMessageDispatcher(config I2NPMessageDispatcherConfig) *I2NPMessageDispatcher
```
NewI2NPMessageDispatcher creates a new message router

#### func (*I2NPMessageDispatcher) GetProcessor

```go
func (mr *I2NPMessageDispatcher) GetProcessor() *MessageProcessor
```
GetProcessor returns the underlying MessageProcessor for direct access. This is
used by the router to set up garlic clove forwarding.

#### func (*I2NPMessageDispatcher) RouteDatabaseMessage

```go
func (mr *I2NPMessageDispatcher) RouteDatabaseMessage(msg interface{}) error
```
RouteDatabaseMessage routes database-related messages

#### func (*I2NPMessageDispatcher) RouteDatabaseMessageFromPeer

```go
func (mr *I2NPMessageDispatcher) RouteDatabaseMessageFromPeer(msg interface{}, source *common.Hash) error
```
RouteDatabaseMessageFromPeer routes database messages with optional source peer
context so storage paths can apply source-aware admission controls.

#### func (*I2NPMessageDispatcher) RouteMessage

```go
func (mr *I2NPMessageDispatcher) RouteMessage(msg I2NPMessage) error
```
RouteMessage routes messages based on their interfaces

#### func (*I2NPMessageDispatcher) RouteTunnelMessage

```go
func (mr *I2NPMessageDispatcher) RouteTunnelMessage(msg interface{}) error
```
RouteTunnelMessage routes tunnel-related messages

#### func (*I2NPMessageDispatcher) SetNetDB

```go
func (mr *I2NPMessageDispatcher) SetNetDB(netdb I2NPNetDBStore)
```
SetNetDB sets the NetDB store for database operations. If the netdb implements
FloodfillSelector, it will also be configured for floodfill functionality.

#### func (*I2NPMessageDispatcher) SetOurRouterHash

```go
func (mr *I2NPMessageDispatcher) SetOurRouterHash(hash common.Hash)
```
SetOurRouterHash sets our router's identity hash for use in DatabaseSearchReply
messages. This should be called during router initialization with the router's
own identity hash. The hash is used in DatabaseSearchReply "from" field to
indicate which router sent the reply.

#### func (*I2NPMessageDispatcher) SetPeerSelector

```go
func (mr *I2NPMessageDispatcher) SetPeerSelector(selector tunnel.PeerSelector)
```
SetPeerSelector sets the peer selector for the TunnelManager

#### func (*I2NPMessageDispatcher) SetSessionProvider

```go
func (mr *I2NPMessageDispatcher) SetSessionProvider(provider SessionProvider)
```
SetSessionProvider configures the session provider for message routing
responses. This method propagates the SessionProvider to both DatabaseManager
and TunnelManager, enabling them to send I2NP response messages (DatabaseStore,
DatabaseSearchReply, etc.) back through the appropriate transport sessions. The
provider must implement SessionProvider interface with GetSessionByHash method.

#### func (*I2NPMessageDispatcher) SetTunnelManager

```go
func (mr *I2NPMessageDispatcher) SetTunnelManager(tm *TunnelManager)
```
SetTunnelManager replaces the internal TunnelManager with an external one. This
must be called from the router after r.tunnelManager is created so that both the
dispatcher and the router share the same pendingBuilds map, enabling build-reply
correlation (A3 fix).

#### type I2NPMessageDispatcherConfig

```go
type I2NPMessageDispatcherConfig struct {
	MaxRetries     int
	DefaultTimeout time.Duration
	EnableLogging  bool
}
```

I2NPMessageDispatcherConfig represents configuration for message routing

#### type I2NPMessageFactory

```go
type I2NPMessageFactory struct{}
```

I2NPMessageFactory provides methods to create I2NP messages as interfaces

#### func  NewI2NPMessageFactory

```go
func NewI2NPMessageFactory() *I2NPMessageFactory
```
NewI2NPMessageFactory creates a new message factory

#### func (*I2NPMessageFactory) CreateDataMessage

```go
func (f *I2NPMessageFactory) CreateDataMessage(payload []byte) I2NPMessage
```
CreateDataMessage creates a new data message

#### func (*I2NPMessageFactory) CreateDeliveryStatusMessage

```go
func (f *I2NPMessageFactory) CreateDeliveryStatusMessage(messageID int, timestamp time.Time) I2NPMessage
```
CreateDeliveryStatusMessage creates a new delivery status message

#### func (*I2NPMessageFactory) CreateTunnelBuildMessage

```go
func (f *I2NPMessageFactory) CreateTunnelBuildMessage(records [8]BuildRequestRecord) I2NPMessage
```
CreateTunnelBuildMessage creates a new tunnel build message

#### func (*I2NPMessageFactory) CreateTunnelDataMessage

```go
func (f *I2NPMessageFactory) CreateTunnelDataMessage(tunnelID tunnel.TunnelID, data [1024]byte) I2NPMessage
```
CreateTunnelDataMessage creates a new tunnel data message with the given tunnel
ID and data.

#### type I2NPNTCPHeader

```go
type I2NPNTCPHeader struct {
	Type       int
	MessageID  int
	Expiration time.Time
	Size       int
	Checksum   int
	Data       []byte
}
```

I2NPNTCPHeader represents a parsed I2NP message header for NTCP transport

#### func  ReadI2NPNTCPHeader

```go
func ReadI2NPNTCPHeader(data []byte) (I2NPNTCPHeader, error)
```
ReadI2NPNTCPHeader reads an entire I2NP message and returns the parsed header
with embedded encrypted data

#### type I2NPNetDBStore

```go
type I2NPNetDBStore interface {
	Store(key common.Hash, data []byte, dataType byte) error
}
```

I2NPNetDBStore defines the interface for storing network database entries.
Implementations must dispatch to the appropriate storage method based on
dataType:

    - 0: RouterInfo
    - 1: LeaseSet
    - 3: LeaseSet2
    - 5: EncryptedLeaseSet
    - 7: MetaLeaseSet

#### type I2NPNetDBStoreWithSource

```go
type I2NPNetDBStoreWithSource interface {
	StoreFromPeer(key common.Hash, data []byte, dataType byte, source common.Hash) error
}
```

I2NPNetDBStoreWithSource extends I2NPNetDBStore with source-peer context.
Implementations can use this for fairness/rate controls on first-seen entries.

#### type I2NPSSUHeader

```go
type I2NPSSUHeader struct {
	Type       int
	Expiration time.Time
}
```

I2NPSSUHeader represents a parsed I2NP message header for SSU transport

#### func  ReadI2NPSSUHeader

```go
func ReadI2NPSSUHeader(data []byte) (I2NPSSUHeader, error)
```
ReadI2NPSSUHeader reads an I2NP SSU header

#### type I2NPSecondGenTransportHeader

```go
type I2NPSecondGenTransportHeader struct {
	Type       int
	MessageID  int
	Expiration time.Time
}
```

I2NPSecondGenTransportHeader represents the compact 9-byte I2NP header used over
NTCP2 and SSU2 transports, replacing the standard 16-byte header.

#### func  ReadI2NPSecondGenTransportHeader

```go
func ReadI2NPSecondGenTransportHeader(dat []byte) (I2NPSecondGenTransportHeader, error)
```
ReadI2NPSecondGenTransportHeader reads an I2NP NTCP2 or SSU2 header When
transmitted over [NTCP2] or [SSU2], the 16-byte standard header is not used.
Only a 1-byte type, 4-byte message id, and a 4-byte expiration in seconds are
included. The size is incorporated in the NTCP2 and SSU2 data packet formats.
The checksum is not required since errors are caught in decryption.

#### type I2NPTransportSession

```go
type I2NPTransportSession interface {
	QueueSendI2NP(msg I2NPMessage) error
	SendQueueSize() int
}
```

I2NPTransportSession defines the interface for sending I2NP messages back to
requesters

#### type MessageExpiration

```go
type MessageExpiration interface {
	Expiration() time.Time
	SetExpiration(exp time.Time)
}
```

MessageExpiration represents types that have expiration management

#### type MessageIdentifier

```go
type MessageIdentifier interface {
	Type() int
	MessageID() int
	SetMessageID(id int)
}
```

MessageIdentifier represents types that have message identification

#### type MessageProcessor

```go
type MessageProcessor struct {
}
```

MessageProcessor routes inbound I2NP messages to type-specific handlers and
pluggable subsystem interfaces.

#### func  NewMessageProcessor

```go
func NewMessageProcessor() *MessageProcessor
```
NewMessageProcessor creates a new message processor

#### func (*MessageProcessor) DisableExpirationCheck

```go
func (p *MessageProcessor) DisableExpirationCheck()
```
DisableExpirationCheck disables expiration validation in the processor. Useful
for testing or special processing scenarios.

#### func (*MessageProcessor) EnableExpirationCheck

```go
func (p *MessageProcessor) EnableExpirationCheck()
```
EnableExpirationCheck enables expiration validation in the processor.

#### func (*MessageProcessor) ProcessMessage

```go
func (p *MessageProcessor) ProcessMessage(msg I2NPMessage) error
```
ProcessMessage processes any I2NP message using interfaces. Messages are first
validated for expiration before processing. Expired messages are rejected with
ErrI2NPMessageExpired.

The lock is acquired only to snapshot handler references and validate
expiration, then released before dispatching. This avoids a deadlock when
processing garlic messages with LOCAL delivery cloves, which recursively call
ProcessMessage (RLock is not re-entrant when a concurrent writer is waiting).

#### func (*MessageProcessor) SetBuildRecordCrypto

```go
func (p *MessageProcessor) SetBuildRecordCrypto(crypto ReplyRecordEncryptor)
```
SetBuildRecordCrypto sets the build record crypto handler for encrypting build
response records. Accepts any implementation of ReplyRecordEncryptor, including
*BuildRecordCrypto and test mocks.

#### func (*MessageProcessor) SetBuildReplyForwarder

```go
func (p *MessageProcessor) SetBuildReplyForwarder(forwarder BuildReplyForwarder)
```
SetBuildReplyForwarder sets the forwarder for sending tunnel build replies to
the next hop. This enables the router to participate in tunnel building by
forwarding replies. If not set, build requests will be processed but replies
will not be sent (logged only).

#### func (*MessageProcessor) SetBuildReplyProcessor

```go
func (p *MessageProcessor) SetBuildReplyProcessor(processor TunnelBuildReplyProcessor)
```
SetBuildReplyProcessor sets the processor for handling incoming tunnel build
reply messages. When set, tunnel build reply message types (22, 24, 26) are
dispatched to this processor which correlates them with pending build requests
and updates tunnel state. If not set, tunnel build replies are logged and
discarded.

#### func (*MessageProcessor) SetBuildRequestDecryptor

```go
func (p *MessageProcessor) SetBuildRequestDecryptor(dec BuildRequestDecryptor)
```
SetBuildRequestDecryptor sets the decryptor used to decrypt inbound build
request records that are destined for this router. If not set, encrypted records
will be attempted as cleartext (testing mode only).

#### func (*MessageProcessor) SetCloveForwarder

```go
func (p *MessageProcessor) SetCloveForwarder(forwarder GarlicCloveForwarder)
```
SetCloveForwarder sets the garlic clove forwarder for handling non-LOCAL
delivery types. This is optional - if not set, only LOCAL delivery (0x00) will
be processed. The forwarder enables DESTINATION (0x01), ROUTER (0x02), and
TUNNEL (0x03) deliveries.

#### func (*MessageProcessor) SetDataMessageHandler

```go
func (p *MessageProcessor) SetDataMessageHandler(handler DataMessageHandler)
```
SetDataMessageHandler sets the handler for processing incoming Data message
payloads. When set, Data message payloads are forwarded to this handler for
delivery to the appropriate I2CP session. If not set, Data messages are logged
but discarded.

#### func (*MessageProcessor) SetDatabaseManager

```go
func (p *MessageProcessor) SetDatabaseManager(dbMgr *DatabaseManager)
```
SetDatabaseManager sets the database manager for processing DatabaseLookup
messages. This must be called before processing DatabaseLookup messages,
otherwise they will fail with an error.

#### func (*MessageProcessor) SetDeliveryStatusHandler

```go
func (p *MessageProcessor) SetDeliveryStatusHandler(handler DeliveryStatusHandler)
```
SetDeliveryStatusHandler sets the handler for processing delivery status
confirmations. When set, delivery status notifications are forwarded to this
handler to confirm message delivery. If not set, DeliveryStatus messages are
logged but discarded.

#### func (*MessageProcessor) SetExpirationValidator

```go
func (p *MessageProcessor) SetExpirationValidator(v *ExpirationValidator)
```
SetExpirationValidator sets a custom expiration validator for message
processing. If not set, a default validator with 5-minute tolerance is used.

#### func (*MessageProcessor) SetGarlicSessionManager

```go
func (p *MessageProcessor) SetGarlicSessionManager(garlicMgr GarlicMessageDecryptor)
```
SetGarlicSessionManager sets the garlic session manager for decrypting garlic
messages. This must be called before processing garlic messages, otherwise they
will fail with an error. Accepts any implementation of GarlicMessageDecryptor,
including *GarlicSessionManager and test mocks.

#### func (*MessageProcessor) SetOurPrivateKey

```go
func (p *MessageProcessor) SetOurPrivateKey(key []byte)
```
SetOurPrivateKey sets the router's static X25519 private key used for decrypting
inbound build request records.

#### func (*MessageProcessor) SetOurRouterHash

```go
func (p *MessageProcessor) SetOurRouterHash(hash common.Hash)
```
SetOurRouterHash sets our router's identity hash so that processAllBuildRecords
can skip records not destined for this router.

#### func (*MessageProcessor) SetParticipantManager

```go
func (p *MessageProcessor) SetParticipantManager(pm ParticipantManager)
```
SetParticipantManager sets the participant manager for processing incoming
tunnel build requests. This enables the router to participate in tunnels built
by other routers. If not set, tunnel build requests will be rejected with an
error.

#### func (*MessageProcessor) SetSearchReplyHandler

```go
func (p *MessageProcessor) SetSearchReplyHandler(handler SearchReplyHandler)
```
SetSearchReplyHandler sets the handler for delivering DatabaseSearchReply
suggestions to pending iterative Kademlia lookups. When set, peer suggestions
from search replies are forwarded to this handler for follow-up queries.

#### func (*MessageProcessor) SetTunnelDataHandler

```go
func (p *MessageProcessor) SetTunnelDataHandler(handler TunnelDataHandler)
```
SetTunnelDataHandler sets the handler for processing inbound TunnelData
messages. When set, incoming TunnelData messages will be delegated to this
handler for tunnel endpoint decryption and I2CP session delivery. If not set,
TunnelData messages will be validated but not delivered to any session.

#### func (*MessageProcessor) SetTunnelGatewayHandler

```go
func (p *MessageProcessor) SetTunnelGatewayHandler(handler TunnelGatewayHandler)
```
SetTunnelGatewayHandler sets the handler for processing TunnelGateway messages.
When set, incoming TunnelGateway messages will be delegated to this handler for
tunnel lookup, encryption, and forwarding. If not set, TunnelGateway messages
will be validated but not forwarded.

#### type MessageSerializer

```go
type MessageSerializer interface {
	MarshalBinary() ([]byte, error)
	UnmarshalBinary(data []byte) error
}
```

MessageSerializer represents types that can be marshaled and unmarshaled

#### type NetDBRetriever

```go
type NetDBRetriever interface {
	GetRouterInfoBytes(hash common.Hash) ([]byte, error)
	GetRouterInfoCount() int
}
```

NetDBRetriever defines the interface for retrieving RouterInfo entries

#### type ParticipantManager

```go
type ParticipantManager interface {
	// ProcessBuildRequest validates a tunnel build request against all limits.
	// Returns whether the request should be accepted, the rejection code if not,
	// and a human-readable reason for logging.
	//
	// Parameters:
	// - sourceHash: The router hash of the requester (from BuildRequestRecord.OurIdent)
	//
	// Returns:
	// - accepted: Whether the request should be accepted
	// - rejectCode: I2P-compliant rejection code if not accepted (0 if accepted)
	// - reason: Human-readable reason for logging (empty if accepted)
	ProcessBuildRequest(sourceHash common.Hash) (accepted bool, rejectCode byte, reason string)

	// RegisterParticipant registers a new participating tunnel after acceptance.
	// This should be called after ProcessBuildRequest returns accepted=true.
	//
	// Parameters:
	// - tunnelID: The tunnel ID for the participating tunnel
	// - sourceHash: The router hash of the requester
	// - expiry: When the tunnel participation expires
	// - layerKey: The layer encryption key from the build request record
	// - ivKey: The IV key from the build request record
	RegisterParticipant(tunnelID tunnel.TunnelID, sourceHash common.Hash, expiry time.Time, layerKey, ivKey session_key.SessionKey) error
}
```

ParticipantManager defines the interface for processing incoming tunnel build
requests. This interface enables the MessageProcessor to delegate tunnel
participation decisions to the tunnel.Manager which handles rate limiting and
resource protection.

#### type PayloadCarrier

```go
type PayloadCarrier interface {
	GetPayload() []byte
}
```

PayloadCarrier represents messages that carry payload data

#### func  NewDataMessageWithPayload

```go
func NewDataMessageWithPayload(payload []byte) PayloadCarrier
```
NewDataMessageWithPayload creates a new Data message and returns it as
PayloadCarrier interface

#### type PendingBuildRequest

```go
type PendingBuildRequest struct {
	TunnelID     tunnel.TunnelID
	RequestedAt  time.Time
	ReplyKeys    []session_key.SessionKey // ECIES-X25519-AEAD keys for decrypting each hop's reply
	ReplyIVs     [][16]byte               // Nonces/IVs for AEAD decryption
	NoiseHashes  [][32]byte               // Per-hop Noise transcript hash (m_H) used as AEAD AD for STBM reply decryption
	Retries      int                      // Number of retry attempts
	IsInbound    bool                     // True for inbound tunnel, false for outbound
	HopCount     int                      // Number of hops in tunnel
	TimeoutTimer *time.Timer              // Timeout timer for this build
}
```

PendingBuildRequest tracks an in-progress tunnel build request.

#### type ReplyProcessor

```go
type ReplyProcessor struct {
}
```

ReplyProcessor handles tunnel build reply processing with timeout and retry
logic. It manages pending build requests, decrypts encrypted reply records, and
coordinates tunnel state transitions based on build success or failure.

#### func  NewReplyProcessor

```go
func NewReplyProcessor(config ReplyProcessorConfig, tm *TunnelManager) *ReplyProcessor
```
NewReplyProcessor creates a new reply processor with the given configuration.

#### func (*ReplyProcessor) CleanupExpiredBuilds

```go
func (rp *ReplyProcessor) CleanupExpiredBuilds() int
```
CleanupExpiredBuilds removes pending builds that have exceeded their timeout.
This is a maintenance function that should be called periodically.

#### func (*ReplyProcessor) GetPendingBuildCount

```go
func (rp *ReplyProcessor) GetPendingBuildCount() int
```
GetPendingBuildCount returns the number of currently pending tunnel builds.

#### func (*ReplyProcessor) GetPendingBuildInfo

```go
func (rp *ReplyProcessor) GetPendingBuildInfo(tunnelID tunnel.TunnelID) *PendingBuildRequest
```
GetPendingBuildInfo returns information about a specific pending build. Returns
nil if the build is not found.

#### func (*ReplyProcessor) ProcessBuildReply

```go
func (rp *ReplyProcessor) ProcessBuildReply(handler TunnelReplyHandler, tunnelID tunnel.TunnelID) error
```
ProcessBuildReply processes a tunnel build reply message. It decrypts encrypted
reply records, validates responses, and updates tunnel state.

The handler parameter should be one of:

    - *TunnelBuildReply (8 hops)
    - *VariableTunnelBuildReply (1-8 hops)
    - *ShortTunnelBuildReply (1-8 hops, modern STBM format)

Returns nil on successful build, error otherwise.

#### func (*ReplyProcessor) RegisterPendingBuild

```go
func (rp *ReplyProcessor) RegisterPendingBuild(
	tunnelID tunnel.TunnelID,
	replyKeys []session_key.SessionKey,
	replyIVs [][16]byte,
	isInbound bool,
	hopCount int,
) error
```
RegisterPendingBuild registers a new tunnel build request for reply tracking.
This must be called before sending the build request to enable proper
correlation.

Parameters:

    - tunnelID: Unique identifier for this tunnel build
    - replyKeys: ECIES-X25519-AEAD decryption keys for each hop's reply record
    - replyIVs: Nonces/initialization vectors for AEAD decryption
    - isInbound: Tunnel direction (true=inbound, false=outbound)
    - hopCount: Number of hops in the tunnel

#### func (*ReplyProcessor) SetPendingBuildNoiseHashes

```go
func (rp *ReplyProcessor) SetPendingBuildNoiseHashes(tunnelID tunnel.TunnelID, noiseHashes [][32]byte) error
```
SetPendingBuildNoiseHashes stores the per-hop Noise transcript hashes for an
in-progress STBM build. These are the m_H values (Noise handshake hash after
EncryptAndHash) needed as AEAD associated data when decrypting each hop's
ShortTunnelBuildReply record. Must be called immediately after
RegisterPendingBuild.

#### func (*ReplyProcessor) SetRetryCallback

```go
func (rp *ReplyProcessor) SetRetryCallback(callback func(tunnel.TunnelID, bool, int) error)
```
SetRetryCallback sets the callback function for retrying failed builds. The
callback receives the tunnel ID, tunnel direction, and hop count.

#### func (*ReplyProcessor) Stop

```go
func (rp *ReplyProcessor) Stop()
```
Stop shuts down the reply processor, cancelling all pending timers and setting
the stopped flag to prevent retry callbacks from executing. This prevents
goroutine leaks from fire-and-forget time.AfterFunc timers that would otherwise
continue running after the processor is torn down.

#### type ReplyProcessorConfig

```go
type ReplyProcessorConfig struct {
	// BuildTimeout is the maximum time to wait for a tunnel build reply.
	// Default: 90 seconds (I2P spec recommendation).
	BuildTimeout time.Duration

	// MaxRetries is the maximum number of build retries for failed tunnels.
	// Default: 3 retries per tunnel.
	MaxRetries int

	// RetryBackoff is the delay between retry attempts.
	// Default: 5 seconds with exponential backoff.
	RetryBackoff time.Duration

	// EnableDecryption enables ECIES-X25519-AEAD (ChaCha20/Poly1305) decryption of encrypted build reply records.
	// This is the modern I2P standard (spec 0.9.44+), replacing legacy AES-256-CBC.
	// Default: true (required for production).
	EnableDecryption bool
}
```

ReplyProcessorConfig configures tunnel reply processing behavior.

#### func  DefaultReplyProcessorConfig

```go
func DefaultReplyProcessorConfig() ReplyProcessorConfig
```
DefaultReplyProcessorConfig returns the default configuration.

#### type ReplyRecordEncryptor

```go
type ReplyRecordEncryptor interface {
	// EncryptReplyRecord encrypts a BuildResponseRecord with the given reply key and IV.
	EncryptReplyRecord(record BuildResponseRecord, replyKey session_key.SessionKey, replyIV [16]byte) ([]byte, error)
}
```

ReplyRecordEncryptor encrypts tunnel build reply records. This interface is
satisfied by both BuildRecordCrypto (the concrete adapter) and test mocks.

#### type SearchReplyHandler

```go
type SearchReplyHandler interface {
	// HandleSearchReply delivers suggested peer hashes from a DatabaseSearchReply.
	// The key is the lookup target hash, and peerHashes are the suggested peers.
	HandleSearchReply(key common.Hash, peerHashes []common.Hash)
}
```

SearchReplyHandler defines the interface for delivering DatabaseSearchReply
suggestions to pending iterative Kademlia lookups.

#### type SessionKeyProvider

```go
type SessionKeyProvider interface {
	GetReplyKey() session_key.SessionKey
	GetLayerKey() session_key.SessionKey
	GetIVKey() session_key.SessionKey
}
```

SessionKeyProvider represents types that provide session keys

#### type SessionProvider

```go
type SessionProvider interface {
	GetSessionByHash(hash common.Hash) (I2NPTransportSession, error)
}
```

SessionProvider defines the interface for obtaining transport sessions

#### type SessionTagProvider

```go
type SessionTagProvider interface {
	GetReplyTags() []session_tag.SessionTag
	GetTagCount() int
}
```

SessionTagProvider represents types that provide session tags

#### type ShortTunnelBuild

```go
type ShortTunnelBuild struct {
	Count               int
	BuildRequestRecords []BuildRequestRecord
}
```

ShortTunnelBuild represents an I2NP ShortTunnelBuild message, a modern compact
format for tunnel build requests introduced in I2P 0.9.51.

#### func (*ShortTunnelBuild) Bytes

```go
func (s *ShortTunnelBuild) Bytes() []byte
```
Bytes serializes the ShortTunnelBuild message to wire format. Format:
[count:1][records...] Each record is 218 bytes per the I2P specification (ECIES
short records). The caller is responsible for applying ECIES encryption to each
record.

#### func (*ShortTunnelBuild) GetBuildRecords

```go
func (s *ShortTunnelBuild) GetBuildRecords() []BuildRequestRecord
```
GetBuildRecords returns the build request records

#### func (*ShortTunnelBuild) GetRecordCount

```go
func (s *ShortTunnelBuild) GetRecordCount() int
```
GetRecordCount returns the number of build records

#### type ShortTunnelBuildReply

```go
type ShortTunnelBuildReply struct {
	Count                int
	BuildResponseRecords []BuildResponseRecord
	RawRecordData        [][]byte // Original encrypted bytes before parsing
}
```

ShortTunnelBuildReply represents an I2NP ShortTunnelBuildReply message, the
reply counterpart to ShortTunnelBuild containing compact build response records.

#### func  NewShortTunnelBuildReply

```go
func NewShortTunnelBuildReply(records []BuildResponseRecord) *ShortTunnelBuildReply
```
NewShortTunnelBuildReply creates a new ShortTunnelBuildReply

#### func (*ShortTunnelBuildReply) GetRawReplyRecords

```go
func (s *ShortTunnelBuildReply) GetRawReplyRecords() [][]byte
```
GetRawReplyRecords returns the original encrypted record bytes.

#### func (*ShortTunnelBuildReply) GetRecordCount

```go
func (s *ShortTunnelBuildReply) GetRecordCount() int
```
GetRecordCount returns the number of response records

#### func (*ShortTunnelBuildReply) GetReplyRecords

```go
func (s *ShortTunnelBuildReply) GetReplyRecords() []BuildResponseRecord
```
GetReplyRecords returns the build response records (TunnelReplyHandler
interface)

#### func (*ShortTunnelBuildReply) GetResponseRecords

```go
func (s *ShortTunnelBuildReply) GetResponseRecords() []BuildResponseRecord
```
GetResponseRecords returns the build response records (legacy method name)

#### func (*ShortTunnelBuildReply) ProcessReply

```go
func (s *ShortTunnelBuildReply) ProcessReply() error
```
ProcessReply processes the short tunnel build reply by analyzing each response
record. Similar to VariableTunnelBuildReply but specifically for short tunnel
builds (v0.9.51+). Validates response integrity and determines tunnel build
success/failure.

#### type StatusReporter

```go
type StatusReporter interface {
	GetStatusMessageID() int
	GetTimestamp() time.Time
}
```

StatusReporter represents types that report delivery status

#### func  NewDeliveryStatusReporter

```go
func NewDeliveryStatusReporter(messageID int, timestamp time.Time) StatusReporter
```
NewDeliveryStatusReporter creates a new DeliveryStatus message and returns it as
StatusReporter interface

#### type TunnelBuild

```go
type TunnelBuild [8]BuildRequestRecord
```

TunnelBuild represents the raw 8 build request records

#### func (*TunnelBuild) GetBuildRecords

```go
func (t *TunnelBuild) GetBuildRecords() []BuildRequestRecord
```
GetBuildRecords returns the build request records

#### func (*TunnelBuild) GetRecordCount

```go
func (t *TunnelBuild) GetRecordCount() int
```
GetRecordCount returns the number of build records

#### type TunnelBuildMessage

```go
type TunnelBuildMessage struct {
	*BaseI2NPMessage
	Records TunnelBuild
}
```

TunnelBuildMessage wraps TunnelBuild to implement I2NPMessage interface

#### func  NewEncryptedTunnelBuildMessage

```go
func NewEncryptedTunnelBuildMessage(records [8]BuildRequestRecord, recipientRouterInfos [8]router_info.RouterInfo) (*TunnelBuildMessage, error)
```
NewEncryptedTunnelBuildMessage creates a new TunnelBuild I2NP message with
encrypted records.

Each BuildRequestRecord is encrypted using ECIES-X25519-AEAD encryption against
the corresponding hop's RouterInfo. This produces specification-compliant
528-byte encrypted records suitable for network transmission.

Parameters:

    - records: The 8 cleartext BuildRequestRecords
    - recipientRouterInfos: The RouterInfo for each hop (one per record)

Returns the encrypted TunnelBuildMessage or an error if encryption fails.

#### func (*TunnelBuildMessage) GetBuildRecords

```go
func (msg *TunnelBuildMessage) GetBuildRecords() []BuildRequestRecord
```
GetBuildRecords implements TunnelBuilder interface

#### func (*TunnelBuildMessage) GetRecordCount

```go
func (msg *TunnelBuildMessage) GetRecordCount() int
```
GetRecordCount implements TunnelBuilder interface

#### func (*TunnelBuildMessage) MarshalBinary

```go
func (msg *TunnelBuildMessage) MarshalBinary() ([]byte, error)
```
MarshalBinary serializes the TunnelBuild message using BaseI2NPMessage. Logs a
warning if the records have not been encrypted, as cleartext build records are
not specification-compliant for network transmission.

#### func (*TunnelBuildMessage) UnmarshalBinary

```go
func (msg *TunnelBuildMessage) UnmarshalBinary(data []byte) error
```
UnmarshalBinary parses a TunnelBuildMessage from the provided byte slice,
populating the base I2NP header and the fixed set of 8 build request records.

#### func (*TunnelBuildMessage) UnmarshalEncryptedBinary

```go
func (msg *TunnelBuildMessage) UnmarshalEncryptedBinary(data, privateKey []byte) error
```
UnmarshalEncryptedBinary deserializes and decrypts a TunnelBuild message.

Each 528-byte record is decrypted using ECIES-X25519-AEAD decryption with the
local router's private key. Only the record addressed to us (identified by
matching identity hash prefix) will decrypt successfully; other records will
fail decryption and are left as zero-value records.

Parameters:

    - data: The raw I2NP message bytes
    - privateKey: Our router's 32-byte X25519 private encryption key

Returns an error if the base message or the targeted record cannot be parsed.

#### type TunnelBuildReply

```go
type TunnelBuildReply struct {
	Records       [8]BuildResponseRecord
	RawRecordData [][]byte // Original encrypted bytes before parsing
}
```

TunnelBuildReply represents an I2NP TunnelBuildReply message containing exactly
8 build response records indicating the success or failure of a tunnel build
request.

#### func (*TunnelBuildReply) GetRawReplyRecords

```go
func (t *TunnelBuildReply) GetRawReplyRecords() [][]byte
```
GetRawReplyRecords returns the original encrypted record bytes.

#### func (*TunnelBuildReply) GetReplyRecords

```go
func (t *TunnelBuildReply) GetReplyRecords() []BuildResponseRecord
```
GetReplyRecords returns the build response records

#### func (*TunnelBuildReply) ProcessReply

```go
func (t *TunnelBuildReply) ProcessReply() error
```
ProcessReply processes the tunnel build reply by analyzing each response record.
It validates response integrity, determines tunnel build success/failure, and
returns detailed results for each hop.

#### type TunnelBuildReplyProcessor

```go
type TunnelBuildReplyProcessor interface {
	// ProcessTunnelBuildReply handles a parsed tunnel build reply.
	// handler provides the reply records, messageID correlates with the original request.
	ProcessTunnelBuildReply(handler TunnelReplyHandler, messageID int) error
}
```

TunnelBuildReplyProcessor defines the interface for processing tunnel build
reply messages. When a tunnel build reply (types 22, 24, 26) arrives, the
processor correlates it with the original build request and updates tunnel state
accordingly.

#### type TunnelBuilder

```go
type TunnelBuilder interface {
	GetBuildRecords() []BuildRequestRecord
	GetRecordCount() int
}
```

TunnelBuilder represents types that can build tunnels

#### func  NewShortTunnelBuilder

```go
func NewShortTunnelBuilder(records []BuildRequestRecord) TunnelBuilder
```
NewShortTunnelBuilder creates a new ShortTunnelBuild and returns it as
TunnelBuilder interface. This is the modern, preferred format for tunnel
building (added in I2P 0.9.51).

#### func  NewTunnelBuilder

```go
func NewTunnelBuilder(records [8]BuildRequestRecord) TunnelBuilder
```
NewTunnelBuilder creates a new TunnelBuild and returns it as TunnelBuilder
interface

#### func  NewVariableTunnelBuilder

```go
func NewVariableTunnelBuilder(records []BuildRequestRecord) TunnelBuilder
```
NewVariableTunnelBuilder creates a new VariableTunnelBuild and returns it as
TunnelBuilder interface

#### type TunnelCarrier

```go
type TunnelCarrier interface {
	GetTunnelData() []byte
	GetTunnelID() tunnel.TunnelID
}
```

TunnelCarrier represents messages that carry tunnel-related data. Per I2P spec
(tunnel-message.rst), TunnelData messages contain TunnelID(4) + IV(16) +
EncryptedData(1008) = 1028 bytes.

#### func  NewTunnelCarrier

```go
func NewTunnelCarrier(tunnelID tunnel.TunnelID, data [1024]byte) TunnelCarrier
```
NewTunnelCarrier creates a new TunnelData message and returns it as
TunnelCarrier interface.

#### type TunnelData

```go
type TunnelData [1028]byte
```

TunnelData is a fixed-size 1028-byte representation of an I2NP TunnelData
message. The first 4 bytes are the tunnel ID and the remaining 1024 bytes are
encrypted tunnel data.

For full I2NP message handling (with headers, serialization, etc.), see
TunnelDataMessage.

#### func (*TunnelData) Data

```go
func (td *TunnelData) Data() [1024]byte
```
Data returns the 1024-byte encrypted tunnel data payload (without the tunnel ID
prefix).

#### func (*TunnelData) SetData

```go
func (td *TunnelData) SetData(data [1024]byte)
```
SetData copies the provided 1024-byte payload into the data portion of the
TunnelData.

#### func (*TunnelData) SetTunnelID

```go
func (td *TunnelData) SetTunnelID(id tunnel.TunnelID)
```
SetTunnelID sets the 4-byte tunnel identifier in the TunnelData.

#### func (*TunnelData) TunnelID

```go
func (td *TunnelData) TunnelID() tunnel.TunnelID
```
TunnelID extracts the 4-byte tunnel identifier from the TunnelData.

#### type TunnelDataHandler

```go
type TunnelDataHandler interface {
	// HandleTunnelData processes an incoming TunnelData message by looking up the
	// tunnel endpoint, decrypting the payload, and delivering it to the owning session.
	HandleTunnelData(msg I2NPMessage) error
}
```

TunnelDataHandler defines the interface for handling incoming TunnelData
messages. When a TunnelData message arrives at our tunnel endpoint, the handler
decrypts it and delivers the embedded I2NP message to the appropriate I2CP
session.

#### type TunnelDataMessage

```go
type TunnelDataMessage struct {
	*BaseI2NPMessage
	TunnelID tunnel.TunnelID // 4-byte tunnel identifier
	Data     [1024]byte      // Fixed size encrypted tunnel data
}
```

TunnelDataMessage represents an I2NP TunnelData message. Per I2P spec
(tunnel-message.rst), TunnelData is TunnelID(4) + IV(16) + EncryptedData(1008) =
1028 bytes. The IV precedes the encrypted payload; the 1024 non-TunnelID bytes
are not a monolithic "data" field.

https://geti2p.net/spec/i2np#tunneldata

#### func  NewTunnelDataMessage

```go
func NewTunnelDataMessage(tunnelID tunnel.TunnelID, data [1024]byte) *TunnelDataMessage
```
NewTunnelDataMessage creates a new TunnelData message with the given tunnel ID
and data.

#### func (*TunnelDataMessage) GetTunnelData

```go
func (t *TunnelDataMessage) GetTunnelData() []byte
```
GetTunnelData returns the 1024-byte tunnel data (without the TunnelID prefix).

#### func (*TunnelDataMessage) GetTunnelID

```go
func (t *TunnelDataMessage) GetTunnelID() tunnel.TunnelID
```
GetTunnelID returns the tunnel identifier for this message.

#### func (*TunnelDataMessage) UnmarshalBinary

```go
func (t *TunnelDataMessage) UnmarshalBinary(data []byte) error
```
UnmarshalBinary deserializes a TunnelData message. The payload must be exactly
1028 bytes: 4-byte TunnelID + 1024-byte Data.

#### type TunnelGateway

```go
type TunnelGateway struct {
	*BaseI2NPMessage
	TunnelID tunnel.TunnelID
	Length   int
	Data     []byte
}
```

TunnelGateway represents an I2NP TunnelGateway message used to wrap and deliver
data through a tunnel gateway.

#### func  NewTunnelGatewayMessage

```go
func NewTunnelGatewayMessage(tunnelID tunnel.TunnelID, payload []byte) *TunnelGateway
```
NewTunnelGatewayMessage creates a new TunnelGateway message

#### func (*TunnelGateway) UnmarshalBinary

```go
func (t *TunnelGateway) UnmarshalBinary(data []byte) error
```
UnmarshalBinary deserializes a TunnelGateway message

#### type TunnelGatewayHandler

```go
type TunnelGatewayHandler interface {
	// HandleGateway processes an incoming TunnelGateway message by looking up the tunnel,
	// encrypting the payload, and forwarding it to the next hop.
	HandleGateway(tunnelID tunnel.TunnelID, payload []byte) error
}
```

TunnelGatewayHandler defines the interface for handling TunnelGateway messages.
When a TunnelGateway message arrives, the handler looks up the tunnel by ID,
encrypts the payload using the tunnel's layered encryption, and forwards the
resulting TunnelData message to the next hop.

#### type TunnelIdentifier

```go
type TunnelIdentifier interface {
	GetReceiveTunnel() tunnel.TunnelID
	GetNextTunnel() tunnel.TunnelID
}
```

TunnelIdentifier represents types that identify tunnel endpoints

#### func  CreateTunnelRecord

```go
func CreateTunnelRecord(receiveTunnel, nextTunnel tunnel.TunnelID,
	ourIdent, nextIdent common.Hash,
) TunnelIdentifier
```
CreateTunnelRecord creates a build request record with interface methods

#### type TunnelManager

```go
type TunnelManager struct {
}
```

TunnelManager coordinates tunnel building and management

#### func  NewTunnelManager

```go
func NewTunnelManager(peerSelector tunnel.PeerSelector) *TunnelManager
```
NewTunnelManager creates a new tunnel manager with build request tracking. The
background cleanup goroutine is started lazily on the first build request,
avoiding resource leaks if the TunnelManager is created but never used. Creates
separate inbound and outbound tunnel pools for proper statistics tracking.

#### func (*TunnelManager) BuildTunnel

```go
func (tm *TunnelManager) BuildTunnel(req tunnel.BuildTunnelRequest) (*tunnel.BuildTunnelResult, error)
```
BuildTunnel implements tunnel.BuilderInterface for automatic pool maintenance.
This adapter method wraps BuildTunnelFromRequest to match the interface
signature. It returns peer hashes extracted from the build request so that
failed builds can report which peers were involved for progressive exclusion on
retry.

#### func (*TunnelManager) BuildTunnelFromRequest

```go
func (tm *TunnelManager) BuildTunnelFromRequest(req tunnel.BuildTunnelRequest) (tunnel.TunnelID, []common.Hash, error)
```
BuildTunnelFromRequest builds a tunnel from a BuildTunnelRequest using the
tunnel.TunnelBuilder. This is the recommended method for building tunnels with
proper request tracking and retry support.

The method: 1. Uses tunnel.TunnelBuilder to create encrypted build records 2.
Generates a unique message ID for request/reply correlation 3. Tracks the
pending build request with reply decryption keys 4. Sends the build request via
appropriate transport 5. Returns the tunnel ID, selected peer hashes, and any
error

#### func (*TunnelManager) BuildTunnelWithBuilder

```go
func (tm *TunnelManager) BuildTunnelWithBuilder(builder TunnelBuilder) error
```
BuildTunnelWithBuilder builds a tunnel using the i2np.TunnelBuilder message
interface. This is used for message routing and differs from BuildTunnel
(tunnel.BuilderInterface).

#### func (*TunnelManager) GetBuildAvgTimeMs

```go
func (tm *TunnelManager) GetBuildAvgTimeMs(windowMs int64) float64
```
GetBuildAvgTimeMs returns the average tunnel build time in milliseconds for
builds completed within windowMs milliseconds. Maps to the Java I2P stat
"tunnel.buildRequestTime". Returns 0 if no successful builds have been recorded
in the window.

#### func (*TunnelManager) GetBuildExpireCount

```go
func (tm *TunnelManager) GetBuildExpireCount(windowMs int64) float64
```
GetBuildExpireCount returns the number of timed-out tunnel builds within
windowMs milliseconds. Maps to the Java I2P stat
"tunnel.buildExploratoryExpire".

#### func (*TunnelManager) GetBuildRejectCount

```go
func (tm *TunnelManager) GetBuildRejectCount(windowMs int64) float64
```
GetBuildRejectCount returns the number of explicitly rejected tunnel builds
within windowMs milliseconds. Maps to the Java I2P stat
"tunnel.buildExploratoryReject".

#### func (*TunnelManager) GetBuildSuccessCount

```go
func (tm *TunnelManager) GetBuildSuccessCount(windowMs int64) float64
```
GetBuildSuccessCount returns the number of successful tunnel builds within
windowMs milliseconds. Maps to the Java I2P stat
"tunnel.buildExploratorySuccess".

#### func (*TunnelManager) GetClientBuildSuccessCount

```go
func (tm *TunnelManager) GetClientBuildSuccessCount(windowMs int64) float64
```
GetClientBuildSuccessCount returns the number of successful I2CP client session
tunnel builds within windowMs milliseconds. Maps to the Java I2P stat
"tunnel.buildClientSuccess".

#### func (*TunnelManager) GetInboundPool

```go
func (tm *TunnelManager) GetInboundPool() *tunnel.Pool
```
GetInboundPool returns the inbound tunnel pool.

#### func (*TunnelManager) GetOutboundPool

```go
func (tm *TunnelManager) GetOutboundPool() *tunnel.Pool
```
GetOutboundPool returns the outbound tunnel pool.

#### func (*TunnelManager) GetPool

```go
func (tm *TunnelManager) GetPool() *tunnel.Pool
```
GetPool returns the outbound tunnel pool for backward compatibility. Deprecated:
Use GetInboundPool() or GetOutboundPool() for specific pools.

#### func (*TunnelManager) ProcessTunnelBuildReply

```go
func (tm *TunnelManager) ProcessTunnelBuildReply(handler TunnelReplyHandler, messageID int) error
```
ProcessTunnelBuildReply satisfies the TunnelBuildReplyProcessor interface used
by MessageProcessor. It delegates to ProcessTunnelReply so that the single
pendingBuilds map is consulted for reply correlation (A4 fix).

#### func (*TunnelManager) ProcessTunnelReply

```go
func (tm *TunnelManager) ProcessTunnelReply(handler TunnelReplyHandler, messageID int) error
```
ProcessTunnelReply processes tunnel build replies using TunnelReplyHandler
interface. This method integrates with the tunnel pool to update tunnel states
and handle build completions. Uses message ID to correlate the reply with the
original build request.

#### func (*TunnelManager) SetGarlicKeyRegistrar

```go
func (tm *TunnelManager) SetGarlicKeyRegistrar(r GarlicKeyRegistrar)
```
SetGarlicKeyRegistrar wires the GarlicKeyRegistrar so that one-time garlic reply
keys derived from STBM builds can be registered for later decryption. Must be
called before the first tunnel build is initiated.

#### func (*TunnelManager) SetOurRouterHash

```go
func (tm *TunnelManager) SetOurRouterHash(hash common.Hash)
```
SetOurRouterHash propagates our router's identity hash to both tunnel pools so
they can populate the ReplyGateway field in build requests. Without this, the
last hop in every tunnel build sends its reply to an all-zeros peer and the
reply is never received.

#### func (*TunnelManager) SetSessionProvider

```go
func (tm *TunnelManager) SetSessionProvider(provider SessionProvider)
```
SetSessionProvider sets the session provider for sending tunnel build messages

#### func (*TunnelManager) Stop

```go
func (tm *TunnelManager) Stop()
```
Stop gracefully stops the tunnel manager and cleans up resources. Safe to call
multiple times — subsequent calls are no-ops. Should be called when shutting
down the router.

#### type TunnelReplyHandler

```go
type TunnelReplyHandler interface {
	GetReplyRecords() []BuildResponseRecord
	// GetRawReplyRecords returns the raw encrypted record bytes before parsing.
	// This is needed for decryption: re-serializing parsed records corrupts
	// the original ciphertext. Returns nil if raw records were not preserved.
	GetRawReplyRecords() [][]byte
	ProcessReply() error
}
```

TunnelReplyHandler represents types that handle tunnel build replies

#### type VariableTunnelBuild

```go
type VariableTunnelBuild struct {
	Count               int
	BuildRequestRecords []BuildRequestRecord
}
```

VariableTunnelBuild represents an I2NP VariableTunnelBuild message containing a
variable number of build request records for tunnel construction.

#### func (*VariableTunnelBuild) GetBuildRecords

```go
func (v *VariableTunnelBuild) GetBuildRecords() []BuildRequestRecord
```
GetBuildRecords returns the build request records

#### func (*VariableTunnelBuild) GetRecordCount

```go
func (v *VariableTunnelBuild) GetRecordCount() int
```
GetRecordCount returns the number of build records

#### type VariableTunnelBuildReply

```go
type VariableTunnelBuildReply struct {
	Count                int
	BuildResponseRecords []BuildResponseRecord
	RawRecordData        [][]byte // Original encrypted bytes before parsing
}
```

VariableTunnelBuildReply represents an I2NP VariableTunnelBuildReply message
containing a variable number of build response records.

#### func (*VariableTunnelBuildReply) GetRawReplyRecords

```go
func (v *VariableTunnelBuildReply) GetRawReplyRecords() [][]byte
```
GetRawReplyRecords returns the original encrypted record bytes.

#### func (*VariableTunnelBuildReply) GetReplyRecords

```go
func (v *VariableTunnelBuildReply) GetReplyRecords() []BuildResponseRecord
```
GetReplyRecords returns the build response records

#### func (*VariableTunnelBuildReply) ProcessReply

```go
func (v *VariableTunnelBuildReply) ProcessReply() error
```
ProcessReply processes the variable tunnel build reply by analyzing each
response record. Similar to TunnelBuildReply but handles variable-length tunnels
(1-8 hops). Validates response integrity and determines tunnel build
success/failure.



i2np 

github.com/go-i2p/go-i2p/lib/i2np

[go-i2p template file](template.md)
