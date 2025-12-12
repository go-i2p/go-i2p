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
    ds, err := i2np.NewDatabaseStoreMessage(hash, data, i2np.ROUTER_INFO_TYPE)
    if err != nil {
        log.Printf("Failed to create message: %v", err)
    }

    // Send via transport
    if err := transport.SendMessage(peerHash, ds); err != nil {
        log.Printf("Failed to send: %v", err)
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
	I2NP_MESSAGE_TYPE_DATABASE_STORE              = 1
	I2NP_MESSAGE_TYPE_DATABASE_LOOKUP             = 2
	I2NP_MESSAGE_TYPE_DATABASE_SEARCH_REPLY       = 3
	I2NP_MESSAGE_TYPE_DELIVERY_STATUS             = 10
	I2NP_MESSAGE_TYPE_GARLIC                      = 11
	I2NP_MESSAGE_TYPE_TUNNEL_DATA                 = 18
	I2NP_MESSAGE_TYPE_TUNNEL_GATEWAY              = 19
	I2NP_MESSAGE_TYPE_DATA                        = 20
	I2NP_MESSAGE_TYPE_TUNNEL_BUILD                = 21
	I2NP_MESSAGE_TYPE_TUNNEL_BUILD_REPLY          = 22
	I2NP_MESSAGE_TYPE_VARIABLE_TUNNEL_BUILD       = 23
	I2NP_MESSAGE_TYPE_VARIABLE_TUNNEL_BUILD_REPLY = 24
	I2NP_MESSAGE_TYPE_SHORT_TUNNEL_BUILD          = 25
	I2NP_MESSAGE_TYPE_SHORT_TUNNEL_BUILD_REPLY    = 26
)
```
I2NP Message Type Constants Moved from: header.go

```go
const (
	// DATABASE_STORE_TYPE_ROUTER_INFO indicates a RouterInfo entry
	DATABASE_STORE_TYPE_ROUTER_INFO = 0
	// DATABASE_STORE_TYPE_LEASESET indicates original LeaseSet (deprecated)
	DATABASE_STORE_TYPE_LEASESET = 1
	// DATABASE_STORE_TYPE_LEASESET2 indicates LeaseSet2 (standard as of 0.9.38+)
	DATABASE_STORE_TYPE_LEASESET2 = 3
	// DATABASE_STORE_TYPE_ENCRYPTED_LEASESET indicates EncryptedLeaseSet (0.9.39+, not yet implemented)
	DATABASE_STORE_TYPE_ENCRYPTED_LEASESET = 5
	// DATABASE_STORE_TYPE_META_LEASESET indicates MetaLeaseSet (0.9.40+, not yet implemented)
	DATABASE_STORE_TYPE_META_LEASESET = 7
)
```
DatabaseStore type constants (bits 3-0 of type field)

```go
const (
	TUNNEL_BUILD_REPLY_SUCCESS   = 0x00 // Tunnel hop accepted the request
	TUNNEL_BUILD_REPLY_REJECT    = 0x01 // General rejection
	TUNNEL_BUILD_REPLY_OVERLOAD  = 0x02 // Router is overloaded
	TUNNEL_BUILD_REPLY_BANDWIDTH = 0x03 // Insufficient bandwidth
	TUNNEL_BUILD_REPLY_INVALID   = 0x04 // Invalid request data
	TUNNEL_BUILD_REPLY_EXPIRED   = 0x05 // Request has expired
)
```
TunnelBuildReply constants for processing responses

```go
var (
	ERR_I2NP_NOT_ENOUGH_DATA                  = oops.Errorf("not enough i2np header data")
	ERR_BUILD_REQUEST_RECORD_NOT_ENOUGH_DATA  = oops.Errorf("not enough i2np build request record data")
	ERR_BUILD_RESPONSE_RECORD_NOT_ENOUGH_DATA = oops.Errorf("not enough i2np build response record data")
	ERR_DATABASE_LOOKUP_NOT_ENOUGH_DATA       = oops.Errorf("not enough i2np database lookup data")
	ERR_DATABASE_LOOKUP_INVALID_SIZE          = oops.Errorf("database lookup excluded peers size exceeds protocol limit")
)
```
I2NP Error Constants Moved from: header.go, build_request_record.go,
build_response_record.go, database_lookup.go

#### func  EncryptBuildRequestRecord

```go
func EncryptBuildRequestRecord(record BuildRequestRecord, recipientRouterInfo router_info.RouterInfo) ([528]byte, error)
```
EncryptBuildRequestRecord encrypts a BuildRequestRecord using ECIES-X25519-AEAD
encryption.

This implements the I2P specification for encrypted tunnel build records. The
222-byte cleartext record is encrypted using the recipient router's X25519
public key, then padded to the standard 528-byte format.

Format:

    - Bytes 0-15: First 16 bytes of SHA-256 hash of recipient's RouterIdentity
    - Bytes 16-527: ECIES-X25519 encrypted data

The ECIES encryption produces:
[ephemeral_pubkey(32)][nonce(12)][aead_ciphertext(222+16_tag=238)] Total ECIES
output: 32 + 12 + 238 = 282 bytes Remaining padding: 512 - 282 = 230 bytes of
zeros

Parameters:

    - record: The cleartext BuildRequestRecord (serializes to 222 bytes)
    - recipientRouterInfo: The RouterInfo of the hop that will decrypt this record

Returns:

    - [528]byte: Encrypted build request record ready for network transmission
    - error: Any encryption error encountered

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

#### func  ExtractIdentityHashPrefix

```go
func ExtractIdentityHashPrefix(encrypted [528]byte) common.Hash
```
ExtractIdentityHashPrefix returns the first 16 bytes of an encrypted record.

This is useful for debugging and logging to identify which router a record is
intended for without performing full decryption.

Parameters:

    - encrypted: The 528-byte encrypted build request record

Returns:

    - common.Hash: The identity hash prefix (first 16 bytes copied to Hash type)

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
func ReadI2NPNTCPMessageExpiration(data []byte) (datalib.Date, error)
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
func ReadI2NPSSUMessageExpiration(data []byte) (datalib.Date, error)
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

#### func  VerifyIdentityHash

```go
func VerifyIdentityHash(encrypted [528]byte, ourRouterInfo router_info.RouterInfo) bool
```
VerifyIdentityHash checks if an encrypted BuildRequestRecord is intended for us.

This provides a fast pre-check before attempting decryption by comparing the
first 16 bytes of the record (identity hash prefix) with our own identity hash.

Parameters:

    - encrypted: The 528-byte encrypted build request record
    - ourRouterInfo: Our router's RouterInfo

Returns:

    - bool: true if the record is likely intended for us, false otherwise

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
NewBaseI2NPMessage creates a new base I2NP message

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
MarshalBinary serializes the I2NP message according to NTCP format

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

#### type BuildRecordCrypto

```go
type BuildRecordCrypto struct {
}
```

BuildRecordCrypto provides encryption/decryption for tunnel build records. Uses
modern ChaCha20-Poly1305 AEAD encryption (I2P 0.9.44+).

#### func  NewBuildRecordCrypto

```go
func NewBuildRecordCrypto() *BuildRecordCrypto
```
NewBuildRecordCrypto creates a new build record crypto handler. Uses modern
ChaCha20-Poly1305 AEAD encryption (I2P 0.9.44+).

#### func (*BuildRecordCrypto) DecryptReplyRecord

```go
func (c *BuildRecordCrypto) DecryptReplyRecord(
	encryptedData []byte,
	replyKey session_key.SessionKey,
	replyIV [16]byte,
) (BuildResponseRecord, error)
```
DecryptReplyRecord decrypts an encrypted BuildResponseRecord. This is the
counterpart to EncryptReplyRecord, used by the tunnel creator to decrypt replies
from participants.

Uses ChaCha20-Poly1305 AEAD decryption (I2P 0.9.44+). Expects 544 bytes input
(528 ciphertext + 16 auth tag).

#### func (*BuildRecordCrypto) EncryptReplyRecord

```go
func (c *BuildRecordCrypto) EncryptReplyRecord(
	record BuildResponseRecord,
	replyKey session_key.SessionKey,
	replyIV [16]byte,
) ([]byte, error)
```
EncryptReplyRecord encrypts a BuildResponseRecord using the reply key and IV.
This encrypts the 528-byte response record that participants send back to the
tunnel creator during tunnel build.

Uses ChaCha20-Poly1305 AEAD encryption (I2P 0.9.44+):

    Output: 528 bytes encrypted data + 16 bytes authentication tag = 544 bytes

Format (cleartext before encryption):

    bytes 0-31:   SHA-256 hash of bytes 32-527
    bytes 32-526: Random data
    byte 527:     Reply status code

The reply key and IV are provided in the BuildRequestRecord.

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


#### func  DecryptBuildRequestRecord

```go
func DecryptBuildRequestRecord(encrypted [528]byte, privateKey []byte) (BuildRequestRecord, error)
```
DecryptBuildRequestRecord decrypts an encrypted BuildRequestRecord using
ECIES-X25519-AEAD.

This implements the I2P specification for decrypting tunnel build records. The
recipient router uses its X25519 private key to decrypt the 512-byte ciphertext
portion, extracting the 222-byte cleartext BuildRequestRecord.

Format:

    - Bytes 0-15: First 16 bytes of SHA-256 hash of our RouterIdentity (ignored during decryption)
    - Bytes 16-527: ECIES-X25519 encrypted data (ephemeral_pubkey + nonce + aead_ciphertext)

Parameters:

    - encrypted: The 528-byte encrypted build request record
    - privateKey: Our router's X25519 private encryption key (32 bytes)

Returns:

    - BuildRequestRecord: Decrypted and parsed build request record
    - error: Any decryption or parsing error encountered

#### func  ReadBuildRequestRecord

```go
func ReadBuildRequestRecord(data []byte) (BuildRequestRecord, error)
```

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

#### func  CreateBuildResponseRecord

```go
func CreateBuildResponseRecord(reply byte, randomData [495]byte) BuildResponseRecord
```
CreateBuildResponseRecord creates a new BuildResponseRecord with proper hash.
This is a helper function for participants to create valid response records.

Parameters:

    - reply: Status code (0=accept, non-zero=reject reason)
    - randomData: 495 bytes of random data (should be cryptographically random)

Returns a BuildResponseRecord with the SHA-256 hash properly computed.

#### func  ReadBuildResponseRecord

```go
func ReadBuildResponseRecord(data []byte) (BuildResponseRecord, error)
```

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

#### type DatabaseLookup

```go
type DatabaseLookup struct {
	Key           common.Hash
	From          common.Hash
	Flags         byte
	ReplyTunnelID [4]byte
	Size          int
	ExcludedPeers []common.Hash
	ReplyKey      session_key.SessionKey
	Tags          int
	ReplyTags     []session_tag.SessionTag
}
```


#### func  ReadDatabaseLookup

```go
func ReadDatabaseLookup(data []byte) (DatabaseLookup, error)
```

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

#### type DatabaseManager

```go
type DatabaseManager struct {
}
```

DatabaseManager demonstrates database-related interface usage DatabaseManager
demonstrates database-related interface usage

#### func  NewDatabaseManager

```go
func NewDatabaseManager(netdb NetDBStore) *DatabaseManager
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
	Key        common.Hash
	Count      int
	PeerHashes []common.Hash
	From       common.Hash
}
```


#### func  NewDatabaseSearchReply

```go
func NewDatabaseSearchReply(key, from common.Hash, peerHashes []common.Hash) *DatabaseSearchReply
```
NewDatabaseSearchReply creates a new DatabaseSearchReply message

#### func (*DatabaseSearchReply) MarshalBinary

```go
func (d *DatabaseSearchReply) MarshalBinary() ([]byte, error)
```
MarshalBinary serializes the DatabaseSearchReply message

#### type DatabaseStore

```go
type DatabaseStore struct {
	Key           common.Hash
	Type          byte
	ReplyToken    [4]byte
	ReplyTunnelID [4]byte
	ReplyGateway  common.Hash
	Data          []byte
}
```


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
field. Returns one of: DATABASE_STORE_TYPE_ROUTER_INFO,
DATABASE_STORE_TYPE_LEASESET, DATABASE_STORE_TYPE_LEASESET2,
DATABASE_STORE_TYPE_ENCRYPTED_LEASESET, or DATABASE_STORE_TYPE_META_LEASESET.

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
MarshalBinary serializes the DatabaseStore message

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

#### type GarlicProcessor

```go
type GarlicProcessor interface {
	GetCloves() []GarlicClove
	GetCloveCount() int
}
```

GarlicProcessor represents types that process garlic messages

#### type GarlicSession

```go
type GarlicSession struct {
	RemotePublicKey  [32]byte
	DHRatchet        *ratchet.DHRatchet
	SymmetricRatchet *ratchet.SymmetricRatchet
	TagRatchet       *ratchet.TagRatchet
	LastUsed         time.Time
	MessageCounter   uint32
}
```

GarlicSession represents an active encrypted session with a remote destination.

#### type GarlicSessionManager

```go
type GarlicSessionManager struct {
}
```

GarlicSessionManager manages ECIES-X25519-AEAD-Ratchet sessions for garlic
encryption. It maintains session state for ongoing encrypted communication with
remote destinations.

Session lifecycle: 1. New Session: First message uses ephemeral-static DH
(ECIES) 2. Existing Session: Subsequent messages use ratchet for forward secrecy
3. Session Expiry: Sessions expire after inactivity timeout

Performance: - O(1) tag lookup using hash-based index - Tag window tracking for
out-of-order message handling

#### func  GenerateGarlicSessionManager

```go
func GenerateGarlicSessionManager() (*GarlicSessionManager, error)
```
GenerateGarlicSessionManager creates a garlic session manager with a freshly
generated key pair.

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
CleanupExpiredSessions removes sessions that haven't been used recently. Should
be called periodically to prevent memory leaks. This also cleans up any tags
associated with expired sessions from the tag index.

#### func (*GarlicSessionManager) DecryptGarlicMessage

```go
func (sm *GarlicSessionManager) DecryptGarlicMessage(encryptedGarlic []byte) ([]byte, [8]byte, error)
```
DecryptGarlicMessage decrypts an encrypted garlic message. This handles both New
Session and Existing Session message types.

Parameters: - encryptedGarlic: Encrypted garlic message received via I2NP

Returns: - Decrypted plaintext garlic message (can be parsed into Garlic struct)
- Session tag (if Existing Session), empty array if New Session

#### func (*GarlicSessionManager) EncryptGarlicMessage

```go
func (sm *GarlicSessionManager) EncryptGarlicMessage(
	destinationHash common.Hash,
	destinationPubKey [32]byte,
	plaintextGarlic []byte,
) ([]byte, error)
```
EncryptGarlicMessage encrypts a plaintext garlic message for the given
destination. This uses ECIES-X25519-AEAD-Ratchet encryption: - First message to
destination: New Session (ephemeral-static DH) - Subsequent messages: Existing
Session (uses ratchet state)

Parameters: - destinationHash: Hash of the destination's public key -
destinationPubKey: The destination's X25519 public key (32 bytes) -
plaintextGarlic: Serialized garlic message (from
GarlicBuilder.BuildAndSerialize)

Returns encrypted garlic message ready to send via I2NP.

#### func (*GarlicSessionManager) GetSessionCount

```go
func (sm *GarlicSessionManager) GetSessionCount() int
```
GetSessionCount returns the number of active sessions.

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
func (f *I2NPMessageFactory) CreateTunnelDataMessage(data [1024]byte) I2NPMessage
```
CreateTunnelDataMessage creates a new tunnel data message

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

When transmitted over [NTCP2] or [SSU2], the 16-byte standard header is not
used. Only a 1-byte type, 4-byte message id, and a 4-byte expiration in seconds
are included. The size is incorporated in the NTCP2 and SSU2 data packet
formats. The checksum is not required since errors are caught in decryption.

#### func  ReadI2NPSecondGenTransportHeader

```go
func ReadI2NPSecondGenTransportHeader(dat []byte) (I2NPSecondGenTransportHeader, error)
```
ReadI2NPSecondGenTransportHeader reads an I2NP NTCP2 or SSU2 header When
transmitted over [NTCP2] or [SSU2], the 16-byte standard header is not used.
Only a 1-byte type, 4-byte message id, and a 4-byte expiration in seconds are
included. The size is incorporated in the NTCP2 and SSU2 data packet formats.
The checksum is not required since errors are caught in decryption.

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

MessageProcessor demonstrates interface-based message processing

#### func  NewMessageProcessor

```go
func NewMessageProcessor() *MessageProcessor
```
NewMessageProcessor creates a new message processor

#### func (*MessageProcessor) ProcessMessage

```go
func (p *MessageProcessor) ProcessMessage(msg I2NPMessage) error
```
ProcessMessage processes any I2NP message using interfaces

#### func (*MessageProcessor) SetCloveForwarder

```go
func (p *MessageProcessor) SetCloveForwarder(forwarder GarlicCloveForwarder)
```
SetCloveForwarder sets the garlic clove forwarder for handling non-LOCAL
delivery types. This is optional - if not set, only LOCAL delivery (0x00) will
be processed. The forwarder enables DESTINATION (0x01), ROUTER (0x02), and
TUNNEL (0x03) deliveries.

#### func (*MessageProcessor) SetGarlicSessionManager

```go
func (p *MessageProcessor) SetGarlicSessionManager(garlicMgr *GarlicSessionManager)
```
SetGarlicSessionManager sets the garlic session manager for decrypting garlic
messages. This must be called before processing garlic messages, otherwise they
will fail with an error.

#### type MessageRouter

```go
type MessageRouter struct {
}
```

MessageRouter demonstrates advanced interface-based routing

#### func  NewMessageRouter

```go
func NewMessageRouter(config MessageRouterConfig) *MessageRouter
```
NewMessageRouter creates a new message router

#### func (*MessageRouter) GetProcessor

```go
func (mr *MessageRouter) GetProcessor() *MessageProcessor
```
GetProcessor returns the underlying MessageProcessor for direct access. This is
used by the router to set up garlic clove forwarding.

#### func (*MessageRouter) RouteDatabaseMessage

```go
func (mr *MessageRouter) RouteDatabaseMessage(msg interface{}) error
```
RouteDatabaseMessage routes database-related messages

#### func (*MessageRouter) RouteMessage

```go
func (mr *MessageRouter) RouteMessage(msg I2NPMessage) error
```
RouteMessage routes messages based on their interfaces

#### func (*MessageRouter) RouteTunnelMessage

```go
func (mr *MessageRouter) RouteTunnelMessage(msg interface{}) error
```
RouteTunnelMessage routes tunnel-related messages

#### func (*MessageRouter) SetNetDB

```go
func (mr *MessageRouter) SetNetDB(netdb NetDBStore)
```
SetNetDB sets the NetDB store for database operations. If the netdb implements
FloodfillSelector, it will also be configured for floodfill functionality.

#### func (*MessageRouter) SetOurRouterHash

```go
func (mr *MessageRouter) SetOurRouterHash(hash common.Hash)
```
SetOurRouterHash sets our router's identity hash for use in DatabaseSearchReply
messages. This should be called during router initialization with the router's
own identity hash. The hash is used in DatabaseSearchReply "from" field to
indicate which router sent the reply.

#### func (*MessageRouter) SetPeerSelector

```go
func (mr *MessageRouter) SetPeerSelector(selector tunnel.PeerSelector)
```
SetPeerSelector sets the peer selector for the TunnelManager

#### func (*MessageRouter) SetSessionProvider

```go
func (mr *MessageRouter) SetSessionProvider(provider SessionProvider)
```
SetSessionProvider configures the session provider for message routing
responses. This method propagates the SessionProvider to both DatabaseManager
and TunnelManager, enabling them to send I2NP response messages (DatabaseStore,
DatabaseSearchReply, etc.) back through the appropriate transport sessions. The
provider must implement SessionProvider interface with GetSessionByHash method.

#### type MessageRouterConfig

```go
type MessageRouterConfig struct {
	MaxRetries     int
	DefaultTimeout time.Duration
	EnableLogging  bool
}
```

MessageRouterConfig represents configuration for message routing

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

#### type NetDBStore

```go
type NetDBStore interface {
	StoreRouterInfo(key common.Hash, data []byte, dataType byte) error
}
```

NetDBStore defines the interface for storing RouterInfo entries

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

#### func (*ReplyProcessor) SetRetryCallback

```go
func (rp *ReplyProcessor) SetRetryCallback(callback func(tunnel.TunnelID, bool, int) error)
```
SetRetryCallback sets the callback function for retrying failed builds. The
callback receives the tunnel ID, tunnel direction, and hop count.

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

#### type SessionKeyProvider

```go
type SessionKeyProvider interface {
	GetReplyKey() session_key.SessionKey
	GetLayerKey() session_key.SessionKey
	GetIVKey() session_key.SessionKey
}
```

SessionKeyProvider represents types that provide session keys

#### type SessionManager

```go
type SessionManager struct{}
```

SessionManager demonstrates session-related interface usage

#### func  NewSessionManager

```go
func NewSessionManager() *SessionManager
```
NewSessionManager creates a new session manager

#### func (*SessionManager) ProcessKeys

```go
func (sm *SessionManager) ProcessKeys(provider SessionKeyProvider) error
```
ProcessKeys processes session keys using SessionKeyProvider interface

#### func (*SessionManager) ProcessTags

```go
func (sm *SessionManager) ProcessTags(provider SessionTagProvider) error
```
ProcessTags processes session tags using SessionTagProvider interface

#### type SessionProvider

```go
type SessionProvider interface {
	GetSessionByHash(hash common.Hash) (TransportSession, error)
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


#### func (*ShortTunnelBuild) Bytes

```go
func (s *ShortTunnelBuild) Bytes() []byte
```
Bytes serializes the ShortTunnelBuild message to wire format. Format:
[count:1][records...] Note: This returns the cleartext records. Encryption must
be applied by the caller.

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
}
```


#### func  NewShortTunnelBuildReply

```go
func NewShortTunnelBuildReply(records []BuildResponseRecord) *ShortTunnelBuildReply
```
NewShortTunnelBuildReply creates a new ShortTunnelBuildReply

#### func (*ShortTunnelBuildReply) GetRecordCount

```go
func (s *ShortTunnelBuildReply) GetRecordCount() int
```
GetRecordCount returns the number of response records

#### func (*ShortTunnelBuildReply) GetResponseRecords

```go
func (s *ShortTunnelBuildReply) GetResponseRecords() []BuildResponseRecord
```
GetResponseRecords returns the build response records

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

#### type TransportSession

```go
type TransportSession interface {
	QueueSendI2NP(msg I2NPMessage)
	SendQueueSize() int
}
```

TransportSession defines the interface for sending I2NP messages back to
requesters

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

#### func  NewTunnelBuildMessage

```go
func NewTunnelBuildMessage(records [8]BuildRequestRecord) *TunnelBuildMessage
```
NewTunnelBuildMessage creates a new TunnelBuild I2NP message

SPECIFICATION COMPLIANCE NOTE: According to I2P specification
(https://geti2p.net/spec/i2np), BuildRequestRecords MUST be encrypted before
transmission using either:

    - ElGamal-2048 encryption (legacy format, 528 bytes)
    - ECIES-X25519-AEAD-Ratchet encryption (modern format, I2P 0.9.44+)

CURRENT LIMITATION: This implementation currently creates CLEARTEXT records (222
bytes + 306 padding = 528 bytes). For specification-compliant tunnel building,
use EncryptBuildRequestRecord() from build_record_crypto.go which implements
proper ECIES-X25519-AEAD encryption.

For specification-compliant tunnel building, encryption must be added using:

    1. Recipient router's encryption public key (from RouterInfo)
    2. ECIES-X25519-AEAD encryption (see build_record_crypto.go)
    3. Proper padding and formatting per specification

Use EncryptBuildRequestRecord() function (defined in build_record_crypto.go)
that takes:

    - BuildRequestRecord (cleartext)
    - Recipient RouterInfo (for encryption public key)
    - Returns encrypted 528-byte record

This method is suitable for:

    - Local testing with cooperating routers that accept cleartext
    - Internal message structure creation before encryption
    - Unit testing of serialization logic

DO NOT USE for production tunnel building without implementing encryption first.

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
MarshalBinary serializes the TunnelBuild message using BaseI2NPMessage

#### func (*TunnelBuildMessage) UnmarshalBinary

```go
func (msg *TunnelBuildMessage) UnmarshalBinary(data []byte) error
```
UnmarshalBinary deserializes the TunnelBuild message

SPECIFICATION COMPLIANCE NOTE: According to I2P specification,
BuildRequestRecords in TunnelBuild messages are encrypted with
ECIES-X25519-AEAD. This implementation assumes CLEARTEXT records (for testing or
from trusted sources).

For specification-compliant processing of network messages:

    1. Decrypt each 528-byte chunk using DecryptBuildRequestRecord() from build_record_crypto.go
    2. This function uses local router's private encryption key
    3. Verifies AEAD authentication and extracts 222-byte cleartext
    4. Parse using ReadBuildRequestRecord()

CURRENT LIMITATION: This method parses cleartext records directly from the
528-byte chunks without decryption. Encrypted records from production I2P
routers will FAIL to parse correctly.

Use DecryptBuildRequestRecord() (defined in build_record_crypto.go) that takes:

    - 528-byte encrypted record
    - Local router's decryption private key
    - Returns decrypted BuildRequestRecord

#### type TunnelBuildReply

```go
type TunnelBuildReply [8]BuildResponseRecord
```


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
}
```

TunnelCarrier represents messages that carry tunnel-related data

#### func  NewTunnelCarrier

```go
func NewTunnelCarrier(data [1024]byte) TunnelCarrier
```
NewTunnelCarrier creates a new TunnelData message and returns it as
TunnelCarrier interface

#### type TunnelData

```go
type TunnelData [1028]byte
```


#### type TunnelDataMessage

```go
type TunnelDataMessage struct {
	*BaseI2NPMessage
	Data [1024]byte // Fixed size tunnel data
}
```

TunnelDataMessage represents an I2NP TunnelData message Moved from: messages.go

#### func  NewTunnelDataMessage

```go
func NewTunnelDataMessage(data [1024]byte) *TunnelDataMessage
```
NewTunnelDataMessage creates a new TunnelData message

#### func (*TunnelDataMessage) GetTunnelData

```go
func (t *TunnelDataMessage) GetTunnelData() []byte
```
GetTunnelData returns the tunnel data

#### func (*TunnelDataMessage) UnmarshalBinary

```go
func (t *TunnelDataMessage) UnmarshalBinary(data []byte) error
```
UnmarshalBinary deserializes a TunnelData message

#### type TunnelGatway

```go
type TunnelGatway struct {
	*BaseI2NPMessage
	TunnelID tunnel.TunnelID
	Length   int
	Data     []byte
}
```


#### func  NewTunnelGatewayMessage

```go
func NewTunnelGatewayMessage(tunnelID tunnel.TunnelID, payload []byte) *TunnelGatway
```
NewTunnelGatewayMessage creates a new TunnelGateway message

#### func (*TunnelGatway) UnmarshalBinary

```go
func (t *TunnelGatway) UnmarshalBinary(data []byte) error
```
UnmarshalBinary deserializes a TunnelGateway message

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
NewTunnelManager creates a new tunnel manager with build request tracking.
Starts a background goroutine for cleaning up expired build requests. Creates
separate inbound and outbound tunnel pools for proper statistics tracking.

#### func (*TunnelManager) BuildTunnel

```go
func (tm *TunnelManager) BuildTunnel(req tunnel.BuildTunnelRequest) (tunnel.TunnelID, error)
```
BuildTunnel implements tunnel.BuilderInterface for automatic pool maintenance.
This adapter method wraps BuildTunnelFromRequest to match the interface
signature.

#### func (*TunnelManager) BuildTunnelFromRequest

```go
func (tm *TunnelManager) BuildTunnelFromRequest(req tunnel.BuildTunnelRequest) (tunnel.TunnelID, error)
```
BuildTunnelFromRequest builds a tunnel from a BuildTunnelRequest using the
tunnel.TunnelBuilder. This is the recommended method for building tunnels with
proper request tracking and retry support.

The method: 1. Uses tunnel.TunnelBuilder to create encrypted build records 2.
Generates a unique message ID for request/reply correlation 3. Tracks the
pending build request with reply decryption keys 4. Sends the build request via
appropriate transport 5. Returns the tunnel ID for tracking

#### func (*TunnelManager) BuildTunnelWithBuilder

```go
func (tm *TunnelManager) BuildTunnelWithBuilder(builder TunnelBuilder) error
```
BuildTunnelWithBuilder builds a tunnel using the i2np.TunnelBuilder message
interface. This is used for message routing and differs from BuildTunnel
(tunnel.BuilderInterface).

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

#### func (*TunnelManager) ProcessTunnelReply

```go
func (tm *TunnelManager) ProcessTunnelReply(handler TunnelReplyHandler, messageID int) error
```
ProcessTunnelReply processes tunnel build replies using TunnelReplyHandler
interface. This method integrates with the tunnel pool to update tunnel states
and handle build completions. Uses message ID to correlate the reply with the
original build request.

#### func (*TunnelManager) SetSessionProvider

```go
func (tm *TunnelManager) SetSessionProvider(provider SessionProvider)
```
SetSessionProvider sets the session provider for sending tunnel build messages

#### func (*TunnelManager) Stop

```go
func (tm *TunnelManager) Stop()
```
Stop gracefully stops the tunnel manager and cleans up resources. Should be
called when shutting down the router.

#### type TunnelReplyHandler

```go
type TunnelReplyHandler interface {
	GetReplyRecords() []BuildResponseRecord
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
}
```


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

[go-i2p template file](/template.md)
