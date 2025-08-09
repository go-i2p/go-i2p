# i2np
--
    import "github.com/go-i2p/go-i2p/lib/i2np"

![i2np.svg](i2np.svg)

## Interface-Based Architecture

This package now features a comprehensive interface-based design that improves testability, flexibility, and maintainability while preserving full backward compatibility. See [REFACTORING.md](REFACTORING.md) for detailed documentation of the interface architecture.

### Key Interfaces

- **`I2NPMessage`**: Core message interface combining serialization, identification, and expiration
- **`PayloadCarrier`**: Messages that carry payload data
- **`TunnelCarrier`**: Messages that carry tunnel-related data  
- **`StatusReporter`**: Messages that report delivery status
- **`DatabaseReader`/`DatabaseWriter`**: Database operation interfaces
- **`TunnelBuilder`/`TunnelReplyHandler`**: Tunnel management interfaces

### Usage Examples

```go
// Interface-based message processing
processor := NewMessageProcessor()
var msg I2NPMessage = NewDataMessage([]byte("test"))
err := processor.ProcessMessage(msg)

// Factory pattern for interface types
factory := NewI2NPMessageFactory()
dataMsg := factory.CreateDataMessage(payload)

// Specialized interface usage
var carrier PayloadCarrier = NewDataMessageWithPayload(payload)
payload := carrier.GetPayload()
```

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
)
```

```go
var ERR_BUILD_REQUEST_RECORD_NOT_ENOUGH_DATA = oops.Errorf("not enough i2np build request record data")
```

```go
var ERR_BUILD_RESPONSE_RECORD_NOT_ENOUGH_DATA = errors.New("not enough i2np build request record data")
```

```go
var ERR_DATABASE_LOOKUP_NOT_ENOUGH_DATA = errors.New("not enough i2np database lookup data")
```

```go
var ERR_I2NP_NOT_ENOUGH_DATA = oops.Errorf("not enough i2np header data")
```

#### func  ReadI2NPNTCPData

```go
func ReadI2NPNTCPData(data []byte, size int) ([]byte, error)
```

#### func  ReadI2NPNTCPMessageChecksum

```go
func ReadI2NPNTCPMessageChecksum(data []byte) (int, error)
```

#### func  ReadI2NPNTCPMessageExpiration

```go
func ReadI2NPNTCPMessageExpiration(data []byte) (datalib.Date, error)
```

#### func  ReadI2NPNTCPMessageID

```go
func ReadI2NPNTCPMessageID(data []byte) (int, error)
```

#### func  ReadI2NPNTCPMessageSize

```go
func ReadI2NPNTCPMessageSize(data []byte) (int, error)
```

#### func  ReadI2NPSSUMessageExpiration

```go
func ReadI2NPSSUMessageExpiration(data []byte) (datalib.Date, error)
```

#### func  ReadI2NPType

```go
func ReadI2NPType(data []byte) (int, error)
```

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


#### func  ReadBuildRequestRecord

```go
func ReadBuildRequestRecord(data []byte) (BuildRequestRecord, error)
```

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

#### type DatabaseSearchReply

```go
type DatabaseSearchReply struct {
	Key        common.Hash
	Count      int
	PeerHashes []common.Hash
	From       common.Hash
}
```


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


#### type DeliveryStatus

```go
type DeliveryStatus struct {
	MessageID int
	Timestamp time.Time
}
```


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


#### type GarlicElGamal

```go
type GarlicElGamal []byte
```


#### type I2NPMessage

```go
type I2NPMessage []byte
```


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


#### func  ReadI2NPNTCPHeader

```go
func ReadI2NPNTCPHeader(data []byte) (I2NPNTCPHeader, error)
```
Read an entire I2NP message and return the parsed header with embedded encrypted
data

#### type I2NPSSUHeader

```go
type I2NPSSUHeader struct {
	Type       int
	Expiration time.Time
}
```


#### func  ReadI2NPSSUHeader

```go
func ReadI2NPSSUHeader(data []byte) (I2NPSSUHeader, error)
```

#### type TunnelBuild

```go
type TunnelBuild [8]BuildRequestRecord
```


#### type TunnelBuildReply

```go
type TunnelBuildReply [8]BuildResponseRecord
```


#### type TunnelData

```go
type TunnelData [1028]byte
```


#### type TunnelGatway

```go
type TunnelGatway struct {
	TunnelID tunnel.TunnelID
	Length   int
	Data     []byte
}
```


#### type VariableTunnelBuild

```go
type VariableTunnelBuild struct {
	Count               int
	BuildRequestRecords []BuildRequestRecord
}
```


#### type VariableTunnelBuildReply

```go
type VariableTunnelBuildReply struct {
	Count                int
	BuildResponseRecords []BuildResponseRecord
}
```



i2np 

github.com/go-i2p/go-i2p/lib/i2np

[go-i2p template file](/template.md)
