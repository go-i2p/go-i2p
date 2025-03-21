# ntcp
--
    import "github.com/go-i2p/go-i2p/lib/transport/ntcp"

![ntcp.svg](ntcp.svg)



## Usage

```go
const (
	NOISE_DH_CURVE25519 = 1

	NOISE_CIPHER_CHACHAPOLY = 1
	NOISE_CIPHER_AESGCM     = 2

	NOISE_HASH_SHA256 = 3

	NOISE_PATTERN_XK = 11

	MaxPayloadSize = math.MaxUint16 - 16 - uint16Size /*data len*/
)
```

```go
const (
	NTCP_PROTOCOL_VERSION = 2
	NTCP_PROTOCOL_NAME    = "NTCP2"
	NTCP_MESSAGE_MAX_SIZE = 65537
)
```

#### type NTCP2Session

```go
type NTCP2Session struct {
	*noise.NoiseSession
	*NTCP2Transport
}
```

NTCP2Session extends the base noise.NoiseSession with NTCP2-specific
functionality

#### func  NewNTCP2Session

```go
func NewNTCP2Session(noiseConfig router_info.RouterInfo) (*NTCP2Session, error)
```
NewNTCP2Session creates a new NTCP2 session using the existing noise
implementation

#### func (*NTCP2Session) ComposeInitiatorHandshakeMessage

```go
func (c *NTCP2Session) ComposeInitiatorHandshakeMessage(
	localStatic noise.DHKey,
	remoteStatic []byte,
	payload []byte,
	ephemeralPrivate []byte,
) (
	negotiationData,
	handshakeMessage []byte,
	handshakeState *noise.HandshakeState,
	err error,
)
```
Modify ComposeInitiatorHandshakeMessage in outgoing_handshake.go At the moment,
remoteStatic is stored in the NTCP2Session() and doesn't need to be passed as an
argument. You actually get it directly out of the remote RouterInfo, which the
NoiseSession also has access to. So maybe, the interface should change so that
we:

    - A: get the localStatic out of the parent NTCP2Transport's routerInfo, which is the "local" routerInfo
    - B: get the remoteStatic out of the NTCP2Session router, which is the "remote" routerInfo

#### func (*NTCP2Session) CreateSessionRequest

```go
func (s *NTCP2Session) CreateSessionRequest() (*SessionRequest, error)
```

#### func (*NTCP2Session) DeobfuscateEphemeral

```go
func (s *NTCP2Session) DeobfuscateEphemeral(obfuscatedEphemeralKey []byte) ([]byte, error)
```
DeobfuscateEphemeral reverses the key obfuscation

#### func (*NTCP2Session) ObfuscateEphemeral

```go
func (s *NTCP2Session) ObfuscateEphemeral(ephemeralKey []byte) ([]byte, error)
```
ObfuscateEphemeral implements NTCP2's key obfuscation using AES-256-CBC

#### type NTCP2Transport

```go
type NTCP2Transport struct {
	*noise.NoiseTransport
	*sntp.RouterTimestamper
}
```

NTCP2Transport is an ntcp2 transport implementing transport.NTCP2Transport
interface

#### func  NewNTCP2Transport

```go
func NewNTCP2Transport(routerInfo *router_info.RouterInfo) (*NTCP2Transport, error)
```

#### func (*NTCP2Transport) Accept

```go
func (t *NTCP2Transport) Accept() (net.Conn, error)
```

#### func (*NTCP2Transport) Address

```go
func (t *NTCP2Transport) Address() (*router_address.RouterAddress, error)
```

#### func (*NTCP2Transport) Compatible

```go
func (t *NTCP2Transport) Compatible(routerInfo router_info.RouterInfo) bool
```

#### func (*NTCP2Transport) GetSession

```go
func (t *NTCP2Transport) GetSession(routerInfo router_info.RouterInfo) (transport.TransportSession, error)
```

#### func (*NTCP2Transport) Name

```go
func (t *NTCP2Transport) Name() string
```

#### type PaddingStrategy

```go
type PaddingStrategy interface {
	AddPadding(message []byte) []byte
	RemovePadding(message []byte) []byte
}
```


#### type SessionRequest

```go
type SessionRequest struct {
	ObfuscatedKey []byte // 32 bytes
	Timestamp     uint32 // 4 bytes
	Padding       []byte // Random padding
}
```



ntcp

github.com/go-i2p/go-i2p/lib/transport/ntcp
