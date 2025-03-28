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
	// Message 1 - SessionRequest
	NTCP2_MSG1_SIZE   = 64
	NTCP2_MSG1_HEADER = 0x00

	// Message 2 - SessionCreated
	NTCP2_MSG2_SIZE   = 64
	NTCP2_MSG2_HEADER = 0x01

	// Message 3 - SessionConfirmed
	NTCP2_MSG3_HEADER = 0x02

	// Timeout for handshake operations
	NTCP2_HANDSHAKE_TIMEOUT = 15 * time.Second
)
```
Constants for NTCP2 handshake

```go
const (
	NTCP_PROTOCOL_VERSION = 2
	NTCP_PROTOCOL_NAME    = "NTCP2"
	NTCP_MESSAGE_MAX_SIZE = 65537
)
```

#### func  PerformOutboundHandshake

```go
func PerformOutboundHandshake(conn net.Conn, hs *HandshakeState) error
```
PerformOutboundHandshake initiates and completes a handshake as the initiator

#### type HandshakeState

```go
type HandshakeState struct {
}
```

HandshakeState maintains the state for an in-progress handshake

#### func  NewHandshakeState

```go
func NewHandshakeState(localKey types.PrivateKey, remoteKey types.PublicKey, ri *router_info.RouterInfo) (*HandshakeState, error)
```
NewHandshakeState creates a new handshake state for initiating a connection

#### func  PerformInboundHandshake

```go
func PerformInboundHandshake(conn net.Conn, localKey types.PrivateKey) (*HandshakeState, error)
```
PerformInboundHandshake handles a handshake initiated by a remote peer

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
func NewNTCP2Session(routerInfo router_info.RouterInfo) (*NTCP2Session, error)
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

#### func (*NTCP2Session) CreateSessionConfirmed

```go
func (c *NTCP2Session) CreateSessionConfirmed(
	handshakeState *noise.HandshakeState,
	localRouterInfo *router_info.RouterInfo,
) (*messages.SessionConfirmed, error)
```
CreateSessionConfirmed builds the SessionConfirmed message (Message 3 in NTCP2
handshake) This is sent by Alice to Bob after receiving SessionCreated

#### func (*NTCP2Session) CreateSessionCreated

```go
func (s *NTCP2Session) CreateSessionCreated(
	handshakeState *noise.HandshakeState,
	localRouterInfo *router_info.RouterInfo,
) (*messages.SessionCreated, error)
```
CreateSessionCreated builds the SessionCreated message (Message 2 in NTCP2
handshake) This is sent by Bob to Alice after receiving SessionRequest

#### func (*NTCP2Session) CreateSessionRequest

```go
func (s *NTCP2Session) CreateSessionRequest() (*messages.SessionRequest, error)
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



ntcp 

github.com/go-i2p/go-i2p/lib/transport/ntcp
