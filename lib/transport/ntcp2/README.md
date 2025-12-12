# ntcp2
--
    import "github.com/go-i2p/go-i2p/lib/transport/ntcp2"

![ntcp2.svg](ntcp2.svg)



## Usage

```go
var (
	ErrNTCP2NotSupported      = oops.New("router does not support NTCP2")
	ErrSessionClosed          = oops.New("NTCP2 session is closed")
	ErrHandshakeFailed        = oops.New("NTCP2 handshake failed")
	ErrInvalidRouterInfo      = oops.New("invalid router info for NTCP2")
	ErrConnectionPoolFull     = oops.New("NTCP2 connection pool full")
	ErrFramingError           = oops.New("I2NP message framing error")
	ErrInvalidListenerAddress = oops.New("invalid listener address for NTCP2")
	ErrInvalidConfig          = oops.New("invalid NTCP2 configuration")
)
```

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

Returns a RouterAddress with transport style "ntcp2" and all required options,
or an error if address extraction or conversion fails.

#### func  ExtractNTCP2Addr

```go
func ExtractNTCP2Addr(routerInfo router_info.RouterInfo) (net.Addr, error)
```
ExtractNTCP2Addr extracts the NTCP2 network address from a RouterInfo structure.
It validates NTCP2 support and returns a properly wrapped NTCP2 address with
router hash metadata.

#### func  FrameI2NPMessage

```go
func FrameI2NPMessage(msg i2np.I2NPMessage) ([]byte, error)
```
Frame an I2NP message for transmission over NTCP2

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

#### func  HasDirectConnectivity

```go
func HasDirectConnectivity(addr *router_address.RouterAddress) bool
```
HasDirectConnectivity checks if a RouterAddress has direct NTCP2 connectivity.
Returns true if the address has both host and port keys (directly dialable).
Returns false if the address is introducer-only (requires NAT traversal).
CRITICAL FIX #1: Pre-filtering utility for peer selection.

#### func  SupportsDirectNTCP2

```go
func SupportsDirectNTCP2(routerInfo *router_info.RouterInfo) bool
```
SupportsDirectNTCP2 checks if a RouterInfo has at least one directly dialable
NTCP2 address. This is a convenience function for peer selection - filters out
introducer-only routers. CRITICAL FIX #1: Exported function for use in peer
selection/filtering.

#### func  SupportsNTCP2

```go
func SupportsNTCP2(routerInfo *router_info.RouterInfo) bool
```
Check if RouterInfo supports NTCP2 TODO: This should be moved to router_info
package

#### func  UnframeI2NPMessage

```go
func UnframeI2NPMessage(conn net.Conn) (i2np.I2NPMessage, error)
```
Unframe I2NP messages from NTCP2 data stream

#### func  WrapNTCP2Addr

```go
func WrapNTCP2Addr(addr net.Addr, routerHash []byte) (*ntcp2.NTCP2Addr, error)
```
Convert net.Addr to NTCP2Addr

#### func  WrapNTCP2Error

```go
func WrapNTCP2Error(err error, operation string) error
```
Wrap go-noise errors with context

#### type Config

```go
type Config struct {
	ListenerAddress string // Address to listen on, e.g., ":42069"
	WorkingDir      string // Working directory for persistent storage (e.g., ~/.go-i2p/config)
	*ntcp2.NTCP2Config
}
```


#### func  NewConfig

```go
func NewConfig(listenerAddress string) (*Config, error)
```

#### func (*Config) Validate

```go
func (c *Config) Validate() error
```

#### type I2NPUnframer

```go
type I2NPUnframer struct {
}
```

Stream-based unframing for continuous reading

#### func  NewI2NPUnframer

```go
func NewI2NPUnframer(conn net.Conn) *I2NPUnframer
```

#### func (*I2NPUnframer) BytesRead

```go
func (u *I2NPUnframer) BytesRead() int
```
BytesRead returns the number of bytes read during the last ReadNextMessage call

#### func (*I2NPUnframer) ReadNextMessage

```go
func (u *I2NPUnframer) ReadNextMessage() (i2np.I2NPMessage, error)
```

#### type KeystoreProvider

```go
type KeystoreProvider interface {
	GetEncryptionPrivateKey() types.PrivateEncryptionKey
}
```


#### type NTCP2Session

```go
type NTCP2Session struct {
}
```


#### func  NewNTCP2Session

```go
func NewNTCP2Session(conn net.Conn, ctx context.Context, logger *logger.Entry) *NTCP2Session
```

#### func (*NTCP2Session) Close

```go
func (s *NTCP2Session) Close() error
```
Close closes the session cleanly.

#### func (*NTCP2Session) GetBandwidthStats

```go
func (s *NTCP2Session) GetBandwidthStats() (bytesSent, bytesReceived uint64)
```
GetBandwidthStats returns the total bytes sent and received by this session. The
values are read atomically and represent cumulative totals since session start.

#### func (*NTCP2Session) QueueSendI2NP

```go
func (s *NTCP2Session) QueueSendI2NP(msg i2np.I2NPMessage)
```
QueueSendI2NP queues an I2NP message to be sent over the session. Will block as
long as the send queue is full.

#### func (*NTCP2Session) ReadNextI2NP

```go
func (s *NTCP2Session) ReadNextI2NP() (i2np.I2NPMessage, error)
```
ReadNextI2NP blocking reads the next fully received I2NP message from this
session.

#### func (*NTCP2Session) SendQueueSize

```go
func (s *NTCP2Session) SendQueueSize() int
```
SendQueueSize returns how many I2NP messages are not completely sent yet.

#### func (*NTCP2Session) SetCleanupCallback

```go
func (s *NTCP2Session) SetCleanupCallback(callback func())
```
SetCleanupCallback sets a callback function that will be called when the session
closes

#### type NTCP2Transport

```go
type NTCP2Transport struct {
}
```


#### func  NewNTCP2Transport

```go
func NewNTCP2Transport(identity router_info.RouterInfo, config *Config, keystore KeystoreProvider) (*NTCP2Transport, error)
```

#### func (*NTCP2Transport) Accept

```go
func (t *NTCP2Transport) Accept() (net.Conn, error)
```
Accept accepts an incoming session.

#### func (*NTCP2Transport) Addr

```go
func (t *NTCP2Transport) Addr() net.Addr
```
Addr returns the network address the transport is bound to.

#### func (*NTCP2Transport) Close

```go
func (t *NTCP2Transport) Close() error
```
Close closes the transport cleanly.

#### func (*NTCP2Transport) Compatible

```go
func (t *NTCP2Transport) Compatible(routerInfo router_info.RouterInfo) bool
```
Compatible returns true if a routerInfo is compatible with this transport.

#### func (*NTCP2Transport) GetSession

```go
func (t *NTCP2Transport) GetSession(routerInfo router_info.RouterInfo) (transport.TransportSession, error)
```
GetSession obtains a transport session with a router given its RouterInfo.

#### func (*NTCP2Transport) GetTotalBandwidth

```go
func (t *NTCP2Transport) GetTotalBandwidth() (totalBytesSent, totalBytesReceived uint64)
```
GetTotalBandwidth returns the total bytes sent and received across all active
sessions. This aggregates bandwidth statistics from all sessions managed by this
transport.

#### func (*NTCP2Transport) Name

```go
func (t *NTCP2Transport) Name() string
```
Name returns the name of this transport.

#### func (*NTCP2Transport) SetIdentity

```go
func (t *NTCP2Transport) SetIdentity(ident router_info.RouterInfo) error
```
SetIdentity sets the router identity for this transport.

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



ntcp2 

github.com/go-i2p/go-i2p/lib/transport/ntcp2

[go-i2p template file](/template.md)
