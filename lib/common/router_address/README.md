# router_address
--
    import "github.com/go-i2p/go-i2p/lib/common/router_address"

![router_address.svg](router_address)

Package router_address implements the I2P RouterAddress common data structure

## Usage

```go
const (
	ROUTER_ADDRESS_MIN_SIZE = 9
)
```
Minimum number of bytes in a valid RouterAddress

#### type RouterAddress

```go
type RouterAddress struct {
	TransportCost    *Integer
	ExpirationDate   *Date
	TransportType    I2PString
	TransportOptions *Mapping
}
```

RouterAddress is the represenation of an I2P RouterAddress.

https://geti2p.net/spec/common-structures#routeraddress

#### func  NewRouterAddress

```go
func NewRouterAddress(cost uint8, expiration time.Time, transportType string, options map[string]string) (*RouterAddress, error)
```
NewRouterAddress creates a new RouterAddress with the provided parameters.
Returns a pointer to RouterAddress.

#### func  ReadRouterAddress

```go
func ReadRouterAddress(data []byte) (router_address RouterAddress, remainder []byte, err error)
```
ReadRouterAddress returns RouterAddress from a []byte. The remaining bytes after
the specified length are also returned. Returns a list of errors that occurred
during parsing.

#### func (RouterAddress) Bytes

```go
func (router_address RouterAddress) Bytes() []byte
```
Bytes returns the router address as a []byte.

#### func (RouterAddress) CapsString

```go
func (router_address RouterAddress) CapsString() I2PString
```

#### func (RouterAddress) Cost

```go
func (router_address RouterAddress) Cost() int
```
Cost returns the cost for this RouterAddress as a Go integer.

#### func (RouterAddress) Expiration

```go
func (router_address RouterAddress) Expiration() Date
```
Expiration returns the expiration for this RouterAddress as an I2P Date.

#### func (RouterAddress) GetOption

```go
func (router_address RouterAddress) GetOption(key I2PString) I2PString
```
GetOption returns the value of the option specified by the key

#### func (RouterAddress) Host

```go
func (router_address RouterAddress) Host() (net.Addr, error)
```

#### func (RouterAddress) HostString

```go
func (router_address RouterAddress) HostString() I2PString
```

#### func (*RouterAddress) IPVersion

```go
func (router_address *RouterAddress) IPVersion() string
```
IPVersion returns a string "4" for IPv4 or 6 for IPv6

#### func (RouterAddress) InitializationVector

```go
func (router_address RouterAddress) InitializationVector() ([16]byte, error)
```

#### func (RouterAddress) InitializationVectorString

```go
func (router_address RouterAddress) InitializationVectorString() I2PString
```

#### func (RouterAddress) IntroducerExpirationString

```go
func (router_address RouterAddress) IntroducerExpirationString(num int) I2PString
```

#### func (RouterAddress) IntroducerHashString

```go
func (router_address RouterAddress) IntroducerHashString(num int) I2PString
```

#### func (RouterAddress) IntroducerTagString

```go
func (router_address RouterAddress) IntroducerTagString(num int) I2PString
```

#### func (*RouterAddress) Network

```go
func (router_address *RouterAddress) Network() string
```
Network implements net.Addr. It returns the transport type plus 4 or 6

#### func (RouterAddress) Options

```go
func (router_address RouterAddress) Options() Mapping
```
Options returns the options for this RouterAddress as an I2P Mapping.

#### func (RouterAddress) Port

```go
func (router_address RouterAddress) Port() (string, error)
```

#### func (RouterAddress) PortString

```go
func (router_address RouterAddress) PortString() I2PString
```

#### func (RouterAddress) ProtocolVersion

```go
func (router_address RouterAddress) ProtocolVersion() (string, error)
```

#### func (RouterAddress) ProtocolVersionString

```go
func (router_address RouterAddress) ProtocolVersionString() I2PString
```

#### func (RouterAddress) StaticKey

```go
func (router_address RouterAddress) StaticKey() ([32]byte, error)
```

#### func (RouterAddress) StaticKeyString

```go
func (router_address RouterAddress) StaticKeyString() I2PString
```

#### func (*RouterAddress) String

```go
func (router_address *RouterAddress) String() string
```
String implements net.Addr. It returns the IP address, followed by the options

#### func (RouterAddress) TransportStyle

```go
func (router_address RouterAddress) TransportStyle() I2PString
```
TransportStyle returns the transport style for this RouterAddress as an
I2PString.

#### func (*RouterAddress) UDP

```go
func (router_address *RouterAddress) UDP() bool
```



router_address

github.com/go-i2p/go-i2p/lib/common/router_address
