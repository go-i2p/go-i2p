# router_identity
--
    import "github.com/go-i2p/go-i2p/lib/common/router_identity"

![router_identity.svg](router_identity)

Package router_identity implements the I2P RouterIdentity common data structure

## Usage

#### type RouterIdentity

```go
type RouterIdentity struct {
	KeysAndCert
}
```

RouterIdentity is the represenation of an I2P RouterIdentity.

https://geti2p.net/spec/common-structures#routeridentity

#### func  NewRouterIdentity

```go
func NewRouterIdentity(publicKey crypto.RecievingPublicKey, signingPublicKey crypto.SigningPublicKey, cert certificate.Certificate, padding []byte) (*RouterIdentity, error)
```

#### func  ReadRouterIdentity

```go
func ReadRouterIdentity(data []byte) (router_identity RouterIdentity, remainder []byte, err error)
```
ReadRouterIdentity returns RouterIdentity from a []byte. The remaining bytes
after the specified length are also returned. Returns a list of errors that
occurred during parsing.

#### func (*RouterIdentity) AsDestination

```go
func (router_identity *RouterIdentity) AsDestination() destination.Destination
```



router_identity

github.com/go-i2p/go-i2p/lib/common/router_identity
