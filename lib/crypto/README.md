# crypto
--
    import "github.com/go-i2p/go-i2p/lib/crypto"

![crypto.svg](crypto.svg)

package for i2p specific crpytography

## Usage

#### type Tunnel

```go
type Tunnel struct {
}
```


#### func  NewTunnelCrypto

```go
func NewTunnelCrypto(layerKey, ivKey TunnelKey) (t *Tunnel, err error)
```

#### func (*Tunnel) Decrypt

```go
func (t *Tunnel) Decrypt(td *TunnelData)
```

#### func (*Tunnel) Encrypt

```go
func (t *Tunnel) Encrypt(td *TunnelData)
```
encrypt tunnel data in place

#### type TunnelData

```go
type TunnelData [1028]byte
```


#### type TunnelIV

```go
type TunnelIV []byte
```

The initialization vector for a tunnel message

#### type TunnelKey

```go
type TunnelKey [32]byte
```

A symetric key for encrypting tunnel messages



crypto 

github.com/go-i2p/go-i2p/lib/crypto

[go-i2p template file](/template.md)
