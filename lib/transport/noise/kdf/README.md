# kdf
--
    import "github.com/go-i2p/go-i2p/lib/transport/noise/kdf"

![kdf.svg](kdf.svg)



## Usage

#### type NoiseKDF

```go
type NoiseKDF struct {
}
```

NoiseKDF handles key derivation functions for Noise protocols

#### func  NewNoiseKDF

```go
func NewNoiseKDF(protocolName []byte) *NoiseKDF
```
NewNoiseKDF creates a new KDF instance with the protocol name

#### func (*NoiseKDF) DeriveSessionKeys

```go
func (k *NoiseKDF) DeriveSessionKeys() (sendKey, recvKey []byte, err error)
```
DeriveSessionKeys derives transport keys from the KDF state

#### func (*NoiseKDF) GetHandshakeHash

```go
func (k *NoiseKDF) GetHandshakeHash() []byte
```
GetHandshakeHash returns the current handshake hash

#### func (*NoiseKDF) MixHash

```go
func (k *NoiseKDF) MixHash(data []byte) error
```
MixHash updates the handshake hash with new data

#### func (*NoiseKDF) MixKey

```go
func (k *NoiseKDF) MixKey(input []byte) ([]byte, error)
```
MixKey derives a new key from the chaining key and input material

#### func (*NoiseKDF) SetHash

```go
func (k *NoiseKDF) SetHash(hash []byte)
```



kdf 

github.com/go-i2p/go-i2p/lib/transport/noise/kdf

[go-i2p template file](/template.md)
