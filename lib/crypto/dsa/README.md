# dsa
--
    import "github.com/go-i2p/go-i2p/lib/crypto/dsa"

![dsa.svg](dsa.svg)



## Usage

#### type DSAPrivateKey

```go
type DSAPrivateKey [20]byte
```


#### func (DSAPrivateKey) Generate

```go
func (k DSAPrivateKey) Generate() (s DSAPrivateKey, err error)
```

#### func (DSAPrivateKey) Len

```go
func (k DSAPrivateKey) Len() int
```

#### func (DSAPrivateKey) NewSigner

```go
func (k DSAPrivateKey) NewSigner() (s types.Signer, err error)
```
create a new dsa signer

#### func (DSAPrivateKey) Public

```go
func (k DSAPrivateKey) Public() (pk DSAPublicKey, err error)
```

#### type DSAPublicKey

```go
type DSAPublicKey [128]byte
```


#### func (DSAPublicKey) Bytes

```go
func (k DSAPublicKey) Bytes() []byte
```

#### func (DSAPublicKey) Len

```go
func (k DSAPublicKey) Len() int
```

#### func (DSAPublicKey) NewVerifier

```go
func (k DSAPublicKey) NewVerifier() (v types.Verifier, err error)
```
create a new dsa verifier

#### type DSASigner

```go
type DSASigner struct {
}
```


#### func (*DSASigner) Sign

```go
func (ds *DSASigner) Sign(data []byte) (sig []byte, err error)
```

#### func (*DSASigner) SignHash

```go
func (ds *DSASigner) SignHash(h []byte) (sig []byte, err error)
```

#### type DSAVerifier

```go
type DSAVerifier struct {
}
```


#### func (*DSAVerifier) Verify

```go
func (v *DSAVerifier) Verify(data, sig []byte) (err error)
```
verify data with a dsa public key

#### func (*DSAVerifier) VerifyHash

```go
func (v *DSAVerifier) VerifyHash(h, sig []byte) (err error)
```
verify hash of data with a dsa public key



dsa 

github.com/go-i2p/go-i2p/lib/crypto/dsa
