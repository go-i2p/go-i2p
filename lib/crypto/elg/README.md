# elgamal
--
    import "github.com/go-i2p/go-i2p/lib/crypto/elg"

![elgamal.svg](elgamal.svg)



## Usage

```go
var (
	ElgDecryptFail   = oops.Errorf("failed to decrypt elgamal encrypted data")
	ElgEncryptTooBig = oops.Errorf("failed to encrypt data, too big for elgamal")
)
```

#### func  ElgamalGenerate

```go
func ElgamalGenerate(priv *elgamal.PrivateKey, rand io.Reader) (err error)
```
generate an elgamal key pair

#### type ElgPrivateKey

```go
type ElgPrivateKey [256]byte
```


#### func (ElgPrivateKey) Len

```go
func (elg ElgPrivateKey) Len() int
```

#### func (ElgPrivateKey) NewDecrypter

```go
func (elg ElgPrivateKey) NewDecrypter() (dec types.Decrypter, err error)
```

#### type ElgPublicKey

```go
type ElgPublicKey [256]byte
```


#### func (ElgPublicKey) Bytes

```go
func (elg ElgPublicKey) Bytes() []byte
```

#### func (ElgPublicKey) Len

```go
func (elg ElgPublicKey) Len() int
```

#### func (ElgPublicKey) NewEncrypter

```go
func (elg ElgPublicKey) NewEncrypter() (enc types.Encrypter, err error)
```

#### type ElgamalEncryption

```go
type ElgamalEncryption struct {
}
```


#### func (*ElgamalEncryption) Encrypt

```go
func (elg *ElgamalEncryption) Encrypt(data []byte) (enc []byte, err error)
```

#### func (*ElgamalEncryption) EncryptPadding

```go
func (elg *ElgamalEncryption) EncryptPadding(data []byte, zeroPadding bool) (encrypted []byte, err error)
```

#### type PrivateKey

```go
type PrivateKey struct {
	elgamal.PrivateKey
}
```



elgamal 

github.com/go-i2p/go-i2p/lib/crypto/elg
