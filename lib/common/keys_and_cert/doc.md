# keys_and_cert
--
    import "github.com/go-i2p/go-i2p/lib/common/keys_and_cert"

Package keys_and_cert implements the I2P KeysAndCert common data structure

## Usage

```go
const (
	KEYS_AND_CERT_PUBKEY_SIZE = 256
	KEYS_AND_CERT_SPK_SIZE    = 128
	KEYS_AND_CERT_MIN_SIZE    = 387
	KEYS_AND_CERT_DATA_SIZE   = 384
)
```
Sizes of various KeysAndCert structures and requirements

#### type KeysAndCert

```go
type KeysAndCert struct {
	KeyCertificate *KeyCertificate
}
```

KeysAndCert is the represenation of an I2P KeysAndCert.

https://geti2p.net/spec/common-structures#keysandcert

#### func  ReadKeysAndCert

```go
func ReadKeysAndCert(data []byte) (keys_and_cert KeysAndCert, remainder []byte, err error)
```
ReadKeysAndCert creates a new *KeysAndCert from []byte using ReadKeysAndCert.
Returns a pointer to KeysAndCert unlike ReadKeysAndCert.

#### func (KeysAndCert) Bytes

```go
func (keys_and_cert KeysAndCert) Bytes() []byte
```
Bytes returns the entire KeyCertificate in []byte form, trims payload to
specified length.

#### func (*KeysAndCert) Certificate

```go
func (keys_and_cert *KeysAndCert) Certificate() (cert Certificate)
```
Certfificate returns the certificate.

#### func (*KeysAndCert) PublicKey

```go
func (keys_and_cert *KeysAndCert) PublicKey() (key crypto.PublicKey)
```
PublicKey returns the public key as a crypto.PublicKey.

#### func (*KeysAndCert) SigningPublicKey

```go
func (keys_and_cert *KeysAndCert) SigningPublicKey() (signing_public_key crypto.SigningPublicKey)
```
SigningPublicKey returns the signing public key.
