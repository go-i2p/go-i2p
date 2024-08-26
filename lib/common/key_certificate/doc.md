# key_certificate
--
    import "github.com/go-i2p/go-i2p/lib/common/key_certificate"

Package key_certificate implements the I2P Destination common data structure

## Usage

```go
const (
	KEYCERT_SIGN_DSA_SHA1 = iota
	KEYCERT_SIGN_P256
	KEYCERT_SIGN_P384
	KEYCERT_SIGN_P521
	KEYCERT_SIGN_RSA2048
	KEYCERT_SIGN_RSA3072
	KEYCERT_SIGN_RSA4096
	KEYCERT_SIGN_ED25519
	KEYCERT_SIGN_ED25519PH
)
```
Key Certificate Signing Key Types

```go
const (
	KEYCERT_CRYPTO_ELG = iota
	KEYCERT_CRYPTO_P256
	KEYCERT_CRYPTO_P384
	KEYCERT_CRYPTO_P521
	KEYCERT_CRYPTO_X25519
)
```
Key Certificate Public Key Types

```go
const (
	KEYCERT_SIGN_DSA_SHA1_SIZE  = 128
	KEYCERT_SIGN_P256_SIZE      = 64
	KEYCERT_SIGN_P384_SIZE      = 96
	KEYCERT_SIGN_P521_SIZE      = 132
	KEYCERT_SIGN_RSA2048_SIZE   = 256
	KEYCERT_SIGN_RSA3072_SIZE   = 384
	KEYCERT_SIGN_RSA4096_SIZE   = 512
	KEYCERT_SIGN_ED25519_SIZE   = 32
	KEYCERT_SIGN_ED25519PH_SIZE = 32
)
```
SigningPublicKey sizes for Signing Key Types

```go
const (
	KEYCERT_CRYPTO_ELG_SIZE    = 256
	KEYCERT_CRYPTO_P256_SIZE   = 64
	KEYCERT_CRYPTO_P384_SIZE   = 96
	KEYCERT_CRYPTO_P521_SIZE   = 132
	KEYCERT_CRYPTO_X25519_SIZE = 32
)
```
PublicKey sizes for Public Key Types

```go
const (
	KEYCERT_PUBKEY_SIZE = 256
	KEYCERT_SPK_SIZE    = 128
)
```
Sizes of structures in KeyCertificates

```go
const (
	KEYCERT_MIN_SIZE = 7
)
```

#### type KeyCertificate

```go
type KeyCertificate struct {
	Certificate
}
```

type KeyCertificate []byte

#### func  KeyCertificateFromCertificate

```go
func KeyCertificateFromCertificate(certificate Certificate) *KeyCertificate
```
KeyCertificateFromCertificate returns a *KeyCertificate from a *Certificate.

#### func  NewKeyCertificate

```go
func NewKeyCertificate(bytes []byte) (key_certificate *KeyCertificate, remainder []byte, err error)
```
NewKeyCertificate creates a new *KeyCertificate from []byte using
ReadCertificate. The remaining bytes after the specified length are also
returned. Returns a list of errors that occurred during parsing.

#### func (KeyCertificate) ConstructPublicKey

```go
func (key_certificate KeyCertificate) ConstructPublicKey(data []byte) (public_key crypto.PublicKey, err error)
```
ConstructPublicKey returns a PublicKey constructed using any excess data that
may be stored in the KeyCertififcate. Returns enr errors encountered while
parsing.

#### func (KeyCertificate) ConstructSigningPublicKey

```go
func (key_certificate KeyCertificate) ConstructSigningPublicKey(data []byte) (signing_public_key crypto.SigningPublicKey, err error)
```
ConstructSigningPublicKey returns a SingingPublicKey constructed using any
excess data that may be stored in the KeyCertificate. Returns any errors
encountered while parsing.

#### func (KeyCertificate) CryptoSize

```go
func (key_certificate KeyCertificate) CryptoSize() (size int)
```
CryptoSize return the size of a Public Key corresponding to the Key
Certificate's PublicKey type.

#### func (KeyCertificate) Data

```go
func (key_certificate KeyCertificate) Data() ([]byte, error)
```
Data returns the raw []byte contained in the Certificate.

#### func (KeyCertificate) PublicKeyType

```go
func (key_certificate KeyCertificate) PublicKeyType() (pubkey_type int)
```
PublicKeyType returns the PublicKey type as a Go integer.

#### func (KeyCertificate) SignatureSize

```go
func (key_certificate KeyCertificate) SignatureSize() (size int)
```
SignatureSize return the size of a Signature corresponding to the Key
Certificate's SigningPublicKey type.

#### func (KeyCertificate) SigningPublicKeyType

```go
func (key_certificate KeyCertificate) SigningPublicKeyType() (signing_pubkey_type int)
```
SigningPublicKeyType returns the SigningPublicKey type as a Go integer.
