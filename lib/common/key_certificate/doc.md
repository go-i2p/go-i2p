# key_certificate
--
    import "github.com/go-i2p/go-i2p/lib/common/key_certificate"

Package key_certificate implements the I2P Destination common data structure

## Usage

```go
const (
	KEYCERT_SIGN_DSA_SHA1  = 0
	KEYCERT_SIGN_P256      = 1
	KEYCERT_SIGN_P384      = 2
	KEYCERT_SIGN_P521      = 3
	KEYCERT_SIGN_RSA2048   = 4
	KEYCERT_SIGN_RSA3072   = 5
	KEYCERT_SIGN_RSA4096   = 6
	KEYCERT_SIGN_ED25519   = 7
	KEYCERT_SIGN_ED25519PH = 8
)
```
Key Certificate Signing Key Types

```go
const (
	KEYCERT_CRYPTO_ELG    = 0
	KEYCERT_CRYPTO_P256   = 1
	KEYCERT_CRYPTO_P384   = 2
	KEYCERT_CRYPTO_P521   = 3
	KEYCERT_CRYPTO_X25519 = 4
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
signingPublicKey sizes for Signing Key Types

```go
const (
	KEYCERT_CRYPTO_ELG_SIZE    = 256
	KEYCERT_CRYPTO_P256_SIZE   = 64
	KEYCERT_CRYPTO_P384_SIZE   = 96
	KEYCERT_CRYPTO_P521_SIZE   = 132
	KEYCERT_CRYPTO_X25519_SIZE = 32
)
```
publicKey sizes for Public Key Types

```go
const (
	KEYCERT_PUBKEY_SIZE = 256
	KEYCERT_SPK_SIZE    = 128
)
```
Sizes of structures in KeyCertificates

```go
const (
	CRYPTO_KEY_TYPE_ELGAMAL = 0 // ElGamal

	// Signature Types
	SIGNATURE_TYPE_DSA_SHA1       = 0 // DSA-SHA1
	SIGNATURE_TYPE_ED25519_SHA512 = 7 // Ed25519
)
```

```go
const (
	KEYCERT_MIN_SIZE = 7
)
```

```go
var CryptoPublicKeySizes = map[uint16]int{
	CRYPTO_KEY_TYPE_ELGAMAL: 256,
}
```

```go
var SignaturePublicKeySizes = map[uint16]int{
	SIGNATURE_TYPE_DSA_SHA1:       128,
	SIGNATURE_TYPE_ED25519_SHA512: 32,
}
```

#### type KeyCertificate

```go
type KeyCertificate struct {
	Certificate
	SpkType Integer
	CpkType Integer
}
```

type KeyCertificate []byte

#### func  KeyCertificateFromCertificate

```go
func KeyCertificateFromCertificate(cert Certificate) (*KeyCertificate, error)
```

#### func  NewKeyCertificate

```go
func NewKeyCertificate(bytes []byte) (key_certificate *KeyCertificate, remainder []byte, err error)
```
NewKeyCertificate creates a new *KeyCertificate from []byte using
ReadCertificate. The remaining bytes after the specified length are also
returned. Returns a list of errors that occurred during parsing.

#### func (KeyCertificate) ConstructPublicKey

```go
func (keyCertificate KeyCertificate) ConstructPublicKey(data []byte) (public_key crypto.RecievingPublicKey, err error)
```
ConstructPublicKey returns a publicKey constructed using any excess data that
may be stored in the KeyCertififcate. Returns enr errors encountered while
parsing.

#### func (KeyCertificate) ConstructSigningPublicKey

```go
func (keyCertificate KeyCertificate) ConstructSigningPublicKey(data []byte) (signing_public_key crypto.SigningPublicKey, err error)
```
ConstructSigningPublicKey returns a SingingPublicKey constructed using any
excess data that may be stored in the KeyCertificate. Returns any errors
encountered while parsing.

#### func (*KeyCertificate) CryptoPublicKeySize

```go
func (keyCertificate *KeyCertificate) CryptoPublicKeySize() (int, error)
```

#### func (KeyCertificate) CryptoSize

```go
func (keyCertificate KeyCertificate) CryptoSize() (size int)
```
CryptoSize return the size of a Public Key corresponding to the Key
Certificate's publicKey type.

#### func (KeyCertificate) Data

```go
func (keyCertificate KeyCertificate) Data() ([]byte, error)
```
Data returns the raw []byte contained in the Certificate.

#### func (KeyCertificate) PublicKeyType

```go
func (keyCertificate KeyCertificate) PublicKeyType() (pubkey_type int)
```
PublicKeyType returns the publicKey type as a Go integer.

#### func (KeyCertificate) SignatureSize

```go
func (keyCertificate KeyCertificate) SignatureSize() (size int)
```
SignatureSize return the size of a Signature corresponding to the Key
Certificate's signingPublicKey type.

#### func (*KeyCertificate) SigningPublicKeySize

```go
func (keyCertificate *KeyCertificate) SigningPublicKeySize() int
```

#### func (KeyCertificate) SigningPublicKeyType

```go
func (keyCertificate KeyCertificate) SigningPublicKeyType() (signing_pubkey_type int)
```
SigningPublicKeyType returns the signingPublicKey type as a Go integer.

# key_certificate
--
    import "github.com/go-i2p/go-i2p/lib/common/key_certificate"

Package key_certificate implements the I2P Destination common data structure

![key_certificate.svg](key_certificate)

## Usage

```go
const (
	KEYCERT_SIGN_DSA_SHA1  = 0
	KEYCERT_SIGN_P256      = 1
	KEYCERT_SIGN_P384      = 2
	KEYCERT_SIGN_P521      = 3
	KEYCERT_SIGN_RSA2048   = 4
	KEYCERT_SIGN_RSA3072   = 5
	KEYCERT_SIGN_RSA4096   = 6
	KEYCERT_SIGN_ED25519   = 7
	KEYCERT_SIGN_ED25519PH = 8
)
```
Key Certificate Signing Key Types

```go
const (
	KEYCERT_CRYPTO_ELG    = 0
	KEYCERT_CRYPTO_P256   = 1
	KEYCERT_CRYPTO_P384   = 2
	KEYCERT_CRYPTO_P521   = 3
	KEYCERT_CRYPTO_X25519 = 4
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
signingPublicKey sizes for Signing Key Types

```go
const (
	KEYCERT_CRYPTO_ELG_SIZE    = 256
	KEYCERT_CRYPTO_P256_SIZE   = 64
	KEYCERT_CRYPTO_P384_SIZE   = 96
	KEYCERT_CRYPTO_P521_SIZE   = 132
	KEYCERT_CRYPTO_X25519_SIZE = 32
)
```
publicKey sizes for Public Key Types

```go
const (
	KEYCERT_PUBKEY_SIZE = 256
	KEYCERT_SPK_SIZE    = 128
)
```
Sizes of structures in KeyCertificates

```go
const (
	CRYPTO_KEY_TYPE_ELGAMAL = 0 // ElGamal

	// Signature Types
	SIGNATURE_TYPE_DSA_SHA1       = 0 // DSA-SHA1
	SIGNATURE_TYPE_ED25519_SHA512 = 7 // Ed25519
)
```

```go
const (
	KEYCERT_MIN_SIZE = 7
)
```

```go
var CryptoPublicKeySizes = map[uint16]int{
	CRYPTO_KEY_TYPE_ELGAMAL: 256,
}
```

```go
var SignaturePublicKeySizes = map[uint16]int{
	SIGNATURE_TYPE_DSA_SHA1:       128,
	SIGNATURE_TYPE_ED25519_SHA512: 32,
}
```

#### type KeyCertificate

```go
type KeyCertificate struct {
	Certificate
	SpkType Integer
	CpkType Integer
}
```

type KeyCertificate []byte

#### func  KeyCertificateFromCertificate

```go
func KeyCertificateFromCertificate(cert Certificate) (*KeyCertificate, error)
```

#### func  NewKeyCertificate

```go
func NewKeyCertificate(bytes []byte) (key_certificate *KeyCertificate, remainder []byte, err error)
```
NewKeyCertificate creates a new *KeyCertificate from []byte using
ReadCertificate. The remaining bytes after the specified length are also
returned. Returns a list of errors that occurred during parsing.

#### func (KeyCertificate) ConstructPublicKey

```go
func (keyCertificate KeyCertificate) ConstructPublicKey(data []byte) (public_key crypto.RecievingPublicKey, err error)
```
ConstructPublicKey returns a publicKey constructed using any excess data that
may be stored in the KeyCertififcate. Returns enr errors encountered while
parsing.

#### func (KeyCertificate) ConstructSigningPublicKey

```go
func (keyCertificate KeyCertificate) ConstructSigningPublicKey(data []byte) (signing_public_key crypto.SigningPublicKey, err error)
```
ConstructSigningPublicKey returns a SingingPublicKey constructed using any
excess data that may be stored in the KeyCertificate. Returns any errors
encountered while parsing.

#### func (*KeyCertificate) CryptoPublicKeySize

```go
func (keyCertificate *KeyCertificate) CryptoPublicKeySize() (int, error)
```

#### func (KeyCertificate) CryptoSize

```go
func (keyCertificate KeyCertificate) CryptoSize() (size int)
```
CryptoSize return the size of a Public Key corresponding to the Key
Certificate's publicKey type.

#### func (KeyCertificate) Data

```go
func (keyCertificate KeyCertificate) Data() ([]byte, error)
```
Data returns the raw []byte contained in the Certificate.

#### func (KeyCertificate) PublicKeyType

```go
func (keyCertificate KeyCertificate) PublicKeyType() (pubkey_type int)
```
PublicKeyType returns the publicKey type as a Go integer.

#### func (KeyCertificate) SignatureSize

```go
func (keyCertificate KeyCertificate) SignatureSize() (size int)
```
SignatureSize return the size of a Signature corresponding to the Key
Certificate's signingPublicKey type.

#### func (*KeyCertificate) SigningPublicKeySize

```go
func (keyCertificate *KeyCertificate) SigningPublicKeySize() int
```

#### func (KeyCertificate) SigningPublicKeyType

```go
func (keyCertificate KeyCertificate) SigningPublicKeyType() (signing_pubkey_type int)
```
SigningPublicKeyType returns the signingPublicKey type as a Go integer.



key_certificate

github.com/go-i2p/go-i2p/lib/common/key_certificate
