# keys_and_cert
--
    import "github.com/go-i2p/go-i2p/lib/common/keys_and_cert"

![keys_and_cert.svg](keys_and_cert.svg)

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
	KeyCertificate  *KeyCertificate
	ReceivingPublic types.RecievingPublicKey
	Padding         []byte
	SigningPublic   types.SigningPublicKey
}
```

KeysAndCert is the represenation of an I2P KeysAndCert.

https://geti2p.net/spec/common-structures#keysandcert

#### func  NewKeysAndCert

```go
func NewKeysAndCert(
	keyCertificate *KeyCertificate,
	publicKey types.RecievingPublicKey,
	padding []byte,
	signingPublicKey types.SigningPublicKey,
) (*KeysAndCert, error)
```
NewKeysAndCert creates a new KeysAndCert instance with the provided parameters.
It validates the sizes of the provided keys and padding before assembling the
struct.

#### func  ReadKeysAndCert

```go
func ReadKeysAndCert(data []byte) (*KeysAndCert, []byte, error)
```
ReadKeysAndCert creates a new *KeysAndCert from []byte using ReadKeysAndCert.
Returns a pointer to KeysAndCert unlike ReadKeysAndCert.

#### func  ReadKeysAndCertElgAndEd25519

```go
func ReadKeysAndCertElgAndEd25519(data []byte) (keysAndCert *KeysAndCert, remainder []byte, err error)
```

#### func (KeysAndCert) Bytes

```go
func (keys_and_cert KeysAndCert) Bytes() []byte
```
Bytes returns the entire keyCertificate in []byte form, trims payload to
specified length.

#### func (*KeysAndCert) Certificate

```go
func (keys_and_cert *KeysAndCert) Certificate() (cert Certificate)
```
Certfificate returns the certificate.

#### func (*KeysAndCert) PublicKey

```go
func (keys_and_cert *KeysAndCert) PublicKey() (key types.RecievingPublicKey)
```
publicKey returns the public key as a types.publicKey.

#### func (*KeysAndCert) SigningPublicKey

```go
func (keys_and_cert *KeysAndCert) SigningPublicKey() (signing_public_key types.SigningPublicKey)
```
signingPublicKey returns the signing public key.

#### type PrivateKeysAndCert

```go
type PrivateKeysAndCert struct {
	KeysAndCert
	PK_KEY  crypto.PrivateKey
	SPK_KEY crypto.PrivateKey
}
```

PrivateKeysAndCert contains a KeysAndCert along with the corresponding private
keys for the Public Key and the Signing Public Key

#### func  NewPrivateKeysAndCert

```go
func NewPrivateKeysAndCert() (*PrivateKeysAndCert, error)
```



keys_and_cert 

github.com/go-i2p/go-i2p/lib/common/keys_and_cert
