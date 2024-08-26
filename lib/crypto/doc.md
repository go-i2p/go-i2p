# crypto
--
    import "github.com/go-i2p/go-i2p/lib/crypto"

package for i2p specific crpytography

## Usage

```go
const (
	IPAD = byte(0x36)
	OPAD = byte(0x5C)
)
```

```go
var (
	ElgDecryptFail   = errors.New("failed to decrypt elgamal encrypted data")
	ElgEncryptTooBig = errors.New("failed to encrypt data, too big for elgamal")
)
```

```go
var (
	ErrBadSignatureSize = errors.New("bad signature size")
	ErrInvalidKeyFormat = errors.New("invalid key format")
	ErrInvalidSignature = errors.New("invalid signature")
)
```

```go
var Ed25519EncryptTooBig = errors.New("failed to encrypt data, too big for Ed25519")
```

```go
var SHA256 = sha256.Sum256
```

#### func  ElgamalGenerate

```go
func ElgamalGenerate(priv *elgamal.PrivateKey, rand io.Reader) (err error)
```
generate an elgamal key pair

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
func (k DSAPrivateKey) NewSigner() (s Signer, err error)
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


#### func (DSAPublicKey) Len

```go
func (k DSAPublicKey) Len() int
```

#### func (DSAPublicKey) NewVerifier

```go
func (k DSAPublicKey) NewVerifier() (v Verifier, err error)
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

#### type Decrypter

```go
type Decrypter interface {
	// decrypt a block of data
	// return decrypted block or nil and error if error happens
	Decrypt(data []byte) ([]byte, error)
}
```

decrypts data

#### type ECDSAVerifier

```go
type ECDSAVerifier struct {
}
```


#### func (*ECDSAVerifier) Verify

```go
func (v *ECDSAVerifier) Verify(data, sig []byte) (err error)
```
verify a block of data by hashing it and comparing the hash against the
signature

#### func (*ECDSAVerifier) VerifyHash

```go
func (v *ECDSAVerifier) VerifyHash(h, sig []byte) (err error)
```
verify a signature given the hash

#### type ECP256PrivateKey

```go
type ECP256PrivateKey [32]byte
```


#### type ECP256PublicKey

```go
type ECP256PublicKey [64]byte
```


#### func (ECP256PublicKey) Len

```go
func (k ECP256PublicKey) Len() int
```

#### func (ECP256PublicKey) NewVerifier

```go
func (k ECP256PublicKey) NewVerifier() (Verifier, error)
```

#### type ECP384PrivateKey

```go
type ECP384PrivateKey [48]byte
```


#### type ECP384PublicKey

```go
type ECP384PublicKey [96]byte
```


#### func (ECP384PublicKey) Len

```go
func (k ECP384PublicKey) Len() int
```

#### func (ECP384PublicKey) NewVerifier

```go
func (k ECP384PublicKey) NewVerifier() (Verifier, error)
```

#### type ECP521PrivateKey

```go
type ECP521PrivateKey [66]byte
```


#### type ECP521PublicKey

```go
type ECP521PublicKey [132]byte
```


#### func (ECP521PublicKey) Len

```go
func (k ECP521PublicKey) Len() int
```

#### func (ECP521PublicKey) NewVerifier

```go
func (k ECP521PublicKey) NewVerifier() (Verifier, error)
```

#### type Ed25519Encryption

```go
type Ed25519Encryption struct {
}
```


#### func (*Ed25519Encryption) Encrypt

```go
func (ed25519 *Ed25519Encryption) Encrypt(data []byte) (enc []byte, err error)
```

#### func (*Ed25519Encryption) EncryptPadding

```go
func (ed25519 *Ed25519Encryption) EncryptPadding(data []byte, zeroPadding bool) (encrypted []byte, err error)
```

#### type Ed25519PrivateKey

```go
type Ed25519PrivateKey ed25519.PrivateKey
```


#### type Ed25519PublicKey

```go
type Ed25519PublicKey []byte
```


#### func (Ed25519PublicKey) Len

```go
func (k Ed25519PublicKey) Len() int
```

#### func (Ed25519PublicKey) NewEncrypter

```go
func (elg Ed25519PublicKey) NewEncrypter() (enc Encrypter, err error)
```

#### func (Ed25519PublicKey) NewVerifier

```go
func (k Ed25519PublicKey) NewVerifier() (v Verifier, err error)
```

#### type Ed25519Signer

```go
type Ed25519Signer struct {
}
```


#### func (*Ed25519Signer) Sign

```go
func (s *Ed25519Signer) Sign(data []byte) (sig []byte, err error)
```

#### func (*Ed25519Signer) SignHash

```go
func (s *Ed25519Signer) SignHash(h []byte) (sig []byte, err error)
```

#### type Ed25519Verifier

```go
type Ed25519Verifier struct {
}
```


#### func (*Ed25519Verifier) Verify

```go
func (v *Ed25519Verifier) Verify(data, sig []byte) (err error)
```

#### func (*Ed25519Verifier) VerifyHash

```go
func (v *Ed25519Verifier) VerifyHash(h, sig []byte) (err error)
```

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
func (elg ElgPrivateKey) NewDecrypter() (dec Decrypter, err error)
```

#### type ElgPublicKey

```go
type ElgPublicKey [256]byte
```


#### func (ElgPublicKey) Len

```go
func (elg ElgPublicKey) Len() int
```

#### func (ElgPublicKey) NewEncrypter

```go
func (elg ElgPublicKey) NewEncrypter() (enc Encrypter, err error)
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

#### type Encrypter

```go
type Encrypter interface {
	// encrypt a block of data
	// return encrypted block or nil and error if an error happened
	Encrypt(data []byte) (enc []byte, err error)
}
```

encrypts data

#### type HMACDigest

```go
type HMACDigest [16]byte
```


#### func  I2PHMAC

```go
func I2PHMAC(data []byte, k HMACKey) (d HMACDigest)
```
do i2p hmac

#### type HMACKey

```go
type HMACKey [32]byte
```


#### type PrivateEncryptionKey

```go
type PrivateEncryptionKey interface {
	// create a new decryption object for this private key to decrypt data encrypted to our public key
	// returns decrypter or nil and error if the private key is in a bad format
	NewDecrypter() (Decrypter, error)
}
```


#### type PublicEncryptionKey

```go
type PublicEncryptionKey interface {
	// create a new encrypter to encrypt data to this public key
	NewEncrypter() (Encrypter, error)

	// length of this public key in bytes
	Len() int
}
```


#### type PublicKey

```go
type PublicKey interface {
	Len() int
	NewEncrypter() (Encrypter, error)
}
```


#### type RSA2048PrivateKey

```go
type RSA2048PrivateKey [512]byte
```


#### type RSA2048PublicKey

```go
type RSA2048PublicKey [256]byte
```


#### type RSA3072PrivateKey

```go
type RSA3072PrivateKey [786]byte
```


#### type RSA3072PublicKey

```go
type RSA3072PublicKey [384]byte
```


#### type RSA4096PrivateKey

```go
type RSA4096PrivateKey [1024]byte
```


#### type RSA4096PublicKey

```go
type RSA4096PublicKey [512]byte
```


#### type Signer

```go
type Signer interface {
	// sign data with our private key by calling SignHash after hashing the data we are given
	// return signature or nil signature and error if an error happened
	Sign(data []byte) (sig []byte, err error)

	// sign hash of data with our private key
	// return signature or nil signature and error if an error happened
	SignHash(h []byte) (sig []byte, err error)
}
```

type for signing data

#### type SigningPrivateKey

```go
type SigningPrivateKey interface {
	// create a new signer to sign data
	// return signer or nil and error if key format is invalid
	NewSigner() (Signer, error)
	// length of this private key
	Len() int
	// get public key or return nil and error if invalid key data in private key
	Public() (SigningPublicKey, error)
	// generate a new private key, put it into itself
	// returns itself or nil and error if an error occurs
	Generate() (SigningPrivateKey, error)
}
```

key for signing data

#### type SigningPublicKey

```go
type SigningPublicKey interface {
	// create new Verifier to verify the validity of signatures
	// return verifier or nil and error if key format is invalid
	NewVerifier() (Verifier, error)
	// get the size of this public key
	Len() int
}
```

key for verifying data

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

#### type Verifier

```go
type Verifier interface {
	// verify hashed data with this signing key
	// return nil on valid signature otherwise error
	VerifyHash(h, sig []byte) error
	// verify an unhashed piece of data by hashing it and calling VerifyHash
	Verify(data, sig []byte) error
}
```

type for verifying signatures
