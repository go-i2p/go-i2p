# types
--
    import "github.com/go-i2p/go-i2p/lib/crypto/types"

![types.svg](types.svg)



## Usage

```go
var (
	ErrBadSignatureSize = oops.Errorf("bad signature size")
	ErrInvalidKeyFormat = oops.Errorf("invalid key format")
	ErrInvalidSignature = oops.Errorf("invalid signature")
)
```

```go
var SHA256 = sha256.Sum256
```

#### type Decrypter

```go
type Decrypter interface {
	// decrypt a block of data
	// return decrypted block or nil and error if error happens
	Decrypt(data []byte) ([]byte, error)
}
```

decrypts data

#### type Encrypter

```go
type Encrypter interface {
	// encrypt a block of data
	// return encrypted block or nil and error if an error happened
	Encrypt(data []byte) (enc []byte, err error)
}
```

encrypts data

#### type PrivateEncryptionKey

```go
type PrivateEncryptionKey interface {
	// create a new decryption object for this private key to decrypt data encrypted to our public key
	// returns decrypter or nil and error if the private key is in a bad format
	NewDecrypter() (Decrypter, error)
	// Public key
	Public() (SigningPublicKey, error)
	// Bytes returns the raw bytes of this private key
	Bytes() []byte
	// Zero clears all sensitive data from the private key
	Zero()
}
```


#### type PrivateKey

```go
type PrivateKey interface {
	// Public returns the public key corresponding to this private key
	Public() (SigningPublicKey, error)
	// Bytes returns the raw bytes of this private key
	Bytes() []byte
	// Zero clears all sensitive data from the private key
	Zero()
}
```

PrivateKey is an interface for private keys

#### type PublicEncryptionKey

```go
type PublicEncryptionKey interface {
	// create a new encrypter to encrypt data to this public key
	NewEncrypter() (Encrypter, error)

	// length of this public key in bytes
	Len() int
	Bytes() []byte
}
```


#### type PublicKey

```go
type PublicKey interface {
	Len() int
	Bytes() []byte
}
```


#### type RecievingPublicKey

```go
type RecievingPublicKey interface {
	Len() int
	Bytes() []byte
	NewEncrypter() (Encrypter, error)
}
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
	Bytes() []byte
}
```

key for verifying data

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



types 

github.com/go-i2p/go-i2p/lib/crypto/types

[go-i2p template file](/template.md)
