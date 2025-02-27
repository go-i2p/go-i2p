# signature
--
    import "github.com/go-i2p/go-i2p/lib/common/signature"

![signature.svg](signature)

Package signature implements the I2P Signature common data structure

## Usage

```go
const (
	DSA_SHA1_SIZE               = 40
	ECDSA_SHA256_P256_SIZE      = 64
	ECDSA_SHA384_P384_SIZE      = 96
	ECDSA_SHA512_P512_SIZE      = 132
	RSA_SHA256_2048_SIZE        = 256
	RSA_SHA384_3072_SIZE        = 384
	RSA_SHA512_4096_SIZE        = 512
	EdDSA_SHA512_Ed25519_SIZE   = 64
	EdDSA_SHA512_Ed25519ph_SIZE = 64
	RedDSA_SHA512_Ed25519_SIZE  = 64
)
```
Lengths of signature keys

```go
const (
	SIGNATURE_TYPE_DSA_SHA1               = 0
	SIGNATURE_TYPE_ECDSA_SHA256_P256      = 1
	SIGNATURE_TYPE_ECDSA_SHA384_P384      = 2
	SIGNATURE_TYPE_ECDSA_SHA512_P521      = 3
	SIGNATURE_TYPE_RSA_SHA256_2048        = 4
	SIGNATURE_TYPE_RSA_SHA384_3072        = 5
	SIGNATURE_TYPE_RSA_SHA512_4096        = 6
	SIGNATURE_TYPE_EDDSA_SHA512_ED25519   = 7
	SIGNATURE_TYPE_EDDSA_SHA512_ED25519PH = 8
	SIGNATURE_TYPE_REDDSA_SHA512_ED25519  = 11
)
```

#### type Signature

```go
type Signature []byte
```

Signature is the represenation of an I2P Signature.

https://geti2p.net/spec/common-structures#signature

#### func  NewSignature

```go
func NewSignature(data []byte, sigType int) (signature *Signature, remainder []byte, err error)
```
NewSignature creates a new *Signature from []byte using ReadSignature. Returns a
pointer to Signature unlike ReadSignature.

#### func  ReadSignature

```go
func ReadSignature(data []byte, sigType int) (sig Signature, remainder []byte, err error)
```
ReadSignature returns a Signature from a []byte. The remaining bytes after the
specified length are also returned. Returns an error if there is insufficient
data to read the signature.

Since the signature type and length are inferred from context (the type of key
used), and are not explicitly stated, this function assumes the default
signature type (DSA_SHA1) with a length of 40 bytes.

If a different signature type is expected based on context, this function should
be modified accordingly to handle the correct signature length.



signature

github.com/go-i2p/go-i2p/lib/common/signature
