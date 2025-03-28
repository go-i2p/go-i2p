# aes
--
    import "github.com/go-i2p/go-i2p/lib/crypto/aes"

![aes.svg](aes.svg)



## Usage

#### func  NewCipher

```go
func NewCipher(c []byte) (cipher.Block, error)
```

#### type AESSymmetricDecrypter

```go
type AESSymmetricDecrypter struct {
	Key []byte
	IV  []byte
}
```

AESSymmetricDecrypter implements the Decrypter interface using AES

#### func (*AESSymmetricDecrypter) Decrypt

```go
func (d *AESSymmetricDecrypter) Decrypt(data []byte) ([]byte, error)
```
Decrypt decrypts data using AES-CBC with PKCS#7 padding

#### func (*AESSymmetricDecrypter) DecryptNoPadding

```go
func (d *AESSymmetricDecrypter) DecryptNoPadding(data []byte) ([]byte, error)
```
DecryptNoPadding decrypts data using AES-CBC without padding

#### type AESSymmetricEncrypter

```go
type AESSymmetricEncrypter struct {
	Key []byte
	IV  []byte
}
```

AESSymmetricEncrypter implements the Encrypter interface using AES

#### func (*AESSymmetricEncrypter) Encrypt

```go
func (e *AESSymmetricEncrypter) Encrypt(data []byte) ([]byte, error)
```
Encrypt encrypts data using AES-CBC with PKCS#7 padding

#### func (*AESSymmetricEncrypter) EncryptNoPadding

```go
func (e *AESSymmetricEncrypter) EncryptNoPadding(data []byte) ([]byte, error)
```
EncryptNoPadding encrypts data using AES-CBC without padding

#### type AESSymmetricKey

```go
type AESSymmetricKey struct {
	Key []byte // AES key (must be 16, 24, or 32 bytes for AES-128, AES-192, AES-256)
	IV  []byte // Initialization Vector (must be 16 bytes for AES)
}
```

AESSymmetricKey represents a symmetric key for AES encryption/decryption

#### func (*AESSymmetricKey) Len

```go
func (k *AESSymmetricKey) Len() int
```
Len returns the length of the key

#### func (*AESSymmetricKey) NewDecrypter

```go
func (k *AESSymmetricKey) NewDecrypter() (types.Decrypter, error)
```
NewDecrypter creates a new AESSymmetricDecrypter

#### func (*AESSymmetricKey) NewEncrypter

```go
func (k *AESSymmetricKey) NewEncrypter() (types.Encrypter, error)
```
NewEncrypter creates a new AESSymmetricEncrypter



aes 

github.com/go-i2p/go-i2p/lib/crypto/aes
