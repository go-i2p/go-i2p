# obfs
--
    import "github.com/go-i2p/go-i2p/lib/transport/obfs"


## Usage

#### func  DeobfuscateEphemeralKey

```go
func DeobfuscateEphemeralKey(message []byte, aesKey *crypto.AESSymmetricKey) ([]byte, error)
```
DeobfuscateEphemeralKey decrypts the ephemeral public key in the message using
AES-256-CBC without padding

#### func  ObfuscateEphemeralKey

```go
func ObfuscateEphemeralKey(message []byte, aesKey *crypto.AESSymmetricKey) ([]byte, error)
```
ObfuscateEphemeralKey encrypts the ephemeral public key in the message using
AES-256-CBC without padding

# obfs
--
    import "github.com/go-i2p/go-i2p/lib/transport/obfs"



![obfs.svg](obfs)

## Usage

#### func  DeobfuscateEphemeralKey

```go
func DeobfuscateEphemeralKey(message []byte, aesKey *crypto.AESSymmetricKey) ([]byte, error)
```
DeobfuscateEphemeralKey decrypts the ephemeral public key in the message using
AES-256-CBC without padding

#### func  ObfuscateEphemeralKey

```go
func ObfuscateEphemeralKey(message []byte, aesKey *crypto.AESSymmetricKey) ([]byte, error)
```
ObfuscateEphemeralKey encrypts the ephemeral public key in the message using
AES-256-CBC without padding



obfs

github.com/go-i2p/go-i2p/lib/transport/obfs
