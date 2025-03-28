# base32
--
    import "github.com/go-i2p/go-i2p/lib/common/base32"

![base32.svg](base32.svg)

Package base32 implements utilities for encoding and decoding text using I2P's
### alphabet

## Usage

```go
const I2PEncodeAlphabet = "abcdefghijklmnopqrstuvwxyz234567"
```
I2PEncodeAlphabet is the base32 encoding used throughout I2P. RFC 3548 using
lowercase characters.

```go
var I2PEncoding *b32.Encoding = b32.NewEncoding(I2PEncodeAlphabet)
```
I2PEncoding is the standard base32 encoding used through I2P.

#### func  DecodeString

```go
func DecodeString(data string) ([]byte, error)
```
DecodeString decodes base32 string to []byte I2PEncoding

#### func  EncodeToString

```go
func EncodeToString(data []byte) string
```
EncodeToString encodes []byte to a base32 string using I2PEncoding



base32 

github.com/go-i2p/go-i2p/lib/common/base32
