# base64
--
    import "github.com/go-i2p/go-i2p/lib/common/base64"

![base64.svg](base64)

Package base64 implmenets utilities for encoding and decoding text using I2P's
### alphabet

## Usage

```go
const I2PEncodeAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-~"
```
I2PEncodeAlphabet is the base64 encoding used throughout I2P. RFC 4648 with "/""
replaced with "~", and "+" replaced with "-".

```go
var I2PEncoding *b64.Encoding = b64.NewEncoding(I2PEncodeAlphabet)
```
I2PEncoding is the standard base64 encoding used through I2P.

#### func  DecodeString

```go
func DecodeString(str string) ([]byte, error)
```
DecodeString decodes base64 string to []byte I2PEncoding

#### func  EncodeToString

```go
func EncodeToString(data []byte) string
```
I2PEncoding is the standard base64 encoding used through I2P.



base64

github.com/go-i2p/go-i2p/lib/common/base64
