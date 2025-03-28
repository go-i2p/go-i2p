# hmac
--
    import "github.com/go-i2p/go-i2p/lib/crypto/hmac"

![hmac.svg](hmac.svg)



## Usage

#### type HMACDigest

```go
type HMACDigest [16]byte
```


#### func  I2PHMAC

```go
func I2PHMAC(data []byte, k HMACKey) (d HMACDigest)
```
I2PHMAC computes HMAC-MD5 using the provided key and data

#### type HMACKey

```go
type HMACKey [32]byte
```



hmac 

github.com/go-i2p/go-i2p/lib/crypto/hmac
