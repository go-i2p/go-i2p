# destination
--
    import "github.com/go-i2p/go-i2p/lib/common/destination"

![destination.svg](destination.svg)

Package destination implements the I2P Destination common data structure

## Usage

#### type Destination

```go
type Destination struct {
	*KeysAndCert
}
```

Destination is the represenation of an I2P Destination.

https://geti2p.net/spec/common-structures#destination

#### func  ReadDestination

```go
func ReadDestination(data []byte) (destination Destination, remainder []byte, err error)
```
ReadDestination returns Destination from a []byte. The remaining bytes after the
specified length are also returned. Returns a list of errors that occurred
during parsing.

#### func (Destination) Base32Address

```go
func (destination Destination) Base32Address() (str string)
```
Base32Address returns the I2P base32 address for this Destination.

#### func (Destination) Base64

```go
func (destination Destination) Base64() string
```
Base64 returns the I2P base64 address for this Destination.



destination 

github.com/go-i2p/go-i2p/lib/common/destination
