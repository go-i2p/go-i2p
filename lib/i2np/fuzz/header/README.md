# header
--
    import "github.com/go-i2p/go-i2p/lib/i2np/fuzz/header"

![header.svg](header.svg)

Package header provides go-fuzz harnesses for the I2NP header parser.

## Usage

#### func  Fuzz

```go
func Fuzz(data []byte) int
```
Fuzz is a go-fuzz entry point that feeds arbitrary data into the I2NP NTCP
header parser to detect panics.



header 

github.com/go-i2p/go-i2p/lib/i2np/fuzz/header

[go-i2p template file](template.md)
