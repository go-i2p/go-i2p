# reseed
--
    import "github.com/go-i2p/go-i2p/lib/netdb/reseed"


## Usage

```go
const (
	I2pUserAgent = "Wget/1.11.4"
)
```

#### type Reseed

```go
type Reseed struct {
	net.Dialer
}
```


#### func (Reseed) SingleReseed

```go
func (r Reseed) SingleReseed(uri string) ([]router_info.RouterInfo, error)
```
