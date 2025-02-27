# bootstrap
--
    import "github.com/go-i2p/go-i2p/lib/bootstrap"

![bootstrap.svg](bootstrap)

provides generic interfaces for initial bootstrap into network and network
### reseeding

## Usage

#### type Bootstrap

```go
type Bootstrap interface {
	// get more peers for bootstrap
	// try obtaining at most n router infos
	// if n is 0 then try obtaining as many router infos as possible
	// returns nil and error if we cannot fetch ANY router infos
	// returns a channel that yields 1 slice of router infos containing n or fewer router infos, caller must close channel after use
	GetPeers(n int) (chan []router_info.RouterInfo, error)
}
```

interface defining a way to bootstrap into the i2p network



bootstrap

github.com/go-i2p/go-i2p/lib/bootstrap
