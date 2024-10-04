# config
--
    import "github.com/go-i2p/go-i2p/lib/config"


## Usage

```go
var DefaultBootstrapConfig = BootstrapConfig{
	LowPeerThreshold: 10,

	ReseedServers: []*ReseedConfig{},
}
```
default configuration for network bootstrap

```go
var DefaultNetDbConfig = NetDbConfig{
	Path: filepath.Join(defaultConfig(), "netDb"),
}
```
default settings for netdb

```go
var RouterConfigProperties = DefaultRouterConfig()
```

#### type BootstrapConfig

```go
type BootstrapConfig struct {
	// if we have less than this many peers we should reseed
	LowPeerThreshold int
	// reseed servers
	ReseedServers []*ReseedConfig
}
```


#### type NetDbConfig

```go
type NetDbConfig struct {
	// path to network database directory
	Path string
}
```

local network database configuration

#### type ReseedConfig

```go
type ReseedConfig struct {
	// url of reseed server
	Url string
	// fingerprint of reseed su3 signing key
	SU3Fingerprint string
}
```

configuration for 1 reseed server

#### type RouterConfig

```go
type RouterConfig struct {
	// the path to the base config directory where per-system defaults are stored
	BaseDir string
	// the path to the working config directory where files are changed
	WorkingDir string
	// netdb configuration
	NetDb *NetDbConfig
	// configuration for bootstrapping into the network
	Bootstrap *BootstrapConfig
}
```

router.config options

#### func  DefaultRouterConfig

```go
func DefaultRouterConfig() *RouterConfig
```
