# config
--
    import "github.com/go-i2p/go-i2p/lib/config"

![config.svg](config.svg)



## Usage

```go
const GOI2P_BASE_DIR = ".go-i2p"
```

```go
var (
	CfgFile string
)
```

```go
var DefaultBootstrapConfig = BootstrapConfig{
	LowPeerThreshold: 10,
	ReseedFilePath:   "",

	ReseedServers: []*ReseedConfig{
		{
			Url:            "https://reseed.i2p-projekt.de/",
			SU3Fingerprint: "PLACEHOLDER_FINGERPRINT_1",
		},
		{
			Url:            "https://i2p.mooo.com/netDb/",
			SU3Fingerprint: "PLACEHOLDER_FINGERPRINT_2",
		},
		{
			Url:            "https://netdb.i2p2.no/",
			SU3Fingerprint: "PLACEHOLDER_FINGERPRINT_3",
		},
	},

	LocalNetDbPaths: []string{},
}
```
default configuration for network bootstrap

```go
var DefaultI2CPConfig = I2CPConfig{
	Enabled:     true,
	Address:     "localhost:7654",
	Network:     "tcp",
	MaxSessions: 100,
}
```
DefaultI2CPConfig provides default I2CP server configuration

```go
var DefaultNetDbConfig = NetDbConfig{
	Path: filepath.Join(defaultConfig(), "netDb"),
}
```
default settings for netdb

```go
var RouterConfigProperties = DefaultRouterConfig()
```
RouterConfigProperties is a global mutable configuration object DEPRECATED: This
global variable is mutated by UpdateRouterConfig() creating hidden dependencies
and making testing difficult. Use NewRouterConfigFromViper() instead to get a
fresh config object without global state issues.

#### func  BuildI2PDirPath

```go
func BuildI2PDirPath() string
```

#### func  InitConfig

```go
func InitConfig()
```

#### func  UpdateRouterConfig

```go
func UpdateRouterConfig()
```
UpdateRouterConfig updates the global RouterConfigProperties from viper settings
DEPRECATED: Use NewRouterConfigFromViper() instead to avoid global state
mutation

#### func  Validate

```go
func Validate(cfg ConfigDefaults) error
```
Validate checks if the provided configuration values are reasonable. Returns an
error describing the first invalid value found.

#### type BootstrapConfig

```go
type BootstrapConfig struct {
	// if we have less than this many peers we should reseed
	LowPeerThreshold int
	// path to a local reseed file (zip or su3) - takes priority over remote reseed servers
	ReseedFilePath string
	// reseed servers
	ReseedServers []*ReseedConfig
	// local netDb paths to search for existing RouterInfo files
	// (supports Java I2P and i2pd netDb directories)
	LocalNetDbPaths []string
}
```


#### type BootstrapDefaults

```go
type BootstrapDefaults struct {
	// LowPeerThreshold triggers reseeding when peer count falls below this
	// Default: 10 peers
	LowPeerThreshold int

	// ReseedTimeout is maximum time to wait for reseed operations
	// Default: 60 seconds
	ReseedTimeout time.Duration

	// MinimumReseedPeers is minimum peers to get from reseed
	// Default: 50 peers
	MinimumReseedPeers int

	// ReseedRetryInterval is time between reseed attempts
	// Default: 5 minutes
	ReseedRetryInterval time.Duration

	// ReseedServers are the default reseed server configurations
	// Note: These contain placeholder fingerprints - production should use real values
	ReseedServers []*ReseedConfig
}
```

BootstrapDefaults contains default values for network bootstrap

#### type ConfigDefaults

```go
type ConfigDefaults struct {
	// Router defaults
	Router RouterDefaults

	// Network Database defaults
	NetDB NetDBDefaults

	// Bootstrap defaults
	Bootstrap BootstrapDefaults

	// I2CP server defaults
	I2CP I2CPDefaults

	// Tunnel defaults
	Tunnel TunnelDefaults

	// Transport defaults
	Transport TransportDefaults

	// Performance tuning defaults
	Performance PerformanceDefaults
}
```

ConfigDefaults contains all default configuration values for go-i2p. This
centralizes default values to make them easy to discover, document, and modify.

Design Principles: - All defaults should be sensible for typical use cases -
Values should match I2P protocol standards where applicable - Performance
defaults balance resource usage with responsiveness - Security defaults favor
safety over convenience

#### func  Defaults

```go
func Defaults() ConfigDefaults
```
Defaults returns a ConfigDefaults instance with all default values set. This is
the single source of truth for all configuration defaults.

#### type I2CPConfig

```go
type I2CPConfig struct {
	// Enable I2CP server
	Enabled bool
	// Address to listen on (default: "localhost:7654")
	Address string
	// Network type: "tcp" or "unix"
	Network string
	// Maximum number of concurrent sessions
	MaxSessions int
}
```

I2CPConfig holds configuration for the I2CP server

#### type I2CPDefaults

```go
type I2CPDefaults struct {
	// Enabled determines if I2CP server starts automatically
	// Default: true
	Enabled bool

	// Address is the listen address for I2CP server
	// Default: "localhost:7654" (I2P protocol standard port)
	Address string

	// Network is the network type: "tcp" or "unix"
	// Default: "tcp"
	Network string

	// MaxSessions is maximum concurrent I2CP sessions
	// Default: 100 sessions
	MaxSessions int

	// MessageQueueSize is the buffer size for outbound messages per session
	// Default: 64 messages
	MessageQueueSize int

	// SessionTimeout is how long idle sessions stay alive
	// Default: 30 minutes
	SessionTimeout time.Duration

	// ReadTimeout is maximum time to wait for client reads
	// Default: 60 seconds
	ReadTimeout time.Duration

	// WriteTimeout is maximum time to wait for client writes
	// Default: 30 seconds
	WriteTimeout time.Duration
}
```

I2CPDefaults contains default values for I2CP server

#### type NetDBDefaults

```go
type NetDBDefaults struct {
	// Path is the directory for storing network database files
	// Default: $HOME/.go-i2p/config/netDb
	Path string

	// MaxRouterInfos is maximum RouterInfos to store locally
	// Default: 5000
	MaxRouterInfos int

	// MaxLeaseSets is maximum LeaseSets to cache
	// Default: 1000
	MaxLeaseSets int

	// ExpirationCheckInterval is how often to check for expired entries
	// Default: 1 minute
	ExpirationCheckInterval time.Duration

	// LeaseSetRefreshThreshold is when to refresh before expiration
	// Default: 2 minutes before expiration
	LeaseSetRefreshThreshold time.Duration

	// ExplorationInterval is how often to explore the network
	// Default: 5 minutes
	ExplorationInterval time.Duration

	// FloodfillEnabled determines if this router acts as floodfill
	// Default: false (regular router mode)
	FloodfillEnabled bool
}
```

NetDBDefaults contains default values for network database configuration

#### type NetDbConfig

```go
type NetDbConfig struct {
	// path to network database directory
	Path string
}
```

local network database configuration

#### type PerformanceDefaults

```go
type PerformanceDefaults struct {
	// MessageQueueSize is the buffer for router message processing
	// Default: 256 messages
	MessageQueueSize int

	// WorkerPoolSize is concurrent message processing workers
	// Default: 8 workers (or GOMAXPROCS)
	WorkerPoolSize int

	// GarlicEncryptionCacheSize is cache size for garlic sessions
	// Default: 1000 sessions
	GarlicEncryptionCacheSize int

	// FragmentCacheSize is cache size for message fragment reassembly
	// Default: 500 fragments
	FragmentCacheSize int

	// CleanupInterval is how often to run cleanup tasks
	// Default: 5 minutes
	CleanupInterval time.Duration
}
```

PerformanceDefaults contains default values for performance tuning

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
	// I2CP server configuration
	I2CP *I2CPConfig
}
```

router.config options

#### func  DefaultRouterConfig

```go
func DefaultRouterConfig() *RouterConfig
```

#### func  NewRouterConfigFromViper

```go
func NewRouterConfigFromViper() *RouterConfig
```
NewRouterConfigFromViper creates a new RouterConfig from current viper settings
This is the preferred way to get config instead of using the global
RouterConfigProperties

#### type RouterDefaults

```go
type RouterDefaults struct {
	// BaseDir is where per-system defaults are stored
	// Default: $HOME/.go-i2p/base
	BaseDir string

	// WorkingDir is where runtime files are modified
	// Default: $HOME/.go-i2p/config
	WorkingDir string

	// RouterInfoRefreshInterval is how often to update our RouterInfo
	// Default: 30 minutes
	RouterInfoRefreshInterval time.Duration

	// MessageExpirationTime is how long messages stay valid
	// Default: 60 seconds (I2P protocol standard)
	MessageExpirationTime time.Duration

	// MaxConcurrentSessions is maximum number of active transport sessions
	// Default: 200
	MaxConcurrentSessions int
}
```

RouterDefaults contains default values for router configuration

#### type TransportDefaults

```go
type TransportDefaults struct {
	// NTCP2Enabled determines if NTCP2 transport is active
	// Default: true
	NTCP2Enabled bool

	// NTCP2Port is the listen port for NTCP2
	// Default: 0 (random port assigned by OS)
	NTCP2Port int

	// NTCP2MaxConnections is maximum concurrent NTCP2 sessions
	// Default: 200
	NTCP2MaxConnections int

	// SSU2Enabled determines if SSU2 transport is active
	// Default: false (not yet implemented)
	SSU2Enabled bool

	// SSU2Port is the listen port for SSU2
	// Default: 0 (random port assigned by OS)
	SSU2Port int

	// ConnectionTimeout is maximum time to establish connection
	// Default: 30 seconds
	ConnectionTimeout time.Duration

	// IdleTimeout is when to close idle connections
	// Default: 5 minutes
	IdleTimeout time.Duration

	// MaxMessageSize is maximum I2NP message size
	// Default: 32768 bytes (32 KiB)
	MaxMessageSize int
}
```

TransportDefaults contains default values for transport layer

#### type TunnelDefaults

```go
type TunnelDefaults struct {
	// MinPoolSize is minimum tunnels to maintain per pool
	// Default: 4 tunnels
	MinPoolSize int

	// MaxPoolSize is maximum tunnels to maintain per pool
	// Default: 6 tunnels
	MaxPoolSize int

	// TunnelLength is hops per tunnel
	// Default: 3 hops (I2P protocol standard)
	TunnelLength int

	// TunnelLifetime is how long tunnels stay active
	// Default: 10 minutes (I2P protocol standard)
	TunnelLifetime time.Duration

	// TunnelTestInterval is how often to test tunnel health
	// Default: 60 seconds
	TunnelTestInterval time.Duration

	// TunnelTestTimeout is maximum time to wait for test response
	// Default: 5 seconds
	TunnelTestTimeout time.Duration

	// BuildTimeout is maximum time to wait for tunnel build
	// Default: 90 seconds (I2P protocol standard)
	BuildTimeout time.Duration

	// BuildRetries is maximum attempts to build a tunnel
	// Default: 3 attempts
	BuildRetries int

	// ReplaceBeforeExpiration is when to build replacement tunnel
	// Default: 2 minutes before expiration
	ReplaceBeforeExpiration time.Duration

	// MaintenanceInterval is how often to run pool maintenance
	// Default: 30 seconds
	MaintenanceInterval time.Duration
}
```

TunnelDefaults contains default values for tunnel management



config 

github.com/go-i2p/go-i2p/lib/config

[go-i2p template file](/template.md)
