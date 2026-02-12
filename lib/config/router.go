package config

import (
	"fmt"
	"path/filepath"
	"sync"
)

// DefaultI2CPPort is the standard I2CP port
const DefaultI2CPPort = 7654

// I2CPConfig holds configuration for the I2CP server
type I2CPConfig struct {
	// Enable I2CP server
	Enabled bool
	// Address to listen on (default: "localhost:7654")
	Address string
	// Network type: "tcp" or "unix"
	Network string
	// Maximum number of concurrent sessions
	MaxSessions int

	// Username for optional I2CP authentication.
	// When both Username and Password are set, clients must provide
	// matching credentials via GetDate options (i2cp.username/i2cp.password)
	// before session-mutating operations are allowed.
	// Leave empty to disable authentication (default).
	Username string

	// Password for optional I2CP authentication.
	// See Username for details.
	Password string
}

// router.config options
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
	// I2PControl RPC server configuration
	I2PControl *I2PControlConfig
	// MaxBandwidth is the maximum bandwidth limit in bytes per second.
	// Default: 1048576 (1 MB/s). Set to 0 for unlimited.
	MaxBandwidth uint64
	// MaxConnections is the maximum number of concurrent transport connections.
	// Default: 200.
	MaxConnections int
	// AcceptTunnels controls whether the router participates in transit tunnels.
	// Default: true.
	AcceptTunnels bool
}

func defaultBase() string {
	return filepath.Join(BuildI2PDirPath(), "base")
}

func defaultConfig() string {
	return filepath.Join(BuildI2PDirPath(), "config")
}

// DefaultI2CPConfig provides default I2CP server configuration
var DefaultI2CPConfig = I2CPConfig{
	Enabled:     true,
	Address:     fmt.Sprintf("localhost:%d", DefaultI2CPPort),
	Network:     "tcp",
	MaxSessions: 100,
}

// defaults for router
var defaultRouterConfig = &RouterConfig{
	NetDb:          &DefaultNetDbConfig,
	Bootstrap:      &DefaultBootstrapConfig,
	I2CP:           &DefaultI2CPConfig,
	I2PControl:     defaultI2PControlConfigPtr(),
	BaseDir:        defaultBase(),
	WorkingDir:     defaultConfig(),
	MaxBandwidth:   1024 * 1024, // 1 MB/s
	MaxConnections: 200,
	AcceptTunnels:  true,
}

func defaultI2PControlConfigPtr() *I2PControlConfig {
	cfg := DefaultI2PControlConfig()
	return &cfg
}

func DefaultRouterConfig() *RouterConfig {
	// Return a deep copy so callers cannot mutate the package-level default.
	cfg := copyBaseFields(defaultRouterConfig)
	copyNestedConfigs(cfg, defaultRouterConfig)
	return cfg
}

// RouterConfigProperties is a global mutable configuration object
// DEPRECATED: This global variable is mutated by UpdateRouterConfig() creating
// hidden dependencies and making testing difficult. Use NewRouterConfigFromViper()
// instead to get a fresh config object without global state issues.
// NOTE: Access to this variable is protected by routerConfigMutex to prevent
// data races during SIGHUP config reloads.
var RouterConfigProperties = DefaultRouterConfig()

// routerConfigMutex protects RouterConfigProperties from concurrent access
// during configuration updates (e.g., SIGHUP reload).
var routerConfigMutex sync.RWMutex

// GetRouterConfig returns a copy of the current router configuration.
// This is the thread-safe way to access RouterConfigProperties.
// The returned copy is safe to use without holding locks.
func GetRouterConfig() *RouterConfig {
	routerConfigMutex.RLock()
	defer routerConfigMutex.RUnlock()

	configCopy := copyBaseFields(RouterConfigProperties)
	copyNestedConfigs(configCopy, RouterConfigProperties)

	return configCopy
}

// copyBaseFields creates a shallow copy of the scalar fields in a RouterConfig.
func copyBaseFields(src *RouterConfig) *RouterConfig {
	return &RouterConfig{
		BaseDir:        src.BaseDir,
		WorkingDir:     src.WorkingDir,
		MaxBandwidth:   src.MaxBandwidth,
		MaxConnections: src.MaxConnections,
		AcceptTunnels:  src.AcceptTunnels,
	}
}

// copyNestedConfigs deep-copies all nested configuration structs from src into dst.
func copyNestedConfigs(dst, src *RouterConfig) {
	if src.NetDb != nil {
		netDbCopy := *src.NetDb
		dst.NetDb = &netDbCopy
	}

	if src.Bootstrap != nil {
		dst.Bootstrap = copyBootstrapConfig(src.Bootstrap)
	}

	if src.I2CP != nil {
		i2cpCopy := *src.I2CP
		dst.I2CP = &i2cpCopy
	}

	if src.I2PControl != nil {
		i2pControlCopy := *src.I2PControl
		dst.I2PControl = &i2pControlCopy
	}
}

// copyBootstrapConfig creates a deep copy of a BootstrapConfig including its slices.
func copyBootstrapConfig(src *BootstrapConfig) *BootstrapConfig {
	bootstrapCopy := *src

	if src.ReseedServers != nil {
		bootstrapCopy.ReseedServers = make([]*ReseedConfig, len(src.ReseedServers))
		for i, server := range src.ReseedServers {
			if server != nil {
				serverCopy := *server
				bootstrapCopy.ReseedServers[i] = &serverCopy
			}
		}
	}

	if src.LocalNetDbPaths != nil {
		bootstrapCopy.LocalNetDbPaths = make([]string, len(src.LocalNetDbPaths))
		copy(bootstrapCopy.LocalNetDbPaths, src.LocalNetDbPaths)
	}

	return &bootstrapCopy
}

// LockRouterConfigForWrite acquires an exclusive write lock on RouterConfigProperties.
// This must be called before directly modifying RouterConfigProperties.
// Always defer UnlockRouterConfigWrite() after acquiring the lock.
func LockRouterConfigForWrite() {
	routerConfigMutex.Lock()
}

// UnlockRouterConfigWrite releases the write lock on RouterConfigProperties.
func UnlockRouterConfigWrite() {
	routerConfigMutex.Unlock()
}
