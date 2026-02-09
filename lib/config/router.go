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
	I2PControl:     &DefaultI2PControlConfig,
	BaseDir:        defaultBase(),
	WorkingDir:     defaultConfig(),
	MaxBandwidth:   1024 * 1024, // 1 MB/s
	MaxConnections: 200,
	AcceptTunnels:  true,
}

func DefaultRouterConfig() *RouterConfig {
	return defaultRouterConfig
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

	// Return a deep copy to prevent race conditions on nested structs
	configCopy := &RouterConfig{
		BaseDir:        RouterConfigProperties.BaseDir,
		WorkingDir:     RouterConfigProperties.WorkingDir,
		MaxBandwidth:   RouterConfigProperties.MaxBandwidth,
		MaxConnections: RouterConfigProperties.MaxConnections,
		AcceptTunnels:  RouterConfigProperties.AcceptTunnels,
	}

	if RouterConfigProperties.NetDb != nil {
		netDbCopy := *RouterConfigProperties.NetDb
		configCopy.NetDb = &netDbCopy
	}

	if RouterConfigProperties.Bootstrap != nil {
		bootstrapCopy := *RouterConfigProperties.Bootstrap
		// Deep copy slices
		if RouterConfigProperties.Bootstrap.ReseedServers != nil {
			bootstrapCopy.ReseedServers = make([]*ReseedConfig, len(RouterConfigProperties.Bootstrap.ReseedServers))
			for i, server := range RouterConfigProperties.Bootstrap.ReseedServers {
				if server != nil {
					serverCopy := *server
					bootstrapCopy.ReseedServers[i] = &serverCopy
				}
			}
		}
		if RouterConfigProperties.Bootstrap.LocalNetDbPaths != nil {
			bootstrapCopy.LocalNetDbPaths = make([]string, len(RouterConfigProperties.Bootstrap.LocalNetDbPaths))
			copy(bootstrapCopy.LocalNetDbPaths, RouterConfigProperties.Bootstrap.LocalNetDbPaths)
		}
		configCopy.Bootstrap = &bootstrapCopy
	}

	if RouterConfigProperties.I2CP != nil {
		i2cpCopy := *RouterConfigProperties.I2CP
		configCopy.I2CP = &i2cpCopy
	}

	if RouterConfigProperties.I2PControl != nil {
		i2pControlCopy := *RouterConfigProperties.I2PControl
		configCopy.I2PControl = &i2pControlCopy
	}

	return configCopy
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
