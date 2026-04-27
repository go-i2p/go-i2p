package config

import (
	"fmt"
	"path/filepath"
	"sync"
	"time"
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

	// MessageQueueSize is the buffer size for outbound messages per session.
	// Default: 64 messages.
	MessageQueueSize int

	// SessionTimeout is how long idle sessions stay alive.
	// Default: 30 minutes. Set to 0 to disable timeout enforcement.
	SessionTimeout time.Duration

	// ReadTimeout is the maximum time to wait for client reads.
	// Default: 60 seconds.
	ReadTimeout time.Duration

	// WriteTimeout is the maximum time to wait for client writes.
	// Default: 30 seconds.
	WriteTimeout time.Duration
}

// RouterConfig holds the router configuration options.
type RouterConfig struct {
	// the path to the base config directory where per-system defaults are stored
	BaseDir string
	// the path to the working config directory where files are changed
	WorkingDir string
	// netdb configuration
	NetDB *NetDBConfig
	// configuration for bootstrapping into the network
	Bootstrap *BootstrapConfig
	// I2CP server configuration
	I2CP *I2CPConfig
	// I2PControl RPC server configuration
	I2PControl *I2PControlConfig
	// MaxBandwidth is the maximum bandwidth limit in bytes per second.
	// Default: 1048576 (1 MB/s). Set to 0 for unlimited.
	MaxBandwidth uint64
	// MaxBandwidthIn is the inbound bandwidth limit in bytes per second.
	// Set to 0 to fall back to MaxBandwidth. Set to 0 with MaxBandwidth=0 for unlimited.
	MaxBandwidthIn uint64
	// MaxBandwidthOut is the outbound bandwidth limit in bytes per second.
	// Set to 0 to fall back to MaxBandwidth. Set to 0 with MaxBandwidth=0 for unlimited.
	MaxBandwidthOut uint64
	// SharePercentage is the percentage (0–100) of bandwidth to share for transit tunnels.
	// Default: 0 (no explicit limit — router participates if AcceptTunnels is true).
	SharePercentage int
	// MaxConnections is the maximum number of concurrent transport connections.
	// Default: 200.
	MaxConnections int
	// AcceptTunnels controls whether the router participates in transit tunnels.
	// Default: true.
	AcceptTunnels bool
	// Tunnel configuration for tunnel pool management and building.
	Tunnel *TunnelDefaults
	// Transport configuration for NTCP2/SSU2 transports.
	Transport *TransportDefaults
	// Performance tuning configuration.
	Performance *PerformanceDefaults
	// Congestion advertisement configuration per Proposal 162.
	Congestion *CongestionDefaults
}

func defaultBase() string {
	return filepath.Join(BuildI2PDirPath(), "base")
}

func defaultConfig() string {
	return filepath.Join(BuildI2PDirPath(), "config")
}

// DefaultI2CPConfig provides default I2CP server configuration
var DefaultI2CPConfig = I2CPConfig{
	Enabled:          true,
	Address:          fmt.Sprintf("localhost:%d", DefaultI2CPPort),
	Network:          "tcp",
	MaxSessions:      100,
	MessageQueueSize: 64,
	SessionTimeout:   30 * time.Minute,
	ReadTimeout:      60 * time.Second,
	WriteTimeout:     30 * time.Second,
}

// DefaultTransportConfig provides default transport layer configuration
var DefaultTransportConfig = buildTransportDefaults()

// defaults for router
var defaultRouterConfig = &RouterConfig{
	NetDB:          &DefaultNetDBConfig,
	Bootstrap:      &DefaultBootstrapConfig,
	I2CP:           &DefaultI2CPConfig,
	I2PControl:     defaultI2PControlConfigPtr(),
	BaseDir:        defaultBase(),
	WorkingDir:     defaultConfig(),
	MaxBandwidth:   1024 * 1024, // 1 MB/s
	MaxConnections: 200,
	AcceptTunnels:  true,
	Tunnel:         defaultTunnelConfigPtr(),
	Transport:      defaultTransportConfigPtr(),
	Performance:    defaultPerformanceConfigPtr(),
	Congestion:     defaultCongestionConfigPtr(),
}

func defaultI2PControlConfigPtr() *I2PControlConfig {
	cfg := DefaultI2PControlConfig()
	return &cfg
}

func defaultTunnelConfigPtr() *TunnelDefaults {
	cfg := buildTunnelDefaults()
	return &cfg
}

func defaultTransportConfigPtr() *TransportDefaults {
	cfg := buildTransportDefaults()
	return &cfg
}

func defaultPerformanceConfigPtr() *PerformanceDefaults {
	cfg := buildPerformanceDefaults()
	return &cfg
}

func defaultCongestionConfigPtr() *CongestionDefaults {
	cfg := buildCongestionDefaults()
	return &cfg
}

// DefaultRouterConfig returns a deep copy of the default RouterConfig so callers cannot mutate the package-level default.
func DefaultRouterConfig() *RouterConfig {
	// Return a deep copy so callers cannot mutate the package-level default.
	cfg := copyBaseFields(defaultRouterConfig)
	copyNestedConfigs(cfg, defaultRouterConfig)
	return cfg
}

// routerConfigProperties is the internal global configuration object.
// All access must go through GetRouterConfig() (reads) or SetRouterConfig() (writes)
// which hold routerConfigMutex. Direct field access is a data race.
var routerConfigProperties = DefaultRouterConfig()

// routerConfigMutex protects routerConfigProperties from concurrent access
// during configuration updates (e.g., SIGHUP reload).
var routerConfigMutex sync.RWMutex

// GetRouterConfig returns a copy of the current router configuration.
// This is the thread-safe way to access routerConfigProperties.
// The returned copy is safe to use without holding locks.
func GetRouterConfig() *RouterConfig {
	routerConfigMutex.RLock()
	defer routerConfigMutex.RUnlock()

	configCopy := copyBaseFields(routerConfigProperties)
	copyNestedConfigs(configCopy, routerConfigProperties)

	return configCopy
}

// copyBaseFields creates a shallow copy of the scalar fields in a RouterConfig.
func copyBaseFields(src *RouterConfig) *RouterConfig {
	return &RouterConfig{
		BaseDir:         src.BaseDir,
		WorkingDir:      src.WorkingDir,
		MaxBandwidth:    src.MaxBandwidth,
		MaxBandwidthIn:  src.MaxBandwidthIn,
		MaxBandwidthOut: src.MaxBandwidthOut,
		SharePercentage: src.SharePercentage,
		MaxConnections:  src.MaxConnections,
		AcceptTunnels:   src.AcceptTunnels,
	}
}

// copyPtr creates a shallow copy of a pointer value.
// Returns nil if src is nil, otherwise returns a pointer to a copy of the value.
func copyPtr[T interface{}](src *T) *T {
	if src == nil {
		return nil
	}
	v := *src
	return &v
}

// copyNestedConfigs deep-copies all nested configuration structs from src into dst.
func copyNestedConfigs(dst, src *RouterConfig) {
	dst.NetDB = copyPtr(src.NetDB)
	dst.Bootstrap = copyBootstrapConfig(src.Bootstrap)
	dst.I2CP = copyPtr(src.I2CP)
	dst.I2PControl = copyPtr(src.I2PControl)
	dst.Tunnel = copyPtr(src.Tunnel)
	dst.Transport = copyPtr(src.Transport)
	dst.Performance = copyPtr(src.Performance)
	dst.Congestion = copyPtr(src.Congestion)
}

// copyBootstrapConfig creates a deep copy of a BootstrapConfig including its slices.
// Returns nil if src is nil.
func copyBootstrapConfig(src *BootstrapConfig) *BootstrapConfig {
	if src == nil {
		return nil
	}
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

	if src.LocalNetDBPaths != nil {
		bootstrapCopy.LocalNetDBPaths = make([]string, len(src.LocalNetDBPaths))
		copy(bootstrapCopy.LocalNetDBPaths, src.LocalNetDBPaths)
	}

	return &bootstrapCopy
}

// SetRouterConfig atomically replaces the global router configuration with cfg.
// This is the preferred way to update the configuration after building it via
// NewRouterConfigFromViper(). Thread-safe.
func SetRouterConfig(cfg *RouterConfig) {
	routerConfigMutex.Lock()
	defer routerConfigMutex.Unlock()
	log.Debug("replacing global router configuration")
	routerConfigProperties = cfg
}

// LockRouterConfigForWrite acquires an exclusive write lock on routerConfigProperties.
// This must be called before directly modifying routerConfigProperties.
// Always defer UnlockRouterConfigWrite() after acquiring the lock.
func LockRouterConfigForWrite() {
	routerConfigMutex.Lock()
}

// UnlockRouterConfigWrite releases the write lock on routerConfigProperties.
func UnlockRouterConfigWrite() {
	routerConfigMutex.Unlock()
}
