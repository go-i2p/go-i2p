package config

import (
	"path/filepath"
)

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
	Address:     "localhost:7654",
	Network:     "tcp",
	MaxSessions: 100,
}

// defaults for router
var defaultRouterConfig = &RouterConfig{
	NetDb:      &DefaultNetDbConfig,
	Bootstrap:  &DefaultBootstrapConfig,
	I2CP:       &DefaultI2CPConfig,
	BaseDir:    defaultBase(),
	WorkingDir: defaultConfig(),
}

func DefaultRouterConfig() *RouterConfig {
	return defaultRouterConfig
}

// RouterConfigProperties is a global mutable configuration object
// DEPRECATED: This global variable is mutated by UpdateRouterConfig() creating
// hidden dependencies and making testing difficult. Use NewRouterConfigFromViper()
// instead to get a fresh config object without global state issues.
var RouterConfigProperties = DefaultRouterConfig()
