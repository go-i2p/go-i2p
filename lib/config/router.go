package config

import (
	"path/filepath"
)

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
}

func defaultBase() string {
	return filepath.Join(BuildI2PDirPath(), "base")
}

func defaultConfig() string {
	return filepath.Join(BuildI2PDirPath(), "config")
}

// defaults for router
var defaultRouterConfig = &RouterConfig{
	NetDb:      &DefaultNetDbConfig,
	Bootstrap:  &DefaultBootstrapConfig,
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
