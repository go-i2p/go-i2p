package config

import (
	"os"
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

func home() string {
	h, err := os.UserHomeDir()
	if err != nil {
		panic(err)
	}
	return h
}

func defaultBase() string {
	return filepath.Join(home(), "go-i2p", "base")
}

func defaultConfig() string {
	return filepath.Join(home(), "go-i2p", "config")
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

var RouterConfigProperties = DefaultRouterConfig()
