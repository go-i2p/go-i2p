package config

import (
	"path/filepath"

	"github.com/go-i2p/go-i2p/lib/util"
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
	return filepath.Join(util.UserHome(), GOI2P_BASE_DIR, "base")
}

func defaultConfig() string {
	return filepath.Join(util.UserHome(), GOI2P_BASE_DIR, "config")
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
