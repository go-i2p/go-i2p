package config

import (
	"path/filepath"
)

// local network database configuration
type NetDbConfig struct {
	// path to network database directory
	Path string
	// FloodfillEnabled determines if this router operates as a floodfill router
	FloodfillEnabled bool
}

// default settings for netdb
var DefaultNetDbConfig = NetDbConfig{
	Path: filepath.Join(defaultConfig(), "netDb"),
}
