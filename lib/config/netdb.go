package config

import (
	"path/filepath"
	"time"
)

// local network database configuration
type NetDbConfig struct {
	// path to network database directory
	Path string
	// MaxRouterInfos is the maximum number of RouterInfos to store locally.
	// When exceeded, oldest entries are evicted. Default: 5000.
	MaxRouterInfos int
	// MaxLeaseSets is the maximum number of LeaseSets to cache.
	// When exceeded, oldest entries are evicted. Default: 1000.
	MaxLeaseSets int
	// ExpirationCheckInterval is how often to check for and remove expired entries.
	// Default: 1 minute.
	ExpirationCheckInterval time.Duration
	// LeaseSetRefreshThreshold is how far before expiration a LeaseSet should be refreshed.
	// Default: 2 minutes.
	LeaseSetRefreshThreshold time.Duration
	// ExplorationInterval is how often to explore the network for new peers.
	// Default: 5 minutes.
	ExplorationInterval time.Duration
	// FloodfillEnabled determines if this router operates as a floodfill router
	FloodfillEnabled bool
}

// default settings for netdb
var DefaultNetDbConfig = NetDbConfig{
	Path:                     filepath.Join(defaultConfig(), "netDb"),
	MaxRouterInfos:           5000,
	MaxLeaseSets:             1000,
	ExpirationCheckInterval:  1 * time.Minute,
	LeaseSetRefreshThreshold: 2 * time.Minute,
	ExplorationInterval:      5 * time.Minute,
}
