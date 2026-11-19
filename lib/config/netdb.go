package config

import (
	"path/filepath"
	"time"
)

// NetDBConfig holds the local network database configuration.
type NetDBConfig struct {
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
	// StrictRouterInfoNetworkValidation enforces required RouterInfo network
	// options (netId and router.version) on ingestion.
	StrictRouterInfoNetworkValidation bool
	// NetID is the I2P network identifier this router advertises and accepts.
	// The default "2" is the production I2P network. Set to another value
	// (e.g. "3") to join an isolated testnet: the local RouterInfo advertises
	// this netId and inbound RouterInfos carrying a different netId are
	// rejected. Keep it in sync with the netId used by the test network's
	// RouterInfos and reseed data.
	NetID string
	// RouterInfoAdmissionPressureThresholdPct controls when per-source
	// admission limits become active as cache pressure rises.
	RouterInfoAdmissionPressureThresholdPct int
}

// DefaultNetDBConfig holds the default settings for netdb.
var DefaultNetDBConfig = NetDBConfig{
	Path:                                    filepath.Join(defaultConfig(), "netDb"),
	MaxRouterInfos:                          DefaultMaxRouterInfos,
	MaxLeaseSets:                            DefaultMaxLeaseSets,
	ExpirationCheckInterval:                 DefaultNetDBExpirationCheckInterval,
	LeaseSetRefreshThreshold:                DefaultNetDBLeaseSetRefreshThreshold,
	ExplorationInterval:                     DefaultNetDBExplorationInterval,
	StrictRouterInfoNetworkValidation:       true,
	NetID:                                   DefaultNetID,
	RouterInfoAdmissionPressureThresholdPct: DefaultRouterInfoAdmissionPressurePct,
}
