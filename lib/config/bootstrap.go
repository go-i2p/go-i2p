package config

import "time"

// ReseedConfig holds configuration for a single reseed server.
// Reseed servers provide initial peer RouterInfo files to bootstrap network connectivity.
type ReseedConfig struct {
	// URL is the HTTPS URL of the reseed server
	URL string
	// SU3Fingerprint is the fingerprint of the reseed server's SU3 signing key
	// used to verify the authenticity of downloaded reseed data
	SU3Fingerprint string
}

// BootstrapConfig configures how the router obtains initial peer information
// to join the I2P network. It supports multiple bootstrap methods including
// remote reseed servers, local reseed files, and existing netDb directories.
type BootstrapConfig struct {
	// LowPeerThreshold defines the minimum number of known peers before reseeding.
	// If the router has fewer peers than this threshold, it will attempt to reseed.
	LowPeerThreshold int
	// ReseedTimeout is maximum time to wait for reseed operations.
	ReseedTimeout time.Duration
	// MinimumReseedPeers is minimum peers to acquire during reseed.
	MinimumReseedPeers int
	// ReseedRetryInterval is time between reseed attempts.
	ReseedRetryInterval time.Duration
	// BootstrapType specifies which bootstrap method to use exclusively.
	// Valid values: "auto" (default, tries all methods), "file", "reseed", "local"
	// When set to a specific type, only that method will be used.
	BootstrapType string
	// ReseedFilePath specifies a local reseed file (zip or su3 format).
	// If set, this takes priority over remote reseed servers.
	ReseedFilePath string
	// ReseedServers is the list of remote reseed servers to contact.
	// By default, uses KnownReseedServers which includes all verified I2P reseed servers.
	ReseedServers []*ReseedConfig
	// LocalNetDBPaths lists directories to search for existing RouterInfo files.
	// Supports Java I2P and i2pd netDb directory formats.
	// These paths are populated at runtime based on the operating system.
	LocalNetDBPaths []string
	// MinReseedServers is the minimum number of successful reseed servers required.
	// If fewer servers respond successfully, the reseed operation fails.
	// Default: DefaultMinReseedServers (2), matching Java I2P MIN_RESEED_SERVERS
	// for enhanced security through multi-server confirmation.
	MinReseedServers int
	// ReseedStrategy determines how RouterInfos from multiple servers are combined:
	// - "union": Use all unique RouterInfos from any successful server (default)
	// - "intersection": Only use RouterInfos present in ALL successful server responses
	// - "random": Randomly select from union, weighted by appearance count
	ReseedStrategy string
	// PeerCacheEnabled controls whether the peer cache mechanism is active.
	// When enabled, recently discovered peers are cached to disk and consulted
	// as the fastest local bootstrap source on repeat startups, reducing
	// bootstrap time.
	PeerCacheEnabled bool
	// PeerCachePath is the on-disk location of the peer cache file.
	// If empty, a default location under the config working directory is used.
	PeerCachePath string
	// PeerCacheMaxSize is the maximum number of peers to keep in the cache.
	// When exceeded, the least-recently-active peers are evicted.
	// If <= 0, a sensible default (500) is used.
	PeerCacheMaxSize int
}

// DefaultBootstrapConfig is the default configuration for network bootstrap.
// Uses all known reseed servers from KnownReseedServers for maximum availability.
// MinReseedServers defaults to DefaultMinReseedServers (2) matching Java I2P.
var DefaultBootstrapConfig = BootstrapConfig{
	LowPeerThreshold:    10,
	ReseedTimeout:       60 * time.Second,
	MinimumReseedPeers:  50,
	ReseedRetryInterval: 5 * time.Minute,
	BootstrapType:       "auto", // Default to composite (tries all methods)
	ReseedFilePath:      "",     // No default reseed file
	// Use all known reseed servers for maximum availability
	ReseedServers: KnownReseedServers,
	// Local netDb paths are populated at runtime based on OS
	LocalNetDBPaths: []string{},
	// Minimum successful servers required (1 for backward compatibility)
	MinReseedServers: DefaultMinReseedServers,
	// Default to union strategy for maximum peer discovery
	ReseedStrategy: ReseedStrategyUnion,
	// Peer cache enabled by default to reduce repeat-startup bootstrap time
	PeerCacheEnabled: true,
	// Peer cache path is populated at runtime based on the OS working directory
	PeerCachePath:  "",
	PeerCacheMaxSize: 500,
}
