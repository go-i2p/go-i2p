package config

// ReseedConfig holds configuration for a single reseed server.
// Reseed servers provide initial peer RouterInfo files to bootstrap network connectivity.
type ReseedConfig struct {
	// Url is the HTTPS URL of the reseed server
	Url string
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
	// LocalNetDbPaths lists directories to search for existing RouterInfo files.
	// Supports Java I2P and i2pd netDb directory formats.
	// These paths are populated at runtime based on the operating system.
	LocalNetDbPaths []string
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
}

// default configuration for network bootstrap
// Uses all known reseed servers from KnownReseedServers for maximum availability.
// MinReseedServers defaults to DefaultMinReseedServers (2) matching Java I2P.
var DefaultBootstrapConfig = BootstrapConfig{
	LowPeerThreshold: 10,
	BootstrapType:    "auto", // Default to composite (tries all methods)
	ReseedFilePath:   "",     // No default reseed file
	// Use all known reseed servers for maximum availability
	ReseedServers: KnownReseedServers,
	// Local netDb paths are populated at runtime based on OS
	LocalNetDbPaths: []string{},
	// Minimum successful servers required (1 for backward compatibility)
	MinReseedServers: DefaultMinReseedServers,
	// Default to union strategy for maximum peer discovery
	ReseedStrategy: ReseedStrategyUnion,
}
