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
	// ReseedFilePath specifies a local reseed file (zip or su3 format).
	// If set, this takes priority over remote reseed servers.
	ReseedFilePath string
	// ReseedServers is the list of remote reseed servers to contact.
	// Only one default server is included; additional servers should be configured via config file.
	ReseedServers []*ReseedConfig
	// LocalNetDbPaths lists directories to search for existing RouterInfo files.
	// Supports Java I2P and i2pd netDb directory formats.
	// These paths are populated at runtime based on the operating system.
	LocalNetDbPaths []string
}

// default configuration for network bootstrap
// Note: Reseed servers should be configured via config file.
// Only reseed.i2pgit.org is included by default as it is maintained by the go-i2p dev team.
// Additional reseed servers from the I2P network can be added via configuration.
var DefaultBootstrapConfig = BootstrapConfig{
	LowPeerThreshold: 10,
	ReseedFilePath:   "", // No default reseed file
	// Default reseed server (run by go-i2p dev team)
	// Additional reseed servers should be configured via config file
	ReseedServers: []*ReseedConfig{
		{
			Url:            "https://reseed.i2pgit.org/",
			SU3Fingerprint: "hankhill19580_at_gmail.com.crt",
		},
	},
	// Local netDb paths are populated at runtime based on OS
	LocalNetDbPaths: []string{},
}
