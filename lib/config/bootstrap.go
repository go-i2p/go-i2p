package config

// configuration for 1 reseed server
type ReseedConfig struct {
	// url of reseed server
	Url string
	// fingerprint of reseed su3 signing key
	SU3Fingerprint string
}

type BootstrapConfig struct {
	// if we have less than this many peers we should reseed
	LowPeerThreshold int
	// path to a local reseed file (zip or su3) - takes priority over remote reseed servers
	ReseedFilePath string
	// reseed servers
	ReseedServers []*ReseedConfig
	// local netDb paths to search for existing RouterInfo files
	// (supports Java I2P and i2pd netDb directories)
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
