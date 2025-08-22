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
	// reseed servers
	ReseedServers []*ReseedConfig
}

// default configuration for network bootstrap
var DefaultBootstrapConfig = BootstrapConfig{
	LowPeerThreshold: 10,
	// Standard I2P reseed servers for network bootstrap
	// These are example reseed servers - in production, use actual I2P reseed servers
	// with their correct SU3 signing key fingerprints
	ReseedServers: []*ReseedConfig{
		{
			Url:            "https://reseed.i2p-projekt.de/",
			SU3Fingerprint: "PLACEHOLDER_FINGERPRINT_1",
		},
		{
			Url:            "https://i2p.mooo.com/netDb/",
			SU3Fingerprint: "PLACEHOLDER_FINGERPRINT_2",
		},
		{
			Url:            "https://netdb.i2p2.no/",
			SU3Fingerprint: "PLACEHOLDER_FINGERPRINT_3",
		},
	},
}
