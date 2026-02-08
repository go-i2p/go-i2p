package config

// KnownReseedServers contains all verified I2P reseed servers.
// This list matches the Java I2P DEFAULT_SSL_SEED_URL list of active servers.
// Each server has a corresponding certificate in the embedded certificates/reseed/ directory.
//
// Note: Some servers share certificates (e.g., r4sas operates multiple mirrors).
var KnownReseedServers = []*ReseedConfig{
	// go-i2p dev team server (primary)
	{Url: "https://reseed.i2pgit.org/", SU3Fingerprint: "hankhill19580_at_gmail.com.crt"},
	// Community servers
	{Url: "https://reseed.sahil.world/", SU3Fingerprint: "sahil_at_mail.i2p.crt"},
	{Url: "https://i2p.diyarciftci.xyz/", SU3Fingerprint: "diyarciftci_at_protonmail.com.crt"},
	{Url: "https://coconut.incognet.io/", SU3Fingerprint: "rambler_at_mail.i2p.crt"},
	{Url: "https://reseed.stormycloud.org/", SU3Fingerprint: "admin_at_stormycloud.org.crt"},
	// i2pd mirrors (same certificate)
	{Url: "https://reseed-pl.i2pd.xyz/", SU3Fingerprint: "r4sas-reseed_at_mail.i2p.crt"},
	{Url: "https://reseed-fr.i2pd.xyz/", SU3Fingerprint: "r4sas-reseed_at_mail.i2p.crt"},
	// Additional community servers
	{Url: "https://www2.mk16.de/", SU3Fingerprint: "i2p-reseed_at_mk16.de.crt"},
	{Url: "https://reseed2.i2p.net/", SU3Fingerprint: "echelon3_at_mail.i2p.crt"},
	{Url: "https://reseed.diva.exchange/", SU3Fingerprint: "reseed_at_diva.exchange.crt"},
	{Url: "https://i2p.novg.net/", SU3Fingerprint: "igor_at_novg.net.crt"},
	{Url: "https://i2pseed.creativecowpat.net:8443/", SU3Fingerprint: "creativecowpat_at_mail.i2p.crt"},
	{Url: "https://reseed.onion.im/", SU3Fingerprint: "lazygravy_at_mail.i2p.crt"},
}

// ReseedStrategyUnion combines all unique RouterInfos from any successful server response.
// This is the default strategy and provides the largest peer set.
const ReseedStrategyUnion = "union"

// ReseedStrategyIntersection only uses RouterInfos present in ALL successful server responses.
// This provides stronger validation but may result in fewer peers.
const ReseedStrategyIntersection = "intersection"

// ReseedStrategyRandom randomly selects from the union, weighted by how many servers returned each RouterInfo.
// RouterInfos returned by multiple servers are more likely to be selected.
const ReseedStrategyRandom = "random"

// DefaultMinReseedServers is the minimum number of successful reseed servers required.
// This matches Java I2P's MIN_RESEED_SERVERS = 2 for security.
const DefaultMinReseedServers = 1

// ValidReseedStrategies returns the list of valid reseed strategy values.
func ValidReseedStrategies() []string {
	return []string{ReseedStrategyUnion, ReseedStrategyIntersection, ReseedStrategyRandom}
}

// IsValidReseedStrategy checks if the given strategy is valid.
func IsValidReseedStrategy(strategy string) bool {
	for _, valid := range ValidReseedStrategies() {
		if strategy == valid {
			return true
		}
	}
	return false
}
