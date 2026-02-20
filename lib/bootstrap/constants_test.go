package bootstrap

import "github.com/go-i2p/go-i2p/lib/config"

// Shared test constants for the bootstrap package.

const (
	// testLowPeerThreshold is the standard low peer threshold used in test configurations.
	testLowPeerThreshold = 10

	// testInvalidServerURL is a reseed server URL that will always fail to connect.
	testInvalidServerURL = "https://localhost:1/invalid"

	// testServerFingerprint is a dummy SU3 fingerprint for test reseed servers.
	testServerFingerprint = "test.crt"

	// testReseedServerURL is a real reseed server URL used in configuration tests.
	testReseedServerURL = "https://reseed.i2pgit.org/"

	// testReseedFingerprint is the fingerprint for the real test reseed server.
	testReseedFingerprint = "hankhill19580_at_gmail.com.crt"

	// testNonExistentFilePath is a file path that should never exist, for error testing.
	testNonExistentFilePath = "/nonexistent/test.su3"

	// testNonExistentNetDbPath is a netDb path that should never exist.
	testNonExistentNetDbPath = "/tmp/non-existent-netdb-12345"

	// testHost is the standard test IP address for router addresses.
	testHost = "192.168.1.1"

	// testPort is the standard test port number for router addresses.
	testPort = "12345"

	// testDummyFileSize is the minimum file size (in bytes) for valid test files.
	testDummyFileSize = 100
)

// newTestInvalidReseedServer creates a ReseedConfig pointing to an unreachable server.
func newTestInvalidReseedServer() *config.ReseedConfig {
	return &config.ReseedConfig{
		Url:            testInvalidServerURL,
		SU3Fingerprint: testServerFingerprint,
	}
}

// newTestInvalidReseedServers creates a slice with a single unreachable reseed server.
func newTestInvalidReseedServers() []*config.ReseedConfig {
	return []*config.ReseedConfig{newTestInvalidReseedServer()}
}

// createDummyContent creates deterministic byte content of the specified size for testing.
func createDummyContent(size int) []byte {
	content := make([]byte, size)
	for i := range content {
		content[i] = byte('A' + (i % 26))
	}
	return content
}
