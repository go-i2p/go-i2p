package tunnel

import "time"

// =============================================================================
// Shared test constants for lib/tunnel test suite
// =============================================================================
// These constants centralise magic numbers and test-specific values
// that appear in multiple test files. Production constants such as
// maxTunnelPayload live in the corresponding source files.

const (
	// testTunnelMessageSize is the fixed I2P tunnel message size (bytes).
	// Every encrypted tunnel message is exactly this long.
	// Reference: I2P spec — "Tunnel Message Delivery"
	testTunnelMessageSize = 1028

	// testTunnelDataSize is the usable data area after removing
	// tunnelID(4) + IV(16) = 20 bytes of header from testTunnelMessageSize.
	// This is the size of the encrypted payload block.
	testTunnelDataSize = testTunnelMessageSize - 4 - 16 // 1008

	// testTunnelOverhead is the per-message overhead:
	// tunnelID(4) + IV(16) + checksum(4) + zero-byte separator(1) = 25.
	testTunnelOverhead = 4 + 16 + 4 + 1 // 25

	// testMaxTunnelPayload is the maximum delivery-instruction + payload
	// size that fits inside one tunnel message.  Must equal maxTunnelPayload
	// from gateway.go.
	testMaxTunnelPayload = testTunnelMessageSize - testTunnelOverhead // 1003

	// testIVSize is the size (bytes) of the IV field in tunnel messages.
	testIVSize = 16

	// testChecksumSize is the size (bytes) of the SHA-256 checksum prefix.
	testChecksumSize = 4

	// testTunnelIDSize is the size (bytes) of a tunnel ID field.
	testTunnelIDSize = 4

	// testHashSize is the size (bytes) of an I2P SHA-256 hash / ident hash.
	testHashSize = 32

	// testTunnelLifetime is the I2P spec tunnel lifetime (10 minutes).
	testTunnelLifetime = 10 * time.Minute

	// testRebuildThreshold is the default rebuild-before-expiry window.
	testRebuildThreshold = 2 * time.Minute

	// testMaxHopCount is the maximum number of hops per I2P spec.
	testMaxHopCount = 8

	// testBuildRecordPadding is the padding length in BuildRequestRecord.
	testBuildRecordPadding = 29
)
