package bootstrap

import (
	"testing"

	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/router_info"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- RouterAddress validation tests ---

func TestValidateRouterAddress_ValidNTCP2(t *testing.T) {
	addr := createTestRouterAddress("ntcp2", map[string]string{
		"host": testHost,
		"port": testPort,
		"s":    "test-static-key",
	})

	err := ValidateRouterAddress(addr)
	assert.NoError(t, err)
}

func TestValidateRouterAddress_ValidNTCP2CaseInsensitive(t *testing.T) {
	addr := createTestRouterAddress("NTCP2", map[string]string{
		"host": testHost,
		"port": testPort,
	})

	err := ValidateRouterAddress(addr)
	assert.NoError(t, err)
}

func TestValidateRouterAddress_NTCP2MissingHost(t *testing.T) {
	addr := createTestRouterAddress("ntcp2", map[string]string{
		"port": testPort,
	})

	err := ValidateRouterAddress(addr)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot retrieve host")
}

func TestValidateRouterAddress_NTCP2EmptyHost(t *testing.T) {
	addr := createTestRouterAddress("ntcp2", map[string]string{
		"host": "",
		"port": testPort,
	})

	err := ValidateRouterAddress(addr)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot retrieve host")
}

func TestValidateRouterAddress_NTCP2MissingPort(t *testing.T) {
	addr := createTestRouterAddress("ntcp2", map[string]string{
		"host": testHost,
	})

	err := ValidateRouterAddress(addr)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot retrieve port")
}

func TestValidateRouterAddress_NTCP2EmptyPort(t *testing.T) {
	addr := createTestRouterAddress("ntcp2", map[string]string{
		"host": testHost,
		"port": "",
	})

	err := ValidateRouterAddress(addr)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot retrieve port")
}

func TestValidateRouterAddress_ValidSSU(t *testing.T) {
	addr := createTestRouterAddress("ssu", map[string]string{
		"host": "10.0.0.1",
		"port": "30777",
	})

	err := ValidateRouterAddress(addr)
	assert.NoError(t, err)
}

func TestValidateRouterAddress_SSUMissingHost(t *testing.T) {
	addr := createTestRouterAddress("ssu", map[string]string{
		"port": "30777",
	})

	err := ValidateRouterAddress(addr)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot retrieve host")
}

func TestValidateRouterAddress_ValidSSU2(t *testing.T) {
	addr := createTestRouterAddress("ssu2", map[string]string{
		"host": "172.16.0.1",
		"port": "41234",
	})

	err := ValidateRouterAddress(addr)
	assert.NoError(t, err)
}

func TestValidateRouterAddress_SSU2MissingPort(t *testing.T) {
	addr := createTestRouterAddress("ssu2", map[string]string{
		"host": "172.16.0.1",
	})

	err := ValidateRouterAddress(addr)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot retrieve port")
}

func TestValidateRouterAddress_UnknownTransport(t *testing.T) {
	addr := createTestRouterAddress("future-transport-v3", map[string]string{
		"host": testHost,
		"port": testPort,
	})

	// Unknown transports should not fail validation (forward compatibility)
	err := ValidateRouterAddress(addr)
	assert.NoError(t, err)
}

// --- ValidationStats tests ---

func TestValidationStats_New(t *testing.T) {
	stats := NewValidationStats()
	assert.NotNil(t, stats)
	assert.Equal(t, 0, stats.TotalProcessed)
	assert.Equal(t, 0, stats.ValidRouterInfos)
	assert.Equal(t, 0, stats.InvalidRouterInfos)
	assert.NotNil(t, stats.InvalidReasons)
	assert.Equal(t, 0, len(stats.InvalidReasons))
}

func TestValidationStats_RecordValid(t *testing.T) {
	stats := NewValidationStats()
	stats.RecordValid()
	stats.RecordValid()

	assert.Equal(t, 2, stats.TotalProcessed)
	assert.Equal(t, 2, stats.ValidRouterInfos)
	assert.Equal(t, 0, stats.InvalidRouterInfos)
}

func TestValidationStats_RecordInvalid(t *testing.T) {
	stats := NewValidationStats()
	stats.RecordInvalid("missing host key")
	stats.RecordInvalid("empty port")
	stats.RecordInvalid("missing host key") // Same reason again

	assert.Equal(t, 3, stats.TotalProcessed)
	assert.Equal(t, 0, stats.ValidRouterInfos)
	assert.Equal(t, 3, stats.InvalidRouterInfos)
	assert.Equal(t, 2, stats.InvalidReasons["missing host key"])
	assert.Equal(t, 1, stats.InvalidReasons["empty port"])
}

func TestValidationStats_ValidityRate(t *testing.T) {
	stats := NewValidationStats()

	// Empty stats
	assert.Equal(t, 0.0, stats.ValidityRate())

	// All valid
	stats.RecordValid()
	stats.RecordValid()
	assert.Equal(t, 100.0, stats.ValidityRate())

	// Mixed
	stats.RecordInvalid("test error")
	stats.RecordInvalid("test error")
	// Now: 2 valid, 2 invalid, 4 total
	assert.InDelta(t, 50.0, stats.ValidityRate(), 0.1)
}

func TestValidationStats_Mixed(t *testing.T) {
	stats := NewValidationStats()

	stats.RecordValid()
	stats.RecordInvalid("missing host")
	stats.RecordValid()
	stats.RecordInvalid("empty port")
	stats.RecordValid()
	stats.RecordInvalid("missing host")

	assert.Equal(t, 6, stats.TotalProcessed)
	assert.Equal(t, 3, stats.ValidRouterInfos)
	assert.Equal(t, 3, stats.InvalidRouterInfos)
	assert.InDelta(t, 50.0, stats.ValidityRate(), 0.1)
	assert.Equal(t, 2, stats.InvalidReasons["missing host"])
	assert.Equal(t, 1, stats.InvalidReasons["empty port"])
}

// --- Signature verification tests ---

// TestVerifyRouterInfoSignature_ValidSignature verifies that a properly signed
// RouterInfo passes signature verification.
func TestVerifyRouterInfoSignature_ValidSignature(t *testing.T) {
	ri := createSignedTestRouterInfo(t, nil)
	err := VerifyRouterInfoSignature(*ri)
	assert.NoError(t, err, "Valid RouterInfo signature should pass verification")
}

// TestVerifyRouterInfoSignature_ValidWithOptions verifies that RouterInfos with
// various option configurations still pass signature verification.
func TestVerifyRouterInfoSignature_ValidWithOptions(t *testing.T) {
	options := map[string]string{
		"caps":           "fR",
		"netId":          "2",
		"router.version": "0.9.67",
	}
	ri := createSignedTestRouterInfo(t, options)
	err := VerifyRouterInfoSignature(*ri)
	assert.NoError(t, err, "RouterInfo with options should pass signature verification")
}

// TestVerifyRouterInfoSignature_CorruptedSignature verifies that a RouterInfo
// with tampered signature bytes is rejected.
func TestVerifyRouterInfoSignature_CorruptedSignature(t *testing.T) {
	ri := createSignedTestRouterInfo(t, nil)

	// Serialize the RouterInfo, corrupt the signature (last bytes), and re-parse
	riBytes, err := ri.Bytes()
	require.NoError(t, err, "Failed to serialize RouterInfo")

	// Corrupt the last byte of the signature
	riBytes[len(riBytes)-1] ^= 0xFF

	// Re-parse the corrupted bytes
	corruptedRI, _, err := router_info.ReadRouterInfo(riBytes)
	require.NoError(t, err, "Failed to re-parse RouterInfo with corrupted signature")

	err = VerifyRouterInfoSignature(corruptedRI)
	assert.Error(t, err, "RouterInfo with corrupted signature should fail verification")
	assert.Contains(t, err.Error(), "signature verification failed",
		"Error should indicate signature verification failure")
}

// TestVerifyRouterInfoSignature_CorruptedData verifies that a RouterInfo
// with tampered data bytes (but original signature) is rejected.
func TestVerifyRouterInfoSignature_CorruptedData(t *testing.T) {
	ri := createSignedTestRouterInfo(t, nil)

	// Serialize the RouterInfo
	riBytes, err := ri.Bytes()
	require.NoError(t, err, "Failed to serialize RouterInfo")

	// Get signature size so we know where data ends
	sigType := ri.RouterIdentity().KeyCertificate.SigningPublicKeyType()
	sigSize, err := key_certificate.GetSignatureSize(sigType)
	require.NoError(t, err, "Failed to get signature size")

	// Corrupt a byte in the data section (before the signature)
	// Pick a byte well into the data section to avoid breaking the parser
	corruptIndex := len(riBytes) - sigSize - 5
	if corruptIndex < 0 {
		corruptIndex = 10
	}
	riBytes[corruptIndex] ^= 0xFF

	// Re-parse the corrupted bytes
	corruptedRI, _, err := router_info.ReadRouterInfo(riBytes)
	require.NoError(t, err, "Failed to re-parse RouterInfo with corrupted data")

	err = VerifyRouterInfoSignature(corruptedRI)
	assert.Error(t, err, "RouterInfo with corrupted data should fail verification")
}

// TestVerifyRouterInfoSignature_DifferentKeySignature verifies that a RouterInfo
// signed with a different key than the one in the RouterIdentity is rejected.
func TestVerifyRouterInfoSignature_DifferentKeySignature(t *testing.T) {
	// Create two RouterInfos with different keys
	ri1 := createSignedTestRouterInfo(t, map[string]string{"test": "first"})
	ri2 := createSignedTestRouterInfo(t, map[string]string{"test": "second"})

	// Serialize ri1, replace its signature with ri2's signature
	ri1Bytes, err := ri1.Bytes()
	require.NoError(t, err)
	ri2Sig := ri2.Signature()

	sigType := ri1.RouterIdentity().KeyCertificate.SigningPublicKeyType()
	sigSize, err := key_certificate.GetSignatureSize(sigType)
	require.NoError(t, err)

	// Replace ri1's signature with ri2's signature
	ri2SigBytes := ri2Sig.Bytes()
	require.Equal(t, sigSize, len(ri2SigBytes), "Signature sizes should match")
	copy(ri1Bytes[len(ri1Bytes)-sigSize:], ri2SigBytes)

	// Re-parse
	crossSignedRI, _, err := router_info.ReadRouterInfo(ri1Bytes)
	require.NoError(t, err)

	err = VerifyRouterInfoSignature(crossSignedRI)
	assert.Error(t, err, "RouterInfo with wrong key's signature should fail verification")
}

// TestVerifyRouterInfoSignature_MultipleValidRouterInfos verifies that multiple
// independently created RouterInfos all pass verification, ensuring the function
// works consistently across different keys.
func TestVerifyRouterInfoSignature_MultipleValidRouterInfos(t *testing.T) {
	for i := 0; i < 5; i++ {
		ri := createSignedTestRouterInfo(t, map[string]string{
			"test.iteration": string(rune('0' + i)),
		})
		err := VerifyRouterInfoSignature(*ri)
		assert.NoError(t, err, "RouterInfo %d should pass signature verification", i)
	}
}

// TestVerifyRouterInfoSignature_EmptySignature verifies that a RouterInfo
// with zero-length signature bytes is rejected.
func TestVerifyRouterInfoSignature_EmptySignature(t *testing.T) {
	ri := createSignedTestRouterInfo(t, nil)

	// Serialize and truncate the signature
	riBytes, err := ri.Bytes()
	require.NoError(t, err)

	sigType := ri.RouterIdentity().KeyCertificate.SigningPublicKeyType()
	sigSize, err := key_certificate.GetSignatureSize(sigType)
	require.NoError(t, err)

	// Zero out the signature bytes
	for i := len(riBytes) - sigSize; i < len(riBytes); i++ {
		riBytes[i] = 0
	}

	// Re-parse
	zeroedRI, _, err := router_info.ReadRouterInfo(riBytes)
	require.NoError(t, err)

	err = VerifyRouterInfoSignature(zeroedRI)
	assert.Error(t, err, "RouterInfo with zeroed signature should fail verification")
}

// TestVerifyRouterInfoSignature_RoundTrip verifies that serialization and
// deserialization preserves the ability to verify signatures.
func TestVerifyRouterInfoSignature_RoundTrip(t *testing.T) {
	ri := createSignedTestRouterInfo(t, map[string]string{
		"caps":           "fR",
		"router.version": "0.9.67",
	})

	// Verify original
	err := VerifyRouterInfoSignature(*ri)
	require.NoError(t, err, "Original RouterInfo should verify")

	// Serialize
	riBytes, err := ri.Bytes()
	require.NoError(t, err, "Serialization should succeed")

	// Deserialize
	parsedRI, _, err := router_info.ReadRouterInfo(riBytes)
	require.NoError(t, err, "Deserialization should succeed")

	// Verify round-tripped
	err = VerifyRouterInfoSignature(parsedRI)
	assert.NoError(t, err, "Round-tripped RouterInfo should still verify")
}
