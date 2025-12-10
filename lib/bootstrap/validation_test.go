package bootstrap

import (
	"testing"
	"time"

	"github.com/go-i2p/common/router_address"
	"github.com/stretchr/testify/assert"
)

// Helper functions for creating test data

// createTestRouterAddress creates a test RouterAddress with the given options
func createTestRouterAddress(transportStyle string, options map[string]string) *router_address.RouterAddress {
	// Create RouterAddress with standard test values
	expiration := time.Now().Add(24 * time.Hour)
	addr, err := router_address.NewRouterAddress(5, expiration, transportStyle, options)
	if err != nil {
		// For test purposes, panic on creation failure
		panic("Failed to create test RouterAddress: " + err.Error())
	}
	return addr
}

// Tests for ValidateRouterAddress (RouterAddress validation)

func TestValidateRouterAddress_ValidNTCP2(t *testing.T) {
	addr := createTestRouterAddress("ntcp2", map[string]string{
		"host": "192.168.1.1",
		"port": "12345",
		"s":    "test-static-key",
	})

	err := ValidateRouterAddress(addr)
	assert.NoError(t, err)
}

func TestValidateRouterAddress_ValidNTCP2CaseInsensitive(t *testing.T) {
	addr := createTestRouterAddress("NTCP2", map[string]string{
		"host": "192.168.1.1",
		"port": "12345",
	})

	err := ValidateRouterAddress(addr)
	assert.NoError(t, err)
}

func TestValidateRouterAddress_NTCP2MissingHost(t *testing.T) {
	addr := createTestRouterAddress("ntcp2", map[string]string{
		"port": "12345",
		// "host" intentionally missing
	})

	err := ValidateRouterAddress(addr)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing required 'host' key")
}

func TestValidateRouterAddress_NTCP2EmptyHost(t *testing.T) {
	addr := createTestRouterAddress("ntcp2", map[string]string{
		"host": "",
		"port": "12345",
	})

	err := ValidateRouterAddress(addr)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "host is empty")
}

func TestValidateRouterAddress_NTCP2MissingPort(t *testing.T) {
	addr := createTestRouterAddress("ntcp2", map[string]string{
		"host": "192.168.1.1",
		// "port" intentionally missing
	})

	err := ValidateRouterAddress(addr)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing required 'port' key")
}

func TestValidateRouterAddress_NTCP2EmptyPort(t *testing.T) {
	addr := createTestRouterAddress("ntcp2", map[string]string{
		"host": "192.168.1.1",
		"port": "",
	})

	err := ValidateRouterAddress(addr)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "port is empty")
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
		// "host" intentionally missing
	})

	err := ValidateRouterAddress(addr)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing required 'host' key")
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
		// "port" intentionally missing
	})

	err := ValidateRouterAddress(addr)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing required 'port' key")
}

func TestValidateRouterAddress_UnknownTransport(t *testing.T) {
	addr := createTestRouterAddress("future-transport-v3", map[string]string{
		"host": "192.168.1.1",
		"port": "12345",
	})

	// Unknown transports should not fail validation (forward compatibility)
	err := ValidateRouterAddress(addr)
	assert.NoError(t, err)
}

// Note: Tests for ValidateRouterInfo require proper RouterInfo construction
// which is complex and requires identity, signatures, etc. These tests
// are better suited for integration tests. The validation logic is tested
// indirectly through RouterAddress validation tests above.

// Tests for ValidationStats

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

// Note: Tests for GetRouterHashString, validateAndFilterRouterInfos,
// and integration tests require proper RouterInfo construction which is
// complex. These are better tested through manual/integration testing
// or by examining logs during actual bootstrap operations.

// Benchmark tests

func BenchmarkValidateRouterAddress_Valid(b *testing.B) {
	addr := createTestRouterAddress("ntcp2", map[string]string{
		"host": "192.168.1.1",
		"port": "12345",
		"s":    "static-key-data",
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ValidateRouterAddress(addr)
	}
}

func BenchmarkValidateRouterAddress_Invalid(b *testing.B) {
	addr := createTestRouterAddress("ntcp2", map[string]string{
		"port": "12345",
		// Missing host
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ValidateRouterAddress(addr)
	}
}

func BenchmarkValidateRouterAddress_MultipleChecks(b *testing.B) {
	addr := createTestRouterAddress("ntcp2", map[string]string{
		"host": "192.168.1.1",
		"port": "12345",
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ValidateRouterAddress(addr)
		_ = validateNTCP2Address(addr)
	}
}
