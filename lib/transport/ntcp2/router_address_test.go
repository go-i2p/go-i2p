package ntcp2

import (
	"context"
	"encoding/base64"
	"net"
	"testing"
	"time"

	"github.com/go-i2p/go-noise/ntcp2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestTransport creates a minimal NTCP2Transport for testing
func createTestTransport(t *testing.T, listenAddr string) *NTCP2Transport {
	// Create a minimal RouterInfo for testing
	routerHash := make([]byte, 32)
	for i := range routerHash {
		routerHash[i] = byte(i)
	}

	// Create NTCP2 config with static key
	ntcp2Config, err := ntcp2.NewNTCP2Config(routerHash, false)
	require.NoError(t, err)

	// Generate a test static key (32 bytes for Curve25519)
	staticKey := make([]byte, 32)
	for i := range staticKey {
		staticKey[i] = byte(i + 64) // Different from router hash
	}
	ntcp2Config.StaticKey = staticKey

	// Create test config
	config := &Config{
		ListenerAddress: listenAddr,
		NTCP2Config:     ntcp2Config,
	}

	// Create TCP listener
	listener, err := net.Listen("tcp", listenAddr)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	t.Cleanup(func() { listener.Close() })

	transport := &NTCP2Transport{
		listener: listener,
		config:   config,
		ctx:      ctx,
		cancel:   cancel,
	}

	return transport
}

// TestConvertToRouterAddress_Success tests successful conversion of NTCP2 transport to RouterAddress
func TestConvertToRouterAddress_Success(t *testing.T) {
	transport := createTestTransport(t, "127.0.0.1:0")

	routerAddr, err := ConvertToRouterAddress(transport)
	require.NoError(t, err)
	require.NotNil(t, routerAddr)

	// Verify transport style
	style := routerAddr.TransportStyle()
	styleData, err := style.Data()
	require.NoError(t, err)
	assert.Equal(t, "ntcp2", styleData)

	// Verify host is set and retrievable
	host, err := routerAddr.Host()
	require.NoError(t, err)
	assert.NotNil(t, host)

	// Verify port is set and valid
	port, err := routerAddr.Port()
	require.NoError(t, err)
	assert.NotEmpty(t, port)

	// Verify static key exists
	staticKeyString := routerAddr.StaticKeyString()
	staticKeyData, err := staticKeyString.Data()
	require.NoError(t, err)
	assert.NotEmpty(t, staticKeyData)

	// Verify static key can be decoded
	_, err = base64.StdEncoding.DecodeString(staticKeyData)
	assert.NoError(t, err, "static key should be valid base64")

	// Verify cost is reasonable
	cost := routerAddr.Cost()
	assert.Greater(t, cost, 0, "cost should be positive")

	// Verify the RouterAddress can be serialized
	bytes := routerAddr.Bytes()
	assert.NotEmpty(t, bytes)
}

// TestConvertToRouterAddress_WithObfuscationIV tests conversion with IV configured
func TestConvertToRouterAddress_WithObfuscationIV(t *testing.T) {
	transport := createTestTransport(t, "127.0.0.1:0")

	// Add obfuscation IV to config
	iv := make([]byte, 16)
	for i := range iv {
		iv[i] = byte(i + 100)
	}
	transport.config.NTCP2Config.ObfuscationIV = iv

	routerAddr, err := ConvertToRouterAddress(transport)
	require.NoError(t, err)
	require.NotNil(t, routerAddr)

	// Verify IV is present in options
	ivString := routerAddr.InitializationVectorString()
	ivData, err := ivString.Data()
	require.NoError(t, err)
	assert.NotEmpty(t, ivData)

	// Verify IV can be decoded and matches
	decodedIV, err := base64.StdEncoding.DecodeString(ivData)
	require.NoError(t, err)
	assert.Equal(t, iv, decodedIV)
}

// TestConvertToRouterAddress_NilTransport tests error handling for nil transport
func TestConvertToRouterAddress_NilTransport(t *testing.T) {
	routerAddr, err := ConvertToRouterAddress(nil)
	assert.Error(t, err)
	assert.Nil(t, routerAddr)
	assert.Contains(t, err.Error(), "transport cannot be nil")
}

// TestConvertToRouterAddress_NoListener tests error handling when transport has no listener
func TestConvertToRouterAddress_NoListener(t *testing.T) {
	transport := &NTCP2Transport{
		listener: nil,
		config:   &Config{},
	}

	routerAddr, err := ConvertToRouterAddress(transport)
	assert.Error(t, err)
	assert.Nil(t, routerAddr)
	assert.Contains(t, err.Error(), "no listening address")
}

// TestConvertToRouterAddress_NoConfig tests error handling when transport has no config
func TestConvertToRouterAddress_NoConfig(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	transport := &NTCP2Transport{
		listener: listener,
		config:   nil,
	}

	routerAddr, err := ConvertToRouterAddress(transport)
	assert.Error(t, err)
	assert.Nil(t, routerAddr)
	assert.Contains(t, err.Error(), "configuration is not initialized")
}

// TestConvertToRouterAddress_InvalidStaticKey tests error handling for invalid static key
func TestConvertToRouterAddress_InvalidStaticKey(t *testing.T) {
	transport := createTestTransport(t, "127.0.0.1:0")

	// Corrupt the static key to wrong length
	transport.config.NTCP2Config.StaticKey = make([]byte, 16) // Wrong length

	routerAddr, err := ConvertToRouterAddress(transport)
	assert.Error(t, err)
	assert.Nil(t, routerAddr)
	assert.Contains(t, err.Error(), "invalid static key length")
}

// TestConvertToRouterAddress_SpecificPort tests conversion with specific port
func TestConvertToRouterAddress_SpecificPort(t *testing.T) {
	// Try to bind to specific port, fall back to random if unavailable
	transport := createTestTransport(t, "127.0.0.1:0")

	routerAddr, err := ConvertToRouterAddress(transport)
	require.NoError(t, err)

	// Verify the address contains valid port
	port, err := routerAddr.Port()
	require.NoError(t, err)
	assert.NotEmpty(t, port)
}

// TestConvertToRouterAddress_IPv6 tests conversion with IPv6 address
func TestConvertToRouterAddress_IPv6(t *testing.T) {
	transport := createTestTransport(t, "[::1]:0")

	routerAddr, err := ConvertToRouterAddress(transport)
	require.NoError(t, err)
	require.NotNil(t, routerAddr)

	// Verify host is IPv6
	hostString := routerAddr.HostString()
	hostData, err := hostString.Data()
	require.NoError(t, err)
	assert.Contains(t, hostData, ":")
}

// TestConvertToRouterAddress_ExpirationTime tests that expiration is set correctly
func TestConvertToRouterAddress_ExpirationTime(t *testing.T) {
	beforeConversion := time.Now()
	transport := createTestTransport(t, "127.0.0.1:0")

	routerAddr, err := ConvertToRouterAddress(transport)
	require.NoError(t, err)
	afterConversion := time.Now()

	expiration := routerAddr.Expiration()
	expirationTime := expiration.Time()

	// Expiration should be ~2 hours in the future
	expectedMin := beforeConversion.Add(2*time.Hour - 10*time.Second)
	expectedMax := afterConversion.Add(2*time.Hour + 10*time.Second)

	assert.True(t, expirationTime.After(expectedMin),
		"expiration %v should be after %v", expirationTime, expectedMin)
	assert.True(t, expirationTime.Before(expectedMax),
		"expiration %v should be before %v", expirationTime, expectedMax)
}

// TestConvertToRouterAddress_Integration tests end-to-end address publishing
func TestConvertToRouterAddress_Integration(t *testing.T) {
	// Create a real transport
	transport := createTestTransport(t, "127.0.0.1:0")

	// Convert to RouterAddress
	routerAddr, err := ConvertToRouterAddress(transport)
	require.NoError(t, err)

	// Verify the RouterAddress can be serialized
	bytes := routerAddr.Bytes()
	assert.NotEmpty(t, bytes)

	// Verify transport style is correct
	style := routerAddr.TransportStyle()
	styleData, _ := style.Data()
	assert.Equal(t, "ntcp2", styleData)

	// Verify we can retrieve host and port
	host, err := routerAddr.Host()
	assert.NoError(t, err)
	assert.NotNil(t, host)

	port, err := routerAddr.Port()
	assert.NoError(t, err)
	assert.NotEmpty(t, port)

	// Verify static key is set
	staticKey := routerAddr.StaticKeyString()
	staticKeyData, _ := staticKey.Data()
	assert.NotEmpty(t, staticKeyData)
}

// BenchmarkConvertToRouterAddress benchmarks the conversion function
func BenchmarkConvertToRouterAddress(b *testing.B) {
	// Create test RouterInfo
	routerHash := make([]byte, 32)
	ntcp2Config, _ := ntcp2.NewNTCP2Config(routerHash, false)

	// Generate a test static key
	staticKey := make([]byte, 32)
	for i := range staticKey {
		staticKey[i] = byte(i + 64)
	}
	ntcp2Config.StaticKey = staticKey

	listener, _ := net.Listen("tcp", "127.0.0.1:0")
	defer listener.Close()

	transport := &NTCP2Transport{
		listener: listener,
		config: &Config{
			ListenerAddress: "127.0.0.1:0",
			NTCP2Config:     ntcp2Config,
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ConvertToRouterAddress(transport)
		if err != nil {
			b.Fatal(err)
		}
	}
}
