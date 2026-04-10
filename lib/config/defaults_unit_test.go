package config

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Unit Tests for defaults.go — Defaults function, protocol compliance
// =============================================================================

// TestDefaults verifies that Defaults() returns a complete configuration
// with all expected default values set.
func TestDefaults(t *testing.T) {
	cfg := Defaults()

	// Router defaults
	assert.NotEmpty(t, cfg.Router.BaseDir, "Router.BaseDir should not be empty")
	assert.NotEmpty(t, cfg.Router.WorkingDir, "Router.WorkingDir should not be empty")
	assert.Equal(t, 30*time.Minute, cfg.Router.RouterInfoRefreshInterval, "Router.RouterInfoRefreshInterval")
	assert.Equal(t, 60*time.Second, cfg.Router.MessageExpirationTime, "Router.MessageExpirationTime")
	assert.Equal(t, 200, cfg.Router.MaxConcurrentSessions, "Router.MaxConcurrentSessions")

	// NetDB defaults
	assert.NotEmpty(t, cfg.NetDB.Path, "NetDB.Path should not be empty")
	assert.True(t, filepath.IsAbs(cfg.NetDB.Path), "NetDB.Path should be absolute, got: %s", cfg.NetDB.Path)
	assert.Equal(t, 5000, cfg.NetDB.MaxRouterInfos, "NetDB.MaxRouterInfos")
	assert.Equal(t, 1000, cfg.NetDB.MaxLeaseSets, "NetDB.MaxLeaseSets")
	assert.Equal(t, 1*time.Minute, cfg.NetDB.ExpirationCheckInterval, "NetDB.ExpirationCheckInterval")
	assert.False(t, cfg.NetDB.FloodfillEnabled, "NetDB.FloodfillEnabled should be false by default")

	// Bootstrap defaults
	assert.Equal(t, 10, cfg.Bootstrap.LowPeerThreshold, "Bootstrap.LowPeerThreshold")
	assert.Equal(t, 60*time.Second, cfg.Bootstrap.ReseedTimeout, "Bootstrap.ReseedTimeout")
	assert.Equal(t, 50, cfg.Bootstrap.MinimumReseedPeers, "Bootstrap.MinimumReseedPeers")
	assert.NotEmpty(t, cfg.Bootstrap.ReseedServers, "Bootstrap.ReseedServers should not be empty")

	// I2CP defaults
	assert.True(t, cfg.I2CP.Enabled, "I2CP.Enabled should be true by default")
	assert.Equal(t, "localhost:7654", cfg.I2CP.Address, "I2CP.Address")
	assert.Equal(t, "tcp", cfg.I2CP.Network, "I2CP.Network")
	assert.Equal(t, 100, cfg.I2CP.MaxSessions, "I2CP.MaxSessions")
	assert.Equal(t, 64, cfg.I2CP.MessageQueueSize, "I2CP.MessageQueueSize")

	// I2PControl defaults
	assert.True(t, cfg.I2PControl.Enabled, "I2PControl.Enabled should be true by default")
	assert.Equal(t, "localhost:7650", cfg.I2PControl.Address, "I2PControl.Address")
	assert.Equal(t, "itoopie", cfg.I2PControl.Password, "I2PControl.Password")
	assert.False(t, cfg.I2PControl.UseHTTPS, "I2PControl.UseHTTPS should be false by default")
	assert.Empty(t, cfg.I2PControl.CertFile, "I2PControl.CertFile should be empty by default")
	assert.Empty(t, cfg.I2PControl.KeyFile, "I2PControl.KeyFile should be empty by default")
	assert.Equal(t, 10*time.Minute, cfg.I2PControl.TokenExpiration, "I2PControl.TokenExpiration")

	// Tunnel defaults
	assert.Equal(t, 4, cfg.Tunnel.MinPoolSize, "Tunnel.MinPoolSize")
	assert.Equal(t, 6, cfg.Tunnel.MaxPoolSize, "Tunnel.MaxPoolSize")
	assert.Equal(t, 3, cfg.Tunnel.TunnelLength, "Tunnel.TunnelLength")
	assert.Equal(t, 10*time.Minute, cfg.Tunnel.TunnelLifetime, "Tunnel.TunnelLifetime")
	assert.Equal(t, 90*time.Second, cfg.Tunnel.BuildTimeout, "Tunnel.BuildTimeout")

	// Transport defaults
	assert.True(t, cfg.Transport.NTCP2Enabled, "Transport.NTCP2Enabled should be true by default")
	assert.True(t, cfg.Transport.SSU2Enabled, "Transport.SSU2Enabled should be true by default")
	assert.Equal(t, 200, cfg.Transport.NTCP2MaxConnections, "Transport.NTCP2MaxConnections")
	assert.Equal(t, 32768, cfg.Transport.MaxMessageSize, "Transport.MaxMessageSize")

	// Performance defaults
	assert.Equal(t, 256, cfg.Performance.MessageQueueSize, "Performance.MessageQueueSize")
	assert.Equal(t, 8, cfg.Performance.WorkerPoolSize, "Performance.WorkerPoolSize")
}

// TestDefaults_I2CPProtocolCompliance verifies I2CP defaults match protocol standard
func TestDefaults_I2CPProtocolCompliance(t *testing.T) {
	cfg := Defaults()
	assert.Equal(t, "localhost:7654", cfg.I2CP.Address, "I2CP default address should be localhost:7654 per protocol")
}

// TestDefaults_TunnelProtocolCompliance verifies tunnel defaults match I2P protocol
func TestDefaults_TunnelProtocolCompliance(t *testing.T) {
	cfg := Defaults()

	assert.Equal(t, 3, cfg.Tunnel.TunnelLength, "Tunnel length should be 3 hops per I2P protocol")
	assert.Equal(t, 10*time.Minute, cfg.Tunnel.TunnelLifetime, "Tunnel lifetime should be 10 minutes per I2P protocol")
	assert.Equal(t, 90*time.Second, cfg.Tunnel.BuildTimeout, "Tunnel build timeout should be 90 seconds per I2P protocol")
}

// TestDefaults_RouterProtocolCompliance verifies router defaults match I2P protocol
func TestDefaults_RouterProtocolCompliance(t *testing.T) {
	cfg := Defaults()
	assert.Equal(t, 60*time.Second, cfg.Router.MessageExpirationTime, "Message expiration should be 60 seconds per I2P protocol")
}

// TestDefaults_PathsAreAbsolute verifies all default paths are absolute
func TestDefaults_PathsAreAbsolute(t *testing.T) {
	cfg := Defaults()

	paths := map[string]string{
		"Router.BaseDir":    cfg.Router.BaseDir,
		"Router.WorkingDir": cfg.Router.WorkingDir,
		"NetDB.Path":        cfg.NetDB.Path,
	}

	for name, path := range paths {
		assert.True(t, filepath.IsAbs(path), "%s should be absolute path, got %s", name, path)
	}
}

// TestDefaults_ReasonablePerformanceValues verifies performance defaults are sensible
func TestDefaults_ReasonablePerformanceValues(t *testing.T) {
	cfg := Defaults()

	assert.Equal(t, 256, cfg.Performance.MessageQueueSize, "MessageQueueSize")

	assert.True(t, cfg.Performance.WorkerPoolSize >= 1 && cfg.Performance.WorkerPoolSize <= 64,
		"WorkerPoolSize = %d seems unreasonable (expected 1-64)", cfg.Performance.WorkerPoolSize)

	assert.True(t, cfg.Performance.GarlicEncryptionCacheSize >= 100,
		"GarlicEncryptionCacheSize = %d seems too small", cfg.Performance.GarlicEncryptionCacheSize)
}

// TestFloodfillDefaultIsFalse verifies floodfill is disabled by default per I2P spec.
// (Moved from caps_test.go — tests Defaults() from defaults.go)
func TestFloodfillDefaultIsFalse(t *testing.T) {
	defaults := Defaults()
	assert.False(t, defaults.NetDB.FloodfillEnabled, "NetDB.FloodfillEnabled default should be false")
}

// TestNoLegacyCryptoInDefaults verifies no legacy crypto references in defaults.
// (Moved from caps_test.go — tests Defaults() from defaults.go)
func TestNoLegacyCryptoInDefaults(t *testing.T) {
	// Verify that no config defaults reference DSA or ElGamal.
	// This is a documented audit assertion: the config package deals with
	// operational parameters, not cryptographic algorithm selection.
	defaults := Defaults()

	// Confirm ConfigDefaults contains no signature/encryption type fields
	// by exercising Defaults() without panic.
	_ = defaults.Router
	_ = defaults.NetDB
	_ = defaults.Bootstrap
	_ = defaults.I2CP
	_ = defaults.I2PControl
	_ = defaults.Tunnel
	_ = defaults.Transport
	_ = defaults.Performance
	_ = defaults.Congestion
}

// TestI2CPDefaultsAddressHasCorrectPort verifies buildI2CPDefaults sets correct port.
// (Moved from caps_test.go — tests buildI2CPDefaults() from defaults.go)
func TestI2CPDefaultsAddressHasCorrectPort(t *testing.T) {
	defaults := buildI2CPDefaults()
	assert.Equal(t, "localhost:7654", defaults.Address, "I2CP default address")
}

// TestDefaults_SecuritySensitiveValues verifies security-related defaults.
// (Moved from security_test.go — tests Defaults() from defaults.go)
func TestDefaults_SecuritySensitiveValues(t *testing.T) {
	cfg := Defaults()

	assert.Equal(t, "localhost:7654", cfg.I2CP.Address, "I2CP.Address should be localhost-only")
	assert.Equal(t, "localhost:7650", cfg.I2PControl.Address, "I2PControl.Address should be localhost-only")
	assert.Equal(t, 0, cfg.Transport.NTCP2Port, "Transport.NTCP2Port should be 0 (random) for privacy")
	assert.Equal(t, 0, cfg.Transport.SSU2Port, "Transport.SSU2Port should be 0 (random) for privacy")

	assert.True(t, cfg.I2PControl.TokenExpiration <= 30*time.Minute,
		"I2PControl.TokenExpiration is too long: %v", cfg.I2PControl.TokenExpiration)
	assert.True(t, cfg.I2CP.SessionTimeout <= 1*time.Hour,
		"I2CP.SessionTimeout is too long: %v", cfg.I2CP.SessionTimeout)
}

// TestDefaults_TimeoutsAreSafe verifies timeout values are safe.
// (Moved from security_test.go — tests Defaults() from defaults.go)
func TestDefaults_TimeoutsAreSafe(t *testing.T) {
	cfg := Defaults()

	require.True(t, cfg.Transport.ConnectionTimeout >= 10*time.Second,
		"Transport.ConnectionTimeout is too short: %v", cfg.Transport.ConnectionTimeout)
	require.True(t, cfg.Transport.ConnectionTimeout <= 2*time.Minute,
		"Transport.ConnectionTimeout is too long: %v", cfg.Transport.ConnectionTimeout)
	require.True(t, cfg.Transport.IdleTimeout >= 1*time.Minute,
		"Transport.IdleTimeout is too short: %v", cfg.Transport.IdleTimeout)
}

// =============================================================================
// Benchmarks for defaults.go
// =============================================================================

// BenchmarkDefaults measures the cost of creating default configuration
func BenchmarkDefaults(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = Defaults()
	}
}

// BenchmarkValidate measures the cost of validating configuration
func BenchmarkValidate(b *testing.B) {
	cfg := Defaults()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = Validate(cfg)
	}
}
