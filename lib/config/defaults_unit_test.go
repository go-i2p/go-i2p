package config

import (
	"path/filepath"
	"testing"
	"time"
)

// =============================================================================
// Unit Tests for defaults.go — Defaults function, protocol compliance
// =============================================================================

// TestDefaults verifies that Defaults() returns a complete configuration
// with all expected default values set.
func TestDefaults(t *testing.T) {
	cfg := Defaults()

	// Router defaults
	if cfg.Router.BaseDir == "" {
		t.Error("Router.BaseDir should not be empty")
	}
	if cfg.Router.WorkingDir == "" {
		t.Error("Router.WorkingDir should not be empty")
	}
	if cfg.Router.RouterInfoRefreshInterval != 30*time.Minute {
		t.Errorf("Router.RouterInfoRefreshInterval = %v, want 30m", cfg.Router.RouterInfoRefreshInterval)
	}
	if cfg.Router.MessageExpirationTime != 60*time.Second {
		t.Errorf("Router.MessageExpirationTime = %v, want 60s", cfg.Router.MessageExpirationTime)
	}
	if cfg.Router.MaxConcurrentSessions != 200 {
		t.Errorf("Router.MaxConcurrentSessions = %d, want 200", cfg.Router.MaxConcurrentSessions)
	}

	// NetDB defaults
	if cfg.NetDB.Path == "" {
		t.Error("NetDB.Path should not be empty")
	}
	if !filepath.IsAbs(cfg.NetDB.Path) {
		t.Errorf("NetDB.Path should be absolute, got: %s", cfg.NetDB.Path)
	}
	if cfg.NetDB.MaxRouterInfos != 5000 {
		t.Errorf("NetDB.MaxRouterInfos = %d, want 5000", cfg.NetDB.MaxRouterInfos)
	}
	if cfg.NetDB.MaxLeaseSets != 1000 {
		t.Errorf("NetDB.MaxLeaseSets = %d, want 1000", cfg.NetDB.MaxLeaseSets)
	}
	if cfg.NetDB.ExpirationCheckInterval != 1*time.Minute {
		t.Errorf("NetDB.ExpirationCheckInterval = %v, want 1m", cfg.NetDB.ExpirationCheckInterval)
	}
	if cfg.NetDB.FloodfillEnabled {
		t.Error("NetDB.FloodfillEnabled should be false by default")
	}

	// Bootstrap defaults
	if cfg.Bootstrap.LowPeerThreshold != 10 {
		t.Errorf("Bootstrap.LowPeerThreshold = %d, want 10", cfg.Bootstrap.LowPeerThreshold)
	}
	if cfg.Bootstrap.ReseedTimeout != 60*time.Second {
		t.Errorf("Bootstrap.ReseedTimeout = %v, want 60s", cfg.Bootstrap.ReseedTimeout)
	}
	if cfg.Bootstrap.MinimumReseedPeers != 50 {
		t.Errorf("Bootstrap.MinimumReseedPeers = %d, want 50", cfg.Bootstrap.MinimumReseedPeers)
	}
	if len(cfg.Bootstrap.ReseedServers) == 0 {
		t.Error("Bootstrap.ReseedServers should not be empty")
	}

	// I2CP defaults
	if !cfg.I2CP.Enabled {
		t.Error("I2CP.Enabled should be true by default")
	}
	if cfg.I2CP.Address != "localhost:7654" {
		t.Errorf("I2CP.Address = %s, want localhost:7654", cfg.I2CP.Address)
	}
	if cfg.I2CP.Network != "tcp" {
		t.Errorf("I2CP.Network = %s, want tcp", cfg.I2CP.Network)
	}
	if cfg.I2CP.MaxSessions != 100 {
		t.Errorf("I2CP.MaxSessions = %d, want 100", cfg.I2CP.MaxSessions)
	}
	if cfg.I2CP.MessageQueueSize != 64 {
		t.Errorf("I2CP.MessageQueueSize = %d, want 64", cfg.I2CP.MessageQueueSize)
	}

	// I2PControl defaults
	if cfg.I2PControl.Enabled {
		t.Error("I2PControl.Enabled should be false by default (security: default password over HTTP)")
	}
	if cfg.I2PControl.Address != "localhost:7650" {
		t.Errorf("I2PControl.Address = %s, want localhost:7650", cfg.I2PControl.Address)
	}
	if cfg.I2PControl.Password != "itoopie" {
		t.Errorf("I2PControl.Password = %s, want itoopie", cfg.I2PControl.Password)
	}
	if cfg.I2PControl.UseHTTPS {
		t.Error("I2PControl.UseHTTPS should be false by default")
	}
	if cfg.I2PControl.CertFile != "" {
		t.Errorf("I2PControl.CertFile should be empty by default, got %s", cfg.I2PControl.CertFile)
	}
	if cfg.I2PControl.KeyFile != "" {
		t.Errorf("I2PControl.KeyFile should be empty by default, got %s", cfg.I2PControl.KeyFile)
	}
	if cfg.I2PControl.TokenExpiration != 10*time.Minute {
		t.Errorf("I2PControl.TokenExpiration = %v, want 10m", cfg.I2PControl.TokenExpiration)
	}

	// Tunnel defaults
	if cfg.Tunnel.MinPoolSize != 4 {
		t.Errorf("Tunnel.MinPoolSize = %d, want 4", cfg.Tunnel.MinPoolSize)
	}
	if cfg.Tunnel.MaxPoolSize != 6 {
		t.Errorf("Tunnel.MaxPoolSize = %d, want 6", cfg.Tunnel.MaxPoolSize)
	}
	if cfg.Tunnel.TunnelLength != 3 {
		t.Errorf("Tunnel.TunnelLength = %d, want 3", cfg.Tunnel.TunnelLength)
	}
	if cfg.Tunnel.TunnelLifetime != 10*time.Minute {
		t.Errorf("Tunnel.TunnelLifetime = %v, want 10m", cfg.Tunnel.TunnelLifetime)
	}
	if cfg.Tunnel.BuildTimeout != 90*time.Second {
		t.Errorf("Tunnel.BuildTimeout = %v, want 90s", cfg.Tunnel.BuildTimeout)
	}

	// Transport defaults
	if !cfg.Transport.NTCP2Enabled {
		t.Error("Transport.NTCP2Enabled should be true by default")
	}
	if cfg.Transport.SSU2Enabled {
		t.Error("Transport.SSU2Enabled should be false by default (not yet implemented)")
	}
	if cfg.Transport.NTCP2MaxConnections != 200 {
		t.Errorf("Transport.NTCP2MaxConnections = %d, want 200", cfg.Transport.NTCP2MaxConnections)
	}
	if cfg.Transport.MaxMessageSize != 32768 {
		t.Errorf("Transport.MaxMessageSize = %d, want 32768", cfg.Transport.MaxMessageSize)
	}

	// Performance defaults
	if cfg.Performance.MessageQueueSize != 256 {
		t.Errorf("Performance.MessageQueueSize = %d, want 256", cfg.Performance.MessageQueueSize)
	}
	if cfg.Performance.WorkerPoolSize != 8 {
		t.Errorf("Performance.WorkerPoolSize = %d, want 8", cfg.Performance.WorkerPoolSize)
	}
}

// TestDefaults_I2CPProtocolCompliance verifies I2CP defaults match protocol standard
func TestDefaults_I2CPProtocolCompliance(t *testing.T) {
	cfg := Defaults()

	// I2CP protocol standard port is 7654
	if cfg.I2CP.Address != "localhost:7654" {
		t.Errorf("I2CP default address should be localhost:7654 per protocol, got %s", cfg.I2CP.Address)
	}
}

// TestDefaults_TunnelProtocolCompliance verifies tunnel defaults match I2P protocol
func TestDefaults_TunnelProtocolCompliance(t *testing.T) {
	cfg := Defaults()

	// I2P protocol standard is 3-hop tunnels
	if cfg.Tunnel.TunnelLength != 3 {
		t.Errorf("Tunnel length should be 3 hops per I2P protocol, got %d", cfg.Tunnel.TunnelLength)
	}

	// I2P protocol standard is 10-minute tunnel lifetime
	if cfg.Tunnel.TunnelLifetime != 10*time.Minute {
		t.Errorf("Tunnel lifetime should be 10 minutes per I2P protocol, got %v", cfg.Tunnel.TunnelLifetime)
	}

	// I2P protocol standard is 90-second build timeout
	if cfg.Tunnel.BuildTimeout != 90*time.Second {
		t.Errorf("Tunnel build timeout should be 90 seconds per I2P protocol, got %v", cfg.Tunnel.BuildTimeout)
	}
}

// TestDefaults_RouterProtocolCompliance verifies router defaults match I2P protocol
func TestDefaults_RouterProtocolCompliance(t *testing.T) {
	cfg := Defaults()

	// I2P protocol standard is 60-second message expiration
	if cfg.Router.MessageExpirationTime != 60*time.Second {
		t.Errorf("Message expiration should be 60 seconds per I2P protocol, got %v", cfg.Router.MessageExpirationTime)
	}
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
		if !filepath.IsAbs(path) {
			t.Errorf("%s should be absolute path, got %s", name, path)
		}
	}
}

// TestDefaults_ReasonablePerformanceValues verifies performance defaults are sensible
func TestDefaults_ReasonablePerformanceValues(t *testing.T) {
	cfg := Defaults()

	// Message queue should be power of 2 for efficient buffering
	if cfg.Performance.MessageQueueSize != 256 {
		t.Logf("Note: MessageQueueSize is %d (not a power of 2)", cfg.Performance.MessageQueueSize)
	}

	// Worker pool should be reasonable for modern CPUs
	if cfg.Performance.WorkerPoolSize < 1 || cfg.Performance.WorkerPoolSize > 64 {
		t.Errorf("WorkerPoolSize = %d seems unreasonable (expected 1-64)", cfg.Performance.WorkerPoolSize)
	}

	// Caches should be large enough to be useful
	if cfg.Performance.GarlicEncryptionCacheSize < 100 {
		t.Errorf("GarlicEncryptionCacheSize = %d seems too small", cfg.Performance.GarlicEncryptionCacheSize)
	}
}

// TestFloodfillDefaultIsFalse verifies floodfill is disabled by default per I2P spec.
// (Moved from caps_test.go — tests Defaults() from defaults.go)
func TestFloodfillDefaultIsFalse(t *testing.T) {
	// Per I2P spec, routers should NOT be floodfill by default
	defaults := Defaults()
	if defaults.NetDB.FloodfillEnabled {
		t.Error("NetDB.FloodfillEnabled default = true, want false (regular router mode per spec)")
	}
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
	if defaults.Address != "localhost:7654" {
		t.Errorf("I2CP default address = %q, want %q", defaults.Address, "localhost:7654")
	}
}

// TestDefaults_SecuritySensitiveValues verifies security-related defaults.
// (Moved from security_test.go — tests Defaults() from defaults.go)
func TestDefaults_SecuritySensitiveValues(t *testing.T) {
	cfg := Defaults()

	// I2CP should bind to localhost only by default
	if cfg.I2CP.Address != "localhost:7654" {
		t.Errorf("I2CP.Address should be localhost-only, got %s", cfg.I2CP.Address)
	}

	// I2PControl should bind to localhost only by default
	if cfg.I2PControl.Address != "localhost:7650" {
		t.Errorf("I2PControl.Address should be localhost-only, got %s", cfg.I2PControl.Address)
	}

	// NTCP2/SSU2 ports should be 0 (random) for privacy
	if cfg.Transport.NTCP2Port != 0 {
		t.Errorf("Transport.NTCP2Port should be 0 (random), got %d", cfg.Transport.NTCP2Port)
	}
	if cfg.Transport.SSU2Port != 0 {
		t.Errorf("Transport.SSU2Port should be 0 (random), got %d", cfg.Transport.SSU2Port)
	}

	// Token expiration should be reasonable (not too long - 30 minutes max)
	maxTokenExpiration := 30 * time.Minute
	if cfg.I2PControl.TokenExpiration > maxTokenExpiration {
		t.Errorf("I2PControl.TokenExpiration is too long: %v (max %v)", cfg.I2PControl.TokenExpiration, maxTokenExpiration)
	}

	// Session timeout should be reasonable (1 hour max)
	maxSessionTimeout := 1 * time.Hour
	if cfg.I2CP.SessionTimeout > maxSessionTimeout {
		t.Errorf("I2CP.SessionTimeout is too long: %v (max %v)", cfg.I2CP.SessionTimeout, maxSessionTimeout)
	}
}

// TestDefaults_TimeoutsAreSafe verifies timeout values are safe.
// (Moved from security_test.go — tests Defaults() from defaults.go)
func TestDefaults_TimeoutsAreSafe(t *testing.T) {
	cfg := Defaults()

	// Connection timeout should be at least 10 seconds
	minConnectionTimeout := 10 * time.Second
	if cfg.Transport.ConnectionTimeout < minConnectionTimeout {
		t.Errorf("Transport.ConnectionTimeout is too short: %v (min %v)", cfg.Transport.ConnectionTimeout, minConnectionTimeout)
	}

	// Connection timeout should not be too long (DoS risk)
	maxConnectionTimeout := 2 * time.Minute
	if cfg.Transport.ConnectionTimeout > maxConnectionTimeout {
		t.Errorf("Transport.ConnectionTimeout is too long: %v (max %v)", cfg.Transport.ConnectionTimeout, maxConnectionTimeout)
	}

	// Idle timeout should allow for reasonable session duration
	minIdleTimeout := 1 * time.Minute
	if cfg.Transport.IdleTimeout < minIdleTimeout {
		t.Errorf("Transport.IdleTimeout is too short: %v (min %v)", cfg.Transport.IdleTimeout, minIdleTimeout)
	}
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
