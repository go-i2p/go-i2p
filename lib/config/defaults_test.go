package config

import (
	"path/filepath"
	"testing"
	"time"
)

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

// TestValidate_ValidConfig verifies that valid configurations pass validation
func TestValidate_ValidConfig(t *testing.T) {
	cfg := Defaults()

	if err := Validate(cfg); err != nil {
		t.Errorf("Validate() failed for default config: %v", err)
	}
}

// TestValidate_RouterInvalidMaxSessions verifies validation catches invalid max sessions
func TestValidate_RouterInvalidMaxSessions(t *testing.T) {
	cfg := Defaults()
	cfg.Router.MaxConcurrentSessions = 0

	err := Validate(cfg)
	if err == nil {
		t.Error("Validate() should fail when MaxConcurrentSessions is 0")
	}
	if _, ok := err.(*validationError); !ok {
		t.Errorf("Validate() should return validationError, got %T", err)
	}
}

// TestValidate_RouterInvalidMessageExpiration verifies validation catches invalid expiration
func TestValidate_RouterInvalidMessageExpiration(t *testing.T) {
	cfg := Defaults()
	cfg.Router.MessageExpirationTime = 500 * time.Millisecond

	err := Validate(cfg)
	if err == nil {
		t.Error("Validate() should fail when MessageExpirationTime < 1s")
	}
}

// TestValidate_NetDBInvalidMaxRouterInfos verifies validation catches invalid max RouterInfos
func TestValidate_NetDBInvalidMaxRouterInfos(t *testing.T) {
	cfg := Defaults()
	cfg.NetDB.MaxRouterInfos = 5

	err := Validate(cfg)
	if err == nil {
		t.Error("Validate() should fail when MaxRouterInfos < 10")
	}
}

// TestValidate_NetDBInvalidMaxLeaseSets verifies validation catches invalid max LeaseSets
func TestValidate_NetDBInvalidMaxLeaseSets(t *testing.T) {
	cfg := Defaults()
	cfg.NetDB.MaxLeaseSets = 0

	err := Validate(cfg)
	if err == nil {
		t.Error("Validate() should fail when MaxLeaseSets < 1")
	}
}

// TestValidate_BootstrapInvalidThreshold verifies validation catches invalid peer threshold
func TestValidate_BootstrapInvalidThreshold(t *testing.T) {
	cfg := Defaults()
	cfg.Bootstrap.LowPeerThreshold = 0

	err := Validate(cfg)
	if err == nil {
		t.Error("Validate() should fail when LowPeerThreshold < 1")
	}
}

// TestValidate_BootstrapInvalidMinPeers verifies validation catches invalid minimum peers
func TestValidate_BootstrapInvalidMinPeers(t *testing.T) {
	cfg := Defaults()
	cfg.Bootstrap.MinimumReseedPeers = 0

	err := Validate(cfg)
	if err == nil {
		t.Error("Validate() should fail when MinimumReseedPeers < 1")
	}
}

// TestValidate_I2CPInvalidMaxSessions verifies validation catches invalid max sessions
func TestValidate_I2CPInvalidMaxSessions(t *testing.T) {
	cfg := Defaults()
	cfg.I2CP.MaxSessions = 0

	err := Validate(cfg)
	if err == nil {
		t.Error("Validate() should fail when I2CP.MaxSessions < 1")
	}
}

// TestValidate_I2CPInvalidQueueSize verifies validation catches invalid queue size
func TestValidate_I2CPInvalidQueueSize(t *testing.T) {
	cfg := Defaults()
	cfg.I2CP.MessageQueueSize = 0

	err := Validate(cfg)
	if err == nil {
		t.Error("Validate() should fail when MessageQueueSize < 1")
	}
}

// TestValidate_TunnelInvalidMinPoolSize verifies validation catches invalid min pool size
func TestValidate_TunnelInvalidMinPoolSize(t *testing.T) {
	cfg := Defaults()
	cfg.Tunnel.MinPoolSize = 0

	err := Validate(cfg)
	if err == nil {
		t.Error("Validate() should fail when MinPoolSize < 1")
	}
}

// TestValidate_TunnelInvalidMaxPoolSize verifies validation catches invalid max pool size
func TestValidate_TunnelInvalidMaxPoolSize(t *testing.T) {
	cfg := Defaults()
	cfg.Tunnel.MinPoolSize = 6
	cfg.Tunnel.MaxPoolSize = 4

	err := Validate(cfg)
	if err == nil {
		t.Error("Validate() should fail when MaxPoolSize < MinPoolSize")
	}
}

// TestValidate_TunnelInvalidLength verifies validation catches invalid tunnel length
func TestValidate_TunnelInvalidLength(t *testing.T) {
	testCases := []struct {
		length int
		name   string
	}{
		{0, "zero"},
		{9, "too long"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Defaults()
			cfg.Tunnel.TunnelLength = tc.length

			err := Validate(cfg)
			if err == nil {
				t.Errorf("Validate() should fail when TunnelLength = %d", tc.length)
			}
		})
	}
}

// TestValidate_TunnelInvalidBuildRetries verifies validation catches invalid build retries
func TestValidate_TunnelInvalidBuildRetries(t *testing.T) {
	cfg := Defaults()
	cfg.Tunnel.BuildRetries = 0

	err := Validate(cfg)
	if err == nil {
		t.Error("Validate() should fail when BuildRetries < 1")
	}
}

// TestValidate_TransportInvalidMaxMessageSize verifies validation catches invalid max message size
func TestValidate_TransportInvalidMaxMessageSize(t *testing.T) {
	cfg := Defaults()
	cfg.Transport.MaxMessageSize = 512

	err := Validate(cfg)
	if err == nil {
		t.Error("Validate() should fail when MaxMessageSize < 1024")
	}
}

// TestValidate_TransportInvalidMaxConnections verifies validation catches invalid max connections
func TestValidate_TransportInvalidMaxConnections(t *testing.T) {
	cfg := Defaults()
	cfg.Transport.NTCP2MaxConnections = 0

	err := Validate(cfg)
	if err == nil {
		t.Error("Validate() should fail when NTCP2MaxConnections < 1")
	}
}

// TestValidate_PerformanceInvalidWorkerPoolSize verifies validation catches invalid worker pool size
func TestValidate_PerformanceInvalidWorkerPoolSize(t *testing.T) {
	cfg := Defaults()
	cfg.Performance.WorkerPoolSize = 0

	err := Validate(cfg)
	if err == nil {
		t.Error("Validate() should fail when WorkerPoolSize < 1")
	}
}

// TestValidate_PerformanceInvalidMessageQueueSize verifies validation catches invalid message queue size
func TestValidate_PerformanceInvalidMessageQueueSize(t *testing.T) {
	cfg := Defaults()
	cfg.Performance.MessageQueueSize = 0

	err := Validate(cfg)
	if err == nil {
		t.Error("Validate() should fail when MessageQueueSize < 1")
	}
}

// TestValidationError_Error verifies validationError implements error interface correctly
func TestValidationError_Error(t *testing.T) {
	err := newValidationError("test message")
	expected := "configuration validation failed: test message"
	if err.Error() != expected {
		t.Errorf("Error() = %q, want %q", err.Error(), expected)
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
