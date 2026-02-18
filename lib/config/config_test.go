package config

import (
	"testing"
	"time"

	"github.com/spf13/viper"
)

// TestCurrentConfigRouterInfoRefreshInterval verifies that CurrentConfig()
// correctly reads the RouterInfoRefreshInterval from the same viper key
// used by setDefaults(). This covers CRITICAL BUG: Viper Key Mismatch
// for RouterInfo Refresh Interval.
func TestCurrentConfigRouterInfoRefreshInterval(t *testing.T) {
	// Reset viper to clear any state from other tests
	viper.Reset()

	// Apply defaults (this uses "router.info_refresh_interval")
	setDefaults()

	cfg := CurrentConfig()

	// The key fix: CurrentConfig() must read from the same key that
	// setDefaults() writes to. Before the fix, it read from a different
	// key ("router.routerinfo_refresh_interval") and always got 0s.
	expected := 30 * time.Minute
	if cfg.Router.RouterInfoRefreshInterval != expected {
		t.Errorf("CurrentConfig().Router.RouterInfoRefreshInterval = %v, want %v",
			cfg.Router.RouterInfoRefreshInterval, expected)
	}
}

// TestCurrentConfigDefaultsRoundTrip verifies that all defaults set via
// setDefaults() are correctly read back by CurrentConfig(). This catches
// any additional key mismatches between SetDefault and Get calls.
func TestCurrentConfigDefaultsRoundTrip(t *testing.T) {
	viper.Reset()
	setDefaults()

	cfg := CurrentConfig()
	defaults := Defaults()

	// Router section
	if cfg.Router.RouterInfoRefreshInterval != defaults.Router.RouterInfoRefreshInterval {
		t.Errorf("RouterInfoRefreshInterval mismatch: got %v, want %v",
			cfg.Router.RouterInfoRefreshInterval, defaults.Router.RouterInfoRefreshInterval)
	}
	if cfg.Router.MessageExpirationTime != defaults.Router.MessageExpirationTime {
		t.Errorf("MessageExpirationTime mismatch: got %v, want %v",
			cfg.Router.MessageExpirationTime, defaults.Router.MessageExpirationTime)
	}
	if cfg.Router.MaxConcurrentSessions != defaults.Router.MaxConcurrentSessions {
		t.Errorf("MaxConcurrentSessions mismatch: got %d, want %d",
			cfg.Router.MaxConcurrentSessions, defaults.Router.MaxConcurrentSessions)
	}

	// NetDB section
	if cfg.NetDB.MaxRouterInfos != defaults.NetDB.MaxRouterInfos {
		t.Errorf("MaxRouterInfos mismatch: got %d, want %d",
			cfg.NetDB.MaxRouterInfos, defaults.NetDB.MaxRouterInfos)
	}
	if cfg.NetDB.ExpirationCheckInterval != defaults.NetDB.ExpirationCheckInterval {
		t.Errorf("ExpirationCheckInterval mismatch: got %v, want %v",
			cfg.NetDB.ExpirationCheckInterval, defaults.NetDB.ExpirationCheckInterval)
	}

	// Bootstrap section
	if cfg.Bootstrap.LowPeerThreshold != defaults.Bootstrap.LowPeerThreshold {
		t.Errorf("LowPeerThreshold mismatch: got %d, want %d",
			cfg.Bootstrap.LowPeerThreshold, defaults.Bootstrap.LowPeerThreshold)
	}

	// I2CP section
	if cfg.I2CP.Enabled != defaults.I2CP.Enabled {
		t.Errorf("I2CP.Enabled mismatch: got %v, want %v",
			cfg.I2CP.Enabled, defaults.I2CP.Enabled)
	}
	if cfg.I2CP.Address != defaults.I2CP.Address {
		t.Errorf("I2CP.Address mismatch: got %v, want %v",
			cfg.I2CP.Address, defaults.I2CP.Address)
	}
}

// TestCurrentConfigViperOverride verifies that RouterInfoRefreshInterval
// can be overridden through viper, confirming the key is correct.
func TestCurrentConfigViperOverride(t *testing.T) {
	viper.Reset()
	setDefaults()

	// Override the value using the key
	override := 45 * time.Minute
	viper.Set("router.info_refresh_interval", override)

	cfg := CurrentConfig()
	if cfg.Router.RouterInfoRefreshInterval != override {
		t.Errorf("Override failed: got %v, want %v",
			cfg.Router.RouterInfoRefreshInterval, override)
	}
}

// TestBuildI2CPConfigAllFields verifies that buildI2CPConfig reads ALL I2CPConfig
// fields from viper, not just a subset. This covers CRITICAL BUG: buildI2CPConfig
// Drops Session Timeout and Queue Size Fields.
func TestBuildI2CPConfigAllFields(t *testing.T) {
	viper.Reset()
	setDefaults()

	cfg := buildI2CPConfig()
	defaults := Defaults()

	// Fields that were previously populated (should still work)
	if cfg.Enabled != defaults.I2CP.Enabled {
		t.Errorf("I2CP.Enabled = %v, want %v", cfg.Enabled, defaults.I2CP.Enabled)
	}
	if cfg.Address != defaults.I2CP.Address {
		t.Errorf("I2CP.Address = %v, want %v", cfg.Address, defaults.I2CP.Address)
	}
	if cfg.Network != defaults.I2CP.Network {
		t.Errorf("I2CP.Network = %v, want %v", cfg.Network, defaults.I2CP.Network)
	}
	if cfg.MaxSessions != defaults.I2CP.MaxSessions {
		t.Errorf("I2CP.MaxSessions = %d, want %d", cfg.MaxSessions, defaults.I2CP.MaxSessions)
	}

	// Fields that were previously MISSING (the bug)
	if cfg.MessageQueueSize != defaults.I2CP.MessageQueueSize {
		t.Errorf("I2CP.MessageQueueSize = %d, want %d (was zero before fix)",
			cfg.MessageQueueSize, defaults.I2CP.MessageQueueSize)
	}
	if cfg.SessionTimeout != defaults.I2CP.SessionTimeout {
		t.Errorf("I2CP.SessionTimeout = %v, want %v (was zero before fix)",
			cfg.SessionTimeout, defaults.I2CP.SessionTimeout)
	}
	if cfg.ReadTimeout != defaults.I2CP.ReadTimeout {
		t.Errorf("I2CP.ReadTimeout = %v, want %v (was zero before fix)",
			cfg.ReadTimeout, defaults.I2CP.ReadTimeout)
	}
	if cfg.WriteTimeout != defaults.I2CP.WriteTimeout {
		t.Errorf("I2CP.WriteTimeout = %v, want %v (was zero before fix)",
			cfg.WriteTimeout, defaults.I2CP.WriteTimeout)
	}

	// Auth fields (default to empty = auth disabled)
	if cfg.Username != "" {
		t.Errorf("I2CP.Username = %q, want empty string", cfg.Username)
	}
	if cfg.Password != "" {
		t.Errorf("I2CP.Password = %q, want empty string", cfg.Password)
	}
}

// TestBuildI2CPConfigViperOverrides verifies that all I2CPConfig fields
// can be overridden through viper, confirming the viper keys are correct.
func TestBuildI2CPConfigViperOverrides(t *testing.T) {
	viper.Reset()
	setDefaults()

	// Override each field
	viper.Set("i2cp.enabled", false)
	viper.Set("i2cp.address", "0.0.0.0:9999")
	viper.Set("i2cp.network", "unix")
	viper.Set("i2cp.max_sessions", 50)
	viper.Set("i2cp.message_queue_size", 128)
	viper.Set("i2cp.session_timeout", 1*time.Hour)
	viper.Set("i2cp.read_timeout", 90*time.Second)
	viper.Set("i2cp.write_timeout", 45*time.Second)
	viper.Set("i2cp.username", "admin")
	viper.Set("i2cp.password", "secret")

	cfg := buildI2CPConfig()

	if cfg.Enabled != false {
		t.Errorf("I2CP.Enabled override failed: got %v, want false", cfg.Enabled)
	}
	if cfg.Address != "0.0.0.0:9999" {
		t.Errorf("I2CP.Address override failed: got %v, want 0.0.0.0:9999", cfg.Address)
	}
	if cfg.Network != "unix" {
		t.Errorf("I2CP.Network override failed: got %v, want unix", cfg.Network)
	}
	if cfg.MaxSessions != 50 {
		t.Errorf("I2CP.MaxSessions override failed: got %d, want 50", cfg.MaxSessions)
	}
	if cfg.MessageQueueSize != 128 {
		t.Errorf("I2CP.MessageQueueSize override failed: got %d, want 128", cfg.MessageQueueSize)
	}
	if cfg.SessionTimeout != 1*time.Hour {
		t.Errorf("I2CP.SessionTimeout override failed: got %v, want 1h", cfg.SessionTimeout)
	}
	if cfg.ReadTimeout != 90*time.Second {
		t.Errorf("I2CP.ReadTimeout override failed: got %v, want 1m30s", cfg.ReadTimeout)
	}
	if cfg.WriteTimeout != 45*time.Second {
		t.Errorf("I2CP.WriteTimeout override failed: got %v, want 45s", cfg.WriteTimeout)
	}
	if cfg.Username != "admin" {
		t.Errorf("I2CP.Username override failed: got %q, want admin", cfg.Username)
	}
	if cfg.Password != "secret" {
		t.Errorf("I2CP.Password override failed: got %q, want secret", cfg.Password)
	}
}

// TestNewRouterConfigFromViperI2CPFields verifies that NewRouterConfigFromViper
// produces an I2CPConfig with all fields populated from viper defaults.
func TestNewRouterConfigFromViperI2CPFields(t *testing.T) {
	viper.Reset()
	setDefaults()

	cfg := NewRouterConfigFromViper()
	defaults := Defaults()

	if cfg.I2CP.SessionTimeout != defaults.I2CP.SessionTimeout {
		t.Errorf("NewRouterConfigFromViper I2CP.SessionTimeout = %v, want %v",
			cfg.I2CP.SessionTimeout, defaults.I2CP.SessionTimeout)
	}
	if cfg.I2CP.MessageQueueSize != defaults.I2CP.MessageQueueSize {
		t.Errorf("NewRouterConfigFromViper I2CP.MessageQueueSize = %d, want %d",
			cfg.I2CP.MessageQueueSize, defaults.I2CP.MessageQueueSize)
	}
	if cfg.I2CP.ReadTimeout != defaults.I2CP.ReadTimeout {
		t.Errorf("NewRouterConfigFromViper I2CP.ReadTimeout = %v, want %v",
			cfg.I2CP.ReadTimeout, defaults.I2CP.ReadTimeout)
	}
	if cfg.I2CP.WriteTimeout != defaults.I2CP.WriteTimeout {
		t.Errorf("NewRouterConfigFromViper I2CP.WriteTimeout = %v, want %v",
			cfg.I2CP.WriteTimeout, defaults.I2CP.WriteTimeout)
	}
}

// TestNewRouterConfigFromViperSubsystemFields verifies that NewRouterConfigFromViper
// populates Tunnel, Transport, Performance, and Congestion config fields.
// This covers CRITICAL-002: RouterConfig missing subsystem config fields.
func TestNewRouterConfigFromViperSubsystemFields(t *testing.T) {
	viper.Reset()
	setDefaults()

	cfg := NewRouterConfigFromViper()
	defaults := Defaults()

	// Tunnel config
	if cfg.Tunnel == nil {
		t.Fatal("NewRouterConfigFromViper Tunnel config is nil")
	}
	if cfg.Tunnel.TunnelLength != defaults.Tunnel.TunnelLength {
		t.Errorf("Tunnel.TunnelLength = %d, want %d",
			cfg.Tunnel.TunnelLength, defaults.Tunnel.TunnelLength)
	}
	if cfg.Tunnel.TunnelLifetime != defaults.Tunnel.TunnelLifetime {
		t.Errorf("Tunnel.TunnelLifetime = %v, want %v",
			cfg.Tunnel.TunnelLifetime, defaults.Tunnel.TunnelLifetime)
	}

	// Transport config
	if cfg.Transport == nil {
		t.Fatal("NewRouterConfigFromViper Transport config is nil")
	}
	if cfg.Transport.NTCP2Enabled != defaults.Transport.NTCP2Enabled {
		t.Errorf("Transport.NTCP2Enabled = %v, want %v",
			cfg.Transport.NTCP2Enabled, defaults.Transport.NTCP2Enabled)
	}
	if cfg.Transport.MaxMessageSize != defaults.Transport.MaxMessageSize {
		t.Errorf("Transport.MaxMessageSize = %d, want %d",
			cfg.Transport.MaxMessageSize, defaults.Transport.MaxMessageSize)
	}

	// Performance config
	if cfg.Performance == nil {
		t.Fatal("NewRouterConfigFromViper Performance config is nil")
	}
	if cfg.Performance.WorkerPoolSize != defaults.Performance.WorkerPoolSize {
		t.Errorf("Performance.WorkerPoolSize = %d, want %d",
			cfg.Performance.WorkerPoolSize, defaults.Performance.WorkerPoolSize)
	}

	// Congestion config
	if cfg.Congestion == nil {
		t.Fatal("NewRouterConfigFromViper Congestion config is nil")
	}
	if cfg.Congestion.DFlagThreshold != defaults.Congestion.DFlagThreshold {
		t.Errorf("Congestion.DFlagThreshold = %f, want %f",
			cfg.Congestion.DFlagThreshold, defaults.Congestion.DFlagThreshold)
	}
}

// TestUpdateRouterConfigSubsystemFields verifies that UpdateRouterConfig
// propagates Tunnel, Transport, Performance, and Congestion config.
func TestUpdateRouterConfigSubsystemFields(t *testing.T) {
	viper.Reset()
	setDefaults()

	// Override a subsystem value
	viper.Set("tunnel.length", 2)
	viper.Set("transport.ntcp2_max_connections", 300)
	viper.Set("performance.worker_pool_size", 16)
	viper.Set("router.congestion.d_flag_threshold", 0.80)

	UpdateRouterConfig()

	cfg := GetRouterConfig()
	if cfg.Tunnel == nil {
		t.Fatal("Tunnel config is nil after UpdateRouterConfig")
	}
	if cfg.Tunnel.TunnelLength != 2 {
		t.Errorf("Tunnel.TunnelLength = %d, want 2", cfg.Tunnel.TunnelLength)
	}
	if cfg.Transport == nil {
		t.Fatal("Transport config is nil after UpdateRouterConfig")
	}
	if cfg.Transport.NTCP2MaxConnections != 300 {
		t.Errorf("Transport.NTCP2MaxConnections = %d, want 300", cfg.Transport.NTCP2MaxConnections)
	}
	if cfg.Performance == nil {
		t.Fatal("Performance config is nil after UpdateRouterConfig")
	}
	if cfg.Performance.WorkerPoolSize != 16 {
		t.Errorf("Performance.WorkerPoolSize = %d, want 16", cfg.Performance.WorkerPoolSize)
	}
	if cfg.Congestion == nil {
		t.Fatal("Congestion config is nil after UpdateRouterConfig")
	}
	if cfg.Congestion.DFlagThreshold != 0.80 {
		t.Errorf("Congestion.DFlagThreshold = %f, want 0.80", cfg.Congestion.DFlagThreshold)
	}
}

// TestGetRouterConfigDeepCopySubsystems verifies deep copy includes subsystem configs.
func TestGetRouterConfigDeepCopySubsystems(t *testing.T) {
	viper.Reset()
	setDefaults()
	UpdateRouterConfig()

	cfg := GetRouterConfig()
	if cfg.Tunnel == nil {
		t.Fatal("Tunnel config is nil")
	}

	// Modify the copy
	cfg.Tunnel.TunnelLength = 99
	cfg.Transport.NTCP2MaxConnections = 99

	// Verify original is unchanged
	original := GetRouterConfig()
	if original.Tunnel.TunnelLength == 99 {
		t.Error("Tunnel deep copy failed: original was modified")
	}
	if original.Transport.NTCP2MaxConnections == 99 {
		t.Error("Transport deep copy failed: original was modified")
	}
}
