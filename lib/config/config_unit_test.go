package config

import (
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Unit Tests for config.go — CurrentConfig, setDefaults, buildI2CPConfig,
// NewRouterConfigFromViper, UpdateRouterConfig
// =============================================================================

// configTestSetup resets viper state, applies defaults, and returns the
// default ConfigDefaults for comparison. Call at the start of each config test.
func configTestSetup(t *testing.T) ConfigDefaults {
	t.Helper()
	viper.Reset()
	setDefaults()
	return Defaults()
}

// TestCurrentConfigRouterInfoRefreshInterval verifies that CurrentConfig()
// correctly reads the RouterInfoRefreshInterval from the same viper key
// used by setDefaults(). This covers CRITICAL BUG: Viper Key Mismatch
// for RouterInfo Refresh Interval.
func TestCurrentConfigRouterInfoRefreshInterval(t *testing.T) {
	configTestSetup(t)

	cfg := CurrentConfig()

	// The key fix: CurrentConfig() must read from the same key that
	// setDefaults() writes to. Before the fix, it read from a different
	// key ("router.routerinfo_refresh_interval") and always got 0s.
	assert.Equal(t, 30*time.Minute, cfg.Router.RouterInfoRefreshInterval, "RouterInfoRefreshInterval")
}

// TestCurrentConfigDefaultsRoundTrip verifies that all defaults set via
// setDefaults() are correctly read back by CurrentConfig(). This catches
// any additional key mismatches between SetDefault and Get calls.
func TestCurrentConfigDefaultsRoundTrip(t *testing.T) {
	defaults := configTestSetup(t)

	cfg := CurrentConfig()

	// Router section
	assert.Equal(t, defaults.Router.RouterInfoRefreshInterval, cfg.Router.RouterInfoRefreshInterval, "RouterInfoRefreshInterval")
	assert.Equal(t, defaults.Router.MessageExpirationTime, cfg.Router.MessageExpirationTime, "MessageExpirationTime")
	assert.Equal(t, defaults.Router.MaxConcurrentSessions, cfg.Router.MaxConcurrentSessions, "MaxConcurrentSessions")

	// NetDB section
	assert.Equal(t, defaults.NetDB.MaxRouterInfos, cfg.NetDB.MaxRouterInfos, "MaxRouterInfos")
	assert.Equal(t, defaults.NetDB.ExpirationCheckInterval, cfg.NetDB.ExpirationCheckInterval, "ExpirationCheckInterval")

	// Bootstrap section
	assert.Equal(t, defaults.Bootstrap.LowPeerThreshold, cfg.Bootstrap.LowPeerThreshold, "LowPeerThreshold")

	// I2CP section
	assert.Equal(t, defaults.I2CP.Enabled, cfg.I2CP.Enabled, "I2CP.Enabled")
	assert.Equal(t, defaults.I2CP.Address, cfg.I2CP.Address, "I2CP.Address")
}

// TestCurrentConfigViperOverride verifies that RouterInfoRefreshInterval
// can be overridden through viper, confirming the key is correct.
func TestCurrentConfigViperOverride(t *testing.T) {
	configTestSetup(t)

	// Override the value using the key
	override := 45 * time.Minute
	viper.Set("router.info_refresh_interval", override)

	cfg := CurrentConfig()
	assert.Equal(t, override, cfg.Router.RouterInfoRefreshInterval, "Override failed")
}

// TestBuildI2CPConfigAllFields verifies that buildI2CPConfig reads ALL I2CPConfig
// fields from viper, not just a subset. This covers CRITICAL BUG: buildI2CPConfig
// Drops Session Timeout and Queue Size Fields.
func TestBuildI2CPConfigAllFields(t *testing.T) {
	defaults := configTestSetup(t)

	cfg := buildI2CPConfig()

	// Fields that were previously populated
	assert.Equal(t, defaults.I2CP.Enabled, cfg.Enabled, "I2CP.Enabled")
	assert.Equal(t, defaults.I2CP.Address, cfg.Address, "I2CP.Address")
	assert.Equal(t, defaults.I2CP.Network, cfg.Network, "I2CP.Network")
	assert.Equal(t, defaults.I2CP.MaxSessions, cfg.MaxSessions, "I2CP.MaxSessions")

	// Fields that were previously MISSING (the bug)
	assert.Equal(t, defaults.I2CP.MessageQueueSize, cfg.MessageQueueSize, "I2CP.MessageQueueSize (was zero before fix)")
	assert.Equal(t, defaults.I2CP.SessionTimeout, cfg.SessionTimeout, "I2CP.SessionTimeout (was zero before fix)")
	assert.Equal(t, defaults.I2CP.ReadTimeout, cfg.ReadTimeout, "I2CP.ReadTimeout (was zero before fix)")
	assert.Equal(t, defaults.I2CP.WriteTimeout, cfg.WriteTimeout, "I2CP.WriteTimeout (was zero before fix)")

	// Auth fields (default to empty = auth disabled)
	assert.Empty(t, cfg.Username, "I2CP.Username should be empty")
	assert.Empty(t, cfg.Password, "I2CP.Password should be empty")
}

// TestBuildI2CPConfigViperOverrides verifies that all I2CPConfig fields
// can be overridden through viper, confirming the viper keys are correct.
func TestBuildI2CPConfigViperOverrides(t *testing.T) {
	configTestSetup(t)

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

	assert.Equal(t, false, cfg.Enabled, "I2CP.Enabled override")
	assert.Equal(t, "0.0.0.0:9999", cfg.Address, "I2CP.Address override")
	assert.Equal(t, "unix", cfg.Network, "I2CP.Network override")
	assert.Equal(t, 50, cfg.MaxSessions, "I2CP.MaxSessions override")
	assert.Equal(t, 128, cfg.MessageQueueSize, "I2CP.MessageQueueSize override")
	assert.Equal(t, 1*time.Hour, cfg.SessionTimeout, "I2CP.SessionTimeout override")
	assert.Equal(t, 90*time.Second, cfg.ReadTimeout, "I2CP.ReadTimeout override")
	assert.Equal(t, 45*time.Second, cfg.WriteTimeout, "I2CP.WriteTimeout override")
	assert.Equal(t, "admin", cfg.Username, "I2CP.Username override")
	assert.Equal(t, "secret", cfg.Password, "I2CP.Password override")
}

// TestNewRouterConfigFromViperI2CPFields verifies that NewRouterConfigFromViper
// produces an I2CPConfig with all fields populated from viper defaults.
func TestNewRouterConfigFromViperI2CPFields(t *testing.T) {
	defaults := configTestSetup(t)

	cfg := NewRouterConfigFromViper()

	assert.Equal(t, defaults.I2CP.SessionTimeout, cfg.I2CP.SessionTimeout, "I2CP.SessionTimeout")
	assert.Equal(t, defaults.I2CP.MessageQueueSize, cfg.I2CP.MessageQueueSize, "I2CP.MessageQueueSize")
	assert.Equal(t, defaults.I2CP.ReadTimeout, cfg.I2CP.ReadTimeout, "I2CP.ReadTimeout")
	assert.Equal(t, defaults.I2CP.WriteTimeout, cfg.I2CP.WriteTimeout, "I2CP.WriteTimeout")
}

// TestNewRouterConfigFromViperSubsystemFields verifies that NewRouterConfigFromViper
// populates Tunnel, Transport, Performance, and Congestion config fields.
// This covers CRITICAL-002: RouterConfig missing subsystem config fields.
func TestNewRouterConfigFromViperSubsystemFields(t *testing.T) {
	defaults := configTestSetup(t)

	cfg := NewRouterConfigFromViper()

	requireSubsystemConfigsNotNil(t, cfg)
	assert.Equal(t, defaults.Tunnel.TunnelLength, cfg.Tunnel.TunnelLength, "Tunnel.TunnelLength")
	assert.Equal(t, defaults.Tunnel.TunnelLifetime, cfg.Tunnel.TunnelLifetime, "Tunnel.TunnelLifetime")
	assert.Equal(t, defaults.Transport.NTCP2Enabled, cfg.Transport.NTCP2Enabled, "Transport.NTCP2Enabled")
	assert.Equal(t, defaults.Transport.MaxMessageSize, cfg.Transport.MaxMessageSize, "Transport.MaxMessageSize")
	assert.Equal(t, defaults.Performance.WorkerPoolSize, cfg.Performance.WorkerPoolSize, "Performance.WorkerPoolSize")
	assert.Equal(t, defaults.Congestion.DFlagThreshold, cfg.Congestion.DFlagThreshold, "Congestion.DFlagThreshold")
}

// TestSetRouterConfigSubsystemFields verifies that SetRouterConfig(NewRouterConfigFromViper())
// propagates Tunnel, Transport, Performance, and Congestion config.
func TestUpdateRouterConfigSubsystemFields(t *testing.T) {
	configTestSetup(t)

	// Override a subsystem value
	viper.Set("tunnel.length", 2)
	viper.Set("transport.ntcp2_max_connections", 300)
	viper.Set("performance.worker_pool_size", 16)
	viper.Set("router.congestion.d_flag_threshold", 0.80)

	SetRouterConfig(NewRouterConfigFromViper())

	cfg := GetRouterConfig()
	requireSubsystemConfigsNotNil(t, cfg)
	assert.Equal(t, 2, cfg.Tunnel.TunnelLength, "Tunnel.TunnelLength")
	assert.Equal(t, 300, cfg.Transport.NTCP2MaxConnections, "Transport.NTCP2MaxConnections")
	assert.Equal(t, 16, cfg.Performance.WorkerPoolSize, "Performance.WorkerPoolSize")
	assert.Equal(t, 0.80, cfg.Congestion.DFlagThreshold, "Congestion.DFlagThreshold")
}

// TestGetRouterConfigDeepCopySubsystems verifies deep copy includes subsystem configs.
func TestGetRouterConfigDeepCopySubsystems(t *testing.T) {
	configTestSetup(t)
	SetRouterConfig(NewRouterConfigFromViper())

	cfg := GetRouterConfig()
	require.NotNil(t, cfg.Tunnel, "Tunnel config is nil")

	// Modify the copy
	cfg.Tunnel.TunnelLength = 99
	cfg.Transport.NTCP2MaxConnections = 99

	// Verify original is unchanged
	original := GetRouterConfig()
	assert.NotEqual(t, 99, original.Tunnel.TunnelLength, "Tunnel deep copy failed: original was modified")
	assert.NotEqual(t, 99, original.Transport.NTCP2MaxConnections, "Transport deep copy failed: original was modified")
}

// TestSetRouterConfigIncludesAllFields verifies SetRouterConfig(NewRouterConfigFromViper()) propagates all fields.
// (Moved from defaults_test.go)
func TestUpdateRouterConfig_IncludesAllFields(t *testing.T) {
	configTestSetup(t)

	viper.Set("router.max_bandwidth", uint64(2048000))
	viper.Set("router.max_connections", 500)
	viper.Set("router.accept_tunnels", false)

	SetRouterConfig(NewRouterConfigFromViper())

	cfg := GetRouterConfig()
	assert.Equal(t, uint64(2048000), cfg.MaxBandwidth, "MaxBandwidth")
	assert.Equal(t, 500, cfg.MaxConnections, "MaxConnections")
	assert.Equal(t, false, cfg.AcceptTunnels, "AcceptTunnels")
}
