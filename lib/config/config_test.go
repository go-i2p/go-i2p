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
