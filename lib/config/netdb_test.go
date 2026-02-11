package config

import (
	"testing"
	"time"
)

// TestDefaultNetDbConfig verifies that DefaultNetDbConfig has sensible defaults
// for all fields, including the previously missing max size and interval fields.
func TestDefaultNetDbConfig(t *testing.T) {
	cfg := DefaultNetDbConfig

	if cfg.Path == "" {
		t.Error("Path should not be empty")
	}
	if cfg.MaxRouterInfos != 5000 {
		t.Errorf("MaxRouterInfos = %d, want 5000", cfg.MaxRouterInfos)
	}
	if cfg.MaxLeaseSets != 1000 {
		t.Errorf("MaxLeaseSets = %d, want 1000", cfg.MaxLeaseSets)
	}
	if cfg.ExpirationCheckInterval != 1*time.Minute {
		t.Errorf("ExpirationCheckInterval = %v, want 1m", cfg.ExpirationCheckInterval)
	}
	if cfg.LeaseSetRefreshThreshold != 2*time.Minute {
		t.Errorf("LeaseSetRefreshThreshold = %v, want 2m", cfg.LeaseSetRefreshThreshold)
	}
	if cfg.ExplorationInterval != 5*time.Minute {
		t.Errorf("ExplorationInterval = %v, want 5m", cfg.ExplorationInterval)
	}
	if cfg.FloodfillEnabled {
		t.Error("FloodfillEnabled should be false by default")
	}
}

// TestNetDbConfigViperRoundTrip verifies that NetDbConfig fields are populated
// from viper when using NewRouterConfigFromViper.
func TestNetDbConfigViperRoundTrip(t *testing.T) {
	InitConfig()

	cfg := NewRouterConfigFromViper()
	if cfg.NetDb == nil {
		t.Fatal("NetDb config should not be nil")
	}

	if cfg.NetDb.MaxRouterInfos == 0 {
		t.Error("MaxRouterInfos should be populated from viper defaults, got 0")
	}
	if cfg.NetDb.MaxLeaseSets == 0 {
		t.Error("MaxLeaseSets should be populated from viper defaults, got 0")
	}
	if cfg.NetDb.ExpirationCheckInterval == 0 {
		t.Error("ExpirationCheckInterval should be populated from viper defaults, got 0")
	}
	if cfg.NetDb.LeaseSetRefreshThreshold == 0 {
		t.Error("LeaseSetRefreshThreshold should be populated from viper defaults, got 0")
	}
	if cfg.NetDb.ExplorationInterval == 0 {
		t.Error("ExplorationInterval should be populated from viper defaults, got 0")
	}
}

// TestNetDbConfigUpdateRoundTrip verifies that UpdateRouterConfig populates
// all NetDbConfig fields from viper.
func TestNetDbConfigUpdateRoundTrip(t *testing.T) {
	InitConfig()
	UpdateRouterConfig()

	netdb := RouterConfigProperties.NetDb
	if netdb == nil {
		t.Fatal("NetDb config should not be nil after UpdateRouterConfig")
	}

	if netdb.MaxRouterInfos == 0 {
		t.Error("MaxRouterInfos should be populated after UpdateRouterConfig, got 0")
	}
	if netdb.MaxLeaseSets == 0 {
		t.Error("MaxLeaseSets should be populated after UpdateRouterConfig, got 0")
	}
	if netdb.ExpirationCheckInterval == 0 {
		t.Error("ExpirationCheckInterval should be populated after UpdateRouterConfig, got 0")
	}
}
