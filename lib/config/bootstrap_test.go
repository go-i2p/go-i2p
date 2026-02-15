package config

import (
	"testing"
)

func TestDefaultBootstrapConfig_ReseedServers(t *testing.T) {
	// Default should use all known reseed servers
	if len(DefaultBootstrapConfig.ReseedServers) != len(KnownReseedServers) {
		t.Errorf("DefaultBootstrapConfig.ReseedServers should have %d servers, got %d",
			len(KnownReseedServers), len(DefaultBootstrapConfig.ReseedServers))
	}
}

func TestDefaultBootstrapConfig_MinReseedServers(t *testing.T) {
	// Should default to 1 for backward compatibility
	if DefaultBootstrapConfig.MinReseedServers != DefaultMinReseedServers {
		t.Errorf("DefaultBootstrapConfig.MinReseedServers should be %d, got %d",
			DefaultMinReseedServers, DefaultBootstrapConfig.MinReseedServers)
	}
}

func TestDefaultBootstrapConfig_ReseedStrategy(t *testing.T) {
	// Should default to union strategy
	if DefaultBootstrapConfig.ReseedStrategy != ReseedStrategyUnion {
		t.Errorf("DefaultBootstrapConfig.ReseedStrategy should be %q, got %q",
			ReseedStrategyUnion, DefaultBootstrapConfig.ReseedStrategy)
	}

	// Verify it's a valid strategy
	if !IsValidReseedStrategy(DefaultBootstrapConfig.ReseedStrategy) {
		t.Errorf("DefaultBootstrapConfig.ReseedStrategy %q is not valid",
			DefaultBootstrapConfig.ReseedStrategy)
	}
}

func TestDefaultBootstrapConfig_BootstrapType(t *testing.T) {
	if DefaultBootstrapConfig.BootstrapType != "auto" {
		t.Errorf("DefaultBootstrapConfig.BootstrapType should be 'auto', got %q",
			DefaultBootstrapConfig.BootstrapType)
	}
}

func TestDefaultBootstrapConfig_LowPeerThreshold(t *testing.T) {
	if DefaultBootstrapConfig.LowPeerThreshold != 10 {
		t.Errorf("DefaultBootstrapConfig.LowPeerThreshold should be 10, got %d",
			DefaultBootstrapConfig.LowPeerThreshold)
	}
}

func TestBootstrapConfig_NewFieldsAccessible(t *testing.T) {
	// Test that we can create a BootstrapConfig with the new fields
	cfg := BootstrapConfig{
		LowPeerThreshold: 5,
		BootstrapType:    "reseed",
		ReseedServers:    KnownReseedServers[:3], // First 3 servers
		MinReseedServers: 2,
		ReseedStrategy:   ReseedStrategyIntersection,
	}

	if cfg.MinReseedServers != 2 {
		t.Errorf("MinReseedServers not set correctly")
	}
	if cfg.ReseedStrategy != ReseedStrategyIntersection {
		t.Errorf("ReseedStrategy not set correctly")
	}
}

// TestBootstrapConfigViperRoundTrip verifies that MinReseedServers and
// ReseedStrategy are populated from viper in NewRouterConfigFromViper.
func TestBootstrapConfigViperRoundTrip(t *testing.T) {
	if err := InitConfig(); err != nil {
		t.Fatalf("InitConfig failed: %v", err)
	}

	cfg := NewRouterConfigFromViper()
	if cfg.Bootstrap == nil {
		t.Fatal("Bootstrap config should not be nil")
	}

	if cfg.Bootstrap.MinReseedServers == 0 {
		t.Error("MinReseedServers should be populated from viper defaults, got 0")
	}
	if cfg.Bootstrap.MinReseedServers != DefaultMinReseedServers {
		t.Errorf("MinReseedServers = %d, want %d", cfg.Bootstrap.MinReseedServers, DefaultMinReseedServers)
	}
	if cfg.Bootstrap.ReseedStrategy == "" {
		t.Error("ReseedStrategy should be populated from viper defaults, got empty string")
	}
	if cfg.Bootstrap.ReseedStrategy != ReseedStrategyUnion {
		t.Errorf("ReseedStrategy = %q, want %q", cfg.Bootstrap.ReseedStrategy, ReseedStrategyUnion)
	}
}

// TestBootstrapConfigUpdateRoundTrip verifies that UpdateRouterConfig populates
// MinReseedServers and ReseedStrategy from viper.
func TestBootstrapConfigUpdateRoundTrip(t *testing.T) {
	if err := InitConfig(); err != nil {
		t.Fatalf("InitConfig failed: %v", err)
	}
	UpdateRouterConfig()

	bootstrap := routerConfigProperties.Bootstrap
	if bootstrap == nil {
		t.Fatal("Bootstrap config should not be nil after UpdateRouterConfig")
	}

	if bootstrap.MinReseedServers == 0 {
		t.Error("MinReseedServers should be populated after UpdateRouterConfig, got 0")
	}
	if bootstrap.ReseedStrategy == "" {
		t.Error("ReseedStrategy should be populated after UpdateRouterConfig, got empty string")
	}
}
