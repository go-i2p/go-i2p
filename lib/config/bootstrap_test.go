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
