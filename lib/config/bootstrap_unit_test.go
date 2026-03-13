package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Unit Tests for bootstrap.go — BootstrapConfig defaults
// =============================================================================

func TestDefaultBootstrapConfig_ReseedServers(t *testing.T) {
	assert.Equal(t, len(KnownReseedServers), len(DefaultBootstrapConfig.ReseedServers),
		"DefaultBootstrapConfig.ReseedServers should have all known reseed servers")
}

func TestDefaultBootstrapConfig_MinReseedServers(t *testing.T) {
	assert.Equal(t, DefaultMinReseedServers, DefaultBootstrapConfig.MinReseedServers, "MinReseedServers")
}

func TestDefaultBootstrapConfig_ReseedStrategy(t *testing.T) {
	assert.Equal(t, ReseedStrategyUnion, DefaultBootstrapConfig.ReseedStrategy, "ReseedStrategy")
	assert.True(t, IsValidReseedStrategy(DefaultBootstrapConfig.ReseedStrategy),
		"DefaultBootstrapConfig.ReseedStrategy %q is not valid", DefaultBootstrapConfig.ReseedStrategy)
}

func TestDefaultBootstrapConfig_BootstrapType(t *testing.T) {
	assert.Equal(t, "auto", DefaultBootstrapConfig.BootstrapType, "BootstrapType")
}

func TestDefaultBootstrapConfig_LowPeerThreshold(t *testing.T) {
	assert.Equal(t, 10, DefaultBootstrapConfig.LowPeerThreshold, "LowPeerThreshold")
}

func TestBootstrapConfig_NewFieldsAccessible(t *testing.T) {
	cfg := BootstrapConfig{
		LowPeerThreshold: 5,
		BootstrapType:    "reseed",
		ReseedServers:    KnownReseedServers[:3],
		MinReseedServers: 2,
		ReseedStrategy:   ReseedStrategyIntersection,
	}

	assert.Equal(t, 2, cfg.MinReseedServers, "MinReseedServers")
	assert.Equal(t, ReseedStrategyIntersection, cfg.ReseedStrategy, "ReseedStrategy")
}

// TestBootstrapConfigViperRoundTrip verifies that MinReseedServers and
// ReseedStrategy are populated from viper in NewRouterConfigFromViper.
func TestBootstrapConfigViperRoundTrip(t *testing.T) {
	cfg := initConfigAndNewFromViper(t)
	require.NotNil(t, cfg.Bootstrap, "Bootstrap config should not be nil")

	assert.Equal(t, DefaultMinReseedServers, cfg.Bootstrap.MinReseedServers, "MinReseedServers")
	assert.Equal(t, ReseedStrategyUnion, cfg.Bootstrap.ReseedStrategy, "ReseedStrategy")
}

// TestBootstrapConfigUpdateRoundTrip verifies that UpdateRouterConfig populates
// MinReseedServers and ReseedStrategy from viper.
func TestBootstrapConfigUpdateRoundTrip(t *testing.T) {
	initConfigAndUpdate(t)

	bootstrap := routerConfigProperties.Bootstrap
	require.NotNil(t, bootstrap, "Bootstrap config should not be nil after UpdateRouterConfig")

	assert.NotZero(t, bootstrap.MinReseedServers, "MinReseedServers should be populated")
	assert.NotEmpty(t, bootstrap.ReseedStrategy, "ReseedStrategy should be populated")
}
