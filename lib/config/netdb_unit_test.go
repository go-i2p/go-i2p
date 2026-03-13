package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Unit Tests for netdb.go — DefaultNetDbConfig, viper round-trips
// =============================================================================

// TestDefaultNetDbConfig verifies that DefaultNetDbConfig has sensible defaults
// for all fields, including the previously missing max size and interval fields.
func TestDefaultNetDbConfig(t *testing.T) {
	cfg := DefaultNetDbConfig

	assert.NotEmpty(t, cfg.Path, "Path should not be empty")
	assert.Equal(t, 5000, cfg.MaxRouterInfos, "MaxRouterInfos")
	assert.Equal(t, 1000, cfg.MaxLeaseSets, "MaxLeaseSets")
	assert.Equal(t, 1*time.Minute, cfg.ExpirationCheckInterval, "ExpirationCheckInterval")
	assert.Equal(t, 2*time.Minute, cfg.LeaseSetRefreshThreshold, "LeaseSetRefreshThreshold")
	assert.Equal(t, 5*time.Minute, cfg.ExplorationInterval, "ExplorationInterval")
	assert.False(t, cfg.FloodfillEnabled, "FloodfillEnabled should be false by default")
}

// TestNetDbConfigViperRoundTrip verifies that NetDbConfig fields are populated
// from viper when using NewRouterConfigFromViper.
func TestNetDbConfigViperRoundTrip(t *testing.T) {
	cfg := initConfigAndNewFromViper(t)
	require.NotNil(t, cfg.NetDb, "NetDb config should not be nil")

	assert.NotZero(t, cfg.NetDb.MaxRouterInfos, "MaxRouterInfos should be populated from viper defaults")
	assert.NotZero(t, cfg.NetDb.MaxLeaseSets, "MaxLeaseSets should be populated from viper defaults")
	assert.NotZero(t, cfg.NetDb.ExpirationCheckInterval, "ExpirationCheckInterval should be populated")
	assert.NotZero(t, cfg.NetDb.LeaseSetRefreshThreshold, "LeaseSetRefreshThreshold should be populated")
	assert.NotZero(t, cfg.NetDb.ExplorationInterval, "ExplorationInterval should be populated")
}

// TestNetDbConfigUpdateRoundTrip verifies that UpdateRouterConfig populates
// all NetDbConfig fields from viper.
func TestNetDbConfigUpdateRoundTrip(t *testing.T) {
	initConfigAndUpdate(t)

	netdb := routerConfigProperties.NetDb
	require.NotNil(t, netdb, "NetDb config should not be nil after UpdateRouterConfig")

	assert.NotZero(t, netdb.MaxRouterInfos, "MaxRouterInfos should be populated after UpdateRouterConfig")
	assert.NotZero(t, netdb.MaxLeaseSets, "MaxLeaseSets should be populated after UpdateRouterConfig")
	assert.NotZero(t, netdb.ExpirationCheckInterval, "ExpirationCheckInterval should be populated after UpdateRouterConfig")
}
