package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Unit Tests for netdb.go — DefaultNetDBConfig, viper round-trips
// =============================================================================

// TestDefaultNetDbConfig verifies that DefaultNetDBConfig has sensible defaults
// for all fields, including the previously missing max size and interval fields.
func TestDefaultNetDbConfig(t *testing.T) {
	cfg := DefaultNetDBConfig

	assert.NotEmpty(t, cfg.Path, "Path should not be empty")
	assert.Equal(t, 5000, cfg.MaxRouterInfos, "MaxRouterInfos")
	assert.Equal(t, 1000, cfg.MaxLeaseSets, "MaxLeaseSets")
	assert.Equal(t, 1*time.Minute, cfg.ExpirationCheckInterval, "ExpirationCheckInterval")
	assert.Equal(t, 2*time.Minute, cfg.LeaseSetRefreshThreshold, "LeaseSetRefreshThreshold")
	assert.Equal(t, 5*time.Minute, cfg.ExplorationInterval, "ExplorationInterval")
	assert.False(t, cfg.FloodfillEnabled, "FloodfillEnabled should be false by default")
}

// TestNetDbConfigViperRoundTrip verifies that NetDBConfig fields are populated
// from viper when using NewRouterConfigFromViper.
func TestNetDbConfigViperRoundTrip(t *testing.T) {
	cfg := initConfigAndNewFromViper(t)
	require.NotNil(t, cfg.NetDB, "NetDB config should not be nil")

	assert.NotZero(t, cfg.NetDB.MaxRouterInfos, "MaxRouterInfos should be populated from viper defaults")
	assert.NotZero(t, cfg.NetDB.MaxLeaseSets, "MaxLeaseSets should be populated from viper defaults")
	assert.NotZero(t, cfg.NetDB.ExpirationCheckInterval, "ExpirationCheckInterval should be populated")
	assert.NotZero(t, cfg.NetDB.LeaseSetRefreshThreshold, "LeaseSetRefreshThreshold should be populated")
	assert.NotZero(t, cfg.NetDB.ExplorationInterval, "ExplorationInterval should be populated")
}

// TestNetDbConfigUpdateRoundTrip verifies that UpdateRouterConfig populates
// all NetDBConfig fields from viper.
func TestNetDbConfigUpdateRoundTrip(t *testing.T) {
	initConfigAndUpdate(t)

	netdb := routerConfigProperties.NetDB
	require.NotNil(t, netdb, "NetDB config should not be nil after UpdateRouterConfig")

	assert.NotZero(t, netdb.MaxRouterInfos, "MaxRouterInfos should be populated after UpdateRouterConfig")
	assert.NotZero(t, netdb.MaxLeaseSets, "MaxLeaseSets should be populated after UpdateRouterConfig")
	assert.NotZero(t, netdb.ExpirationCheckInterval, "ExpirationCheckInterval should be populated after UpdateRouterConfig")
}
