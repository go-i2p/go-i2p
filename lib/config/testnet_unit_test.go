// Tests for router.testnet: the setting that makes a router express no bootstrap
// peer floor, so a small test network is not reported as a startup failure.
package config

import (
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRouterConfigTestnetDefaultIsFalse verifies Testnet defaults to false: the
// production bootstrap floor must stay on unless an operator opts out.
func TestRouterConfigTestnetDefaultIsFalse(t *testing.T) {
	cfg := DefaultRouterConfig()
	assert.False(t, cfg.Testnet, "Testnet must default to false; the bootstrap peer floor is on by default")
}

// TestRouterConfigTestnetIsCopied verifies Testnet survives the deep copy
// performed by GetRouterConfig / DefaultRouterConfig.
func TestRouterConfigTestnetIsCopied(t *testing.T) {
	LockRouterConfigForWrite()
	prev := routerConfigProperties.Testnet
	routerConfigProperties.Testnet = true
	UnlockRouterConfigWrite()
	defer func() {
		LockRouterConfigForWrite()
		routerConfigProperties.Testnet = prev
		UnlockRouterConfigWrite()
	}()

	cfg := GetRouterConfig()
	assert.True(t, cfg.Testnet, "GetRouterConfig must propagate Testnet=true")
}

// TestRouterConfigTestnetViperRoundTrip verifies NewRouterConfigFromViper reads
// Testnet from the same viper key setRouterDefaults writes, and that the value
// survives SetRouterConfig/GetRouterConfig. A key typo here silently leaves the
// router gating startup on the production floor.
func TestRouterConfigTestnetViperRoundTrip(t *testing.T) {
	configTestSetup(t)

	viper.Set("router.testnet", true)
	cfg, err := NewRouterConfigFromViper()
	require.NoError(t, err)
	assert.True(t, cfg.Testnet, "Testnet must be read from router.testnet")

	SetRouterConfig(cfg)
	require.NotNil(t, GetRouterConfig().Bootstrap, "Bootstrap config should not be nil after SetRouterConfig")
	assert.True(t, GetRouterConfig().Testnet, "Testnet must survive SetRouterConfig")
}

// TestRouterConfigTestnetDefaultsToFalseFromViper verifies an unset router.testnet
// yields false rather than an accidental opt-out of the floor.
func TestRouterConfigTestnetDefaultsToFalseFromViper(t *testing.T) {
	configTestSetup(t)

	cfg, err := NewRouterConfigFromViper()
	require.NoError(t, err)
	assert.False(t, cfg.Testnet, "unset router.testnet must resolve to false")
}
