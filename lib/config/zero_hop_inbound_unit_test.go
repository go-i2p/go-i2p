// Tests for router.always_zero_hop_inbound: the knob that forces every
// exploratory inbound tunnel to be built as a 0-hop tunnel (the router serves
// as both inbound gateway and inbound endpoint). This is the I2P-H-3 fix: the
// field and its router wiring existed, but no viper key/flag fed it, so an
// operator's always_zero_hop_inbound setting was silently ignored.
package config

import (
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRouterConfigAlwaysZeroHopInboundDefaultIsFalse verifies the knob defaults
// to false: zero-hop inbound is opt-in and must never be the default posture.
func TestRouterConfigAlwaysZeroHopInboundDefaultIsFalse(t *testing.T) {
	cfg := DefaultRouterConfig()
	assert.False(t, cfg.AlwaysZeroHopInbound,
		"AlwaysZeroHopInbound must default to false; zero-hop inbound is opt-in")
}

// TestRouterConfigAlwaysZeroHopInboundIsCopied verifies the field survives the
// deep copy performed by GetRouterConfig / DefaultRouterConfig. A field dropped
// in copyBaseFields would be invisible to the router's consumer.
func TestRouterConfigAlwaysZeroHopInboundIsCopied(t *testing.T) {
	LockRouterConfigForWrite()
	prev := routerConfigProperties.AlwaysZeroHopInbound
	routerConfigProperties.AlwaysZeroHopInbound = true
	UnlockRouterConfigWrite()
	defer func() {
		LockRouterConfigForWrite()
		routerConfigProperties.AlwaysZeroHopInbound = prev
		UnlockRouterConfigWrite()
	}()

	cfg := GetRouterConfig()
	assert.True(t, cfg.AlwaysZeroHopInbound,
		"GetRouterConfig must propagate AlwaysZeroHopInbound=true")
}

// TestRouterConfigAlwaysZeroHopInboundViperRoundTrip is the I2P-H-3 regression
// test: NewRouterConfigFromViper must read AlwaysZeroHopInbound from the exact
// viper key setRouterDefaults registers. Before the fix the key was never
// registered nor read, so config.yaml's always_zero_hop_inbound was ignored and
// the router's consumer always saw the zero value.
func TestRouterConfigAlwaysZeroHopInboundViperRoundTrip(t *testing.T) {
	configTestSetup(t)

	viper.Set("router.always_zero_hop_inbound", true)
	cfg, err := NewRouterConfigFromViper()
	require.NoError(t, err)
	assert.True(t, cfg.AlwaysZeroHopInbound,
		"AlwaysZeroHopInbound must be read from router.always_zero_hop_inbound")

	SetRouterConfig(cfg)
	assert.True(t, GetRouterConfig().AlwaysZeroHopInbound,
		"AlwaysZeroHopInbound must survive SetRouterConfig")
}

// TestRouterConfigAlwaysZeroHopInboundDefaultsToFalseFromViper verifies an unset
// router.always_zero_hop_inbound yields false rather than an accidental opt-in.
func TestRouterConfigAlwaysZeroHopInboundDefaultsToFalseFromViper(t *testing.T) {
	configTestSetup(t)

	cfg, err := NewRouterConfigFromViper()
	require.NoError(t, err)
	assert.False(t, cfg.AlwaysZeroHopInbound,
		"unset router.always_zero_hop_inbound must resolve to false")
}
