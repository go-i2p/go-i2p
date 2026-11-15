package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestUpnpEnabledDefaultsTrue pins the default posture: UPnP/NAT-PMP port
// mapping is on by default (matching the reference implementation and prior
// go-i2p behavior), so making it disableable does not silently change the
// default. Both the ConfigDefaults view and the RouterConfig view must agree.
func TestUpnpEnabledDefaultsTrue(t *testing.T) {
	assert.True(t, Defaults().Router.UpnpEnabled,
		"Router.UpnpEnabled default must be true")
	assert.True(t, DefaultRouterConfig().UpnpEnabled,
		"DefaultRouterConfig().UpnpEnabled must be true")
}

// TestUpnpEnabledSurvivesDeepCopy guards the copy path: GetRouterConfig deep
// copies via copyBaseFields, and a field omitted there would silently reset to
// false on every read, so an operator who set upnp_enabled=false would have it
// ignored. copyBaseFields is the exact function that would drop it.
func TestUpnpEnabledSurvivesDeepCopy(t *testing.T) {
	src := &RouterConfig{UpnpEnabled: false}
	copied := copyBaseFields(src)
	assert.False(t, copied.UpnpEnabled,
		"UpnpEnabled=false must be preserved by copyBaseFields")

	src2 := &RouterConfig{UpnpEnabled: true}
	copied2 := copyBaseFields(src2)
	assert.True(t, copied2.UpnpEnabled,
		"UpnpEnabled=true must be preserved by copyBaseFields")
}
