package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestExternalAddressDefaultsEmpty pins the default posture: no operator
// override, so the router auto-detects its advertised address. Both the
// ConfigDefaults view and the RouterConfig view must agree.
func TestExternalAddressDefaultsEmpty(t *testing.T) {
	assert.Empty(t, Defaults().Router.ExternalAddress,
		"Router.ExternalAddress default must be empty")
	assert.Empty(t, DefaultRouterConfig().ExternalAddress,
		"DefaultRouterConfig().ExternalAddress must be empty")
}

// TestExternalAddressSurvivesDeepCopy guards the copy path: GetRouterConfig deep
// copies via copyBaseFields, and a field omitted there would silently reset to
// "" on every read, so an operator who set external_address would have it
// ignored. copyBaseFields is the exact function that would drop it.
func TestExternalAddressSurvivesDeepCopy(t *testing.T) {
	src := &RouterConfig{ExternalAddress: "203.0.113.7:8888"}
	copied := copyBaseFields(src)
	assert.Equal(t, "203.0.113.7:8888", copied.ExternalAddress,
		"ExternalAddress must be preserved by copyBaseFields")
}
