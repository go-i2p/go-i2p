// Tests for the configuration surface added for small-network operation:
// bootstrap.emergency_reseed_floor (a floor a testnet can actually satisfy) and
// router.router_info_file (the file external tooling parses for our ident
// hash). Both are read through viper and handed to the router via
// GetRouterConfig, so a typo in a key or a field missing from the deep copy
// silently reverts a router to mainnet behaviour.
package config

import (
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEmergencyReseedFloorDefaultIsProductionValue verifies the default floor
// is unchanged: mainnet routers must keep gating startup at 40 RouterInfos.
func TestEmergencyReseedFloorDefaultIsProductionValue(t *testing.T) {
	assert.Equal(t, DefaultEmergencyReseedFloor, DefaultBootstrapConfig.EmergencyReseedFloor,
		"DefaultBootstrapConfig must carry the production floor")
	assert.Equal(t, 40, DefaultEmergencyReseedFloor,
		"the production floor value is part of the documented contract")
}

// TestEmergencyReseedFloorViperRoundTrip verifies the key spelled in
// setBootstrapDefaults is the same key buildBootstrapConfig reads, and that the
// value survives SetRouterConfig/GetRouterConfig.
func TestEmergencyReseedFloorViperRoundTrip(t *testing.T) {
	configTestSetup(t)

	viper.Set("bootstrap.emergency_reseed_floor", 1)
	cfg, err := NewRouterConfigFromViper()
	require.NoError(t, err)
	require.NotNil(t, cfg.Bootstrap)
	assert.Equal(t, 1, cfg.Bootstrap.EmergencyReseedFloor,
		"EmergencyReseedFloor must be read from bootstrap.emergency_reseed_floor")

	SetRouterConfig(cfg)
	assert.Equal(t, 1, GetRouterConfig().Bootstrap.EmergencyReseedFloor,
		"EmergencyReseedFloor must survive the GetRouterConfig deep copy")
}

// TestEmergencyReseedFloorDefaultsFromViper verifies an unset key resolves to
// the production floor rather than 0, which the router would read as "unset"
// anyway but which would hide a binding mistake.
func TestEmergencyReseedFloorDefaultsFromViper(t *testing.T) {
	configTestSetup(t)

	cfg, err := NewRouterConfigFromViper()
	require.NoError(t, err)
	require.NotNil(t, cfg.Bootstrap)
	assert.Equal(t, DefaultEmergencyReseedFloor, cfg.Bootstrap.EmergencyReseedFloor)
}

// TestEmergencyReseedFloorValidationRejectsNegative verifies a negative floor
// is rejected at startup: it would silently disable the floor, which is what
// router.testnet expresses explicitly.
func TestEmergencyReseedFloorValidationRejectsNegative(t *testing.T) {
	defaults := Defaults()
	defaults.Bootstrap.EmergencyReseedFloor = -1
	require.Error(t, Validate(defaults), "a negative emergency reseed floor must fail validation")
}

// TestEmergencyReseedFloorValidationAcceptsZeroAndPositive verifies the
// documented accepted range: 0 means "use the default", any positive value is
// an explicit floor.
func TestEmergencyReseedFloorValidationAcceptsZeroAndPositive(t *testing.T) {
	for _, floor := range []int{0, 1, 40, 500} {
		defaults := Defaults()
		defaults.Bootstrap.EmergencyReseedFloor = floor
		require.NoError(t, Validate(defaults), "floor %d must be accepted", floor)
	}
}

// TestRouterInfoFileDefaultIsUnderWorkingDir verifies the default path is the
// documented one inside the working directory, which is what container images
// and dashboards rely on.
func TestRouterInfoFileDefaultIsUnderWorkingDir(t *testing.T) {
	cfg := DefaultRouterConfig()
	require.NotEmpty(t, cfg.RouterInfoFile, "router.info must be published by default")
	assert.Equal(t, filepath.Join(cfg.WorkingDir, "router.info"), filepath.Clean(cfg.RouterInfoFile),
		"the default router.info path must sit in the working directory")
}

// TestRouterInfoFileViperRoundTrip verifies the key is read from viper and,
// critically, survives copyBaseFields: that helper enumerates fields by hand,
// so a new field that is not added there is silently dropped on every
// GetRouterConfig call.
func TestRouterInfoFileViperRoundTrip(t *testing.T) {
	configTestSetup(t)

	viper.Set("router.router_info_file", "/var/lib/go-i2p/router.info")
	cfg, err := NewRouterConfigFromViper()
	require.NoError(t, err)
	assert.Equal(t, "/var/lib/go-i2p/router.info", cfg.RouterInfoFile,
		"RouterInfoFile must be read from router.router_info_file")

	SetRouterConfig(cfg)
	assert.Equal(t, "/var/lib/go-i2p/router.info", GetRouterConfig().RouterInfoFile,
		"RouterInfoFile must survive the GetRouterConfig deep copy")
}

// TestRouterInfoFileEmptyDisablesPublishing verifies an operator can opt out by
// setting the key to an empty string, and that the empty value is not replaced
// by the default on the way through the copy.
func TestRouterInfoFileEmptyDisablesPublishing(t *testing.T) {
	configTestSetup(t)

	viper.Set("router.router_info_file", "")
	cfg, err := NewRouterConfigFromViper()
	require.NoError(t, err)
	assert.Empty(t, cfg.RouterInfoFile, "an explicit empty path must stay empty")

	SetRouterConfig(cfg)
	assert.Empty(t, GetRouterConfig().RouterInfoFile,
		"the opt-out must survive the deep copy, or the file reappears")
}
