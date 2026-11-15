package cliflags

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRouterUpnpFlagReachesItsViperKey proves --router.upnp-enabled is bound to
// the exact viper key lib/config's builders read ("router.upnp_enabled"). The
// flag name uses a hyphen and the viper key an underscore, which is where a
// mismatch would come from; bind() only errors when the flag is missing, so a
// wrong viper key would silently leave the setting unreachable.
func TestRouterUpnpFlagReachesItsViperKey(t *testing.T) {
	cmd := &cobra.Command{Use: "go-i2p-test"}
	v := viper.New()

	RegisterAll(cmd)
	require.NoError(t, BindAll(cmd, v), "every registered flag must bind to its viper key")

	require.NoError(t, cmd.PersistentFlags().Set("router.upnp-enabled", "false"),
		"router.upnp-enabled must be registered before it can be set")
	assert.False(t, v.GetBool("router.upnp_enabled"),
		"--router.upnp-enabled=false must resolve to viper key \"router.upnp_enabled\"")

	// Left unset, the key must resolve true: port mapping is on by default,
	// matching the reference implementation and prior go-i2p behavior.
	unsetCmd := &cobra.Command{Use: "go-i2p-test-unset"}
	RegisterAll(unsetCmd)
	unset := viper.New()
	require.NoError(t, BindAll(unsetCmd, unset))
	assert.True(t, unset.GetBool("router.upnp_enabled"),
		"an unset router.upnp_enabled must stay true; port mapping is on by default")
}
