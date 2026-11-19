package cliflags

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRouterExternalAddressFlagReachesItsViperKey proves --router.external-address
// is bound to the exact viper key lib/config's builders read
// ("router.external_address"). The flag name uses a hyphen and the viper key an
// underscore, which is where a mismatch would come from; a wrong viper key would
// silently leave the override unreachable.
func TestRouterExternalAddressFlagReachesItsViperKey(t *testing.T) {
	cmd := &cobra.Command{Use: "go-i2p-test"}
	v := viper.New()

	RegisterAll(cmd)
	require.NoError(t, BindAll(cmd, v), "every registered flag must bind to its viper key")

	require.NoError(t, cmd.PersistentFlags().Set("router.external-address", "203.0.113.7:8888"),
		"router.external-address must be registered before it can be set")
	assert.Equal(t, "203.0.113.7:8888", v.GetString("router.external_address"),
		"--router.external-address must resolve to viper key \"router.external_address\"")

	// Left unset, the key must resolve empty: auto-detection is the default.
	unsetCmd := &cobra.Command{Use: "go-i2p-test-unset"}
	RegisterAll(unsetCmd)
	unset := viper.New()
	require.NoError(t, BindAll(unsetCmd, unset))
	assert.Empty(t, unset.GetString("router.external_address"),
		"an unset router.external_address must stay empty; auto-detection is the default")
}
