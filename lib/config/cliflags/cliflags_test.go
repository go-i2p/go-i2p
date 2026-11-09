// Tests for the CLI flag <-> viper key bindings.
//
// Flags are declared in two parallel lists that nothing but convention keeps in
// step: registerTransportFlags declares the flag, and bindTransportFlags pairs a
// flag name with a viper key. A typo in either half fails silently -- bind only
// errors when the flag is missing, so a wrong *viper key* just means the setting
// never reaches the config struct the router reads. The pairing has to be proven
// by setting the flag and reading the value back out of viper.

package cliflags

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTransportFlagsReachTheirViperKeys proves each NTCP2 transport flag is bound
// to the exact viper key lib/config's buildTransportConfig reads. Flag names use
// hyphens and viper keys use underscores, which is where a mismatch comes from.
func TestTransportFlagsReachTheirViperKeys(t *testing.T) {
	tests := []struct {
		flag     string // flag name, without the leading dashes
		viperKey string // key buildTransportConfig reads
		value    string
		want     int
	}{
		{
			flag:     "transport.ntcp2-max-connections",
			viperKey: "transport.ntcp2_max_connections",
			value:    "77",
			want:     77,
		},
		{
			flag:     "transport.ntcp2-max-inflight-handshakes",
			viperKey: "transport.ntcp2_max_inflight_handshakes",
			value:    "32",
			want:     32,
		},
		{
			flag:     "transport.ntcp2-max-handshakes-per-source",
			viperKey: "transport.ntcp2_max_handshakes_per_source",
			value:    "4",
			want:     4,
		},
		{
			flag:     "transport.ssu2-max-connections",
			viperKey: "transport.ssu2_max_connections",
			value:    "77",
			want:     77,
		},
		{
			flag:     "transport.ssu2-max-inflight-handshakes",
			viperKey: "transport.ssu2_max_inflight_handshakes",
			value:    "32",
			want:     32,
		},
		{
			flag:     "transport.ssu2-max-handshakes-per-source",
			viperKey: "transport.ssu2_max_handshakes_per_source",
			value:    "4",
			want:     4,
		},
	}

	for _, tc := range tests {
		t.Run(tc.flag, func(t *testing.T) {
			cmd := &cobra.Command{Use: "go-i2p-test"}
			v := viper.New()

			RegisterAll(cmd)
			require.NoError(t, BindAll(cmd, v), "every registered flag must bind to its viper key")

			require.NoErrorf(t, cmd.PersistentFlags().Set(tc.flag, tc.value),
				"flag %s must be registered before it can be set", tc.flag)

			assert.Equalf(t, tc.want, v.GetInt(tc.viperKey),
				"--%s=%s must resolve to viper key %q; a mismatch means the setting is silently ignored",
				tc.flag, tc.value, tc.viperKey)
		})
	}
}

// TestTransportHandshakeBoundFlagsDefaultToZero verifies the two handshake flags
// default to 0 rather than a number, so an operator who sets nothing leaves the
// transport to resolve its own documented default instead of this package's copy
// of it.
func TestTransportHandshakeBoundFlagsDefaultToZero(t *testing.T) {
	cmd := &cobra.Command{Use: "go-i2p-test"}
	v := viper.New()

	RegisterAll(cmd)
	require.NoError(t, BindAll(cmd, v))

	for _, key := range []string{
		"transport.ntcp2_max_inflight_handshakes",
		"transport.ntcp2_max_handshakes_per_source",
		"transport.ssu2_max_connections",
		"transport.ssu2_max_inflight_handshakes",
		"transport.ssu2_max_handshakes_per_source",
	} {
		assert.Zerof(t, v.GetInt(key),
			"an unset %s must stay 0 so the transport resolves its own default", key)
	}

	// RequireRetry must default off via the flag too: enabling it makes the pinned
	// go-noise reject every inbound SessionRequest.
	assert.False(t, v.GetBool("transport.ssu2_require_retry"),
		"an unset transport.ssu2_require_retry must stay false; enabling it breaks all inbound SSU2")
}

// TestBindAllRejectsUnregisteredFlag pins the one failure mode bind() does catch,
// so a future flag rename in one of the two lists is not mistaken for the silent
// mismatch the tests above guard against.
func TestBindAllRejectsUnregisteredFlag(t *testing.T) {
	cmd := &cobra.Command{Use: "go-i2p-test"}
	registerTransportFlags(cmd)
	require.NoError(t, bindTransportFlags(cmd, viper.New()), "binding registered flags must succeed")

	unregistered := &cobra.Command{Use: "go-i2p-test-unregistered"}
	err := bindPairs(unregistered, viper.New(), [][2]string{{"transport.nope", "transport.nope"}})
	require.Error(t, err, "binding a nonexistent flag must error")
	assert.Contains(t, err.Error(), "not registered")
}
