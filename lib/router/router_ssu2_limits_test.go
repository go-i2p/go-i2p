// Tests for plumbing the operator's SSU2 limits from lib/config into the SSU2
// transport config — the SSU2 counterpart of router_ntcp2_limits_test.go, added
// for the finding 005 pre-authentication follow-up.
//
// transport.ssu2_max_connections used to be dropped on the floor: the transport
// always ran with its own DefaultMaxSessions, and the go-noise listener ran with
// its built-in 65536 cap, so a router's session limit was never enforced. These
// tests pin that the value reaches the transport (which then publishes it onto the
// listener), plus the two handshake bounds and the RequireRetry opt-in.

package router

import (
	"testing"

	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/go-i2p/go-i2p/lib/transport/ssu2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestApplySSU2SessionLimits_PropagatesOperatorValues(t *testing.T) {
	dst, err := ssu2.NewConfig("127.0.0.1:0")
	require.NoError(t, err)

	applySSU2SessionLimits(dst, &config.TransportDefaults{
		SSU2MaxConnections:         50,
		SSU2MaxInflightHandshakes:  12,
		SSU2MaxHandshakesPerSource: 3,
		SSU2RequireRetry:           true,
	})

	assert.Equal(t, 50, dst.GetMaxSessions(),
		"transport.ssu2_max_connections must reach the transport, not be overridden by its default")
	assert.Equal(t, 12, dst.GetMaxInflightHandshakes(), "handshake global cap must reach the transport")
	assert.Equal(t, 3, dst.GetMaxHandshakesPerSource(), "handshake per-source cap must reach the transport")
	assert.True(t, dst.RequireRetry, "an explicit RequireRetry opt-in must be copied through")
}

// TestApplySSU2SessionLimits_UnsetDefersToTransport pins that a zero config value
// is passed through as zero rather than replaced here, so the transport's
// documented defaults are the single source of truth for the numbers. lib/config
// cannot import the transport package (cycle), so restating them would let the two
// drift.
func TestApplySSU2SessionLimits_UnsetDefersToTransport(t *testing.T) {
	dst := &ssu2.Config{MaxSessions: ssu2.DefaultMaxSessions}
	applySSU2SessionLimits(dst, &config.TransportDefaults{})

	assert.Equal(t, 0, dst.MaxSessions, "unset must stay unset so the transport resolves its own default")
	assert.Equal(t, 0, dst.MaxInflightHandshakes)
	assert.Equal(t, 0, dst.MaxHandshakesPerSource)

	// And the transport really does resolve zero to its documented defaults.
	assert.Equal(t, ssu2.DefaultMaxSessions, dst.GetMaxSessions())
	assert.Equal(t, ssu2.DefaultMaxInflightHandshakes, dst.GetMaxInflightHandshakes())
	assert.Equal(t, ssu2.DefaultMaxHandshakesPerSource, dst.GetMaxHandshakesPerSource())
}

// TestApplySSU2SessionLimits_NegativeDisablesBound mirrors the transport's rule
// that a negative limit means the bound is off, rather than "no connections
// allowed".
func TestApplySSU2SessionLimits_NegativeDisablesBound(t *testing.T) {
	dst := &ssu2.Config{}
	applySSU2SessionLimits(dst, &config.TransportDefaults{
		SSU2MaxConnections:         200,
		SSU2MaxInflightHandshakes:  -1,
		SSU2MaxHandshakesPerSource: -1,
	})

	assert.Equal(t, -1, dst.GetMaxInflightHandshakes(), "negative must pass through as disabled")
	assert.Equal(t, -1, dst.GetMaxHandshakesPerSource(), "negative must pass through as disabled")
	assert.Equal(t, 200, dst.GetMaxSessions())
}

// TestApplySSU2SessionLimits_NilInputsAreSafe covers a RouterConfig built without
// a Transport section, which leaves the pointer nil.
func TestApplySSU2SessionLimits_NilInputsAreSafe(t *testing.T) {
	dst := &ssu2.Config{MaxSessions: 7}
	assert.NotPanics(t, func() { applySSU2SessionLimits(dst, nil) })
	assert.Equal(t, 7, dst.MaxSessions, "a nil transport config must leave the config untouched")

	assert.NotPanics(t, func() { applySSU2SessionLimits(nil, &config.TransportDefaults{}) })
}

// TestApplySSU2SessionLimits_DefaultTransportKeepsRequireRetryOff is the safety
// property that matters: the shipped default must NOT enable RequireRetry, because
// the pinned go-noise rejects every inbound SessionRequest when it is on. A
// zero-valued TransportDefaults (struct literal, or a config with no transport
// section) must therefore leave it off.
func TestApplySSU2SessionLimits_DefaultTransportKeepsRequireRetryOff(t *testing.T) {
	// The zero value of the operator config leaves RequireRetry off…
	dst := &ssu2.Config{}
	applySSU2SessionLimits(dst, &config.TransportDefaults{})
	assert.False(t, dst.RequireRetry,
		"a default/zero transport config must leave RequireRetry off (enabling it breaks all inbound SSU2)")

	// …and so does the fully-populated built-in default.
	assert.False(t, config.Defaults().Transport.SSU2RequireRetry,
		"the built-in transport defaults must ship RequireRetry off")

	// The transport's own NewConfig also defaults it off, independently.
	tc, err := ssu2.NewConfig("127.0.0.1:0")
	require.NoError(t, err)
	assert.False(t, tc.RequireRetry, "ssu2.NewConfig must default RequireRetry off")
}
