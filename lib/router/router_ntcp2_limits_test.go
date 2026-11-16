// Tests for plumbing the operator's NTCP2 limits from lib/config into the
// transport config.
//
// transport.ntcp2-max-connections used to be read into RouterConfig and then
// dropped on the floor: the transport always ran with its own DefaultMaxSessions,
// so setting 50 in config.yaml still allowed 512 sessions. These tests pin that
// the value reaches the transport, including for the two handshake bounds added
// for the finding 004 pre-authentication follow-up.

package router

import (
	"testing"
	"time"

	"github.com/go-i2p/go-i2p/lib/config"
	ntcp "github.com/go-i2p/go-i2p/lib/transport/ntcp2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestApplyNTCP2SessionLimits_PropagatesOperatorValues(t *testing.T) {
	dst := &ntcp.Config{}
	applyNTCP2SessionLimits(dst, &config.TransportDefaults{
		NTCP2MaxConnections:         50,
		NTCP2MaxInflightHandshakes:  12,
		NTCP2MaxHandshakesPerSource: 3,
		ConnectionTimeout:           5 * time.Second,
		IdleTimeout:                 3 * time.Minute,
	})

	assert.Equal(t, 50, dst.GetMaxSessions(),
		"transport.ntcp2-max-connections must reach the transport, not be overridden by its default")
	assert.Equal(t, 12, dst.GetMaxInflightHandshakes(), "handshake global cap must reach the transport")
	assert.Equal(t, 3, dst.GetMaxHandshakesPerSource(), "handshake per-source cap must reach the transport")
	assert.Equal(t, 5*time.Second, dst.GetConnectionTimeout(),
		"transport.connection_timeout must reach the transport's dial deadline (I2P C1)")
	assert.Equal(t, 3*time.Minute, dst.GetIdleTimeout(),
		"transport.idle_timeout must seed the idle-expire window (I2P C1)")
}

// TestApplyNTCP2SessionLimits_IdleTimeoutClampedToProtocolBounds pins that an
// operator idle_timeout outside the protocol's [min,max] window is clamped by the
// transport rather than accepted verbatim.
func TestApplyNTCP2SessionLimits_IdleTimeoutClampedToProtocolBounds(t *testing.T) {
	dst := &ntcp.Config{}
	applyNTCP2SessionLimits(dst, &config.TransportDefaults{IdleTimeout: 1 * time.Second})
	assert.GreaterOrEqual(t, dst.GetIdleTimeout(), 2*time.Minute,
		"a too-small idle_timeout must clamp up to the protocol minimum")

	dst2 := &ntcp.Config{}
	applyNTCP2SessionLimits(dst2, &config.TransportDefaults{IdleTimeout: 100 * time.Hour})
	assert.LessOrEqual(t, dst2.GetIdleTimeout(), 11*time.Minute,
		"a too-large idle_timeout must clamp down to the protocol maximum")
}

// TestApplyNTCP2SessionLimits_ConnectionTimeoutUnsetDefersToDefault pins that an
// unset connection_timeout stays zero so the transport resolves its own default
// dial deadline rather than lib/config restating the number.
func TestApplyNTCP2SessionLimits_ConnectionTimeoutUnsetDefersToDefault(t *testing.T) {
	dst := &ntcp.Config{}
	applyNTCP2SessionLimits(dst, &config.TransportDefaults{})

	assert.Equal(t, 0*time.Second, dst.ConnectionTimeout, "unset must stay unset")
	assert.NotZero(t, dst.GetConnectionTimeout(), "the transport must resolve unset to a non-zero default")
}

// TestApplyNTCP2SessionLimits_UnsetDefersToTransport pins that a zero config
// value is passed through as zero rather than replaced here, so the transport's
// documented defaults are the single source of truth for the numbers. lib/config
// cannot import the transport package (cycle), so restating them here is exactly
// what would let the two drift.
func TestApplyNTCP2SessionLimits_UnsetDefersToTransport(t *testing.T) {
	dst := &ntcp.Config{MaxSessions: ntcp.DefaultMaxSessions}
	applyNTCP2SessionLimits(dst, &config.TransportDefaults{})

	assert.Equal(t, 0, dst.MaxSessions, "unset must stay unset so the transport resolves its own default")
	assert.Equal(t, 0, dst.MaxInflightHandshakes)
	assert.Equal(t, 0, dst.MaxHandshakesPerSource)

	// And the transport really does resolve zero to its defaults.
	assert.Equal(t, ntcp.DefaultMaxSessions, dst.GetMaxSessions())
	assert.Equal(t, ntcp.DefaultMaxInflightHandshakes, dst.GetMaxInflightHandshakes())
	assert.Equal(t, ntcp.DefaultMaxHandshakesPerSource, dst.GetMaxHandshakesPerSource())
}

// TestApplyNTCP2SessionLimits_NegativeDisablesBound mirrors the transport's rule
// that a negative limit means the bound is off, rather than "no connections
// allowed" — the difference matters, because GetMax* returns the value verbatim
// for anything non-zero and admission treats non-positive as unlimited.
func TestApplyNTCP2SessionLimits_NegativeDisablesBound(t *testing.T) {
	dst := &ntcp.Config{}
	applyNTCP2SessionLimits(dst, &config.TransportDefaults{
		NTCP2MaxConnections:         200,
		NTCP2MaxInflightHandshakes:  -1,
		NTCP2MaxHandshakesPerSource: -1,
	})

	assert.Equal(t, -1, dst.GetMaxInflightHandshakes(), "negative must pass through as disabled")
	assert.Equal(t, -1, dst.GetMaxHandshakesPerSource(), "negative must pass through as disabled")
	assert.Equal(t, 200, dst.GetMaxSessions())
}

// TestApplyNTCP2SessionLimits_NilInputsAreSafe covers a RouterConfig built
// without a Transport section, which leaves the pointer nil.
func TestApplyNTCP2SessionLimits_NilInputsAreSafe(t *testing.T) {
	dst := &ntcp.Config{MaxSessions: 7}
	assert.NotPanics(t, func() { applyNTCP2SessionLimits(dst, nil) })
	assert.Equal(t, 7, dst.MaxSessions, "a nil transport config must leave the config untouched")

	assert.NotPanics(t, func() { applyNTCP2SessionLimits(nil, &config.TransportDefaults{}) })
}

// TestApplyNTCP2SessionLimits_LiveTransportHonoursLimits proves the values are
// not just copied into a struct that is then thrown away: a transport built with
// the limits set enforces them. This is the end of the plumbing path the config
// keys exist for.
func TestApplyNTCP2SessionLimits_LiveTransportHonoursLimits(t *testing.T) {
	cfg := &ntcp.Config{ListenerAddress: "127.0.0.1:0"}
	applyNTCP2SessionLimits(cfg, &config.TransportDefaults{
		NTCP2MaxConnections:         9,
		NTCP2MaxInflightHandshakes:  4,
		NTCP2MaxHandshakesPerSource: 2,
	})
	require.Equal(t, 9, cfg.GetMaxSessions())
	require.Equal(t, 4, cfg.GetMaxInflightHandshakes())
	require.Equal(t, 2, cfg.GetMaxHandshakesPerSource())
}
