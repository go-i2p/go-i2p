// Wiring guards for operator-configurable knobs that were previously dead.
//
// startCongestionMonitor used to read config.Defaults().Congestion (the
// hardcoded defaults), so every congestion.* threshold was validated in
// lib/config but never reached the monitor that uses it. wireParticipantManager
// used to call tunnel.NewManager(), which likewise used hardcoded defaults, so
// every tunnel.* participation limit was validated but never reached the
// manager that enforces it. Both now read r.cfg. These tests pin that the
// operator's values actually arrive.

package router

import (
	"testing"

	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestStartCongestionMonitor_UsesOperatorConfig verifies the monitor is built
// from r.cfg.Congestion, not config.Defaults().Congestion. A bare Router with a
// custom threshold must produce a monitor carrying that threshold.
func TestStartCongestionMonitor_UsesOperatorConfig(t *testing.T) {
	// Pick a value distinct from DefaultDFlagThreshold (0.70) so a regression
	// to the hardcoded default is detectable.
	r := &Router{
		cfg: &config.RouterConfig{
			Congestion: &config.CongestionDefaults{
				DFlagThreshold: 0.42,
			},
		},
	}

	r.startCongestionMonitor()
	require.NotNil(t, r.congestionMonitor, "startCongestionMonitor must create the monitor")
	t.Cleanup(r.congestionMonitor.Stop)

	assert.InDelta(t, 0.42, r.congestionMonitor.cfg.DFlagThreshold, 1e-9,
		"congestion monitor must use the operator's DFlagThreshold, not the default 0.70")
}

// TestStartCongestionMonitor_NilConfigFallsBackToDefaults pins the nil-safe
// fallback: with no congestion config the monitor uses config.Defaults().
func TestStartCongestionMonitor_NilConfigFallsBackToDefaults(t *testing.T) {
	r := &Router{cfg: &config.RouterConfig{}}

	r.startCongestionMonitor()
	require.NotNil(t, r.congestionMonitor)
	t.Cleanup(r.congestionMonitor.Stop)

	assert.InDelta(t, config.Defaults().Congestion.DFlagThreshold,
		r.congestionMonitor.cfg.DFlagThreshold, 1e-9,
		"a nil congestion config must fall back to the documented default")
}

// TestWireParticipantManager_UsesOperatorConfig verifies the participant manager
// is built from r.cfg.Tunnel, so tunnel.max_participating_tunnels reaches the
// manager that enforces it. A bare Router with a custom limit must produce a
// manager carrying that limit rather than the default 15000.
func TestWireParticipantManager_UsesOperatorConfig(t *testing.T) {
	r := &Router{
		cfg: &config.RouterConfig{
			Tunnel: &config.TunnelDefaults{
				MaxParticipatingTunnels: 777,
			},
		},
		messageRouter: i2np.NewI2NPMessageDispatcher(i2np.I2NPMessageDispatcherConfig{
			MaxRetries:     3,
			DefaultTimeout: 30,
			EnableLogging:  false,
		}),
	}

	r.wireParticipantManager()
	require.NotNil(t, r.participantManager, "wireParticipantManager must create the manager")
	t.Cleanup(func() { r.participantManager.Stop() })

	assert.Equal(t, 777, r.participantManager.MaxParticipants(),
		"participant manager must use the operator's max_participating_tunnels, not the default 15000")
}
