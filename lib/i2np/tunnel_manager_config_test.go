package i2np

import (
	"testing"
	"time"

	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewTunnelManagerWithConfig_PoolsHonorOperatorConfig is the C1 wiring guard
// at the manager level: NewTunnelManagerWithConfig must build its inbound and
// outbound pools from the operator's tunnel config, not DefaultPoolConfig().
// Before this fix the manager always used DefaultPoolConfig(), so tunnel.length
// (and every other pool knob) was a dead setting.
//
// HopCount is the one PoolConfig field with a public accessor, so it stands in
// for the whole mapping: a non-default tunnel.length must surface on both pools.
func TestNewTunnelManagerWithConfig_PoolsHonorOperatorConfig(t *testing.T) {
	cfg := config.Defaults().Tunnel
	cfg.TunnelLength = 4 // distinct from the default 3
	cfg.MaintenanceInterval = 45 * time.Second

	tm := NewTunnelManagerWithConfig(nil, cfg)
	require.NotNil(t, tm)
	t.Cleanup(tm.Stop)

	inbound := tm.GetInboundPool()
	outbound := tm.GetOutboundPool()
	require.NotNil(t, inbound)
	require.NotNil(t, outbound)

	assert.Equal(t, 4, inbound.HopCount(),
		"inbound pool must use the operator's tunnel.length, not the default 3")
	assert.Equal(t, 4, outbound.HopCount(),
		"outbound pool must use the operator's tunnel.length, not the default 3")
}

// TestSetPeerSelector_PreservesOperatorConfig pins that rebuilding the pools on
// SetPeerSelector (which the router calls during wiring) keeps the operator's
// config rather than reverting to DefaultPoolConfig().
func TestSetPeerSelector_PreservesOperatorConfig(t *testing.T) {
	cfg := config.Defaults().Tunnel
	cfg.TunnelLength = 5

	tm := NewTunnelManagerWithConfig(nil, cfg)
	require.NotNil(t, tm)
	t.Cleanup(tm.Stop)

	// Replacing the (nil) peer selector rebuilds both pools.
	tm.SetPeerSelector(nil)

	require.NotNil(t, tm.GetInboundPool())
	require.NotNil(t, tm.GetOutboundPool())
	assert.Equal(t, 5, tm.GetInboundPool().HopCount(),
		"rebuilt inbound pool must keep the operator's tunnel.length")
	assert.Equal(t, 5, tm.GetOutboundPool().HopCount(),
		"rebuilt outbound pool must keep the operator's tunnel.length")
}
