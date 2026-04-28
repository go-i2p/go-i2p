package i2np

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-i2p/go-i2p/lib/tunnel"
)

// TestBuildTunnelFromRequest_ZeroHopInbound exercises the short-circuit path
// for a zero-hop inbound build: no peer is selected, no message is sent,
// and the tunnel is registered as Active in the inbound pool immediately.
func TestBuildTunnelFromRequest_ZeroHopInbound(t *testing.T) {
	tm := NewTunnelManager(&MockTestPeerSelector{})
	defer tm.Stop()

	req := tunnel.BuildTunnelRequest{
		IsInbound: true,
		HopCount:  0,
	}
	tunnelID, peerHashes, err := tm.BuildTunnelFromRequest(req)
	require.NoError(t, err, "0-hop inbound build must not fail even with zero peers available")
	assert.NotZero(t, tunnelID)
	assert.Empty(t, peerHashes)

	pool := tm.GetInboundPool()
	require.NotNil(t, pool)
	stats := pool.GetPoolStats()
	assert.Equal(t, 1, stats.Active, "0-hop inbound tunnel must be registered as Active")
	assert.Equal(t, 0, stats.Building)

	state, ok := pool.GetTunnel(tunnelID)
	require.True(t, ok, "tunnel must be present in inbound pool")
	assert.Equal(t, tunnel.TunnelReady, state.State)
	assert.True(t, state.IsInbound)
	assert.Empty(t, state.Hops, "0-hop tunnel has no remote hops")
}
