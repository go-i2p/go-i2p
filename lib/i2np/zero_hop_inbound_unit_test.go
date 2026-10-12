// Tests for zero-hop inbound tunnel build validation.
// A zero-hop tunnel has no intermediate hops, so the reply path must be
// established before the outbound tunnel can be built.
package i2np

import (
	"testing"

	common "github.com/go-i2p/common/data"
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

	var ourHash common.Hash
	ourHash[0] = 0x01

	req := tunnel.BuildTunnelRequest{
		IsInbound:    true,
		HopCount:     0,
		OurIdentity:  ourHash,
		ReplyGateway: ourHash,
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

// Validates that a zero-hop build request is rejected when the router identity is unset.
func TestBuildTunnelFromRequest_RejectsZeroRouterIdentity(t *testing.T) {
	tm := NewTunnelManager(&MockTestPeerSelector{})
	defer tm.Stop()

	_, _, err := tm.BuildTunnelFromRequest(tunnel.BuildTunnelRequest{IsInbound: true, HopCount: 0})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "identity is unset")
}

// Validates that an outbound build request is rejected when no inbound reply
// tunnel is available to carry the TunnelBuildReply back.
func TestBuildTunnelFromRequest_RejectsOutboundWithoutInboundReplyPath(t *testing.T) {
	tm := NewTunnelManager(&MockTestPeerSelector{})
	defer tm.Stop()

	var ourHash common.Hash
	ourHash[0] = 0x02

	_, _, err := tm.BuildTunnelFromRequest(tunnel.BuildTunnelRequest{
		IsInbound:     false,
		HopCount:      1,
		OurIdentity:   ourHash,
		ReplyGateway:  ourHash,
		ReplyTunnelID: 0,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires active inbound tunnel")
}
