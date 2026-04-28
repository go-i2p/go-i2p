package tunnel

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
)

// emptyPeerSelector returns no peers and no error. It exists to verify that
// zero-hop inbound builds never invoke peer selection.
type emptyPeerSelector struct {
	called bool
}

func (s *emptyPeerSelector) SelectPeers(count int, exclude []common.Hash) ([]router_info.RouterInfo, error) {
	s.called = true
	return nil, nil
}

// TestCreateBuildRequest_ZeroHopInbound verifies a 0-hop inbound build
// returns a usable TunnelID without selecting peers or emitting records.
func TestCreateBuildRequest_ZeroHopInbound(t *testing.T) {
	sel := &emptyPeerSelector{}
	tb, err := NewTunnelBuilder(sel)
	require.NoError(t, err)

	result, err := tb.CreateBuildRequest(BuildTunnelRequest{
		HopCount:  0,
		IsInbound: true,
	})
	require.NoError(t, err, "zero-hop inbound build should succeed")
	require.NotNil(t, result)
	assert.NotZero(t, result.TunnelID, "tunnel ID must be allocated")
	assert.Empty(t, result.Hops, "no peers should be selected for 0-hop")
	assert.Empty(t, result.Records, "no build records emitted for 0-hop")
	assert.Empty(t, result.ReplyKeys, "no reply keys for 0-hop")
	assert.True(t, result.IsInbound)
	assert.False(t, sel.called, "peer selector must not be invoked for 0-hop inbound")
}

// TestCreateBuildRequest_ZeroHopOutboundRejected verifies that 0-hop is
// rejected for outbound tunnels (the OBGW is us, so 0-hop outbound is
// meaningless: there is no peer to send the build to and no path to
// the network).
func TestCreateBuildRequest_ZeroHopOutboundRejected(t *testing.T) {
	sel := &emptyPeerSelector{}
	tb, err := NewTunnelBuilder(sel)
	require.NoError(t, err)

	_, err = tb.CreateBuildRequest(BuildTunnelRequest{
		HopCount:  0,
		IsInbound: false,
	})
	require.Error(t, err, "zero-hop outbound must be rejected")
	assert.Contains(t, err.Error(), "hop count")
}

// TestPool_SetHopCount_InboundAcceptsZero verifies SetHopCount(0) is
// permitted on inbound pools and rejected on outbound pools.
func TestPool_SetHopCount_InboundAcceptsZero(t *testing.T) {
	cfg := DefaultPoolConfig()
	cfg.IsInbound = true
	pool := NewTunnelPoolWithConfig(&emptyPeerSelector{}, cfg)
	defer pool.Stop()

	require.NoError(t, pool.SetHopCount(0), "0-hop allowed on inbound pool")
	assert.Equal(t, 0, pool.HopCount())

	require.NoError(t, pool.SetHopCount(3), "3-hop still valid on inbound pool")
	assert.Equal(t, 3, pool.HopCount())

	assert.Error(t, pool.SetHopCount(9), "9-hop exceeds spec maximum")
	assert.Error(t, pool.SetHopCount(-1), "negative hop count rejected")
}

// TestPool_SetHopCount_OutboundRejectsZero verifies that 0-hop is rejected
// on outbound pools.
func TestPool_SetHopCount_OutboundRejectsZero(t *testing.T) {
	cfg := DefaultPoolConfig()
	cfg.IsInbound = false
	pool := NewTunnelPoolWithConfig(&emptyPeerSelector{}, cfg)
	defer pool.Stop()

	assert.Error(t, pool.SetHopCount(0), "0-hop outbound must be rejected")
	require.NoError(t, pool.SetHopCount(2))
	assert.Equal(t, 2, pool.HopCount())
}
