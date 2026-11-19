// Regression test for Issue 4: a tunnel go-i2p builds as its own gateway/creator
// must retain the per-hop layer keys so the creator-side gateway can encapsulate
// traffic. The runtime symptom was "tunnel has no retained layer keys"
// (ErrNoLayerKeys) on every TunnelGateway (type 19) message that needed to be
// injected into one of our own built tunnels.
//
// The retention itself lives in lib/i2np.TunnelManager.retainLayerKeys, which
// copies each build record's derived layer/IV keys and routing IDs onto the
// pool's TunnelState.Layers. lib/tunnel cannot import lib/i2np (that would be a
// cycle), so this test drives the real lib/tunnel build producer
// (TunnelBuilder.CreateBuildRequest) and applies the exact record -> layer
// mapping retainLayerKeys performs, then feeds the result to the real consumer
// (CreatorGateway / NewGatewayFromState). It pins two things:
//
//   1. A successful build yields one record per hop, each carrying a non-zero
//      layer key, IV key and receive/next tunnel IDs — i.e. there is real data
//      to retain. A build that produced empty records would reproduce the bug.
//   2. Mapping those records onto TunnelState.Layers in path order makes
//      NewGatewayFromState succeed and produce a gateway that encapsulates with
//      every hop's layer, addressed to hop 0's receive ID.
//
// Together with lib/i2np/tunnel_manager_retain_keys_test.go (which proves the
// i2np-side producer calls SetLayers), this closes the loop from build to send.

package tunnel

import (
	"testing"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// retainLayersFromBuildResult mirrors lib/i2np.retainLayerKeys: it maps each
// path-ordered build record onto a TunnelLayer carrying that hop's layer/IV keys
// and receive/next tunnel IDs. It is the lib/tunnel-local mirror of
// lib/i2np.TunnelManager.retainLayerKeys, kept here because lib/tunnel cannot
// import lib/i2np without an import cycle.
func retainLayersFromBuildResult(result *TunnelBuildResult) []TunnelLayer {
	layers := make([]TunnelLayer, len(result.Records))
	for i := range result.Records {
		rec := &result.Records[i]
		var lk, ivk [32]byte
		copy(lk[:], rec.LayerKey[:])
		copy(ivk[:], rec.IVKey[:])
		layers[i] = TunnelLayer{
			LayerKey:      lk,
			IVKey:         ivk,
			ReceiveTunnel: rec.ReceiveTunnel,
			NextTunnel:    rec.NextTunnel,
		}
	}
	return layers
}

// buildStateFromResult mirrors lib/i2np.createTunnelStateFromResult plus
// retainLayerKeys: it turns a finished lib/tunnel build result into a ready
// TunnelState whose Layers were populated from the build records.
func buildStateFromResult(t *testing.T, result *TunnelBuildResult) *TunnelState {
	t.Helper()

	hops := make([]common.Hash, len(result.Hops))
	for i, peer := range result.Hops {
		hash, err := peer.IdentHash()
		require.NoError(t, err, "hop %d identity hash", i)
		hops[i] = hash
	}

	state := &TunnelState{
		ID:              result.TunnelID,
		GatewayTunnelID: result.GatewayTunnelID,
		Hops:            hops,
		State:           TunnelReady,
		IsInbound:       result.IsInbound,
	}
	if len(hops) > 0 {
		state.GatewayHash = hops[0]
	}
	state.SetLayers(retainLayersFromBuildResult(result))
	return state
}

// TestBuildPath_PopulatesLayersAndYieldsGateway is the lib/tunnel-side
// regression for Issue 4. It drives the real builder, retains the per-hop layer
// keys the way the runtime does, and asserts the creator-side gateway can then
// be built and encapsulate traffic. Before the fix, a built tunnel reached
// TunnelReady with an empty Layers slice, so CreatorGateway returned
// ErrNoLayerKeys and every TunnelGateway injection failed.
func TestBuildPath_PopulatesLayersAndYieldsGateway(t *testing.T) {
	const hopCount = 3

	peers := make([]router_info.RouterInfo, hopCount)
	for i := range peers {
		peers[i] = specMakeRouterInfo(byte(i + 10))
	}
	selector := &mockBuilderPeerSelector{peers: peers}
	builder, err := NewTunnelBuilder(selector)
	require.NoError(t, err)

	result, err := builder.CreateBuildRequest(BuildTunnelRequest{
		HopCount:  hopCount,
		IsInbound: false,
	})
	require.NoError(t, err)
	require.NotNil(t, result)

	// The build must produce exactly one record per hop, each with real (non-zero)
	// layer/IV keys and a non-zero receive ID. An empty or zero-key record set is
	// precisely the condition that left built tunnels unable to encapsulate.
	require.Len(t, result.Records, hopCount, "one build record per hop")
	require.Len(t, result.Hops, hopCount)
	for i := range result.Records {
		assert.NotEqual(t, [32]byte{}, result.Records[i].LayerKey,
			"hop %d build record must carry a layer key to retain", i)
		assert.NotEqual(t, [32]byte{}, result.Records[i].IVKey,
			"hop %d build record must carry an IV key to retain", i)
		assert.NotEqual(t, TunnelID(0), result.Records[i].ReceiveTunnel,
			"hop %d must have registered a non-zero receive tunnel ID", i)
	}

	// A state built from this result, with layers retained, must yield a working
	// creator gateway — the exact call the TunnelGateway dispatcher makes.
	state := buildStateFromResult(t, result)
	require.Equal(t, hopCount, state.LayerCount(),
		"retention must populate one layer per hop")

	gw, err := state.CreatorGateway()
	require.NoError(t, err, "a built tunnel with retained layers must not return ErrNoLayerKeys")
	require.NotNil(t, gw)
	assert.Equal(t, hopCount, gw.HopCount(), "gateway must apply every hop's layer")

	// The gateway addresses records at hop 0's own receive ID, which is the ID
	// hop 0 registered when it accepted our build.
	assert.Equal(t, result.Records[0].ReceiveTunnel, gw.HopReceiveTunnelID(),
		"gateway must address records at hop 0's receive ID")

	// Encapsulation must actually produce a full-size layered record.
	records, err := gw.SendWithDelivery([]byte("payload into our own built tunnel"), LocalDelivery())
	require.NoError(t, err)
	require.NotEmpty(t, records)
	for _, r := range records {
		assert.Len(t, r, TunnelMessageSize)
	}
}

// TestBuildPath_RetainedLayersMatchBuildRecords pins the record -> layer mapping
// so a regression that drops or reorders a field is caught: each retained layer
// must carry the matching record's layer key, IV key and routing IDs verbatim,
// in path order.
func TestBuildPath_RetainedLayersMatchBuildRecords(t *testing.T) {
	const hopCount = 4

	peers := make([]router_info.RouterInfo, hopCount)
	for i := range peers {
		peers[i] = specMakeRouterInfo(byte(i + 50))
	}
	selector := &mockBuilderPeerSelector{peers: peers}
	builder, err := NewTunnelBuilder(selector)
	require.NoError(t, err)

	result, err := builder.CreateBuildRequest(BuildTunnelRequest{
		HopCount:  hopCount,
		IsInbound: true,
	})
	require.NoError(t, err)

	state := buildStateFromResult(t, result)
	layers := state.GetLayers()
	require.Len(t, layers, hopCount, "one layer per hop, in path order")

	for i := range layers {
		rec := &result.Records[i]
		assert.Equal(t, rec.LayerKey[:], layers[i].LayerKey[:],
			"hop %d retained layer key must match the build record", i)
		assert.Equal(t, rec.IVKey[:], layers[i].IVKey[:],
			"hop %d retained IV key must match the build record", i)
		assert.Equal(t, rec.ReceiveTunnel, layers[i].ReceiveTunnel,
			"hop %d retained receive ID must match the build record", i)
		assert.Equal(t, rec.NextTunnel, layers[i].NextTunnel,
			"hop %d retained next ID must match the build record", i)
	}
}

// TestBuildPath_NoRetentionFailsClosed documents the pre-fix failure mode: a
// built tunnel whose layers were never retained must fail closed with
// ErrNoLayerKeys rather than silently send single-layer (undecryptable) traffic.
func TestBuildPath_NoRetentionFailsClosed(t *testing.T) {
	const hopCount = 3

	peers := make([]router_info.RouterInfo, hopCount)
	for i := range peers {
		peers[i] = specMakeRouterInfo(byte(i + 90))
	}
	selector := &mockBuilderPeerSelector{peers: peers}
	builder, err := NewTunnelBuilder(selector)
	require.NoError(t, err)

	result, err := builder.CreateBuildRequest(BuildTunnelRequest{
		HopCount:  hopCount,
		IsInbound: false,
	})
	require.NoError(t, err)

	// Same state, but WITHOUT SetLayers — this is the buggy runtime condition.
	hops := make([]common.Hash, len(result.Hops))
	for i, peer := range result.Hops {
		hops[i], err = peer.IdentHash()
		require.NoError(t, err)
	}
	state := &TunnelState{
		ID:              result.TunnelID,
		GatewayTunnelID: result.GatewayTunnelID,
		Hops:            hops,
		State:           TunnelReady,
	}
	if len(hops) > 0 {
		state.GatewayHash = hops[0]
	}

	_, err = state.CreatorGateway()
	require.ErrorIs(t, err, ErrNoLayerKeys,
		"a built tunnel that did not retain layers must fail closed")
}
