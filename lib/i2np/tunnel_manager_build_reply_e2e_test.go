// End-to-end proof for Issue 4 that the existing retainLayerKeys tests do not
// provide.
//
// lib/i2np/tunnel_manager_retain_keys_test.go fabricates result.Records with
// hand-set keys and then calls retainLayerKeys, so it proves the copier works
// but never proves the *producer* installs real keys. The keys the creator needs
// are not the random placeholders the builder puts in the record — for STBM the
// cleartext carries no layer/IV keys, so each hop derives them from its Noise
// chaining key, and the creator must derive the SAME values. That derivation
// happens inside createSerializedShortTunnelBuildMessage, which calls
// encryptRecordsAndDeriveKeys and then updateLayerKeys to overwrite
// result.Records[i].LayerKey/IVKey with the derived keys.
//
// This test runs that real chain (real signed RouterInfos with real X25519 keys,
// the real message factory) and asserts:
//   - the derived layer/IV keys land in result.Records and are non-zero,
//   - they REPLACE the builder's random placeholders (so updateLayerKeys ran),
//   - after retainLayerKeys the creator gateway builds and encapsulates.
//
// If a regression dropped updateLayerKeys or retained the placeholder keys, the
// hops would reject our traffic and this test would fail — which is exactly the
// "tunnel has no retained layer keys" / undecryptable-traffic class of bug.

package i2np

import (
	"testing"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/testutil"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// realPeerSelector hands out real signed RouterInfos (each with a valid X25519
// encryption key), which the STBM serializer needs to encrypt each hop's record.
// The shared mockPeerSelector returns empty RouterInfos, which fail key
// extraction, so it cannot drive the real serialization path.
type realPeerSelector struct {
	peers []router_info.RouterInfo
}

func (m *realPeerSelector) SelectPeers(count int, exclude []common.Hash) ([]router_info.RouterInfo, error) {
	if len(m.peers) < count {
		return m.peers, nil
	}
	return m.peers[:count], nil
}

// TestBuildReplyPath_RetainsDerivedLayerKeys drives the genuine creator-side
// build: real build records, real STBM serialization (which derives and installs
// the per-hop layer/IV keys), then retention onto the pool state, then a working
// creator gateway.
func TestBuildReplyPath_RetainsDerivedLayerKeys(t *testing.T) {
	const hopCount = 3

	peers := make([]router_info.RouterInfo, hopCount)
	for i := range peers {
		ri := testutil.CreateSignedTestRouterInfo(t, nil, nil)
		require.NotNil(t, ri)
		peers[i] = *ri
	}

	tm := NewTunnelManager(&realPeerSelector{peers: peers})
	require.NotNil(t, tm)
	t.Cleanup(tm.Stop)

	result, messageID, err := tm.createBuildRequestAndID(tunnel.BuildTunnelRequest{
		HopCount:  hopCount,
		IsInbound: false,
	})
	require.NoError(t, err)
	require.Len(t, result.Records, hopCount)
	require.Len(t, result.Hops, hopCount)

	// Snapshot the builder's random placeholder keys. updateLayerKeys must replace
	// these with the Noise-derived keys the hops will actually install.
	placeholder := make([][32]byte, hopCount)
	for i := range result.Records {
		copy(placeholder[i][:], result.Records[i].LayerKey[:])
	}

	// The real serializer: encryptRecordsAndDeriveKeys + updateLayerKeys. This is
	// the step every other test skips by fabricating result.Records.
	serialized, err := tm.createSerializedShortTunnelBuildMessage(result, messageID)
	require.NoError(t, err)
	require.NotEmpty(t, serialized, "real STBM serialization must produce a wire message")

	for i := range result.Records {
		var zero [32]byte
		assert.NotEqual(t, zero, result.Records[i].LayerKey,
			"hop %d derived layer key must be non-zero after serialization", i)
		assert.NotEqual(t, zero, result.Records[i].IVKey,
			"hop %d derived IV key must be non-zero after serialization", i)
		assert.NotEqual(t, placeholder[i], result.Records[i].LayerKey,
			"hop %d layer key must be the derived key, not the builder placeholder", i)
	}

	// Retain the derived keys onto the pool state, exactly as prepareAndSendBuild
	// does after sendBuildMessage.
	state := tm.createTunnelStateFromResult(result)
	require.NotNil(t, state)
	tm.retainLayerKeys(state, result)

	require.Equal(t, hopCount, state.LayerCount(),
		"retention must populate one layer per hop from the real build")

	gw, err := state.CreatorGateway()
	require.NoError(t, err, "a real built tunnel must yield a creator gateway, not ErrNoLayerKeys")
	require.Equal(t, hopCount, gw.HopCount())

	// The retained layer keys must be the derived ones, byte for byte.
	layers := state.GetLayers()
	for i := range layers {
		assert.Equal(t, result.Records[i].LayerKey[:], layers[i].LayerKey[:],
			"hop %d retained layer key must match the derived key", i)
		assert.Equal(t, result.Records[i].IVKey[:], layers[i].IVKey[:],
			"hop %d retained IV key must match the derived key", i)
	}

	records, err := gw.SendWithDelivery([]byte("real built tunnel payload"),
		tunnel.TunnelDelivery(0x11223344, [32]byte{}))
	require.NoError(t, err)
	require.NotEmpty(t, records)
	for _, r := range records {
		assert.Len(t, r, tunnel.TunnelMessageSize)
	}
}
