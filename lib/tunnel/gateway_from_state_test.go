// Tests for building the creator-side gateway from a tunnel's retained build
// keys. This is the runtime path that makes Gateway.SendWithDelivery usable:
// the keys come from the same place the router's build tracking keeps them, not
// from a test-synthesized encryptor.

package tunnel

import (
	"crypto/rand"
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/crypto/tunnel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stateWithRetainedLayers builds a TunnelState whose retained layers mirror
// exactly what i2np.TunnelManager.retainLayerKeys writes after a build: one
// entry per hop in path order, each carrying that hop's layer/IV keys and the
// receive/next tunnel IDs from its build record.
//
// It returns the state, the per-hop keys (for peeling), and the per-hop receive
// IDs (for asserting the in-clear record address).
func stateWithRetainedLayers(t *testing.T, hopCnt int) (*TunnelState, []tunnel.TunnelKey, []tunnel.TunnelKey, []TunnelID) {
	t.Helper()
	require.Positive(t, hopCnt)

	layerKeys := make([]tunnel.TunnelKey, hopCnt)
	ivKeys := make([]tunnel.TunnelKey, hopCnt)
	layers := make([]TunnelLayer, hopCnt)
	receiveIDs := make([]TunnelID, hopCnt)

	for i := 0; i < hopCnt; i++ {
		_, err := rand.Read(layerKeys[i][:])
		require.NoError(t, err)
		_, err = rand.Read(ivKeys[i][:])
		require.NoError(t, err)

		// Each hop gets its own unique receive ID, as generateHopTunnelIDs does.
		var idBuf [4]byte
		_, err = rand.Read(idBuf[:])
		require.NoError(t, err)
		receive := TunnelID(uint32(idBuf[0])<<24 | uint32(idBuf[1])<<16 | uint32(idBuf[2])<<8 | uint32(idBuf[3]))
		require.NotEqual(t, TunnelID(0), receive)
		receiveIDs[i] = receive

		var lk, ivk [32]byte
		copy(lk[:], layerKeys[i][:])
		copy(ivk[:], ivKeys[i][:])
		layers[i] = TunnelLayer{
			LayerKey:      lk,
			IVKey:         ivk,
			ReceiveTunnel: receive,
			NextTunnel:    TunnelID(0x1000 + uint32(i)),
		}
	}

	hops := make([]common.Hash, hopCnt)
	for i := range hops {
		_, err := rand.Read(hops[i][:])
		require.NoError(t, err)
	}

	state := &TunnelState{
		ID:              layers[0].ReceiveTunnel,
		GatewayTunnelID: layers[0].ReceiveTunnel,
		Hops:            hops,
		State:           TunnelReady,
		CreatedAt:       time.Now(),
		IsInbound:       false,
		GatewayHash:     hops[0],
	}
	state.SetLayers(layers)
	return state, layerKeys, ivKeys, receiveIDs
}

// TestCreatorGateway_SendsAndPeelsWithRetainedKeys proves the retained build
// keys are sufficient to produce a record that the tunnel's own hops can peel
// in path order, and that the in-clear header is addressed to hop 0's receive ID.
func TestCreatorGateway_SendsAndPeelsWithRetainedKeys(t *testing.T) {
	const hopCnt = 3

	state, layerKeys, ivKeys, receiveIDs := stateWithRetainedLayers(t, hopCnt)

	gw, err := state.CreatorGateway()
	require.NoError(t, err)
	require.NotNil(t, gw)
	assert.Equal(t, hopCnt, gw.HopCount(), "gateway must carry one layer per hop")

	var destGateway [HashSize]byte
	_, err = rand.Read(destGateway[:])
	require.NoError(t, err)

	msg := make([]byte, 200)
	_, err = rand.Read(msg)
	require.NoError(t, err)

	records, err := gw.SendWithDelivery(msg, TunnelDelivery(0x9999, destGateway))
	require.NoError(t, err)
	require.Len(t, records, 1)

	// Both ID fields name hop 0: the in-clear ID at the front of the record and
	// the TunnelData envelope ID the caller addresses. They must agree, and
	// both must be hop 0's own receive ID from its build record — the ID hop 0
	// registered when it accepted our build, and what the receiving router
	// looks up to find the participant that owns the tunnel.
	assert.Equal(t, uint32(receiveIDs[0]), readTunnelIDFromRecord(records[0]),
		"record must carry hop 0's receive ID in the clear")
	assert.Equal(t, receiveIDs[0], gw.HopReceiveTunnelID(),
		"gateway must expose hop 0's receive ID for the TunnelData envelope")
	assert.Equal(t, gw.NextHopID(), gw.HopReceiveTunnelID(),
		"record ID and envelope ID are the same value")

	// Peel every hop's layer in path order.
	current := records[0]
	for hop := 0; hop < hopCnt; hop++ {
		enc, err := tunnel.NewAESEncryptor(layerKeys[hop], ivKeys[hop])
		require.NoError(t, err)
		current, err = enc.Decrypt(current)
		require.NoError(t, err, "hop %d must peel its layer", hop)
	}

	assertValidChecksum(t, current)
	payload, di := extractPayloadFromRecord(t, current)
	assert.Equal(t, msg, payload)
	assert.Equal(t, uint32(0x9999), di.tunnelID)
	assert.Equal(t, common.Hash(destGateway), di.hash)
}

// TestCreatorGateway_Memoized confirms the gateway is built once per key set and
// that rotating the keys drops the cache.
func TestCreatorGateway_Memoized(t *testing.T) {
	state, _, _, _ := stateWithRetainedLayers(t, 3)

	gw1, err := state.CreatorGateway()
	require.NoError(t, err)
	gw2, err := state.CreatorGateway()
	require.NoError(t, err)
	assert.Same(t, gw1, gw2, "creator gateway must be cached on the state")

	// Rotating the keys must invalidate the cache, otherwise a rebuilt tunnel
	// would keep sending with the old hops' keys.
	rotated := state.GetLayers()
	_, err = rand.Read(rotated[0].LayerKey[:])
	require.NoError(t, err)
	state.SetLayers(rotated)

	gw3, err := state.CreatorGateway()
	require.NoError(t, err)
	assert.NotSame(t, gw1, gw3, "SetLayers must drop the cached gateway")
}

// TestCreatorGateway_FailsClosedWithoutRetainedKeys pins the fail-closed
// behaviour: a tunnel that never retained its keys must not be usable as a
// send path, so callers cannot silently fall back to bare transmission.
func TestCreatorGateway_FailsClosedWithoutRetainedKeys(t *testing.T) {
	t.Run("no layers", func(t *testing.T) {
		state := &TunnelState{
			ID:   TunnelID(1),
			Hops: []common.Hash{{1}, {2}, {3}},
		}
		_, err := state.CreatorGateway()
		require.ErrorIs(t, err, ErrNoLayerKeys)

		_, err = NewGatewayFromState(state)
		require.ErrorIs(t, err, ErrNoLayerKeys)
	})

	t.Run("layers fewer than hops", func(t *testing.T) {
		state := &TunnelState{
			ID:   TunnelID(1),
			Hops: []common.Hash{{1}, {2}, {3}},
		}
		state.SetLayers([]TunnelLayer{
			{LayerKey: [32]byte{1}, IVKey: [32]byte{2}},
			{LayerKey: [32]byte{3}, IVKey: [32]byte{4}},
		})
		_, err := state.CreatorGateway()
		require.ErrorIs(t, err, ErrLayerKeyIncomplete)
	})

	t.Run("nil state", func(t *testing.T) {
		_, err := NewGatewayFromState(nil)
		require.ErrorIs(t, err, ErrNoLayerKeys)
	})
}

// TestNewGatewayFromStateUncached exercises the direct constructor, which must
// produce the same layered behaviour without touching the state cache.
func TestNewGatewayFromStateUncached(t *testing.T) {
	state, layerKeys, ivKeys, receiveIDs := stateWithRetainedLayers(t, 2)

	gw, err := NewGatewayFromState(state)
	require.NoError(t, err)
	assert.Equal(t, 2, gw.HopCount())

	msg := []byte("payload through a two-hop outbound tunnel")
	record, err := gw.Send(msg)
	require.NoError(t, err)
	require.Len(t, record, TunnelMessageSize)

	assert.Equal(t, uint32(receiveIDs[0]), readTunnelIDFromRecord(record),
		"record must carry hop 0's receive ID in the clear")
	assert.Equal(t, receiveIDs[0], gw.HopReceiveTunnelID())

	enc0, err := tunnel.NewAESEncryptor(layerKeys[0], ivKeys[0])
	require.NoError(t, err)
	after0, err := enc0.Decrypt(record)
	require.NoError(t, err)

	enc1, err := tunnel.NewAESEncryptor(layerKeys[1], ivKeys[1])
	require.NoError(t, err)
	final, err := enc1.Decrypt(after0)
	require.NoError(t, err)

	assertValidChecksum(t, final)
	_, di := extractPayloadFromRecord(t, final)
	assert.Equal(t, byte(DTLocal), di.deliveryType, "Send uses local delivery by default")
}
