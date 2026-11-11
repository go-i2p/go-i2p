// The one test that closes the gap every other I2P-002 test left open.
//
// The gateway, pool-state and I2CP encapsulation tests all FABRICATE a tunnel's
// retained layers by calling TunnelState.SetLayers directly. That proves the
// consumer of those keys works, but nothing proves the producer does: the keys
// are created during a build, installed on the build records by updateLayerKeys,
// and then dropped when the pending build is deleted. retainLayerKeys is the
// only thing that carries them onto the pool state, and it had no coverage, so a
// regression there would leave every test green while the network still received
// no correctly layered traffic.
//
// This test drives the real producer and feeds its output to the real consumer.

package i2np

import (
	"testing"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/go-i2p/go-i2p/lib/tunnel/buildrecord"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildResultWithDerivedKeys makes a TunnelBuildResult the way a real STBM build
// leaves one: updateLayerKeys has already overwritten each record's placeholder
// keys with the values derived from that hop's Noise chaining key.
func buildResultWithDerivedKeys(t *testing.T, hopCount int) *tunnel.TunnelBuildResult {
	t.Helper()

	hops := make([]router_info.RouterInfo, hopCount)
	records := make([]buildrecord.BuildRequestRecord, hopCount)
	receive := make([]tunnel.TunnelID, hopCount)

	base := tunnel.TunnelID(0xB01B_0001)
	for i := 0; i < hopCount; i++ {
		receive[i] = base + tunnel.TunnelID(i)

		var lk, ivk [32]byte
		for j := 0; j < 32; j++ {
			lk[j] = byte(i*31 + j + 1)
			ivk[j] = byte(i*17 + j + 200)
		}

		records[i] = buildrecord.BuildRequestRecord{
			ReceiveTunnel: receive[i],
			NextTunnel:    receive[retainMinInt(i+1, hopCount-1)],
		}
		copy(records[i].LayerKey[:], lk[:])
		copy(records[i].IVKey[:], ivk[:])
	}

	return &tunnel.TunnelBuildResult{
		TunnelID:        receive[0],
		GatewayTunnelID: receive[0],
		Hops:            hops,
		Records:         records,
	}
}

func retainMinInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func hashFromByte(b byte) common.Hash {
	var h common.Hash
	for i := range h {
		h[i] = b
	}
	return h
}

// TestRetainLayerKeys_ProducesAWorkingCreatorGateway is the end-to-end proof for
// the producer: keys taken from a finished build must be enough to encapsulate
// traffic, because that is the only reason they are kept.
func TestRetainLayerKeys_ProducesAWorkingCreatorGateway(t *testing.T) {
	const hopCount = 3

	tm := NewTunnelManager(&mockPeerSelector{})
	require.NotNil(t, tm)
	t.Cleanup(tm.Stop)

	result := buildResultWithDerivedKeys(t, hopCount)
	for i := range result.Hops {
		result.Hops[i] = router_info.RouterInfo{}
	}

	state := tm.createTunnelStateFromResult(result)
	require.NotNil(t, state)
	require.Len(t, state.Hops, hopCount)

	// Before retention the state cannot send anything: this is the pre-I2P-002
	// runtime condition, where a built tunnel looked ready but held no keys.
	_, err := state.CreatorGateway()
	require.Error(t, err, "a fresh build result must not yield a gateway before retention")

	tm.retainLayerKeys(state, result)

	gw, err := state.CreatorGateway()
	require.NoError(t, err, "retained build keys must be enough to act as the tunnel's gateway")
	require.Equal(t, hopCount, gw.HopCount(), "every hop's layer must be present")

	records, err := gw.SendWithDelivery([]byte("leaseset or i2cp payload"),
		tunnel.TunnelDelivery(0x11223344, [32]byte(hashFromByte(0xEE))))
	require.NoError(t, err)
	require.NotEmpty(t, records)
	for _, r := range records {
		assert.Len(t, r, tunnel.TunnelMessageSize)
	}
}

func TestRetainLayerKeys_CopiesKeysAndIDsVerbatim(t *testing.T) {
	const hopCount = 4

	tm := NewTunnelManager(&mockPeerSelector{})
	t.Cleanup(tm.Stop)

	result := buildResultWithDerivedKeys(t, hopCount)
	state := tm.createTunnelStateFromResult(result)
	tm.retainLayerKeys(state, result)

	layers := state.GetLayers()
	require.Len(t, layers, hopCount, "one layer per hop, in path order")

	for i := range layers {
		assert.Equal(t, result.Records[i].LayerKey[:], layers[i].LayerKey[:],
			"hop %d layer key must match what the build derived", i)
		assert.Equal(t, result.Records[i].IVKey[:], layers[i].IVKey[:],
			"hop %d IV key must match what the build derived", i)
		assert.Equal(t, result.Records[i].ReceiveTunnel, layers[i].ReceiveTunnel,
			"hop %d must be addressed by the receive ID it registered", i)
		assert.Equal(t, result.Records[i].NextTunnel, layers[i].NextTunnel)
	}

	// The gateway is hop 0, so hop 0's receive ID is what the TunnelData header
	// must carry and what the creator's gateway must name as its next hop.
	gw, err := state.CreatorGateway()
	require.NoError(t, err)
	assert.Equal(t, result.Records[0].ReceiveTunnel, gw.HopReceiveTunnelID(),
		"hop 0's receive ID must be what the creator addresses records at")
}

func TestRetainLayerKeys_GatewayHashIsHopZero(t *testing.T) {
	tm := NewTunnelManager(&mockPeerSelector{})
	t.Cleanup(tm.Stop)

	result := buildResultWithDerivedKeys(t, 3)
	// createTunnelStateFromResult derives Hops from result.Hops, so hop 0's
	// identity is what GatewayHash must carry: that is the peer the layered
	// records get addressed to.
	state := tm.createTunnelStateFromResult(result)
	require.NotEmpty(t, state.Hops)
	assert.Equal(t, state.Hops[0], state.GatewayHash,
		"GatewayHash must be the peer the layered records go to")
}

func TestRetainLayerKeys_RefusesMismatchedRecordCount(t *testing.T) {
	tm := NewTunnelManager(&mockPeerSelector{})
	t.Cleanup(tm.Stop)

	result := buildResultWithDerivedKeys(t, 3)
	result.Records = result.Records[:2] // truncated: cannot map keys to hops

	state := tm.createTunnelStateFromResult(result)
	tm.retainLayerKeys(state, result)

	assert.Empty(t, state.GetLayers(),
		"a record/hop mismatch must leave the tunnel unusable rather than half-populated")

	_, err := state.CreatorGateway()
	require.Error(t, err, "and the tunnel must fail closed instead of sending single-layer traffic")
}

func TestRetainLayerKeys_IdempotentAcrossRepeatedCalls(t *testing.T) {
	tm := NewTunnelManager(&mockPeerSelector{})
	t.Cleanup(tm.Stop)

	result := buildResultWithDerivedKeys(t, 3)
	state := tm.createTunnelStateFromResult(result)

	tm.retainLayerKeys(state, result)
	first, err := state.CreatorGateway()
	require.NoError(t, err)

	// A retried or refreshed build reuses the same state path; retention must not
	// corrupt it or leave a stale memoized gateway.
	tm.retainLayerKeys(state, result)
	second, err := state.CreatorGateway()
	require.NoError(t, err)

	require.Equal(t, first.HopCount(), second.HopCount())
}
