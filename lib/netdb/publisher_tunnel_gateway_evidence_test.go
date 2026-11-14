// Evidence for the leaseset-publish investigation opened by I2P-002.
//
// I2P-002 was about outbound I2CP traffic being handed to the transport
// unencapsulated. LeaseSet publication turns out to do the same thing, so these
// tests record it rather than leave it as a claim in a comment. Nothing here
// changes behavior.
//
// For an OUTBOUND tunnel this router is the gateway: the builder retains every
// hop's layer key on TunnelState.Layers, so the creator is the only component
// that can build delivery instructions, fragment, encrypt one layer per hop, and
// emit type-20 TunnelData at hop 0. That is what tunnel.Gateway.SendWithDelivery
// does, and what the I2CP send path now calls.
//
// The publisher does not call it. It builds a type-19 TunnelGateway addressed at
// selectedTunnel.Hops[0] and sends it there directly. Two things are verifiable
// in this repo about that:
//
//  1. Nothing is encapsulated - no delivery instructions, no fragments, no AES
//     layers - and our own router is the peer on the connection, which is the
//     same anonymity leak I2P-002 removed for I2CP traffic.
//  2. Hop 0 cannot consume a type-19 for a tunnel we created. When it accepted
//     our build it registered itself as a PARTICIPANT under that ID, holding only
//     its own single layer key, and participants are reachable only from type-20
//     TunnelData (InboundMessageHandler.HandleTunnelData). The only type-19
//     handler anywhere in this router, tunnelGatewayDispatcher, parses the inner
//     I2NP and dispatches it LOCALLY - so at best the remote router would store
//     our DatabaseStore in its own NetDB rather than forward it to a floodfill.
//
// The RouterInfo branch of sendDatabaseStoreToFloodfill deliberately sends direct
// instead, citing a different concern: an injected store reaches the tunnel's
// endpoint rather than the explicitly chosen floodfill. That is a real property
// of outbound tunnels, but it does not make the type-19 path work for LeaseSets -
// the correct target is the floodfill, and reaching it through our own outbound
// tunnel means encapsulating, exactly as I2CP now does.

package netdb

import (
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEvidence_LeaseSetPublishEncapsulatesIntoTunnelDataForHopZero pins the
// fixed publication path: the DatabaseStore is encapsulated by the tunnel's
// creator and handed to hop 0 as one or more layered type-18 TunnelData
// records, never as a bare cleartext type-19 TunnelGateway.
//
// Before the fix (I2P-031) this test asserted the opposite: exactly one
// unencapsulated type-19 to hop 0 and zero TunnelData records. The bug shared
// its root cause with I2P-023 (no IBGW role) but had a distinct fix site: the
// publisher already held a ready TunnelState and only needed to use it.
func TestEvidence_LeaseSetPublishEncapsulatesIntoTunnelDataForHopZero(t *testing.T) {
	const outboundTunnelID = tunnel.TunnelID(0x0BAD_0001)

	env := setupPublisherWithTunnel(t, outboundTunnelID, []common.Hash{
		{0x11, 0x12, 0x13, 0x14},
		{0x21, 0x22, 0x23, 0x24},
	})

	hash := common.Hash{9, 10, 11, 12}
	data := []byte("leaseset bytes")
	floodfill := createValidRouterInfo(t)

	_, err := env.publisher.sendDatabaseStoreToFloodfill(hash, data, i2np.DatabaseStoreTypeLeaseSet2, floodfill)
	require.NoError(t, err)

	sent := env.transport.GetSentMessages(env.gatewayHash)
	require.NotEmpty(t, sent, "at least one record goes to hop 0")

	// Every message to hop 0 is a layered TunnelData record; no cleartext
	// TunnelGateway remains on the wire.
	for _, m := range sent {
		assert.Equal(t, i2np.I2NPMessageTypeTunnelData, m.Type(),
			"publication must send encapsulated tunnel records, not a bare type-19")
		td, ok := m.(*i2np.TunnelDataMessage)
		require.True(t, ok, "TunnelData messages must be the typed record")
		assert.NotEqual(t, tunnel.TunnelID(0), td.TunnelID,
			"the record is addressed to hop 0's receive tunnel ID")
	}
}

// TestEvidence_PublisherTunnelCanEncapsulateButDoesNot shows the fix is available
// on the very object the publisher already has: a ready TunnelState now exposes
// a creator-side gateway, so publication can encapsulate the way I2CP does.
func TestEvidence_PublisherTunnelCanEncapsulateButDoesNot(t *testing.T) {
	state := &tunnel.TunnelState{
		ID:              9000,
		GatewayTunnelID: 9000,
		Hops:            []common.Hash{{0xAA}, {0xBB}, {0xCC}},
		State:           tunnel.TunnelReady,
		CreatedAt:       time.Now(),
	}
	state.SetLayers([]tunnel.TunnelLayer{
		{LayerKey: [32]byte{1}, IVKey: [32]byte{2}, ReceiveTunnel: 9000, NextTunnel: 9001},
		{LayerKey: [32]byte{3}, IVKey: [32]byte{4}, ReceiveTunnel: 9001, NextTunnel: 9002},
		{LayerKey: [32]byte{5}, IVKey: [32]byte{6}, ReceiveTunnel: 9002, NextTunnel: 9002},
	})

	gw, err := state.CreatorGateway()
	require.NoError(t, err, "a built tunnel retains the keys needed to act as its own gateway")
	require.Equal(t, 3, gw.HopCount())

	records, err := gw.SendWithDelivery(
		[]byte("a DatabaseStore that should have gone down the tunnel"),
		tunnel.TunnelDelivery(0x11223344, [32]byte{0xFF}),
	)
	require.NoError(t, err)
	require.NotEmpty(t, records)
	for _, r := range records {
		assert.Len(t, r, tunnel.TunnelMessageSize, "encapsulated records are full tunnel blocks")
	}

	// So the publisher's selectedTunnel - the same *tunnel.TunnelState type - can
	// produce correct layered records. It simply is not asked to.
}
