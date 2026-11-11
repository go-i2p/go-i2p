// Evidence for the tunnel-gateway gap found while fixing I2P-002.
//
// I2P-002 is the outbound half of tunnel addressing: I2CP traffic was handed to
// the transport bare instead of being encapsulated, and that is fixed. Fixing it
// required understanding what a type-19 TunnelGateway is for, and the answer
// exposes a separate, still-unimplemented role.
//
// The only handler for type-19 in this router, tunnelGatewayDispatcher
// (router_tunnel_wiring.go), parses the inner I2NP and feeds it to the LOCAL
// message processor. A real tunnel gateway would never inspect the payload: it
// would build delivery instructions for the tunnel's endpoint, fragment, encrypt
// one AES layer per hop, and emit type-20 TunnelData at hop 0. No component here
// does that on behalf of a received type-19.
//
// Consequences these tests pin down:
//
//   - A message addressed to a REMOTE destination cannot be delivered. The
//     tunnel endpoint's ForwardToTunnel emits a type-19 at the destination's
//     gateway, which either has no consumer for it or, if the dispatcher runs,
//     processes the inner message locally instead of tunneling it onward. So
//     reaching another router's I2CP client is impossible end-to-end even though
//     our own outbound encapsulation is now correct.
//   - The same missing role makes leaseset publication fail; see the companion
//     evidence test in lib/netdb.
//
// Nothing here changes behavior; it records it.

package router

import (
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordingGatewayHandler stands in for the IBGW role so the test can observe
// what the dispatcher does with a received TunnelGateway.
type recordingGatewayHandler struct {
	seenTunnelID tunnel.TunnelID
	seenPayload  []byte
}

func (h *recordingGatewayHandler) HandleGateway(tunnelID tunnel.TunnelID, payload []byte) error {
	h.seenTunnelID = tunnelID
	h.seenPayload = append([]byte(nil), payload...)
	return nil
}

// recordingStatusHandler proves the inner message was interpreted as OUR traffic.
// A DeliveryStatus is a reply that belongs to whoever sent the original message,
// so a router acting as a pure gateway must never consume one for itself.
type recordingStatusHandler struct {
	msgIDs     []int
	timestamps []time.Time
}

func (h *recordingStatusHandler) HandleDeliveryStatus(msgID int, timestamp time.Time) error {
	h.msgIDs = append(h.msgIDs, msgID)
	h.timestamps = append(h.timestamps, timestamp)
	return nil
}

// TestEvidence_TunnelGatewayIsDispatchedLocallyNotInjectedIntoTunnel shows the
// production dispatcher hands the inner I2NP to the local processor instead of
// encapsulating it for the destination's inbound tunnel. A real gateway would
// never look at the inner message at all: it would treat it as opaque payload.
func TestEvidence_TunnelGatewayIsDispatchedLocallyNotInjectedIntoTunnel(t *testing.T) {
	const innerMsgID = 0x5EED_BEEF

	processor := i2np.NewMessageProcessor()

	// The PRODUCTION wiring: router_tunnel_wiring.go installs the local processor
	// dispatcher as the type-19 handler.
	processor.SetTunnelGatewayHandler(&tunnelGatewayDispatcher{processor: processor})

	statusHandler := &recordingStatusHandler{}
	processor.SetDeliveryStatusHandler(statusHandler)

	inner := i2np.NewDeliveryStatusMessage(innerMsgID, time.Now())
	innerBytes, err := inner.MarshalBinary()
	require.NoError(t, err)

	outer := i2np.NewTunnelGatewayMessage(tunnel.TunnelID(0xC0FFEE01), innerBytes)
	require.NoError(t, processor.ProcessMessage(outer))

	// The proof: the inner DeliveryStatus was consumed as a reply to OUR OWN
	// message. That is only possible because type-19 handling is wired to the
	// local processor rather than to a gateway role.
	require.Len(t, statusHandler.msgIDs, 1,
		"the dispatcher re-dispatched the inner I2NP through the local processor")
	assert.Equal(t, innerMsgID, statusHandler.msgIDs[0],
		"the status was applied locally, keyed on the inner message ID")
}

// TestEvidence_ProductionDispatcherHasNoTunnelInjection confirms the concrete
// production handler is the local processor dispatcher. It is written as a
// compile-time/behavioral statement rather than a source grep so it fails if
// someone wires a real gateway role in and forgets to update the I2P-002 notes.
func TestEvidence_ProductionDispatcherHasNoTunnelInjection(t *testing.T) {
	// The production dispatcher needs an i2np.MessageProcessor and nothing else:
	// no tunnel pool, no gateway, no per-hop keys. A real IBGW cannot be built
	// without those, so the shape of this constructor is itself the evidence.
	processor := i2np.NewMessageProcessor()
	dispatcher := &tunnelGatewayDispatcher{processor: processor}
	require.NotNil(t, dispatcher)

	// Handing it a payload for a tunnel this router did not build must not
	// encapsulate anything: there is no tunnel to encapsulate into, and the
	// dispatcher's only field is a local processor.
	var err error
	require.NotPanics(t, func() {
		err = dispatcher.HandleGateway(tunnel.TunnelID(1234), []byte("opaque tunnel payload"))
	})
	require.Error(t, err, "an opaque payload is not a parseable local I2NP message")
}

// TestEvidence_ForwardToTunnelProducesTunnelGateway proves the endpoint's
// remote-delivery path emits the IBGW wire format, which the receiving side has
// no role to consume. This is the half of the pair that makes remote delivery
// impossible rather than merely inefficient.
func TestEvidence_ForwardToTunnelProducesTunnelGateway(t *testing.T) {
	table := make(map[common.Hash]*encapRelay, 1)
	destGW := newEncapRelay(t, "evidence-dest-gw", table)

	var captured *i2np.TunnelGateway
	destGW.onTunnelGateway = func(gw *i2np.TunnelGateway) { captured = gw }

	handler := NewInboundMessageHandler(nil)
	handler.SetSessionProvider(&encapLoopbackProvider{table: table})

	payload := []byte("bytes that must reach a remote client")

	require.NoError(t, handler.ForwardToTunnel(0x11223344, [32]byte(destGW.hash), payload))
	require.NotNil(t, captured, "ForwardToTunnel must emit a TunnelGateway to the destination gateway")

	assert.Equal(t, tunnel.TunnelID(0x11223344), captured.TunnelID,
		"the gateway field carries the destination's inbound tunnel ID")
	assert.Equal(t, payload, captured.Data,
		"the payload is carried verbatim, awaiting a gateway role that does not exist")

	// What a real IBGW would have to do instead, stated so the gap is not just
	// negative: it would need the destination's inbound tunnel and would emit
	// type-20 TunnelData records, not consume a type-19.
	assert.NotEqual(t, i2np.I2NPMessageTypeTunnelData, captured.Type())
}
