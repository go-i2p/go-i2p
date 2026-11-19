// Regression test for Issue 4's remaining live failure: a zero-hop inbound
// tunnel cannot encapsulate traffic.
//
// The multi-hop retention fix (retainLayerKeys) does not cover zero-hop inbound
// tunnels: buildZeroHopInbound marks the state TunnelReady with Hops=nil and
// never retains per-hop layer keys, because there are no remote hops. A NAT'd
// router auto-falls-back to zero-hop inbound tunnels when it has no public
// address, so this is the dominant path in a testnet. Before this fix, a
// type-19 TunnelGateway addressed to such a tunnel hit CreatorGateway() and
// failed with "tunnel has no retained layer keys" (ErrNoLayerKeys).
//
// For a zero-hop inbound tunnel we are simultaneously the gateway (IBGW) and the
// endpoint (IBEP): there is no remote hop 0 to forward layered records to, so the
// payload must be delivered to our own router context (DTLocal). These tests pin
// that behavior.

package router

import (
	"testing"
	"time"

	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// zeroHopInboundPool builds a pool holding one ready ZERO-HOP inbound tunnel:
// Hops=nil, no retained layers, exactly what buildZeroHopInbound produces.
func zeroHopInboundPool(t *testing.T) (*tunnel.Pool, tunnel.TunnelID) {
	t.Helper()

	tunnelID := tunnel.TunnelID(0xBEEF_0001)
	state := &tunnel.TunnelState{
		ID:              tunnelID,
		GatewayTunnelID: tunnelID,
		Hops:            nil, // zero-hop: no remote hops
		State:           tunnel.TunnelReady,
		CreatedAt:       time.Now(),
		IsInbound:       true,
	}
	// No SetLayers call: a zero-hop build retains nothing, which is the whole
	// point — CreatorGateway() would return ErrNoLayerKeys.

	pool := tunnel.NewTunnelPool(nil)
	pool.AddTunnel(state)
	return pool, tunnelID
}

// TestZeroHopTunnelGateway_DeliversLocally proves the dispatcher routes a
// type-19 addressed to a zero-hop inbound tunnel to local delivery instead of
// failing with ErrNoLayerKeys or emitting type-18 records to a (nonexistent)
// remote hop 0.
func TestZeroHopTunnelGateway_DeliversLocally(t *testing.T) {
	pool, tunnelID := zeroHopInboundPool(t)

	var deliveredTunnel tunnel.TunnelID
	var deliveredPayload []byte
	calls := 0
	dispatcher := &tunnelGatewayDispatcher{
		inboundPool: pool,
		// sessions is intentionally nil: a zero-hop tunnel must never reach the
		// session-to-hop-0 path, so if the branch is wrong this would error.
		sessions: nil,
		localDeliver: func(id tunnel.TunnelID, payload []byte) error {
			calls++
			deliveredTunnel = id
			deliveredPayload = payload
			return nil
		},
	}

	payload := []byte("opaque payload destined for our own router context")
	require.NoError(t, dispatcher.HandleGateway(tunnelID, payload),
		"a zero-hop inbound tunnel must accept injection via local delivery")

	assert.Equal(t, 1, calls, "local delivery must be invoked exactly once")
	assert.Equal(t, tunnelID, deliveredTunnel)
	assert.Equal(t, payload, deliveredPayload, "the payload is delivered verbatim")
}

// TestZeroHopTunnelGateway_FailsClosedWithoutLocalDeliver confirms that if no
// local-delivery path is wired, the zero-hop branch fails with a clear error
// rather than falling through to CreatorGateway (which would surface the old
// misleading ErrNoLayerKeys).
func TestZeroHopTunnelGateway_FailsClosedWithoutLocalDeliver(t *testing.T) {
	pool, tunnelID := zeroHopInboundPool(t)

	dispatcher := &tunnelGatewayDispatcher{
		inboundPool:  pool,
		sessions:     nil,
		localDeliver: nil,
	}

	err := dispatcher.HandleGateway(tunnelID, []byte("payload"))
	require.Error(t, err, "a zero-hop tunnel with no local-deliver path must fail closed")
	assert.NotErrorIs(t, err, tunnel.ErrNoLayerKeys,
		"the failure must be the missing-local-delivery error, not the old ErrNoLayerKeys")
}

// recordingDeliveryStatusHandler observes a DeliveryStatus dispatched through a
// real MessageProcessor, so the test can prove the production local-deliver
// closure parses the inner I2NP and feeds it to the processor.
type recordingDeliveryStatusHandler struct {
	msgID int
	calls int
}

func (h *recordingDeliveryStatusHandler) HandleDeliveryStatus(msgID int, _ time.Time) error {
	h.calls++
	h.msgID = msgID
	return nil
}

// TestZeroHopTunnelGateway_ProductionClosureDispatchesInnerI2NP wires a real
// MessageProcessor with the same local-deliver closure the production dispatcher
// uses, and proves a type-19 carrying an inner DeliveryStatus reaches the
// processor's delivery-status handler — i.e. the payload is consumed in our own
// context (DTLocal), not dropped or mis-injected.
func TestZeroHopTunnelGateway_ProductionClosureDispatchesInnerI2NP(t *testing.T) {
	const innerMsgID = 0x0BEE_F00D

	pool, tunnelID := zeroHopInboundPool(t)

	processor := i2np.NewMessageProcessor()
	handler := &recordingDeliveryStatusHandler{}
	processor.SetDeliveryStatusHandler(handler)

	// Mirror the production closure from wireTunnelGatewayHandler.
	dispatcher := &tunnelGatewayDispatcher{
		inboundPool: pool,
		sessions:    nil,
		localDeliver: func(_ tunnel.TunnelID, payload []byte) error {
			inner := &i2np.BaseI2NPMessage{}
			if err := inner.UnmarshalBinary(payload); err != nil {
				if err2 := inner.UnmarshalShortI2NP(payload); err2 != nil {
					return err2
				}
			}
			inner.SetReceivedViaTunnel(true)
			return processor.ProcessMessage(inner)
		},
	}

	inner := i2np.NewDeliveryStatusMessage(innerMsgID, time.Now())
	innerBytes, err := inner.MarshalBinary()
	require.NoError(t, err)

	require.NoError(t, dispatcher.HandleGateway(tunnelID, innerBytes),
		"a zero-hop inbound tunnel must dispatch the inner I2NP locally")

	assert.Equal(t, 1, handler.calls,
		"the inner DeliveryStatus must reach the local processor exactly once")
	assert.Equal(t, innerMsgID, handler.msgID,
		"the dispatched message must be the inner I2NP from the type-19 payload")
}

// TestZeroHopTunnelGateway_NotConfusedWithMultiHop guards the branch boundary:
// a multi-hop inbound tunnel with retained layers must still take the
// layer-and-forward path (type-18 records to hop 0), NOT local delivery.
func TestZeroHopTunnelGateway_NotConfusedWithMultiHop(t *testing.T) {
	pool, tunnelID, hop0Hash := readyInboundPool(t, 3)

	session := &recordingGatewaySession{}
	localCalled := 0
	dispatcher := &tunnelGatewayDispatcher{
		inboundPool: pool,
		sessions:    &recordingGatewayProvider{hash: hop0Hash, session: session},
		localDeliver: func(_ tunnel.TunnelID, _ []byte) error {
			localCalled++
			return nil
		},
	}

	require.NoError(t, dispatcher.HandleGateway(tunnelID, []byte("opaque multi-hop payload")))
	assert.Zero(t, localCalled, "a multi-hop tunnel must not use local delivery")
	assert.NotEmpty(t, session.sent, "a multi-hop tunnel must emit layered records to hop 0")
	for _, m := range session.sent {
		assert.Equal(t, i2np.I2NPMessageTypeTunnelData, m.Type())
	}
}
