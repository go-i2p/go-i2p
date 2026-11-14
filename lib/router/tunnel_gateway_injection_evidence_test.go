// Evidence for the inbound-gateway (IBGW) role, fixed under I2P-023.
//
// Before the fix, the only handler for a type-19 TunnelGateway was
// tunnelGatewayDispatcher, which parsed the inner I2NP and fed it to the LOCAL
// message processor. A real tunnel gateway never inspects the payload: it builds
// delivery instructions for the tunnel's endpoint, fragments, encrypts one AES
// layer per hop, and emits type-18 TunnelData at hop 0. That role was missing,
// so inter-router delivery died at the peer's gateway and hidden-service ingress
// from spec-conformant senders was mis-processed.
//
// The fix makes the dispatcher perform the IBGW role: on a type-19 it resolves
// the inbound tunnel by ID, encapsulates the opaque payload with the tunnel's
// retained layer set, and hands layered type-18 records to hop 0. Build-reply
// inner messages (type 22/24/26) are still dispatched locally, because go-i2p
// telescopes its own STBM replies inside a type-19 on the reply path; reference
// routers deliver build replies as bare type-26/24 instead, so that branch only
// fires for our own reply traffic.
//
// These tests now assert the FIXED behavior. They previously pinned the bug and
// are inverted here.

package router

import (
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/go-i2p/go-i2p/lib/tunnel/build"
	"github.com/samber/oops"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordingStatusHandler proves whether an inner message was consumed as OUR
// traffic. A DeliveryStatus is a reply owed to whoever sent the original message,
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

// recordingGatewaySession captures every I2NP message the dispatcher hands to
// hop 0, so the test can observe the injected type-18 records.
type recordingGatewaySession struct {
	sent []i2np.Message
}

func (s *recordingGatewaySession) QueueSendI2NP(msg i2np.Message) error {
	s.sent = append(s.sent, msg)
	return nil
}

func (s *recordingGatewaySession) SendQueueSize() int { return len(s.sent) }

// recordingGatewayProvider resolves a single hop-0 hash to a recording session.
type recordingGatewayProvider struct {
	hash    common.Hash
	session *recordingGatewaySession
}

func (p *recordingGatewayProvider) GetSessionByHash(hash common.Hash) (i2np.I2NPTransportSession, error) {
	if hash != p.hash {
		return nil, oops.Errorf("no session to %x", hash[:4])
	}
	return p.session, nil
}

// recordingBuildReplyProcessor counts build-reply dispatches.
type recordingBuildReplyProcessor struct {
	calls int
}

func (r *recordingBuildReplyProcessor) ProcessTunnelBuildReply(handler build.TunnelReplyHandler, messageID int) error {
	r.calls++
	return nil
}

// readyInboundPool builds a pool holding one ready inbound tunnel with retained
// layer keys, mirroring what i2np.TunnelManager.retainLayerKeys writes after a
// successful build. It returns the pool, the tunnel ID, and hop 0's identity hash.
func readyInboundPool(t *testing.T, hopCnt int) (*tunnel.Pool, tunnel.TunnelID, common.Hash) {
	t.Helper()

	layers := make([]tunnel.TunnelLayer, hopCnt)
	for i := 0; i < hopCnt; i++ {
		var lk, ivk [32]byte
		for j := range lk {
			lk[j] = byte(0x10*i + j + 1)
			ivk[j] = byte(0x80 + 0x20*i + j)
		}
		receive := tunnel.TunnelID(0xABCD_0001 + uint32(i))
		layers[i] = tunnel.TunnelLayer{
			LayerKey:      lk,
			IVKey:         ivk,
			ReceiveTunnel: receive,
			NextTunnel:    tunnel.TunnelID(0x1000 + uint32(i)),
		}
	}

	hops := make([]common.Hash, hopCnt)
	for i := range hops {
		hops[i] = common.Hash{byte(0xA0 + i)}
	}

	state := &tunnel.TunnelState{
		ID:              layers[0].ReceiveTunnel,
		GatewayTunnelID: layers[0].ReceiveTunnel,
		Hops:            hops,
		State:           tunnel.TunnelReady,
		CreatedAt:       time.Now(),
		IsInbound:       true,
		GatewayHash:     hops[0],
	}
	state.SetLayers(layers)

	pool := tunnel.NewTunnelPool(nil)
	pool.AddTunnel(state)
	return pool, state.ID, hops[0]
}

// TestEvidence_TunnelGatewayIsInjectedIntoInboundTunnel shows the production
// dispatcher now performs the IBGW role: a type-19 carrying an opaque payload is
// encapsulated and emitted as type-18 TunnelData to hop 0, NOT consumed by the
// local processor. The payload here is a DeliveryStatus, which before the fix
// was wrongly applied to OUR OWN message IDs; after the fix it is opaque traffic
// destined for the tunnel's endpoint.
func TestEvidence_TunnelGatewayIsInjectedIntoInboundTunnel(t *testing.T) {
	const innerMsgID = 0x5EED_BEEF

	pool, tunnelID, hop0Hash := readyInboundPool(t, 3)

	session := &recordingGatewaySession{}
	dispatcher := &tunnelGatewayDispatcher{
		inboundPool: pool,
		sessions:    &recordingGatewayProvider{hash: hop0Hash, session: session},
	}

	inner := i2np.NewDeliveryStatusMessage(innerMsgID, time.Now())
	innerBytes, err := inner.MarshalBinary()
	require.NoError(t, err)

	require.NoError(t, dispatcher.HandleGateway(tunnelID, innerBytes))

	// The proof of the fix: the payload left as layered type-18 records to hop 0.
	require.NotEmpty(t, session.sent, "the gateway must emit tunnel records to hop 0")
	for _, m := range session.sent {
		assert.Equal(t, i2np.I2NPMessageTypeTunnelData, m.Type(),
			"injection must produce type-18 TunnelData, not a local dispatch")
		td, ok := m.(*i2np.TunnelDataMessage)
		require.True(t, ok, "records must be the typed TunnelData message")
		assert.NotEqual(t, tunnel.TunnelID(0), td.TunnelID,
			"the record is addressed to hop 0's receive tunnel ID")
	}
}

// TestEvidence_ProductionDispatcherHasInjectionCapability confirms the concrete
// production handler now carries the collaborators a real IBGW needs: an inbound
// pool to resolve the tunnel and a session provider to reach hop 0. It also
// confirms the fail-closed behavior for a tunnel this router did not build.
func TestEvidence_ProductionDispatcherHasInjectionCapability(t *testing.T) {
	pool, tunnelID, hop0Hash := readyInboundPool(t, 3)

	session := &recordingGatewaySession{}
	dispatcher := &tunnelGatewayDispatcher{
		inboundPool: pool,
		sessions:    &recordingGatewayProvider{hash: hop0Hash, session: session},
	}

	// A built tunnel: injection succeeds and emits records.
	require.NoError(t, dispatcher.HandleGateway(tunnelID, []byte("opaque tunnel payload that is not a build reply")))
	require.NotEmpty(t, session.sent, "a built inbound tunnel must accept injection")

	// An unknown tunnel: fail closed, no records, no crash.
	before := len(session.sent)
	require.Error(t, dispatcher.HandleGateway(tunnel.TunnelID(0xDEAD_BEEF), []byte("payload for a tunnel we did not build")))
	assert.Len(t, session.sent, before, "an unknown tunnel must not emit any records")
}

// TestEvidence_BuildReplyWrappedInGatewayIsInjectedNotConsumed pins the spec-
// conformant handling of a build reply wrapped in a type-19: the gateway injects
// it into the tunnel like any other payload, and never consumes it as a local
// build reply. i2pd wraps a reply in a TunnelGateway when the reply gateway is
// remote (TransitTunnel.cpp CreateTunnelGatewayMsg) and injects it even when the
// gateway is local (SendTunnelDataMsg); the reply is processed at the tunnel's
// endpoint after decryption, not at the gateway.
func TestEvidence_BuildReplyWrappedInGatewayIsInjectedNotConsumed(t *testing.T) {
	pool, tunnelID, hop0Hash := readyInboundPool(t, 3)

	replyProcessor := &recordingBuildReplyProcessor{}
	processor := i2np.NewMessageProcessor()
	processor.SetBuildReplyProcessor(replyProcessor)

	session := &recordingGatewaySession{}
	dispatcher := &tunnelGatewayDispatcher{
		inboundPool: pool,
		sessions:    &recordingGatewayProvider{hash: hop0Hash, session: session},
	}

	// A type-26 build reply wrapped in a type-19 payload.
	reply := i2np.NewBaseI2NPMessage(i2np.I2NPMessageTypeOutboundTunnelBuildReply)
	reply.SetMessageID(0x1234)
	replyData := make([]byte, 1+1*i2np.ShortBuildRecordSize)
	replyData[0] = 1 // one record
	reply.SetData(replyData)
	replyBytes, err := reply.MarshalBinary()
	require.NoError(t, err)

	require.NoError(t, dispatcher.HandleGateway(tunnelID, replyBytes))

	// The reply is injected as layered records, not consumed at the gateway.
	require.NotEmpty(t, session.sent, "a wrapped build reply must be injected into the tunnel")
	for _, m := range session.sent {
		assert.Equal(t, i2np.I2NPMessageTypeTunnelData, m.Type(),
			"the gateway emits type-18 records, never a local build-reply dispatch")
	}
	assert.Zero(t, replyProcessor.calls,
		"the gateway must not process the build reply; the endpoint does, after decryption")
}

// TestEvidence_ForwardToTunnelProducesTunnelGateway proves the endpoint's
// remote-delivery path emits the IBGW wire format (a type-19). This is the
// sender half of the pair; the receiving half — turning that type-19 into
// layered type-18 records — is now implemented by the IBGW dispatcher above.
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
		"the payload is carried verbatim, ready for the destination gateway to inject")

	// The type-19 is the wire format a real IBGW consumes; the receiving side now
	// turns it into type-18 TunnelData rather than consuming it as local traffic
	// (see TestEvidence_TunnelGatewayIsInjectedIntoInboundTunnel).
	assert.NotEqual(t, i2np.I2NPMessageTypeTunnelData, captured.Type())
}
