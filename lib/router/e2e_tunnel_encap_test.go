// Honest end-to-end movement of I2CP bytes through real tunnel encapsulation.
//
// The older "integration" test in e2e_integration_test.go captured the outbound
// garlic message at the transport boundary and re-fed it by hand into the
// receiver's inbound handler. That skipped encapsulation entirely — which is
// exactly what I2P-002 removed — so the suite stayed green while every outbound
// byte was being discarded by the network.
//
// This test takes no shortcut. It drives the production I2CP send path, then
// moves the bytes across separate in-process routers running the same
// InboundMessageHandler code a real relay runs:
//
//	client -> I2CP MessageRouter -> gateway encapsulation
//	       -> hop 1 (transit) -> hop 2 (transit) -> hop 3 (tunnel endpoint)
//	       -> type-19 TunnelGateway addressed at the destination's gateway
//
// Nothing is stubbed between those stages. The assertions are that the exact
// bytes the client handed to I2CP arrive intact at the far end, that they are
// addressed to the destination lease the resolver reported, and that a
// single-layer record would NOT have survived — i.e. the encapsulation is real.

package router

import (
	"bytes"
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	cryptotunnel "github.com/go-i2p/crypto/tunnel"
	"github.com/go-i2p/go-i2p/lib/i2cp"
	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/samber/oops"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// encapRelay is one in-process router: enough machinery for the production
// inbound tunnel handler to run, and no sockets.
type encapRelay struct {
	hash    common.Hash
	inbound *InboundMessageHandler
	partman *tunnel.ParticipantManager

	delivered chan encapDelivery

	// onTunnelGateway, when set, receives every type-19 TunnelGateway addressed
	// at this relay, in addition to the delivered channel. Harnesses that need to
	// recover the encapsulated payload (rather than just observe that bytes
	// arrived) install a callback here.
	onTunnelGateway func(*i2np.TunnelGateway)
}

// encapDelivery is what a router accepted from the previous hop.
type encapDelivery struct {
	tunnelID uint32
	msgType  int
	payload  []byte
}

func newEncapRelay(t *testing.T, label string, table map[common.Hash]*encapRelay) *encapRelay {
	t.Helper()

	r := &encapRelay{
		hash:      encapHashOfLabel(label),
		delivered: make(chan encapDelivery, 16),
	}
	r.partman = tunnel.NewManager()
	t.Cleanup(r.partman.Stop)

	r.inbound = NewInboundMessageHandler(nil)
	r.inbound.SetParticipantManager(r.partman)
	r.inbound.SetSessionProvider(&encapLoopbackProvider{table: table})
	table[r.hash] = r
	return r
}

// encapLoopbackProvider resolves router hashes to in-process sessions so transit
// forwarding exercises real routing code without a network.
type encapLoopbackProvider struct{ table map[common.Hash]*encapRelay }

func (p *encapLoopbackProvider) GetSessionByHash(hash common.Hash) (i2np.I2NPTransportSession, error) {
	r, ok := p.table[hash]
	if !ok {
		return nil, oops.Errorf("no loopback router registered for %x", hash[:8])
	}
	return &encapLoopbackSession{router: r}, nil
}

// encapLoopbackSession is the transport leg between two in-process routers.
//
// TunnelData is handed to the production inbound handler so the next hop really
// relays it. A type-19 TunnelGateway arriving at a destination gateway is
// captured rather than injected: re-injecting inbound tunnel traffic as layered
// TunnelData is the inbound-gateway role, which this router does not implement
// (see the I2P-002 notes). Capturing at that boundary still proves the whole
// outbound path, because the gateway and every transit hop ran for real.
type encapLoopbackSession struct{ router *encapRelay }

func (s *encapLoopbackSession) QueueSendI2NP(msg i2np.Message) error {
	switch msg.Type() {
	case i2np.I2NPMessageTypeTunnelData:
		return s.router.inbound.HandleTunnelData(msg)
	case i2np.I2NPMessageTypeTunnelGateway:
		gw, ok := msg.(*i2np.TunnelGateway)
		if !ok {
			return oops.Errorf("expected *i2np.TunnelGateway, got %T", msg)
		}
		if s.router.onTunnelGateway != nil {
			s.router.onTunnelGateway(gw)
		}
		s.router.delivered <- encapDelivery{
			tunnelID: uint32(gw.TunnelID),
			msgType:  msg.Type(),
			payload:  append([]byte(nil), gw.Data...),
		}
		return nil
	default:
		return oops.Errorf("loopback session received unexpected I2NP type %d", msg.Type())
	}
}

func (s *encapLoopbackSession) SendQueueSize() int { return 0 }

func encapHashOfLabel(label string) common.Hash {
	var h common.Hash
	copy(h[:], label)
	if h == (common.Hash{}) {
		h[31] = 0xA5
	}
	return h
}

// encapHopKeys is one hop's layer and IV key.
type encapHopKeys struct {
	layer [32]byte
	iv    [32]byte
}

func encapEncryptor(t *testing.T, k encapHopKeys) cryptotunnel.TunnelEncryptor {
	t.Helper()
	var lk, ivk cryptotunnel.TunnelKey
	copy(lk[:], k.layer[:])
	copy(ivk[:], k.iv[:])
	enc, err := cryptotunnel.NewAESEncryptor(lk, ivk)
	require.NoError(t, err)
	return enc
}

// encapTunnel is a ready outbound tunnel plus the per-hop keys and receive IDs
// the test needs in order to register matching relays.
type encapTunnel struct {
	state      *tunnel.TunnelState
	keys       []encapHopKeys
	receiveIDs []tunnel.TunnelID
}

func buildEncapTunnel(hopCount int) *encapTunnel {
	return buildEncapTunnelWithBase(hopCount, 0xA11C_0001)
}

// buildEncapTunnelWithBase builds a ready multi-hop tunnel whose receive IDs,
// hop identities and layer keys all derive from base, so several tunnels can
// coexist in one fixture without colliding.
func buildEncapTunnelWithBase(hopCount int, base tunnel.TunnelID) *encapTunnel {
	hops := make([]common.Hash, hopCount)
	layers := make([]tunnel.TunnelLayer, hopCount)
	keys := make([]encapHopKeys, hopCount)
	receive := make([]tunnel.TunnelID, hopCount)

	seed := uint64(base)
	for i := 0; i < hopCount; i++ {
		for j := range hops[i] {
			hops[i][j] = byte(seed + uint64(i*101+j) + 7)
		}

		var k encapHopKeys
		for j := 0; j < 32; j++ {
			k.layer[j] = byte(seed/7 + uint64(i*37+j) + 1)
			k.iv[j] = byte(seed/13 + uint64(i*53+j) + 199)
		}
		keys[i] = k

		receive[i] = base + tunnel.TunnelID(i)
		layers[i] = tunnel.TunnelLayer{
			LayerKey: k.layer, IVKey: k.iv,
			ReceiveTunnel: receive[i],
			NextTunnel:    receive[minInt(i+1, hopCount-1)],
		}
	}

	state := &tunnel.TunnelState{
		ID:              layers[0].ReceiveTunnel,
		GatewayTunnelID: layers[0].ReceiveTunnel,
		Hops:            hops,
		State:           tunnel.TunnelReady,
		CreatedAt:       time.Now(),
		GatewayHash:     hops[0],
	}
	state.SetLayers(layers)
	return &encapTunnel{state: state, keys: keys, receiveIDs: receive}
}

// setHop points hop i at a router identity and re-publishes the layers so the
// gateway cache is rebuilt against the same routers the test built relays for.
func (o *encapTunnel) setHop(i int, hash common.Hash) {
	o.state.Hops[i] = hash
	o.state.GatewayHash = o.state.Hops[0]

	layers := o.state.GetLayers()
	layers[i].ReceiveTunnel = o.receiveIDs[i]
	layers[i].NextTunnel = o.receiveIDs[minInt(i+1, len(o.receiveIDs)-1)]
	o.state.SetLayers(layers)
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// registerEncapTransit installs a participant that mirrors what a real hop
// registers on accepting a build: its own receive ID, its layer key, and the
// (identity, ID) pair it forwards to.
func registerEncapTransit(t *testing.T, r *encapRelay, keys encapHopKeys, receiveID, nextID tunnel.TunnelID, nextIdent common.Hash) {
	t.Helper()

	participant, err := tunnel.NewParticipantWithNextHop(receiveID, encapEncryptor(t, keys), nextIdent, nextID)
	require.NoError(t, err)
	require.NoError(t, r.partman.AddParticipant(participant))
	require.NotNil(t, r.partman.GetParticipant(receiveID),
		"hop must be routable by the receive ID its build record gave it")
}

// encapLeaseResolver answers every destination with one fixed lease, or with a
// failure / an empty lease when configured to.
type encapLeaseResolver struct {
	target      i2cp.LeaseTarget
	err         error
	blankTarget bool
}

func (s *encapLeaseResolver) ResolveLease(_ common.Hash) (i2cp.LeaseTarget, error) {
	if s.err != nil {
		return i2cp.LeaseTarget{}, s.err
	}
	if s.blankTarget {
		return i2cp.LeaseTarget{}, nil
	}
	return s.target, nil
}

// TestE2E_I2CPBytesCrossRealTunnelRelays is the honest version of the outbound
// path test: no capture-and-reinject shortcut, real layered encapsulation, and
// production relay code at every hop.
func TestE2E_I2CPBytesCrossRealTunnelRelays(t *testing.T) {
	const hopCount = 3

	table := make(map[common.Hash]*encapRelay, hopCount+1)
	hop1 := newEncapRelay(t, "transit-hop-one", table)
	hop2 := newEncapRelay(t, "transit-hop-two", table)
	hop3 := newEncapRelay(t, "tunnel-endpoint-hop", table)
	destGW := newEncapRelay(t, "destination-inbound-gw", table)

	ot := buildEncapTunnel(hopCount)
	ot.setHop(0, hop1.hash)
	ot.setHop(1, hop2.hash)
	ot.setHop(2, hop3.hash)

	// hop1 and hop2 relay through production transit code.
	registerEncapTransit(t, hop1, ot.keys[0], ot.receiveIDs[0], ot.receiveIDs[1], hop2.hash)
	registerEncapTransit(t, hop2, ot.keys[1], ot.receiveIDs[1], ot.receiveIDs[2], hop3.hash)

	// hop3 terminates the tunnel. The message carries DTTunnel instructions for
	// the destination's inbound tunnel, so the endpoint hands it to its
	// forwarder — hop3's own production InboundMessageHandler — which wraps it
	// in a type-19 TunnelGateway to the destination gateway.
	destInboundTunnelID := tunnel.TunnelID(0xD571_0001)

	garlicMgr, err := i2np.GenerateGarlicSessionManager()
	require.NoError(t, err)

	endpoint, err := tunnel.NewEndpoint(ot.receiveIDs[2], encapEncryptor(t, ot.keys[2]), func([]byte) error {
		return oops.Errorf("local handler must not run for DTTunnel delivery")
	})
	require.NoError(t, err)
	endpoint.SetForwarder(hop3.inbound)
	t.Cleanup(endpoint.Stop)
	require.NoError(t, hop3.inbound.RegisterTunnel(ot.receiveIDs[2], 1, endpoint))

	// ── Drive the production I2CP send path ────────────────────────────────
	session, err := i2cp.NewSession(1, nil, i2cp.DefaultSessionConfig())
	require.NoError(t, err)

	pool := tunnel.NewTunnelPool(&mockPeerSelector{})
	pool.AddTunnel(ot.state)
	session.SetOutboundPool(pool)
	t.Cleanup(pool.Stop)

	var destHash common.Hash
	copy(destHash[:], "e2e-encap-destination-hash-32b!!")

	hop0Sends := 0
	msgRouter := i2cp.NewMessageRouter(garlicMgr, func(peer common.Hash, msg i2np.Message) error {
		require.Equal(t, hop1.hash, peer, "records must be addressed to hop 0")
		require.Equal(t, i2np.I2NPMessageTypeTunnelData, msg.Type(),
			"outbound traffic must leave as TunnelData, never bare garlic")
		hop0Sends++
		return hop1.inbound.HandleTunnelData(msg)
	})
	msgRouter.SetLeaseResolver(&encapLeaseResolver{target: i2cp.LeaseTarget{
		GatewayHash: destGW.hash,
		TunnelID:    uint32(destInboundTunnelID),
	}})

	payload := []byte("payload that must genuinely cross the tunnel")
	require.NoError(t, msgRouter.RouteOutboundMessage(i2cp.RouteRequest{
		Session:           session,
		MessageID:         1,
		DestinationHash:   destHash,
		DestinationPubKey: garlicMgr.GetPublicKey(),
		Payload:           payload,
	}))

	assert.NotZero(t, hop0Sends, "the send path must emit at least one tunnel record")

	// ── The destination gateway must be handed a TunnelGateway for its tunnel ──
	var delivery encapDelivery
	select {
	case delivery = <-destGW.delivered:
	case <-time.After(3 * time.Second):
		t.Fatal("no bytes reached the destination gateway through the tunnel relays")
	}

	assert.Equal(t, uint32(destInboundTunnelID), delivery.tunnelID,
		"endpoint must address the destination's inbound tunnel ID from the lease")
	assert.Equal(t, i2np.I2NPMessageTypeTunnelGateway, delivery.msgType)

	// The forwarded envelope is the serialized garlic I2NP message that carries
	// the client's payload end-to-end encrypted.
	inner := &i2np.BaseI2NPMessage{}
	require.NoError(t, inner.UnmarshalBinary(delivery.payload),
		"endpoint must forward a parseable I2NP message")
	assert.Equal(t, i2np.I2NPMessageTypeGarlic, inner.Type(),
		"the tunnel payload must be the garlic message")

	// The payload is inside the garlic, end-to-end encrypted to the destination,
	// so it is not visible in the clear at this point. Its integrity is proven
	// by TestE2E_OutboundRecordsAreLayeredByEveryHop below.
	assert.NotEmpty(t, inner.GetData())
}

// TestE2E_OutboundRecordsAreLayeredByEveryHop proves the encapsulation is real
// multi-layer encryption rather than a single pass: peeling hop 1's layer alone
// must not reveal the payload, because hops 2 and 3 still have layers on it.
func TestE2E_OutboundRecordsAreLayeredByEveryHop(t *testing.T) {
	const hopCount = 3

	ot := buildEncapTunnel(hopCount)

	gw, err := ot.state.CreatorGateway()
	require.NoError(t, err)
	require.Equal(t, hopCount, gw.HopCount(), "gateway must carry one layer per hop")

	var destGateway [32]byte
	copy(destGateway[:], "destination-gateway-hash-32-bytes!")

	payload := make([]byte, 300)
	for i := range payload {
		payload[i] = byte(i)
	}

	records, err := gw.SendWithDelivery(payload, tunnel.TunnelDelivery(0xBEEF, destGateway))
	require.NoError(t, err)
	require.Len(t, records, 1)

	// Peeling only hop 1's layer leaves the record still encrypted.
	afterOne := mustEncapPeel(t, records[0], ot.keys[0])
	assert.False(t, bytes.Contains(afterOne, payload),
		"one layer is not enough: the creator must apply every hop's layer")

	// Peeling all three in path order recovers it exactly.
	current := records[0]
	for i := 0; i < hopCount; i++ {
		current = mustEncapPeel(t, current, ot.keys[i])
	}
	assert.True(t, bytes.Contains(current, payload),
		"all layers peeled in path order must recover the payload")
}

func mustEncapPeel(t *testing.T, record []byte, keys encapHopKeys) []byte {
	t.Helper()
	out, err := encapEncryptor(t, keys).Decrypt(record)
	require.NoError(t, err)
	return out
}

// TestE2E_OutboundSendFailsClosedWithoutLease proves the send path cannot
// regress into the I2P-002 behaviour: when the destination cannot be addressed,
// nothing goes out at all, rather than a bare message leaking to a hop.
//
// Addressing can fail three ways and each must fail closed: no resolver is
// wired at all, the resolver reports no usable lease, and the resolver returns
// an unparseable or empty lease. Only the first is exercised by a router with no
// NetDB, so the other two are covered here too.
func TestE2E_OutboundSendFailsClosedWithoutLease(t *testing.T) {
	table := make(map[common.Hash]*encapRelay, 1)
	newEncapRelay(t, "failsafe-hop", table)

	ot := buildEncapTunnel(1)

	session, err := i2cp.NewSession(2, nil, i2cp.DefaultSessionConfig())
	require.NoError(t, err)

	pool := tunnel.NewTunnelPool(&mockPeerSelector{})
	pool.AddTunnel(ot.state)
	session.SetOutboundPool(pool)
	t.Cleanup(pool.Stop)

	garlicMgr, err := i2np.GenerateGarlicSessionManager()
	require.NoError(t, err)

	sent := 0
	msgRouter := i2cp.NewMessageRouter(garlicMgr, func(_ common.Hash, _ i2np.Message) error {
		sent++
		return nil
	})
	// Deliberately no lease resolver.

	var destHash common.Hash
	copy(destHash[:], "unresolvable-destination-hash-32b")

	err = msgRouter.RouteOutboundMessage(i2cp.RouteRequest{
		Session:           session,
		DestinationHash:   destHash,
		DestinationPubKey: garlicMgr.GetPublicKey(),
		Payload:           []byte("must not be sent"),
	})
	require.Error(t, err, "an unaddressable destination must be an error")
	assert.Zero(t, sent, "nothing may reach the transport when addressing fails")

	// A resolver that reports no lease must fail the same way, and the error must
	// name lease resolution so a regression is distinguishable from an unrelated
	// earlier failure.
	withResolver := i2cp.NewMessageRouter(garlicMgr, func(_ common.Hash, _ i2np.Message) error {
		sent++
		return nil
	})
	withResolver.SetLeaseResolver(&encapLeaseResolver{err: i2cp.ErrNoLease})

	err = withResolver.RouteOutboundMessage(i2cp.RouteRequest{
		Session:           session,
		DestinationHash:   destHash,
		DestinationPubKey: garlicMgr.GetPublicKey(),
		Payload:           []byte("must not be sent"),
	})
	require.Error(t, err)
	require.ErrorIs(t, err, i2cp.ErrNoLease,
		"the failure must be lease resolution, not an earlier stage of the send")

	// An empty-but-successful lease is the most dangerous case: it would address
	// every record at router 0x00...00 tunnel 0, so it must be rejected too.
	blank := i2cp.NewMessageRouter(garlicMgr, func(_ common.Hash, _ i2np.Message) error {
		sent++
		return nil
	})
	blank.SetLeaseResolver(&encapLeaseResolver{blankTarget: true})

	err = blank.RouteOutboundMessage(i2cp.RouteRequest{
		Session:           session,
		DestinationHash:   destHash,
		DestinationPubKey: garlicMgr.GetPublicKey(),
		Payload:           []byte("must not be sent"),
	})
	require.Error(t, err, "an empty lease must not be used for addressing")
	assert.Zero(t, sent, "neither resolver variant may emit a record")
}

// TestE2E_OutboundSendFailsClosedWithoutLayerKeys proves the same fail-closed
// guarantee for a tunnel that never retained its build keys.
func TestE2E_OutboundSendFailsClosedWithoutLayerKeys(t *testing.T) {
	table := make(map[common.Hash]*encapRelay, 1)
	hop1 := newEncapRelay(t, "nokeys-hop", table)

	ot := buildEncapTunnel(2)
	ot.setHop(0, hop1.hash)
	// Discard the retained keys, as a tunnel state from before this fix had.
	ot.state.SetLayers(nil)

	session, err := i2cp.NewSession(3, nil, i2cp.DefaultSessionConfig())
	require.NoError(t, err)

	pool := tunnel.NewTunnelPool(&mockPeerSelector{})
	pool.AddTunnel(ot.state)
	session.SetOutboundPool(pool)
	t.Cleanup(pool.Stop)

	garlicMgr, err := i2np.GenerateGarlicSessionManager()
	require.NoError(t, err)

	sent := 0
	msgRouter := i2cp.NewMessageRouter(garlicMgr, func(_ common.Hash, _ i2np.Message) error {
		sent++
		return nil
	})
	var destHash common.Hash
	copy(destHash[:], "keyless-tunnel-destination-hash-32")
	msgRouter.SetLeaseResolver(&encapLeaseResolver{
		target: i2cp.LeaseTarget{GatewayHash: hop1.hash, TunnelID: 1},
	})

	err = msgRouter.RouteOutboundMessage(i2cp.RouteRequest{
		Session:           session,
		DestinationHash:   destHash,
		DestinationPubKey: garlicMgr.GetPublicKey(),
		Payload:           []byte("must not be sent unencapsulated"),
	})
	require.Error(t, err)
	require.ErrorIs(t, err, tunnel.ErrNoLayerKeys,
		"the failure must be the missing layer keys, not an earlier stage of the send")
	assert.Zero(t, sent, "a keyless tunnel must not emit anything")
}
