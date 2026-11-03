// End-to-end test: two routers must be able to connect in BOTH directions.
//
// Finding 004 made inbound NTCP2 unusable: the accepted-connection path ran the
// generic length-prefixed Noise handshake instead of the NTCP2 wire handshake,
// so no peer could ever complete a session with a go-i2p router. A single-pair
// test that only dials outbound cannot catch that, because the defect lived
// entirely on the responder side. This test therefore runs the same dial twice
// with the roles swapped, so each router's inbound accept path is exercised,
// and pins that both directions establish a real session and deliver a
// connection to Accept().
//
// The transports are built the way lib/router builds them (NewNTCP2Transport
// from a signed RouterInfo + keystore), so the test covers the production
// construction path, not just the go-noise handshake primitives.

package ntcp2

import (
	"net"
	"testing"
	"time"

	i2pbase64 "github.com/go-i2p/common/base64"
	"github.com/go-i2p/common/router_address"
	"github.com/go-i2p/common/router_info"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ntcp2PeerPair is two live transports that know each other's reachable address.
type ntcp2PeerPair struct {
	a *NTCP2Transport
	b *NTCP2Transport
	// aRI/bRI advertise the transport's real bound host/port plus the s=, i= and
	// v= options a dialer requires (ntcp2.rst:1861-1862).
	aRI router_info.RouterInfo
	bRI router_info.RouterInfo
}

// newNTCP2PeerPair builds two NTCP2 transports on loopback with distinct static
// keys, each publishing a dialable NTCP2 address for the other.
func newNTCP2PeerPair(t *testing.T) ntcp2PeerPair {
	t.Helper()

	// Two distinct, valid Curve25519 private keys.
	privA := make([]byte, 32)
	privB := make([]byte, 32)
	for i := range privA {
		privA[i] = byte(i + 1)
		privB[i] = byte(i + 101)
	}

	a := newFallbackIntegrationTransport(t, "127.0.0.1:0", privA)
	b := newFallbackIntegrationTransport(t, "127.0.0.1:0", privB)

	return ntcp2PeerPair{
		a:   a,
		b:   b,
		aRI: publishLiveNTCP2Address(t, a),
		bRI: publishLiveNTCP2Address(t, b),
	}
}

// publishLiveNTCP2Address returns a peer's RouterInfo with its NTCP2 address
// rewritten to the address the transport is actually listening on, carrying the
// s=, i= and v= options every dialer validates.
//
// The transport's own identity advertises the port it was *configured* with,
// which is 0 when the OS assigned the port, and no IV. That is fine as a local
// identity but cannot be dialed, so the dial-target copy is rebuilt here the way
// the router does when it publishes an address after binding.
func publishLiveNTCP2Address(t *testing.T, tr *NTCP2Transport) router_info.RouterInfo {
	t.Helper()

	peerRI := tr.identity

	host, port, err := net.SplitHostPort(tr.Addr().String())
	require.NoError(t, err)

	cfg := tr.config.Load()
	require.NotNil(t, cfg)
	require.NotNil(t, cfg.Config)
	require.Len(t, cfg.Config.ObfuscationIV, 16, "published NTCP2 addresses carry the obfuscation IV")

	// Derive the s= value from the live static key rather than trusting the
	// fixture's, so the published address cannot drift from what the handshake
	// authenticates.
	staticPub, err := validateAndExtractStaticKey(tr)
	require.NoError(t, err)

	options := map[string]string{
		"host": host,
		"port": port,
		"s":    staticPub,
		"i":    i2pbase64.I2PEncoding.EncodeToString(cfg.Config.ObfuscationIV),
		"v":    "2",
	}
	addr, err := router_address.NewRouterAddress(3, time.Now().Add(24*time.Hour), "NTCP2", options)
	require.NoError(t, err)

	live, remainder, err := router_info.ReadRouterInfo(mustRouterInfoBytes(t, peerRI))
	require.NoError(t, err)
	require.Len(t, remainder, 0)
	// Replace the fixture's port-0 address instead of adding a second candidate,
	// so the dialer has exactly one address to try.
	addresses := live.RouterAddresses()
	require.NotEmpty(t, addresses)
	addresses[0] = addr

	return live
}

func mustRouterInfoBytes(t *testing.T, ri router_info.RouterInfo) []byte {
	t.Helper()
	b, err := ri.Bytes()
	require.NoError(t, err)
	return b
}

// dialOneWay has dialer open an NTCP2 session to listener and proves both ends
// completed a real handshake: the dialer got a session, the listener delivered a
// connection out of Accept(), and the listener authenticated the dialer's msg3
// RouterInfo enough to count the session.
func dialOneWay(t *testing.T, dialer, listener *NTCP2Transport, target router_info.RouterInfo) {
	t.Helper()

	// The listener's accept runner starts lazily on the first Accept() call, and
	// msg1/msg2 interleave with the handshake, so Accept must run concurrently
	// with the dial. The delivered connection is left open on purpose: closing it
	// would tear down the session the assertions below are about. Transport Close
	// reclaims it when the test ends.
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			acceptErr <- err
			return
		}
		_ = conn
		acceptErr <- nil
	}()

	session, err := dialer.GetSession(target)
	if err != nil {
		var listenerErr error
		select {
		case listenerErr = <-acceptErr:
		default:
		}
		require.FailNowf(t, "inbound NTCP2 handshake failed",
			"dialer GetSession: %v\nlistener Accept: %v", err, listenerErr)
	}
	require.NotNil(t, session)

	select {
	case listenerErr := <-acceptErr:
		require.NoErrorf(t, listenerErr, "listener must deliver the inbound connection to Accept()")
	case <-time.After(10 * time.Second):
		t.Fatal("listener never delivered the inbound connection to Accept()")
	}

	assert.EqualValues(t, 1, listener.GetSessionCount(),
		"the inbound connection must become exactly one session on the listener")
	assert.EqualValues(t, 1, dialer.GetSessionCount(),
		"the outbound connection must become exactly one session on the dialer")

	require.NoError(t, session.Close())
}

// TestNTCP2TwoRoutersConnectInBothDirections is the end-to-end regression test
// for finding 004. Both directions are required: the defect was that the
// responder (inbound) side spoke a different protocol than the initiator, so an
// outbound-only test passes even when inbound is completely broken.
//
// Fresh transports are used for each direction, because once a session exists in
// either direction GetSession returns it instead of dialing — which would let a
// broken inbound path hide behind the session established in the first leg.
func TestNTCP2TwoRoutersConnectInBothDirections(t *testing.T) {
	t.Run("A dials B: B's inbound accept path", func(t *testing.T) {
		p := newNTCP2PeerPair(t)
		dialOneWay(t, p.a, p.b, p.bRI)
	})

	t.Run("B dials A: A's inbound accept path", func(t *testing.T) {
		p := newNTCP2PeerPair(t)
		dialOneWay(t, p.b, p.a, p.aRI)
	})
}

// TestNTCP2InboundRejectsUnauthenticatedPeerWithoutSession is the pre-auth
// counterpart: a peer that connects and never completes the handshake must not
// be counted as a session, and must not be able to hold the listener's accept
// path. This is the shape of the finding 004 impact where the only reachable
// inbound surface was unauthenticated.
func TestNTCP2InboundSilentConnectionDoesNotCreateSession(t *testing.T) {
	p := newNTCP2PeerPair(t)

	// Occupy the inbound handshake budget so the probe connection cannot be
	// admitted, and pin that a bare TCP connection alone never becomes a session.
	conn, err := net.Dial("tcp", p.b.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	assert.EqualValues(t, 0, p.b.GetSessionCount(),
		"an unauthenticated TCP connection must never count as a session")

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		assert.EqualValues(t, 0, p.b.GetSessionCount())
		time.Sleep(50 * time.Millisecond)
	}
}
