package ssu2

// session_integration_test.go – Integration tests for SSU2Session over loopback UDP.
//
// These tests verify M2 (loopback handshake + I2NP round-trip) and M3 (fragment
// reassembly for oversized I2NP messages) from the SSU2 integration plan.
//
// Each test spins up two SSU2Conn instances sharing a pair of UDP sockets and
// wraps them with SSU2Session objects to exercise the full send/receive path.
//
// Run with:
//
//	go test -run TestSessionIntegration ./lib/transport/ssu2/...
//	go test -run TestFragmentIntegration ./lib/transport/ssu2/...

import (
	"context"
	"crypto/rand"
	"net"
	"testing"
	"time"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/go-i2p/lib/i2np"
	ssu2noise "github.com/go-i2p/go-noise/ssu2"
	"github.com/go-i2p/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/curve25519"
)

// ----- helpers ---------------------------------------------------------------

// deriveSSU2PublicKey derives the Curve25519 public key from a private key,
// applying the curve25519 clamping convention first.
func deriveSSU2PublicKey(priv []byte) []byte {
	clamped := make([]byte, 32)
	copy(clamped, priv)
	clamped[0] &= 248
	clamped[31] &= 127
	clamped[31] |= 64
	pub, err := curve25519.X25519(clamped, curve25519.Basepoint)
	if err != nil {
		panic("curve25519.X25519: " + err.Error())
	}
	return pub
}

// genKey generates a random 32-byte private key and its public counterpart.
func genKey(t testing.TB) (priv, pub []byte) {
	t.Helper()
	priv = make([]byte, 32)
	_, err := rand.Read(priv)
	require.NoError(t, err)
	pub = deriveSSU2PublicKey(priv)
	return priv, pub
}

// genRouterHash generates a random 32-byte router identity hash.
func genRouterHash(t testing.TB) data.Hash {
	t.Helper()
	var h data.Hash
	_, err := rand.Read(h[:])
	require.NoError(t, err)
	return h
}

// loopbackPair creates a server and client SSU2Conn connected over loopback
// UDP, performs the XK handshake, and returns both established connections.
//
// The caller is responsible for closing both connections.
func loopbackPair(t testing.TB, ctx context.Context) (serverConn, clientConn *ssu2noise.SSU2Conn) {
	t.Helper()

	serverPriv, serverPub := genKey(t)
	clientPriv, _ := genKey(t)
	serverHash := genRouterHash(t)
	clientHash := genRouterHash(t)

	// Bind server socket first so the client knows where to connect.
	serverPC, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	t.Cleanup(func() { serverPC.Close() })
	serverAddr := serverPC.LocalAddr().(*net.UDPAddr)

	// Bind client socket so the server knows the client's address.
	clientPC, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	t.Cleanup(func() { clientPC.Close() })
	clientAddr := clientPC.LocalAddr().(*net.UDPAddr)

	// Server config (responder) — no RemoteRouterHash needed for responders.
	// Use permissive RouterInfo validator for tests (no real RouterInfo exchanged).
	serverCfg, err := ssu2noise.NewSSU2Config(serverHash, false)
	require.NoError(t, err)
	// Generate explicit ConnectionIDs. NewSSU2Conn generates one internally but
	// does not write it back to the config, so handshakeInitiator/handshakeResponder
	// would see ConnectionID=0. Set them before NewSSU2Conn to avoid this.
	serverConnID, err := ssu2noise.GenerateConnectionID()
	require.NoError(t, err)
	serverCfg = serverCfg.WithStaticKey(serverPriv).WithConnectionID(serverConnID).WithHandshakeTimeout(5 * time.Second).WithRouterInfoValidator(func(routerInfo, authenticatedStaticKey []byte) error {
		return nil
	})

	// Client config (initiator) — must know server's public key for XK.
	clientCfg, err := ssu2noise.NewSSU2Config(clientHash, true)
	require.NoError(t, err)
	clientConnID, err := ssu2noise.GenerateConnectionID()
	require.NoError(t, err)
	var serverPubHash data.Hash
	copy(serverPubHash[:], serverPub)
	clientCfg = clientCfg.WithStaticKey(clientPriv).WithConnectionID(clientConnID).WithRemoteRouterHash(serverPubHash).WithRemoteStaticKey(serverPub)

	// Build both connections (no handshake yet).
	serverConn, err = ssu2noise.NewSSU2Conn(serverPC, clientAddr, serverCfg, false, serverPriv, nil)
	require.NoError(t, err)

	clientConn, err = ssu2noise.NewSSU2Conn(clientPC, serverAddr, clientCfg, true, clientPriv, serverPub)
	require.NoError(t, err)

	// Run the XK handshake concurrently.
	start := time.Now()
	serverErr := make(chan error, 1)
	go func() { serverErr <- serverConn.Handshake(ctx) }()

	cErr := clientConn.Handshake(ctx)
	t.Logf("handshake took %v (client err: %v)", time.Since(start), cErr)
	require.NoError(t, cErr, "client handshake")
	sErr := <-serverErr
	t.Logf("server handshake err: %v", sErr)
	require.NoError(t, sErr, "server handshake")

	return serverConn, clientConn
}

// newTestLogger returns a logger entry suitable for test sessions.
func newTestLogger(name string) *logger.Entry {
	return logger.WithField("test", name)
}

// newTestI2NPMessage creates a valid I2NP DeliveryStatus message with the
// given payload bytes. DeliveryStatus (type 10) is the simplest I2NP type.
func newTestI2NPMessage(payload []byte) *i2np.BaseI2NPMessage {
	msg := i2np.NewBaseI2NPMessage(i2np.I2NPMessageTypeDeliveryStatus)
	msg.SetData(payload)
	return msg
}

// ----- M2: Loopback handshake + I2NP round-trip ---------------------------------

// TestSessionIntegration_ClientToServerI2NP verifies M2: a single I2NP message
// written by the client is received intact on the server side.
func TestSessionIntegration_ClientToServerI2NP(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping SSU2 loopback integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	serverConn, clientConn := loopbackPair(t, ctx)

	l := newTestLogger("ssu2_integration")
	serverSess := NewSSU2Session(serverConn, ctx, l)
	clientSess := NewSSU2Session(clientConn, ctx, l)
	defer serverSess.Close()
	defer clientSess.Close()

	want := []byte("hello from ssu2 client")
	msg := newTestI2NPMessage(want)

	sendErr := clientSess.QueueSendI2NP(msg)
	t.Logf("QueueSendI2NP err: %v", sendErr)
	require.NoError(t, sendErr)

	t.Log("waiting for ReadNextI2NP...")
	received, err := serverSess.ReadNextI2NP()
	t.Logf("ReadNextI2NP err: %v", err)
	require.NoError(t, err)

	assert.Equal(t, msg.Type(), received.Type(), "message type should match")
	wantBytes, err := msg.MarshalBinary()
	require.NoError(t, err)
	gotBytes, err := received.MarshalBinary()
	require.NoError(t, err)
	assert.Equal(t, wantBytes, gotBytes, "message payload should survive round-trip")
}

// TestSessionIntegration_BidirectionalI2NP extends M2 by verifying that
// both the client→server and server→client paths work in the same session.
func TestSessionIntegration_BidirectionalI2NP(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping SSU2 loopback integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	serverConn, clientConn := loopbackPair(t, ctx)

	l := newTestLogger("ssu2_bidir")
	serverSess := NewSSU2Session(serverConn, ctx, l)
	clientSess := NewSSU2Session(clientConn, ctx, l)
	defer serverSess.Close()
	defer clientSess.Close()

	// Client → server
	c2s := []byte("client to server")
	require.NoError(t, clientSess.QueueSendI2NP(newTestI2NPMessage(c2s)))
	got, err := serverSess.ReadNextI2NP()
	require.NoError(t, err)
	gotDC, ok := got.(i2np.DataCarrier)
	require.True(t, ok, "received c2s message must implement DataCarrier")
	assert.Equal(t, c2s, gotDC.GetData())

	// Server → client
	s2c := []byte("server to client")
	require.NoError(t, serverSess.QueueSendI2NP(newTestI2NPMessage(s2c)))
	got2, err := clientSess.ReadNextI2NP()
	require.NoError(t, err)
	got2DC, ok := got2.(i2np.DataCarrier)
	require.True(t, ok, "received s2c message must implement DataCarrier")
	assert.Equal(t, s2c, got2DC.GetData())
}

// ----- M3: Fragment reassembly --------------------------------------------------

// TestFragmentIntegration_LargeMessage verifies M3: an I2NP message whose
// serialised form exceeds a single SSU2 packet MTU is split into fragments
// by FragmentI2NPMessage and reassembled transparently by DataHandler.
//
// We send payload data that is larger than the maximum SSU2 IPv4 payload
// (1440 bytes) but still fits in a few packets.
func TestFragmentIntegration_LargeMessage(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping SSU2 fragment integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	serverConn, clientConn := loopbackPair(t, ctx)

	l := newTestLogger("ssu2_fragment")
	serverSess := NewSSU2Session(serverConn, ctx, l)
	clientSess := NewSSU2Session(clientConn, ctx, l)
	defer serverSess.Close()
	defer clientSess.Close()

	// Generate a payload that forces fragmentation (larger than 1440 bytes).
	largePayload := make([]byte, 3000)
	_, err := rand.Read(largePayload)
	require.NoError(t, err)

	msg := newTestI2NPMessage(largePayload)
	require.NoError(t, clientSess.QueueSendI2NP(msg))

	received, err := serverSess.ReadNextI2NP()
	require.NoError(t, err)

	assert.Equal(t, msg.Type(), received.Type(), "fragmented message type should match")
	wantBytes, err := msg.MarshalBinary()
	require.NoError(t, err)
	gotBytes, err := received.MarshalBinary()
	require.NoError(t, err)
	assert.Equal(t, wantBytes, gotBytes, "reassembled payload should match original")
}

// TestSessionIntegration_CloseTerminatesSession verifies that closing the
// client session causes ReadNextI2NP on the server to eventually unblock (or
// the server session detects the close via the Termination callback).
func TestSessionIntegration_CloseTerminatesSession(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping SSU2 close integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	serverConn, clientConn := loopbackPair(t, ctx)

	l := newTestLogger("ssu2_close")
	serverSess := NewSSU2Session(serverConn, ctx, l)
	clientSess := NewSSU2Session(clientConn, ctx, l)
	defer serverSess.Close()

	// Send one message to confirm the session is working.
	require.NoError(t, clientSess.QueueSendI2NP(newTestI2NPMessage([]byte("ping"))))
	_, err := serverSess.ReadNextI2NP()
	require.NoError(t, err)

	// Close the client; the server session should detect termination.
	require.NoError(t, clientSess.Close())

	// Give the termination block time to arrive.
	time.Sleep(200 * time.Millisecond)

	// Server session context should have been cancelled via OnTermination callback.
	assert.Error(t, serverSess.ctx.Err(), "server session context should be cancelled after peer termination")
}
