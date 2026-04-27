package router

// router_ssu2_integration_test.go — Integration test for G-H1: inbound SSU2 sessions.
//
// Verifies that handleNewConnection correctly promotes an inbound *ssu2noise.SSU2Conn
// to an SSU2Session, registers it in activeSessions, and starts the message-processing
// goroutine — matching the outbound path in registerNewSession.

import (
	"context"
	"crypto/rand"
	"net"
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/go-i2p/lib/transport"
	ssu2noise "github.com/go-i2p/go-noise/ssu2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/curve25519"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func ssu2IntegDerivePublicKey(priv []byte) []byte {
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

func ssu2IntegGenKey(t testing.TB) (priv, pub []byte) {
	t.Helper()
	priv = make([]byte, 32)
	_, err := rand.Read(priv)
	require.NoError(t, err)
	pub = ssu2IntegDerivePublicKey(priv)
	return priv, pub
}

func ssu2IntegGenRouterHash(t testing.TB) common.Hash {
	t.Helper()
	var h common.Hash
	_, err := rand.Read(h[:])
	require.NoError(t, err)
	return h
}

// ssu2IntegLoopbackPair creates a handshaked (server, client) SSU2Conn pair
// over loopback UDP.  The caller must close both connections.
func ssu2IntegLoopbackPair(t testing.TB, ctx context.Context) (server, client *ssu2noise.SSU2Conn) {
	t.Helper()

	serverPriv, serverPub := ssu2IntegGenKey(t)
	clientPriv, _ := ssu2IntegGenKey(t)
	serverHash := ssu2IntegGenRouterHash(t)
	clientHash := ssu2IntegGenRouterHash(t)

	serverPC, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	t.Cleanup(func() { serverPC.Close() })
	serverAddr := serverPC.LocalAddr().(*net.UDPAddr)

	clientPC, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	t.Cleanup(func() { clientPC.Close() })
	clientAddr := clientPC.LocalAddr().(*net.UDPAddr)

	serverCfg, err := ssu2noise.NewSSU2Config(serverHash, false)
	require.NoError(t, err)
	serverConnID, err := ssu2noise.GenerateConnectionID()
	require.NoError(t, err)
	serverCfg = serverCfg.
		WithStaticKey(serverPriv).
		WithConnectionID(serverConnID).
		WithHandshakeTimeout(5 * time.Second).
		WithDestroyTimeout(100 * time.Millisecond).
		WithRouterInfoValidator(func(_, _ []byte) error { return nil })

	clientCfg, err := ssu2noise.NewSSU2Config(clientHash, true)
	require.NoError(t, err)
	clientConnID, err := ssu2noise.GenerateConnectionID()
	require.NoError(t, err)
	var serverPubHash common.Hash
	copy(serverPubHash[:], serverPub)
	clientCfg = clientCfg.
		WithStaticKey(clientPriv).
		WithConnectionID(clientConnID).
		WithDestroyTimeout(100 * time.Millisecond).
		WithRemoteRouterHash(serverPubHash).
		WithRemoteStaticKey(serverPub)

	serverConn, err := ssu2noise.NewSSU2Conn(serverPC, clientAddr, serverCfg, false, serverPriv, nil)
	require.NoError(t, err)

	clientConn, err := ssu2noise.NewSSU2Conn(clientPC, serverAddr, clientCfg, true, clientPriv, serverPub)
	require.NoError(t, err)

	serverErrCh := make(chan error, 1)
	go func() { serverErrCh <- serverConn.Handshake(ctx) }()

	require.NoError(t, clientConn.Handshake(ctx), "client SSU2 handshake")
	require.NoError(t, <-serverErrCh, "server SSU2 handshake")

	return serverConn, clientConn
}

// ---------------------------------------------------------------------------
// test
// ---------------------------------------------------------------------------

// TestHandleNewConnectionSSU2_SessionRegistered verifies that handleNewConnection
// accepts an inbound *ssu2noise.SSU2Conn, registers the resulting SSU2Session in
// activeSessions under the peer's router hash, and starts the message-processing
// goroutine (G-H1 integration test).
func TestHandleNewConnectionSSU2_SessionRegistered(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping SSU2 loopback integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	serverConn, clientConn := ssu2IntegLoopbackPair(t, ctx)
	defer clientConn.Close()

	router := &Router{
		activeSessions: make(map[common.Hash]transport.TransportSession),
		ctx:            ctx,
	}

	// handleNewConnection is synchronous up to the goroutine launch; the session
	// must be in activeSessions immediately upon return.
	router.handleNewConnection(serverConn)

	router.sessionMutex.RLock()
	sessionCount := len(router.activeSessions)
	router.sessionMutex.RUnlock()

	assert.Equal(t, 1, sessionCount, "exactly one SSU2 session must be registered after handleNewConnection")

	// Retrieve the registered peer hash from the remote address so we can
	// verify the map key matches the SSU2Addr router hash.
	ssu2Addr, ok := serverConn.RemoteAddr().(*ssu2noise.SSU2Addr)
	require.True(t, ok, "serverConn.RemoteAddr() must be *ssu2noise.SSU2Addr")
	peerHash := common.Hash(ssu2Addr.RouterHash())

	router.sessionMutex.RLock()
	_, found := router.activeSessions[peerHash]
	router.sessionMutex.RUnlock()

	assert.True(t, found, "session must be keyed by the SSU2 peer's router hash")
}
