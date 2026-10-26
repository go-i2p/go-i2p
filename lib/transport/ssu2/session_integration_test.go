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

package ssu2

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	i2pbase64 "github.com/go-i2p/common/base64"
	"github.com/go-i2p/common/data"
	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/go-i2p/go-i2p/lib/testutil"
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

// buildSSU2RouterInfoForTest creates a RouterInfo with an SSU2 address that
// includes the static key parameter (s=), matching the production code's
// addStaticKeyOption behavior. This is required for go-noise's
// verifyPeerRouterInfoStaticKey check during handshake.
func buildSSU2RouterInfoForTest(t testing.TB, staticPrivKey []byte, addr string, port int, introKey []byte) []byte {
	t.Helper()

	// Derive the public static key from the private key (mirroring addStaticKeyOption)
	pub, err := curve25519.X25519(staticPrivKey, curve25519.Basepoint)
	require.NoError(t, err, "failed to derive public key")

	// Build SSU2 options with the static key, intro key, host, and port
	ssu2Options := map[string]string{
		"host": addr,
		"port": fmt.Sprintf("%d", port),
		"v":    "2",
		"s":    i2pbase64.EncodeToString(pub),
		"i":    i2pbase64.EncodeToString(introKey),
	}

	// Use testutil to create a RouterInfo with an SSU2 address
	addrCfg := &testutil.RouterAddressConfig{
		Cost:       3,
		Expiration: time.Now().Add(24 * time.Hour),
		Transport:  "SSU2",
		Options:    ssu2Options,
	}

	ri := testutil.CreateSignedTestRouterInfo(t, nil, addrCfg)
	riBytes, err := ri.Bytes()
	require.NoError(t, err, "failed to serialize RouterInfo")

	return riBytes
}

// loopbackPair creates a server (responder) and client (initiator) SSU2Conn
// pair connected over loopback UDP, performs the XK handshake, and returns both
// established connections.
//
// The responder side is built with the upstream [ssu2noise.SSU2Listener], which
// is how production establishes inbound SSU2 sessions (see startSSU2Listener in
// transport.go). This matters for spec compliance: ssu2.rst:1537-1538 requires
// SessionCreated's Source Connection ID to be the Destination Connection ID the
// initiator put in its Session Request, and ssu2.rst:1587-1588 requires the
// initiator to drop a SessionCreated whose IDs do not mirror the Session
// Request. The listener adopts the Session Request's destination ID as the
// responder's own connection ID (go-noise listener.go responderConnID /
// buildConnConfig), so the SessionCreated echoes correctly. A responder
// constructed directly with NewSSU2Conn uses its own locally generated ID
// instead, and the initiator's destination ID is generated randomly inside
// go-noise with no external setter, so a direct-conn harness can never satisfy
// the mirror requirement.
//
// The caller is responsible for closing both connections.
func loopbackPair(t testing.TB, ctx context.Context) (serverConn, clientConn *ssu2noise.SSU2Conn) {
	t.Helper()

	// The responder-side SessionConfirmed inbound header protector is installed
	// asynchronously on the listener path: go-noise fires
	// SSU2Conn.notifySessConfirmedKey (ssu2/session/conn_handshake.go) into a
	// buffered channel, and a separate listener goroutine receives it and calls
	// AcceptedSessionRegistry.SetSessionConfirmedProtector (ssu2/server/
	// listener.go). AcceptedSessionRegistry.TrialDeobfuscate can only match a
	// session whose protector is already installed, so on loopback Alice's
	// SessionConfirmed can arrive in the window before the install lands and be
	// dropped. This is a scheduling race, not a packet-loss race: a real RouterInfo
	// here is 650 bytes, which fits a single fragment (sessionConfirmedMaxPerPacket
	// is 1216), so exactly one packet has to arrive after the install.
	//
	// The drop is unrecoverable because ssu2.rst:1965 ("If Alice does not receive an
	// ACK of packet number 0, she must retransmit all session confirmed packets
	// as-is") is not implemented: go-noise's initiator calls sendSessionConfirmed
	// and then finalizeHandshake with no further socket reads, so it never learns
	// the responder is still waiting. The responder retransmits SessionCreated
	// several times to no effect and times out.
	//
	// That is go-noise's handshake state machine, so it is reported upstream rather
	// than patched here. These tests assert on go-i2p session behaviour, not on the
	// handshake, so retrying pair setup bounds the race without weakening any
	// assertion about this repository.
	const maxPairAttempts = 5
	var lastErr error
	for attempt := 1; attempt <= maxPairAttempts; attempt++ {
		// Honour caller cancellation between attempts so a test that is already
		// being torn down cannot be pinned by a retry.
		if err := ctx.Err(); err != nil {
			if lastErr == nil {
				lastErr = err
			}
			break
		}
		connPair, err := attemptLoopbackPair(t)
		if err == nil {
			return connPair.server, connPair.client
		}
		lastErr = err
		t.Logf("loopback pair attempt %d/%d failed (known go-noise listener SC-protector race): %v",
			attempt, maxPairAttempts, err)
	}
	require.NoErrorf(t, lastErr, "SSU2 loopback pair handshake failed after %d attempts", maxPairAttempts)
	return nil, nil
}

type establishedPair struct {
	server *ssu2noise.SSU2Conn
	client *ssu2noise.SSU2Conn
}

// pairHandshakeTimeout bounds one handshake attempt. It is deliberately short:
// the handshake normally completes in about 5ms over loopback, so a whole budget
// means the attempt hit the upstream race and a retry is cheaper than waiting.
const pairHandshakeTimeout = 4 * time.Second

func attemptLoopbackPair(t testing.TB) (establishedPair, error) {
	t.Helper()

	// Deliberately NOT derived from the caller's context. That context bounds the
	// session's whole lifetime (tests pass it to NewSSU2Session), so letting a
	// doomed handshake consume it starves every retry: with the 5s some tests use,
	// one attempt's 7s retransmit schedule alone exhausts it. Each attempt gets a
	// fresh budget instead, and a healthy loopback handshake finishes in ~5ms, so
	// the budget only ever matters when the attempt is already lost.
	hsCtx, hsCancel := context.WithTimeout(context.Background(), pairHandshakeTimeout)
	defer hsCancel()

	serverPriv, serverPub := genKey(t)
	clientPriv, _ := genKey(t)
	serverHash := genRouterHash(t)
	clientHash := genRouterHash(t)

	serverIntroKey := make([]byte, 32)
	if _, err := rand.Read(serverIntroKey); err != nil {
		return establishedPair{}, err
	}
	clientIntroKey := make([]byte, 32)
	if _, err := rand.Read(clientIntroKey); err != nil {
		return establishedPair{}, err
	}

	// Bind server socket first so the client knows where to connect.
	serverPC, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		return establishedPair{}, err
	}
	serverAddr := serverPC.LocalAddr().(*net.UDPAddr)

	// Everything below is released on the failure path so a retried attempt does
	// not leak a listener, two sockets and two handshake goroutines.
	cleanup := func(conns ...io.Closer) {
		for _, c := range conns {
			if c != nil {
				_ = c.Close()
			}
		}
	}

	// Server config (responder). The listener owns the socket and adopts the
	// initiator's Session Request destination ID per session, so no
	// WithConnectionID is set here.
	serverCfg, err := ssu2noise.NewSSU2Config(serverHash, false)
	if err != nil {
		cleanup(serverPC)
		return establishedPair{}, err
	}
	serverCfg = serverCfg.
		WithStaticKey(serverPriv).
		WithHandshakeTimeout(pairHandshakeTimeout).
		WithDestroyTimeout(100 * time.Millisecond).
		WithRouterInfoValidator(func(routerInfo, authenticatedStaticKey []byte) error {
			return nil
		})
	serverCfg.IntroKey = serverIntroKey
	// WORKAROUND for an upstream go-noise gap (reported, not fixed here): per
	// ssu2.rst:751 and :2026 the Data-phase header key k_header_1 is the
	// RECEIVER's intro key, so a responder must seal outbound Data with
	// Alice's intro key, which it learns from the "i" parameter of the
	// RouterInfo carried in SessionConfirmed. go-noise never extracts it:
	// ssu2/handshake/session_confirmed.go has no intro-key handling, and
	// wire.HeaderProtectorManager.SetRemoteIntroKey (ssu2/wire/header_keys.go:281)
	// is unreachable because SSU2Conn exposes no accessor for its protector
	// manager. Without this, the listener-accepted responder cannot send a
	// single data-phase packet and fails with
	// "remote intro key required for Data phase k_header_1". Production wires
	// the same value via the dial path (transport.go applyRemotePeerConfig),
	// so supplying it here mirrors production rather than weakening the test.
	serverCfg.RemoteIntroKey = clientIntroKey

	listener, err := ssu2noise.NewSSU2Listener(serverPC, serverCfg)
	if err != nil {
		cleanup(serverPC)
		return establishedPair{}, err
	}
	if err := listener.Start(); err != nil {
		cleanup(listener, serverPC)
		return establishedPair{}, err
	}

	// Accept the inbound session in the background and drive the responder half
	// of the XK handshake. Accept() returns the not-yet-established connection
	// with the Session Request already buffered in its receive queue.
	type acceptResult struct {
		conn *ssu2noise.SSU2Conn
		err  error
	}
	acceptCh := make(chan acceptResult, 1)
	go func() {
		c, aerr := listener.Accept()
		if aerr != nil {
			acceptCh <- acceptResult{err: aerr}
			return
		}
		sc, ok := c.(*ssu2noise.SSU2Conn)
		if !ok {
			acceptCh <- acceptResult{err: fmt.Errorf("accepted conn is not *ssu2noise.SSU2Conn: %T", c)}
			return
		}
		if herr := sc.Handshake(hsCtx); herr != nil {
			acceptCh <- acceptResult{conn: sc, err: herr}
			return
		}
		acceptCh <- acceptResult{conn: sc}
	}()

	// Bind client socket so the server knows the client's address.
	clientPC, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		cleanup(listener, serverPC)
		return establishedPair{}, err
	}
	clientAddr := clientPC.LocalAddr().(*net.UDPAddr)

	// Client config (initiator) - must know server's public key for XK.
	clientCfg, err := ssu2noise.NewSSU2Config(clientHash, true)
	if err != nil {
		cleanup(clientPC, listener, serverPC)
		return establishedPair{}, err
	}
	clientConnID, err := ssu2noise.GenerateConnectionID()
	if err != nil {
		cleanup(clientPC, listener, serverPC)
		return establishedPair{}, err
	}
	var serverPubHash data.Hash
	copy(serverPubHash[:], serverPub)

	// Build client RouterInfo with an SSU2 address containing the static key so
	// the responder can bind the Noise-authenticated key to the advertised RI.
	clientRouterInfo := buildSSU2RouterInfoForTest(t, clientPriv, clientAddr.IP.String(), clientAddr.Port, clientIntroKey)

	clientCfg = clientCfg.WithStaticKey(clientPriv).
		WithConnectionID(clientConnID).
		WithDestroyTimeout(100 * time.Millisecond).
		WithRemoteRouterHash(serverPubHash).
		WithRemoteStaticKey(serverPub).
		WithLocalRouterInfo(clientRouterInfo)
	clientCfg.IntroKey = clientIntroKey
	clientCfg.RemoteIntroKey = serverIntroKey

	// Dial over the client's own socket; the listener is the sole reader of the
	// server socket, so only the initiator needs an explicit handshake call.
	clientConn, err := ssu2noise.DialSSU2WithConn(clientPC, serverAddr, clientCfg)
	if err != nil {
		cleanup(clientPC, listener, serverPC)
		return establishedPair{}, err
	}

	start := time.Now()
	cErr := clientConn.Handshake(hsCtx)
	t.Logf("handshake took %v (client err: %v)", time.Since(start), cErr)
	if cErr != nil {
		cleanup(clientConn, clientPC, listener, serverPC)
		return establishedPair{}, cErr
	}

	var serverConn *ssu2noise.SSU2Conn
	select {
	case res := <-acceptCh:
		if res.err != nil {
			cleanup(res.conn, clientConn, clientPC, listener, serverPC)
			return establishedPair{}, res.err
		}
		serverConn = res.conn
	case <-hsCtx.Done():
		cleanup(clientConn, clientPC, listener, serverPC)
		return establishedPair{}, fmt.Errorf("waiting for listener accept/handshake: %w", hsCtx.Err())
	}

	if serverConn == nil {
		cleanup(clientConn, clientPC, listener, serverPC)
		return establishedPair{}, fmt.Errorf("listener returned no connection")
	}

	// Sanity check the spec invariant the restructure exists to satisfy: the
	// responder's connection ID must be the one the initiator used as its
	// Session Request destination, i.e. the SessionCreated source echoed back.
	if serverConn.GetSSU2Addr().ConnectionID() == 0 {
		cleanup(serverConn, clientConn, clientPC, listener, serverPC)
		return establishedPair{}, fmt.Errorf("responder connection ID must be non-zero")
	}

	// Success: hand the resources to the caller's cleanup so the established
	// pair survives for the duration of the test.
	t.Cleanup(func() {
		cleanup(serverConn, clientConn, clientPC, listener, serverPC)
	})
	return establishedPair{server: serverConn, client: clientConn}, nil
}

// establishedSessionPair builds an SSU2 session pair over loopback UDP and
// verifies that both data directions actually work before returning it.
//
// The verification is not redundant with the tests that use it. go-noise installs
// a listener-accepted session's data-phase inbound header protector from a
// separate goroutine: SSU2Conn.notifyRecvDataKey (ssu2/session/conn_handshake.go)
// does a *non-blocking* send (select with a default branch) into a buffered
// channel that only exists after the listener calls
// SetAcceptedDataKeyNotify (ssu2/server/listener.go), and the receiving goroutine
// then calls AcceptedSessionRegistry.SetDataPhaseProtector. If the notify runs
// before the channel is wired, the protector is never installed for that session,
// and AcceptedSessionRegistry.TrialDeobfuscate silently drops every inbound Data
// packet it can no longer deobfuscate.
//
// That failure is permanent for the session, not a microsecond window: the sender
// has no delivery feedback and data packets are retransmitted only on RTO expiry
// for unACKed packets, so a message the peer cannot even deobfuscate is lost for
// good. Retrying the send therefore cannot recover it; only re-establishing the
// session can. That is why the readiness probe lives here, in the pair
// establishment loop, rather than in the tests' send path.
//
// go-noise's own suite does not cover this because it has no test that delivers
// data over a listener-accepted session. The defect is reported upstream rather
// than patched here, since the fix belongs in go-noise's handshake/listener
// state machine.
//
// The caller's ctx bounds session lifetime, not establishment: each attempt uses
// its own probe deadline and cancellation is only checked between attempts, so one
// slow attempt cannot starve the rest.
func establishedSessionPair(t testing.TB, ctx context.Context, name string) (serverSess, clientSess *SSU2Session) {
	t.Helper()

	const maxPairAttempts = 5
	const probeTimeout = 2 * time.Second

	var lastErr error
	for attempt := 1; attempt <= maxPairAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			if lastErr == nil {
				lastErr = err
			}
			break
		}

		connPair, err := attemptLoopbackPair(t)
		if err != nil {
			lastErr = err
			t.Logf("session pair attempt %d/%d handshake failed: %v", attempt, maxPairAttempts, err)
			continue
		}

		l := newTestLogger(name)
		srv := NewSSU2Session(connPair.server, ctx, l)
		clt := NewSSU2Session(connPair.client, ctx, l)

		// Close is idempotent (CloseOnce) and closes the underlying connection, so
		// a rejected attempt releases the sockets and the AcceptedSessionRegistry
		// entry via go-noise's close hook.
		if perr := probeSessionPairReady(srv, clt, probeTimeout); perr != nil {
			_ = srv.Close()
			_ = clt.Close()
			lastErr = perr
			t.Logf("session pair attempt %d/%d not data-ready (go-noise protector install race): %v",
				attempt, maxPairAttempts, perr)
			continue
		}

		t.Cleanup(func() {
			_ = srv.Close()
			_ = clt.Close()
		})
		if attempt > 1 {
			t.Logf("session pair established on attempt %d/%d", attempt, maxPairAttempts)
		}
		return srv, clt
	}
	require.NoErrorf(t, lastErr, "SSU2 session pair not data-ready after %d attempts", maxPairAttempts)
	return nil, nil
}

// probeSessionPairReady sends one I2NP in each direction and requires the peer to
// deliver it. It asserts nothing, so the caller can retry establishment.
func probeSessionPairReady(serverSess, clientSess *SSU2Session, timeout time.Duration) error {
	if err := probeOneDirection(clientSess, serverSess, timeout); err != nil {
		return fmt.Errorf("client to server: %w", err)
	}
	if err := probeOneDirection(serverSess, clientSess, timeout); err != nil {
		return fmt.Errorf("server to client: %w", err)
	}
	return nil
}

// probeOneDirection queues a tagged message on sender and waits for the receiver
// to deliver exactly that message.
func probeOneDirection(sender, receiver *SSU2Session, timeout time.Duration) error {
	want := []byte("readiness probe")
	if err := sender.QueueSendI2NP(newTestI2NPMessage(want)); err != nil {
		return fmt.Errorf("QueueSendI2NP: %w", err)
	}

	type outcome struct {
		msg i2np.Message
		err error
	}
	ch := make(chan outcome, 1)
	go func() {
		msg, err := receiver.ReadNextI2NP()
		ch <- outcome{msg, err}
	}()

	select {
	case res := <-ch:
		if res.err != nil {
			return fmt.Errorf("ReadNextI2NP: %w", res.err)
		}
		dc, ok := res.msg.(i2np.DataCarrier)
		if !ok {
			return fmt.Errorf("probe message does not implement DataCarrier: %T", res.msg)
		}
		if !bytes.Equal(dc.GetData(), want) {
			return fmt.Errorf("probe delivered %q, want %q", dc.GetData(), want)
		}
		return nil
	case <-time.After(timeout):
		return fmt.Errorf("probe message not delivered within %s", timeout)
	}
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

	// The session context bounds the test body only; pair establishment is
	// budgeted separately inside establishedSessionPair.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	serverSess, clientSess := establishedSessionPair(t, ctx, "ssu2_integration")

	want := []byte("hello from ssu2 client")
	msg := newTestI2NPMessage(want)

	received := sendAndReadI2NP(t, clientSess, serverSess, msg)

	assert.Equal(t, msg.Type(), received.Type(), "message type should match")
	assert.Equal(t, msg.MessageID(), received.MessageID(), "message ID should match")
	receivedDC, ok := received.(i2np.DataCarrier)
	require.True(t, ok, "received message must implement DataCarrier")
	assert.Equal(t, want, receivedDC.GetData(), "message payload should survive round-trip")
}

// TestSessionIntegration_BidirectionalI2NP extends M2 by verifying that
// both the client→server and server→client paths work in the same session.
func TestSessionIntegration_BidirectionalI2NP(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping SSU2 loopback integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	serverSess, clientSess := establishedSessionPair(t, ctx, "ssu2_bidir")

	// Client → server
	c2s := []byte("client to server")
	got := sendAndReadI2NP(t, clientSess, serverSess, newTestI2NPMessage(c2s))
	gotDC, ok := got.(i2np.DataCarrier)
	require.True(t, ok, "received c2s message must implement DataCarrier")
	assert.Equal(t, c2s, gotDC.GetData())

	// Server → client
	s2c := []byte("server to client")
	got2 := sendAndReadI2NP(t, serverSess, clientSess, newTestI2NPMessage(s2c))
	got2DC, ok := got2.(i2np.DataCarrier)
	require.True(t, ok, "received s2c message must implement DataCarrier")
	assert.Equal(t, s2c, got2DC.GetData())
}

// ----- M3: Fragment reassembly + delivery ---------------------------------------

// sendAndReadI2NP queues msg on sender and returns the message the receiver
// delivers, failing with a clear error rather than hanging if it never arrives.
//
// establishedSessionPair already verified both data directions work, so no retry
// is needed here: a message that fails to arrive now indicates a real defect in
// the path under test, not the go-noise protector-install race. That is what makes
// this helper strict - it bounds the wait so a dropped packet fails the test
// instead of blocking ReadNextI2NP until the package test timeout.
func sendAndReadI2NP(t testing.TB, sender, receiver *SSU2Session, msg i2np.Message) i2np.Message {
	t.Helper()

	const readTimeout = 10 * time.Second

	require.NoError(t, sender.QueueSendI2NP(msg), "QueueSendI2NP() error")

	// A buffered channel of size 1 so the reader never blocks on delivery after
	// the test has already moved on or failed.
	msgCh := make(chan i2np.Message, 1)
	go func() {
		got, err := receiver.ReadNextI2NP()
		if err != nil {
			t.Logf("ReadNextI2NP stopped: %v", err)
			return
		}
		msgCh <- got
	}()

	select {
	case got := <-msgCh:
		return got
	case <-time.After(readTimeout):
		t.Fatalf("message not delivered within %s after session readiness was established", readTimeout)
		return nil
	}
}

func TestFragmentIntegration_LargeMessage(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping SSU2 fragment integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	serverSess, clientSess := establishedSessionPair(t, ctx, "ssu2_fragment")

	// Generate a payload that forces fragmentation (larger than 1440 bytes).
	largePayload := make([]byte, 3000)
	_, err := rand.Read(largePayload)
	require.NoError(t, err)

	msg := newTestI2NPMessage(largePayload)

	// 3000 bytes exceeds the SSU2 IPv4 payload maximum, so this exercises the
	// fragmentation the plain round-trip tests do not: the send path splits the
	// message through fragmentSSU2Short and the peer reassembles it. Verified by
	// mutation: dropping a follow-on fragment in fragmentSSU2Short fails here.
	received := sendAndReadI2NP(t, clientSess, serverSess, msg)

	assert.Equal(t, msg.Type(), received.Type(), "fragmented message type should match")
	assert.Equal(t, msg.MessageID(), received.MessageID(), "fragmented message ID should match")
	receivedDC, ok := received.(i2np.DataCarrier)
	require.True(t, ok, "received message must implement DataCarrier")
	assert.Equal(t, largePayload, receivedDC.GetData(), "reassembled payload should match original")
}

// TestSessionIntegration_CloseTerminatesSession verifies that closing the
// client session causes ReadNextI2NP on the server to eventually unblock (or
// the server session detects the close via the Termination callback).
func TestSessionIntegration_CloseTerminatesSession(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping SSU2 close integration test in short mode")
	}

	// Deliberately no deadline on the session context. This test asserts that the
	// context is cancelled, and a shared deadline would make that assertion pass
	// vacuously when the budget merely expires - which is exactly what happened
	// when establishment and delivery retries were allowed to outrun a fixed
	// session budget. Cancellation now has only one possible cause: the peer
	// termination callback.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverSess, clientSess := establishedSessionPair(t, ctx, "ssu2_close")

	// Close the client; the server session should detect termination. establishedSessionPair
	// already proved both data directions work, so the session is live here.
	require.NoError(t, clientSess.Close())

	// Poll for the termination block instead of sleeping a fixed interval: the
	// delivery is asynchronous, and a bare sleep makes the test both slower and
	// timing-dependent.
	deadline := time.Now().Add(5 * time.Second)
	var serr error
	for time.Now().Before(deadline) {
		serr = serverSess.GetContext().Err()
		if serr != nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Assert the specific cause, not merely that an error occurred.
	require.Error(t, serr, "server session context should be cancelled after peer termination")
	assert.True(t, errors.Is(serr, context.Canceled),
		"server session should be cancelled by the peer termination callback, got %v", serr)
}
