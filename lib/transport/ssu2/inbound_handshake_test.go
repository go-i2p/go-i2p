// Transport-level regression tests for finding 005: inbound SSU2 never
// handshaked, and every rejected connection stalled the accept loop for 11 s.
//
// Before the fix, SSU2Transport.Accept() returned the connection exactly as
// go-noise's listener produced it — in StateInit, holding nothing but a parsed
// SessionRequest — and nothing in the transport ever called Handshake() on it.
// The router then type-asserted that half-open connection to *ssu2noise.SSU2Conn,
// failed on the double TrackedConn wrapping, and closed it inline, paying
// go-noise's DestroyTimeout on the single goroutine that also served NTCP2.
//
// These tests drive the restructured path with a real go-noise listener and real
// UDP sockets, and pin the properties the fix is about:
//
//   - Accept() delivers an ESTABLISHED connection the router can assert on;
//   - a SessionRequest from a peer that never completes the handshake costs a
//     bounded handshake slot rather than an 11 s stall or a session slot;
//   - the transport-wide handshake budget sheds a flood without blocking;
//   - the session cap and source-address validation are published into the
//     go-noise listener, where they actually take effect.

package ssu2

import (
	"context"
	"crypto/rand"
	"net"
	"testing"
	"time"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/go-i2p/lib/transport"
	ssu2noise "github.com/go-i2p/go-noise/ssu2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Accept() must deliver an established connection
// ---------------------------------------------------------------------------

// TestAcceptDeliversEstablishedConnection is the headline regression. A real
// initiator handshaking with a real bound transport must produce a connection
// from Accept() that unwraps to an established *ssu2noise.SSU2Conn. Before the
// fix the delivered value was a StateInit shell and the router's assertion always
// failed, so no inbound SSU2 session ever completed.
func TestAcceptDeliversEstablishedConnection(t *testing.T) {
	tr, _ := newBoundSSU2TransportWith(t, func(c *Config) {
		// The listener's source-address gate is exercised by its own test below;
		// here the point is the transport's handshake path. RequireRetry is off by
		// default anyway (enabling it makes the pinned go-noise drop every
		// SessionRequest), so this is just spelling the precondition out.
		c.RequireRetry = false
	})
	defer func() { _ = tr.Close() }()

	// The accept loop runs in the background; a real router starts it from the
	// muxer's accept runner, so start it the same way here.
	go tr.startInboundAcceptRunner()

	// The transport's intro key is what seals the SessionRequest header.
	introKey := tr.GetIntroKey()
	require.Len(t, introKey, 32, "a bound transport must have an intro key")

	hsCtx, hsCancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer hsCancel()

	accepted := make(chan net.Conn, 1)
	errCh := make(chan error, 1)
	go func() {
		conn, aerr := tr.Accept()
		if aerr != nil {
			errCh <- aerr
			return
		}
		accepted <- conn
	}()

	// DialSSU2WithConn does not perform the handshake — the caller drives it with
	// Handshake(), which is exactly the step the transport used to omit.
	// The initiator must dial the transport's REAL static key: SSU2's XK handshake
	// authenticates the responder against the key the initiator expected, and the
	// transport's key comes from its keystore rather than from anything this test
	// generates.
	transportStaticPub := deriveSSU2PublicKey(tr.config.Load().SSU2Config.StaticKey)
	initiator := dialSSU2Transport(t, transportUDPAddr(t, tr), introKey, transportStaticPub)
	defer func() { _ = initiator.Close() }()
	require.NoError(t, initiator.Handshake(hsCtx), "initiator handshake must complete")

	select {
	case conn := <-accepted:
		require.NotNil(t, conn)

		// The value the router receives is transport-wrapped; unwrapping must
		// reach the concrete go-noise connection, which is what the router's
		// type assertion needs.
		inner := transport.UnwrapTrackedConn(conn)
		ssu2Conn, ok := inner.(*ssu2noise.SSU2Conn)
		require.Truef(t, ok, "unwrapped accepted conn must be *ssu2noise.SSU2Conn, got %T", inner)

		assert.Equal(t, ssu2noise.StateEstablished, ssu2Conn.GetState(),
			"Accept() must deliver an established session, not a SessionRequest-only shell")

		// The replay material the anti-replay check depends on only exists past
		// the handshake; a populated token proves the check now has real input
		// instead of always deferring. GetReplayToken returns a 32-byte
		// deterministic hash derived from the validated SessionRequest.
		assert.Len(t, ssu2Conn.GetReplayToken(), 32,
			"a post-handshake connection must expose replay material")
		assert.Len(t, ssu2Conn.GetPeerEphemeralKey(), 32,
			"a post-handshake connection must expose the peer ephemeral key")

		assert.EqualValues(t, 1, tr.reachMetrics.inboundHandshakeSuccess.Load(),
			"a completed inbound handshake must be counted")
		assert.Zero(t, tr.reachMetrics.replayChecksDeferred.Load(),
			"the replay check must have had real input rather than being deferred")
		_ = conn.Close()
	case err := <-errCh:
		t.Fatalf("Accept() failed instead of delivering an established connection: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("Accept() never delivered an inbound connection: the inbound handshake path is not working")
	}
}

// ---------------------------------------------------------------------------
// A SessionRequest that never completes must not stall anything
// ---------------------------------------------------------------------------

// TestSessionRequestWithoutHandshakeDoesNotStallAccept is the availability half of
// finding 005. One unauthenticated SessionRequest — no valid key material,
// possibly a spoofed source — used to occupy the shared inbound accept loop for
// go-noise's 11 s DestroyTimeout while the router's inline Close() waited for a
// Termination round-trip that could never arrive. The request must now cost a
// bounded handshake slot and nothing else.
func TestSessionRequestWithoutHandshakeDoesNotStallAccept(t *testing.T) {
	// Bound the handshake window so the abandoned request is released quickly, and
	// take the per-source cap out of the picture so the request is genuinely
	// admitted and reaches the handshake path, as a real peer's would. Both
	// timeouts must be set before the listener exists: go-noise copies its config
	// into every session and reads it from its packet workers.
	tr, _ := newBoundSSU2TransportWith(t, func(c *Config) {
		c.InboundHandshakeTimeout = 500 * time.Millisecond
		c.MaxHandshakesPerSource = -1
	})
	defer func() { _ = tr.Close() }()

	go tr.startInboundAcceptRunner()

	sent := time.Now()
	newSilentSessionRequest(t, transportUDPAddr(t, tr))

	// Wait for the worker to actually run the handshake and give up. The request
	// is delivered asynchronously, so admission.current() == 0 alone is true at
	// t=0 before the packet even arrives — the failure counter is what proves the
	// abandoned handshake completed its bounded wait and released its slot.
	require.Eventuallyf(t, func() bool {
		return tr.reachMetrics.inboundHandshakeFailures.Load() >= 1 &&
			tr.admission.current() == 0
	}, 5*time.Second, 10*time.Millisecond,
		"an abandoned SessionRequest must run a bounded handshake and release its slot (failures=%d in flight=%d)",
		tr.reachMetrics.inboundHandshakeFailures.Load(), tr.admission.current())

	elapsed := time.Since(sent)
	assert.Less(t, elapsed, 5*time.Second,
		"serving an abandoned SessionRequest must not approach the 11 s destroy wait (took %v)", elapsed)
	assert.EqualValues(t, 0, tr.GetSessionCount(),
		"an uncompleted SessionRequest must not consume a session slot")
	assert.Zero(t, len(tr.pendingConns),
		"nothing may be delivered to Accept() without a completed handshake")

	// The watchdog is what keeps the slot bounded: go-noise's Handshake() runs
	// CloseWithReason in its defer, which would otherwise hold the worker (and its
	// admission slot) for the full 11 s destroy timeout even after the handshake
	// context expired at 500 ms.
	assert.GreaterOrEqual(t, tr.reachMetrics.handshakeWatchdogsFired.Load(), uint64(1),
		"the destroy-wait watchdog must fire so the slot comes back promptly")

	// The queue must still be usable: a consumer can read it without blocking.
	select {
	case conn := <-tr.pendingConns:
		t.Fatalf("unexpected connection delivered without a handshake: %v", conn)
	default:
	}
}

// TestGlobalHandshakeBudgetShedsFloodWithoutStalling pins the flood behaviour:
// with the budget spent, further SessionRequests are refused at admission and the
// accept loop keeps running rather than queueing them up. This is what stops one
// host with a spoofed source from making the router spend a handshake goroutine
// per packet.
func TestGlobalHandshakeBudgetShedsFloodWithoutStalling(t *testing.T) {
	tr, _ := newBoundSSU2TransportWith(t, func(c *Config) {
		c.MaxInflightHandshakes = 2
		c.MaxHandshakesPerSource = -1 // one source is the point of the test
		c.InboundHandshakeTimeout = 300 * time.Millisecond
	})
	defer func() { _ = tr.Close() }()

	go tr.startInboundAcceptRunner()

	const requests = 8
	for i := 0; i < requests; i++ {
		newSilentSessionRequest(t, transportUDPAddr(t, tr))
	}

	require.Eventuallyf(t, func() bool {
		return tr.reachMetrics.handshakeRefusedGlobal.Load() >= 3
	}, 8*time.Second, 25*time.Millisecond,
		"requests beyond the budget must be refused at admission (refused=%d)",
		tr.reachMetrics.handshakeRefusedGlobal.Load())

	assert.LessOrEqual(t, tr.admission.current(), int64(2),
		"the in-flight handshake count must never exceed the budget")
	assert.EqualValues(t, 0, tr.GetSessionCount(),
		"shed requests must not occupy session slots")
	assert.Zero(t, len(tr.pendingConns),
		"no connection can be established in this test")

	// The accept loop survived the flood: every admitted handshake finishes and
	// returns its slot, so the budget drains rather than leaking.
	require.Eventuallyf(t, func() bool {
		return tr.admission.current() == 0
	}, 8*time.Second, 25*time.Millisecond,
		"every admitted handshake must finish and return its slot")
}

// ---------------------------------------------------------------------------
// Limits published into the go-noise listener
// ---------------------------------------------------------------------------

// TestApplyListenerLimitsPublishedAtConstruction pins that the transport's own
// limits reach the go-noise listener config before the listener is built. go-noise
// caps its session map at config.MaxSessions, whose built-in value is 65536, so
// without this the router's 512-slot pool was never passed down and the listener
// registered a session for every SessionRequest it saw.
func TestApplyListenerLimitsPublishedAtConstruction(t *testing.T) {
	noiseCfg, err := ssu2noise.NewSSU2Config(data.Hash{1}, false)
	require.NoError(t, err)

	transportCfg, err := NewConfig("127.0.0.1:0")
	require.NoError(t, err)
	transportCfg.MaxSessions = 42
	transportCfg.RequireRetry = true

	// Precondition: go-noise's own defaults are the permissive ones.
	require.NotEqual(t, 42, noiseCfg.MaxSessions)
	require.False(t, noiseCfg.RequireRetry, "go-noise ships RequireRetry off by default")

	applyListenerLimits(noiseCfg, transportCfg)
	assert.Equal(t, 42, noiseCfg.MaxSessions, "the session cap must be passed down")
	assert.True(t, noiseCfg.RequireRetry, "source-address validation must be passed down")

	// The transport's own default keeps the gate off, because the pinned go-noise
	// rejects every SessionRequest when it is on. See DefaultRequireRetry.
	defaultCfg, err := NewConfig("127.0.0.1:0")
	require.NoError(t, err)
	assert.False(t, defaultCfg.RequireRetry,
		"RequireRetry must default off: the pinned go-noise drops every inbound SessionRequest when it is on")

	// A nil argument must not panic: construction and SetIdentity both call this.
	applyListenerLimits(nil, transportCfg)
	applyListenerLimits(noiseCfg, nil)
}

// TestBoundTransportPublishesLimitsIntoListener checks the same thing through the
// real constructor, on the config the live listener actually holds.
func TestBoundTransportPublishesLimitsIntoListener(t *testing.T) {
	tr, _ := newBoundSSU2Transport(t)
	defer func() { _ = tr.Close() }()

	cfg := tr.config.Load()
	require.NotNil(t, cfg.SSU2Config)
	assert.Equal(t, cfg.GetMaxSessions(), cfg.SSU2Config.MaxSessions,
		"a constructed transport must have published its session cap onto the noise config")
	assert.False(t, cfg.SSU2Config.RequireRetry,
		"a constructed transport must have source-address validation off by default (see DefaultRequireRetry)")

	// The intro key must be on the noise config BEFORE the listener was built, so
	// the listener's inbound header protector is live. This is the ordering fix
	// that lets an inbound SessionRequest be deobfuscated at all.
	assert.Len(t, cfg.SSU2Config.IntroKey, 32,
		"the listener must be constructed with the intro key so its header protector works")
	assert.NotNil(t, tr.GetIntroKey(), "key management must be initialised")
}

// TestSetIdentityKeepsListenerLimits pins the regression that an identity update
// silently restores go-noise's permissive defaults: createSSU2Config starts from
// scratch, so the transport's limits have to be re-published on every swap.
func TestSetIdentityKeepsListenerLimits(t *testing.T) {
	tr, _ := newBoundSSU2Transport(t)
	defer func() { _ = tr.Close() }()

	cfg := tr.config.Load()
	cfg.MaxSessions = 33
	cfg.RequireRetry = true
	require.NoError(t, tr.SetIdentity(tr.identity), "SetIdentity must succeed")

	after := tr.config.Load()
	require.NotNil(t, after.SSU2Config)
	assert.Equal(t, 33, after.GetMaxSessions(), "the transport must keep its own cap")
	assert.Equal(t, 33, after.SSU2Config.MaxSessions,
		"SetIdentity must re-publish the session cap: without it the listener reverts to 65536")
	assert.True(t, after.SSU2Config.RequireRetry,
		"SetIdentity must keep source-address validation on")
}

// ---------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------

// transportUDPAddr returns the transport's plain UDP "host:port". Addr() yields an
// *ssu2noise.SSU2Addr whose String() embeds a router hash and connection ID, which
// net.ResolveUDPAddr cannot parse.
func transportUDPAddr(t testing.TB, tr *SSU2Transport) string {
	t.Helper()
	addr := tr.Addr()
	if ssu2Addr, ok := addr.(*ssu2noise.SSU2Addr); ok {
		addr = ssu2Addr.UnderlyingAddr()
	}
	require.NotNil(t, addr, "transport must be listening")
	return addr.String()
}

// dialSSU2Transport dials addr as a real SSU2 initiator on its own UDP socket and
// returns the un-handshaked connection. The caller drives Handshake() and closes
// the connection.
//
// peerIntroKey is the transport's own introduction key: per ssu2.rst §"Header
// Protection" a SessionRequest is sealed with the RECEIVER's intro key, so an
// initiator that does not know it is not deobfuscated by the listener's
// intro-key stage at all.
func dialSSU2Transport(t testing.TB, addr string, peerIntroKey, peerStaticPub []byte) *ssu2noise.SSU2Conn {
	t.Helper()

	remote, err := net.ResolveUDPAddr("udp", addr)
	require.NoError(t, err)

	socket, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	t.Cleanup(func() { _ = socket.Close() })

	priv, _ := genKey(t)
	ourIntroKey := make([]byte, 32)
	_, err = rand.Read(ourIntroKey)
	require.NoError(t, err)

	ourAddr := socket.LocalAddr().(*net.UDPAddr)
	routerInfo := buildSSU2RouterInfoForTest(t, priv, ourAddr.IP.String(), ourAddr.Port, ourIntroKey)

	cfg, err := ssu2noise.NewSSU2Config(genRouterHash(t), true)
	require.NoError(t, err)
	cfg = cfg.
		WithStaticKey(priv).
		WithRemoteStaticKey(peerStaticPub).
		WithLocalRouterInfo(routerInfo).
		WithHandshakeTimeout(5 * time.Second).
		WithDestroyTimeout(100 * time.Millisecond)
	cfg.IntroKey = ourIntroKey
	cfg.RemoteIntroKey = peerIntroKey

	conn, err := ssu2noise.DialSSU2WithConn(socket, remote, cfg)
	require.NoError(t, err)
	return conn
}

// newSilentSessionRequest sends one structurally valid SSU2 SessionRequest to
// addr and then does nothing further — no SessionConfirmed, no retransmit, no
// intention of ever completing the handshake. This is the attacker's cheapest
// primitive in finding 005.
//
// The packet is built with go-noise's own handshake handler, header-sealed with
// the transport's intro key so the listener's parser recognises it, and then
// tampered with: its MAC is corrupted so the responder can buffer the request but
// can never authenticate the peer's static key. Nothing about the transport side
// is stubbed.
func newSilentSessionRequest(t testing.TB, addr string) {
	t.Helper()

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	require.NoError(t, err)

	socket, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	t.Cleanup(func() { _ = socket.Close() })

	staticKey := make([]byte, 32)
	_, err = rand.Read(staticKey)
	require.NoError(t, err)

	handler, err := ssu2noise.NewHandshakeHandler(true, staticKey, staticKey, nil)
	require.NoError(t, err)
	t.Cleanup(handler.Close)

	sourceConnID, err := ssu2noise.GenerateConnectionID()
	require.NoError(t, err)
	destConnID, err := ssu2noise.GenerateConnectionID()
	require.NoError(t, err)

	packet, err := handler.CreateSessionRequest(sourceConnID, destConnID)
	require.NoError(t, err)

	wire, err := packet.Serialize()
	require.NoError(t, err)
	require.NotEmpty(t, wire)
	// Corrupt the trailing MAC so the handshake cannot complete. go-noise's
	// receiveSessionRequest buffers the packet and only fails when the responder
	// tries to decrypt the peer's static key, which is exactly the "silent peer"
	// case the accept loop has to survive.
	wire[len(wire)-1] ^= 0xFF

	_, err = socket.WriteTo(wire, udpAddr)
	require.NoError(t, err, "sending a SessionRequest must succeed")
}
