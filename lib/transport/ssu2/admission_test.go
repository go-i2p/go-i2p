// Tests for pre-authentication inbound handshake admission control on SSU2
// (finding 005).
//
// go-noise hands the transport a connection as soon as a SessionRequest parses,
// before the peer has proven anything. Completing the responder handshake on it
// costs this router a goroutine, listener state and a handshake window, and the
// request's source address may be forged. These tests pin the two bounds added
// for that — the transport-wide cap and the per-source cap — and the rule that a
// refusal closes the connection without ever opening a handshake.

package ssu2

import (
	"context"
	"crypto/rand"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/go-i2p/lib/transport"
	ssu2noise "github.com/go-i2p/go-noise/ssu2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// handshakeAdmission
// ---------------------------------------------------------------------------

func TestHandshakeAdmission_GlobalCapBoundsConcurrentHandshakes(t *testing.T) {
	a := newHandshakeAdmission()
	const global = 3

	releases := make([]func(), 0, global+1)
	for i := 0; i < global; i++ {
		release, err := a.admit(&net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 1000 + i}, global, -1)
		require.NoErrorf(t, err, "handshake %d within the budget must be admitted", i)
		releases = append(releases, release)
	}
	assert.EqualValues(t, global, a.current(), "all slots accounted as in flight")

	// Budget spent: the next connection is refused, not queued.
	release, err := a.admit(&net.UDPAddr{IP: net.ParseIP("203.0.113.2"), Port: 2000}, global, -1)
	assert.ErrorIs(t, err, errAdmissionGlobalFull, "connection beyond the budget must be refused")
	assert.EqualValues(t, global, a.current(),
		"a refusal must back out its own reservation and leave the admitted ones intact")
	release() // the release returned on failure must be safe to call
	assert.EqualValues(t, global, a.current(), "a failed release must be a no-op")

	// Freeing one slot admits exactly one more.
	releases[0]()
	assert.EqualValues(t, global-1, a.current(), "released slot returned to the budget")

	release, err = a.admit(&net.UDPAddr{IP: net.ParseIP("203.0.113.3"), Port: 3000}, global, -1)
	require.NoError(t, err, "a freed slot must admit the next connection")
	releases = append(releases, release)

	for _, r := range releases {
		r()
	}
	assert.Zero(t, a.current(), "budget fully returned after all releases")
}

func TestHandshakeAdmission_PerSourceCapStopsOneHostConsumingBudget(t *testing.T) {
	a := newHandshakeAdmission()
	const global = 10
	const perSource = 2

	host := net.ParseIP("198.51.100.7")
	releases := make([]func(), 0, perSource)
	for i := 0; i < perSource; i++ {
		release, err := a.admit(&net.UDPAddr{IP: host, Port: 5000 + i}, global, perSource)
		require.NoErrorf(t, err, "handshake %d from one source within its share must be admitted", i)
		releases = append(releases, release)
	}
	assert.Equal(t, perSource, a.sourceCount(&net.UDPAddr{IP: host, Port: 0}),
		"the per-source count must be keyed on the IP alone")

	// The source has spent its share, though the transport-wide budget is not full.
	release, err := a.admit(&net.UDPAddr{IP: host, Port: 6000}, global, perSource)
	assert.ErrorIs(t, err, errAdmissionSourceFull,
		"a third handshake from one source must be refused while the global budget has room")
	assert.EqualValues(t, perSource, a.current(),
		"a per-source refusal must back out its global reservation, leaving only the admitted ones")
	release()

	// A different source is unaffected by the first one's saturation.
	release, err = a.admit(&net.UDPAddr{IP: net.ParseIP("198.51.100.8"), Port: 7000}, global, perSource)
	require.NoError(t, err, "another source must still be admitted")
	release()

	for _, r := range releases {
		r()
	}
	assert.Zero(t, a.current())
	assert.Zero(t, a.sourceCount(&net.UDPAddr{IP: host, Port: 0}),
		"releases must return the per-source budget")
}

// TestHandshakeAdmission_PerSourceMapStaysBounded pins that the per-source map
// does not itself become the thing a many-source flood grows: an entry is deleted
// as soon as its count reaches zero.
func TestHandshakeAdmission_PerSourceMapStaysBounded(t *testing.T) {
	a := newHandshakeAdmission()
	const perSource = 1

	for i := 0; i < 50; i++ {
		addr := &net.UDPAddr{IP: net.IPv4(203, 0, 113, byte(i)), Port: 4000}
		release, err := a.admit(addr, -1, perSource)
		require.NoErrorf(t, err, "source %d must be admitted", i)
		release()
	}

	a.mu.Lock()
	sources := len(a.bySource)
	a.mu.Unlock()
	assert.Zero(t, sources, "released reservations must not leave per-source entries behind")
	assert.Zero(t, a.current())
}

func TestHandshakeAdmission_DisablingBoundsAdmitsEverything(t *testing.T) {
	a := newHandshakeAdmission()
	for i := 0; i < 200; i++ {
		release, err := a.admit(&net.UDPAddr{IP: net.ParseIP("203.0.113.9"), Port: 1000 + i}, -1, -1)
		require.NoError(t, err, "a disabled bound must admit, not refuse")
		release()
	}
	assert.Zero(t, a.current(), "disabled bounds must not leak reservations")
}

func TestHandshakeAdmission_NilReceiverAdmits(t *testing.T) {
	var a *handshakeAdmission
	release, err := a.admit(&net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 1}, 1, 1)
	require.NoError(t, err, "a transport without an admission controller admits everything")
	release()
	assert.Zero(t, a.current())
	assert.Zero(t, a.sourceCount(&net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 1}))
}

// TestHandshakeAdmission_ReleaseIsIdempotent guards the accounting against a
// worker that releases twice.
func TestHandshakeAdmission_ReleaseIsIdempotent(t *testing.T) {
	a := newHandshakeAdmission()
	addr := &net.UDPAddr{IP: net.ParseIP("203.0.113.11"), Port: 1234}

	release, err := a.admit(addr, 2, 1)
	require.NoError(t, err)
	release()
	release()
	release()

	assert.Zero(t, a.current(), "repeated releases must not drive the counter negative")
	assert.Zero(t, a.sourceCount(addr), "repeated releases must not drive the per-source count negative")
}

// ---------------------------------------------------------------------------
// handshakeSourceKey
// ---------------------------------------------------------------------------

// TestHandshakeSourceKey_UnwrapsSSU2Addr pins the per-source keying. Accepted SSU2
// connections carry an *ssu2noise.SSU2Addr whose String() embeds a placeholder
// router hash and the connection ID, so keying on the wrapper would let one host
// split into many keys and dodge the per-source cap.
func TestHandshakeSourceKey_UnwrapsSSU2Addr(t *testing.T) {
	udp := &net.UDPAddr{IP: net.ParseIP("203.0.113.9"), Port: 4242}
	otherPort := &net.UDPAddr{IP: net.ParseIP("203.0.113.9"), Port: 9999}
	require.Equal(t, handshakeSourceKey(udp), handshakeSourceKey(otherPort),
		"same IP, different port must be one source")

	wrapped, err := ssu2noise.NewSSU2Addr(udp, data.Hash{1, 2, 3}, 7, "responder")
	require.NoError(t, err)
	require.NotEqual(t, wrapped.String(), udp.String(), "the SSU2 wrapper must carry extra text")
	assert.Equal(t, handshakeSourceKey(udp), handshakeSourceKey(wrapped),
		"an *ssu2noise.SSU2Addr must key on the underlying UDP address's IP")

	// A different IP is a different source.
	assert.NotEqual(t,
		handshakeSourceKey(&net.UDPAddr{IP: net.ParseIP("203.0.113.9"), Port: 1}),
		handshakeSourceKey(&net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 1}))

	// A non-IP address still keys on something stable rather than being dropped.
	assert.Equal(t, "pipe-1", handshakeSourceKey(&mockAddr{name: "pipe-1"}))
	assert.Empty(t, handshakeSourceKey(nil), "a nil address must not panic")
	assert.Empty(t, handshakeSourceKey(&mockAddr{name: ""}),
		"an address with no name must not be keyed on the empty string")
}

type mockAddr struct{ name string }

func (m *mockAddr) Network() string { return "mock" }
func (m *mockAddr) String() string  { return m.name }

// ---------------------------------------------------------------------------
// SSU2Transport.admitInboundHandshake
// ---------------------------------------------------------------------------

// TestAdmitInboundHandshake_RefusedConnectionClosesWithoutHandshake is the
// regression test for the pre-authentication cost in finding 005: a connection
// that arrives while the handshake budget is spent must be closed immediately and
// must never reach the handshake path, so it costs no goroutine and no handshake
// window.
func TestAdmitInboundHandshake_RefusedConnectionClosesWithoutHandshake(t *testing.T) {
	tr := newAdmissionTestTransport(t, 1, -1)

	// An admitted connection yields a release and is left open.
	allowed := newUnestablishedSSU2Conn(t, "10.0.0.3:5556")
	release := tr.admitInboundHandshake(allowed)
	require.NotNil(t, release, "a connection within the budget must be admitted")
	assert.Equal(t, ssu2noise.StateInit, allowed.GetState(),
		"an admitted connection must be left open for the handshake worker")
	assert.Zero(t, tr.reachMetrics.handshakeRefusedGlobal.Load())

	// Budget now spent: the next connection is refused outright.
	refused := newUnestablishedSSU2Conn(t, "10.0.0.2:5555")
	refusedRelease := tr.admitInboundHandshake(refused)
	assert.Nil(t, refusedRelease, "a refused connection must not yield a release function")
	assert.Equal(t, ssu2noise.StateClosed, refused.GetState(),
		"a refused connection must be closed at once")
	assert.EqualValues(t, 1, tr.reachMetrics.handshakeRefusedGlobal.Load(),
		"the refusal must be counted for alerting")
	assert.EqualValues(t, 0, tr.GetSessionCount(),
		"refusing a connection must not consume a session slot")
	assert.EqualValues(t, 1, tr.admission.current(),
		"a refusal must not disturb the in-flight accounting")

	// Releasing the admitted slot returns the budget, and a second release must
	// not over-return it.
	release()
	assert.Zero(t, tr.admission.current())
	release()
	assert.Zero(t, tr.admission.current())

	// With the slot free again, a new connection is admitted.
	next := newUnestablishedSSU2Conn(t, "10.0.0.4:1111")
	release2 := tr.admitInboundHandshake(next)
	assert.NotNil(t, release2, "a freed budget must admit the next connection")
	release2()
}

// TestAdmitInboundHandshake_PerSourceRefusalCounted pins that a refusal caused by
// one host's share, rather than the transport-wide budget, is counted separately:
// the two mean different things to an operator.
func TestAdmitInboundHandshake_PerSourceRefusalCounted(t *testing.T) {
	tr := newAdmissionTestTransport(t, -1, 1)

	first := newUnestablishedSSU2Conn(t, "10.0.0.4:1000")
	release := tr.admitInboundHandshake(first)
	require.NotNil(t, release)

	sameHost := newUnestablishedSSU2Conn(t, "10.0.0.4:2000")
	assert.Nil(t, tr.admitInboundHandshake(sameHost),
		"a second handshake from one source must be refused")
	assert.Equal(t, ssu2noise.StateClosed, sameHost.GetState())
	assert.EqualValues(t, 1, tr.reachMetrics.handshakeRefusedSource.Load())
	assert.Zero(t, tr.reachMetrics.handshakeRefusedGlobal.Load(),
		"a per-source refusal must not be counted as a global one")

	// Same IP, different port is still the same source.
	anotherPort := newUnestablishedSSU2Conn(t, "10.0.0.4:3000")
	assert.Nil(t, tr.admitInboundHandshake(anotherPort),
		"changing the port must not buy a host another handshake")
	assert.EqualValues(t, 2, tr.reachMetrics.handshakeRefusedSource.Load())

	release()
}

// ---------------------------------------------------------------------------
// closeConnImmediately
// ---------------------------------------------------------------------------

// TestCloseConnImmediately_SkipsDestroyWait pins that rejected connections are
// torn down through CloseImmediate rather than Close. Close waits the spec's
// DestroyTimeout (11 s by default) for a Termination round-trip that a session
// which never established will never get — that wait is exactly what let one
// SessionRequest stall the inbound accept loop for 11 seconds.
func TestCloseConnImmediately_SkipsDestroyWait(t *testing.T) {
	conn := newUnestablishedSSU2ConnWithDestroy(t, newListeningPeer(t), 3*time.Second)
	require.Equal(t, ssu2noise.StateInit, conn.GetState(),
		"precondition: the connection has not handshaked")

	start := time.Now()
	closeConnImmediately(conn)
	elapsed := time.Since(start)

	assert.Less(t, elapsed, time.Second,
		"CloseImmediate must not wait the destroy timeout (took %v)", elapsed)
	assert.Equal(t, ssu2noise.StateClosed, conn.GetState())

	// A connection without CloseImmediate still gets closed.
	plain := &closeCountingConn{}
	closeConnImmediately(plain)
	assert.True(t, plain.closed.Load(), "the fallback path must call Close")

	closeConnImmediately(nil) // must not panic
}

// TestUnestablishedConnClosePaysDestroyWait documents the behaviour the fix avoids:
// with a non-zero DestroyTimeout, plain Close on a never-established connection
// blocks for that long. If go-noise ever makes Close non-blocking, this test is the
// signal that closeConnImmediately's rationale needs revisiting.
func TestUnestablishedConnClosePaysDestroyWait(t *testing.T) {
	conn := newUnestablishedSSU2ConnWithDestroy(t, newListeningPeer(t), 900*time.Millisecond)

	start := time.Now()
	_ = conn.Close()
	elapsed := time.Since(start)

	assert.GreaterOrEqual(t, elapsed, 800*time.Millisecond,
		"Close is expected to pay the destroy wait — finding 005's stall")
}

// ---------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------

// newAdmissionTestTransport builds a transport with only what the admission path
// touches: a config carrying the two bounds, a fresh admission controller, a
// session registry and a logger. global and perSource follow Config's semantics:
// negative disables the bound.
func newAdmissionTestTransport(t *testing.T, global, perSource int) *SSU2Transport {
	t.Helper()
	cfg, err := NewConfig("127.0.0.1:0")
	require.NoError(t, err)
	cfg.MaxInflightHandshakes = global
	cfg.MaxHandshakesPerSource = perSource

	tr := &SSU2Transport{
		admission:       newHandshakeAdmission(),
		logger:          testLogger(),
		sessionRegistry: transport.NewSessionRegistry(testLogger()),
		ctx:             context.Background(),
	}
	tr.config.Store(cfg)
	return tr
}

// newListeningPeer binds a throwaway UDP socket and returns its address, so a
// connection closed against it has a reachable destination. go-noise short-circuits
// the Termination destroy wait when the send fails with a socket-dead error, so an
// unreachable address would make the destroy-wait test pass for the wrong reason.
func newListeningPeer(t testing.TB) string {
	t.Helper()
	peer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	t.Cleanup(func() { _ = peer.Close() })
	return peer.LocalAddr().String()
}

// newUnestablishedSSU2Conn returns a responder *ssu2noise.SSU2Conn in StateInit,
// which is precisely the state go-noise's listener hands to the transport.
func newUnestablishedSSU2Conn(t testing.TB, remote string) *ssu2noise.SSU2Conn {
	t.Helper()
	return newUnestablishedSSU2ConnWithDestroy(t, remote, 100*time.Millisecond)
}

func newUnestablishedSSU2ConnWithDestroy(t testing.TB, remote string, destroy time.Duration) *ssu2noise.SSU2Conn {
	t.Helper()

	var hash data.Hash
	_, err := rand.Read(hash[:])
	require.NoError(t, err)

	staticKey := make([]byte, 32)
	_, err = rand.Read(staticKey)
	require.NoError(t, err)

	socket, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	t.Cleanup(func() { _ = socket.Close() })

	remoteAddr, err := net.ResolveUDPAddr("udp", remote)
	require.NoError(t, err)

	cfg, err := ssu2noise.NewSSU2Config(hash, false)
	require.NoError(t, err)
	cfg = cfg.
		WithStaticKey(staticKey).
		WithDestroyTimeout(destroy).
		WithRouterInfoValidator(func(_, _ []byte) error { return nil })

	conn, err := ssu2noise.NewSSU2Conn(socket, remoteAddr, cfg, false, staticKey, nil)
	require.NoError(t, err)
	return conn
}

// closeCountingConn records whether it was closed, standing in for a connection
// type that does not implement CloseImmediate.
type closeCountingConn struct {
	net.Conn
	closed atomic.Bool
}

func (c *closeCountingConn) Close() error {
	c.closed.Store(true)
	return nil
}
