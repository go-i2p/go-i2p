// Router-side regression tests for finding 005.
//
// The reported defect had two halves on the router side:
//
//   - handleNewConnection type-asserted the accepted connection to
//     *ssu2noise.SSU2Conn, but the muxer and the transport each wrap it in a
//     transport.TrackedConn, so the assertion always failed and no inbound SSU2
//     session was ever registered; and
//   - on that failure the router called conn.Close() inline on the single
//     monitorInboundSessions goroutine, which also serves NTCP2 accepts. go-noise's
//     Close waits the spec's 11 s DestroyTimeout, so one rejected connection stalled
//     every inbound transport for that long.
//
// These tests drive handleNewConnection with a connection wrapped exactly the way
// the real path wraps it, and prove the session registers and the drop path
// returns without waiting on a slow close.

package router

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/go-i2p/lib/transport"
	ssu2noise "github.com/go-i2p/go-noise/ssu2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHandleNewConnectionSSU2_DoubleWrappedRegisters is the core regression: the
// value the router receives from the muxer is transport.TrackedConn wrapping
// transport.TrackedConn wrapping the *ssu2noise.SSU2Conn. handleNewConnection must
// unwrap both layers, build the session, and register it under the peer's router
// hash. Before the fix the assertion failed on the outer wrapper and the session
// was dropped.
func TestHandleNewConnectionSSU2_DoubleWrappedRegisters(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping SSU2 loopback integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	serverConn, clientConn := ssu2IntegLoopbackPair(t, ctx)
	defer func() { _ = clientConn.Close() }()

	// Wrap exactly like the transport and the muxer do. The transport wraps for
	// its own session accounting; the muxer wraps again in handleAcceptResultCommon.
	transportWrapped := transport.NewTrackedConn(serverConn, func() {})
	muxerWrapped := transport.NewTrackedConn(transportWrapped, func() {})

	// Sanity: the outermost type is *TrackedConn, which is what broke the old
	// assertion. A bare conn.(*ssu2noise.SSU2Conn) here must fail.
	_, bare := net.Conn(muxerWrapped).(*ssu2noise.SSU2Conn)
	require.False(t, bare, "precondition: the double-wrapped conn must NOT assert directly to *SSU2Conn")

	router := &Router{
		activeSessions: make(map[common.Hash]transport.TransportSession),
		ctx:            ctx,
	}

	router.handleNewConnection(muxerWrapped)

	router.sessionMutex.RLock()
	sessionCount := len(router.activeSessions)
	router.sessionMutex.RUnlock()
	require.Equal(t, 1, sessionCount,
		"a double-wrapped inbound SSU2 conn must register exactly one session after unwrap")

	ssu2Addr, ok := serverConn.RemoteAddr().(*ssu2noise.SSU2Addr)
	require.True(t, ok, "serverConn.RemoteAddr() must be *ssu2noise.SSU2Addr")
	peerHash := common.Hash(ssu2Addr.RouterHash())

	router.sessionMutex.RLock()
	_, found := router.activeSessions[peerHash]
	router.sessionMutex.RUnlock()
	assert.True(t, found, "the session must be keyed by the SSU2 peer's router hash")
}

// TestHandleNewConnectionSSU2_UnwrappabilityOfRealPath pins that
// transport.UnwrapTrackedConn reaches the concrete connection through the exact
// double wrapping the transport applies, so the router's assertion succeeds. This
// is the mechanism the fix relies on.
func TestHandleNewConnectionSSU2_UnwrappabilityOfRealPath(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping SSU2 loopback integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	serverConn, clientConn := ssu2IntegLoopbackPair(t, ctx)
	defer func() { _ = clientConn.Close() }()

	muxerWrapped := transport.NewTrackedConn(transport.NewTrackedConn(serverConn, func() {}), func() {})

	inner := transport.UnwrapTrackedConn(muxerWrapped)
	ssu2Conn, ok := inner.(*ssu2noise.SSU2Conn)
	require.Truef(t, ok, "unwrapping the double TrackedConn must yield *ssu2noise.SSU2Conn, got %T", inner)
	assert.Same(t, serverConn, ssu2Conn, "the unwrapped conn must be the original connection")
}

// TestHandleNewConnectionDropPathDoesNotBlock is the availability half: a
// connection the router discards (here one whose address type is unrecognised)
// must be closed asynchronously. A Close that blocks for the destroy timeout must
// not delay handleNewConnection, because that call runs on the goroutine that also
// serves NTCP2 accepts.
func TestHandleNewConnectionDropPathDoesNotBlock(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	router := &Router{
		activeSessions: make(map[common.Hash]transport.TransportSession),
		ctx:            ctx,
	}

	slow := &slowCloseConn{
		remoteAddr:   &mockAddr{network: "weird", address: "not-ssu2-or-ntcp"},
		closeDelay:   2 * time.Second, // stands in for go-noise's 11 s DestroyTimeout
		closeStarted: make(chan struct{}),
	}

	start := time.Now()
	router.handleNewConnection(slow)
	elapsed := time.Since(start)

	assert.Less(t, elapsed, 100*time.Millisecond,
		"handleNewConnection must return immediately, not wait on the discarded connection's close (took %v)", elapsed)

	select {
	case <-slow.closeStarted:
		// The close was launched on its own goroutine.
	default:
		// Give the async close a moment to begin.
		select {
		case <-slow.closeStarted:
		case <-time.After(200 * time.Millisecond):
			t.Error("the discarded connection was never closed")
		}
	}

	assert.Zero(t, len(router.activeSessions), "a dropped connection must not register a session")
}

// TestHandleNewConnectionSSU2_BadConnTypeClosesAsync pins the SSU2 branch's own
// drop path: an SSU2Addr whose underlying conn is not a *ssu2noise.SSU2Conn (so
// the unwrap + assertion fails) must be closed asynchronously rather than inline.
func TestHandleNewConnectionSSU2_BadConnTypeClosesAsync(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	router := &Router{
		activeSessions: make(map[common.Hash]transport.TransportSession),
		ctx:            ctx,
	}

	// A TrackedConn whose inner conn is not an SSU2Conn but whose RemoteAddr is an
	// *ssu2noise.SSU2Addr: the switch selects the SSU2 branch, then the unwrap
	// assertion fails.
	addr, err := ssu2noise.NewSSU2Addr(
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9000},
		common.Hash{9}, 1234, "responder",
	)
	require.NoError(t, err)

	bad := &fixedAddrConn{remoteAddr: addr, closeDelay: 2 * time.Second, closeStarted: make(chan struct{})}
	wrapped := transport.NewTrackedConn(bad, func() {})

	start := time.Now()
	router.handleNewConnection(wrapped)
	elapsed := time.Since(start)

	assert.Less(t, elapsed, 100*time.Millisecond,
		"the SSU2 failed-assertion branch must not block on close (took %v)", elapsed)
	select {
	case <-bad.closeStarted:
	case <-time.After(200 * time.Millisecond):
		t.Error("the rejected SSU2 connection was never closed")
	}
	assert.Zero(t, len(router.activeSessions))
}

// ---------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------

// slowCloseConn blocks in Close for closeDelay, modelling go-noise's DestroyTimeout,
// and records that the close was entered.
type slowCloseConn struct {
	remoteAddr   net.Addr
	closeDelay   time.Duration
	closeEntry   atomic.Bool
	closeDone    atomic.Bool
	closeStarted chan struct{}
}

func (c *slowCloseConn) Read(_ []byte) (int, error)  { return 0, net.ErrClosed }
func (c *slowCloseConn) Write(b []byte) (int, error) { return len(b), nil }
func (c *slowCloseConn) Close() error {
	if c.closeEntry.CompareAndSwap(false, true) {
		close(c.closeStarted)
	}
	time.Sleep(c.closeDelay)
	c.closeDone.Store(true)
	return nil
}

func (c *slowCloseConn) LocalAddr() net.Addr {
	return &mockAddr{network: "udp", address: "127.0.0.1:0"}
}
func (c *slowCloseConn) RemoteAddr() net.Addr             { return c.remoteAddr }
func (c *slowCloseConn) SetDeadline(time.Time) error      { return nil }
func (c *slowCloseConn) SetReadDeadline(time.Time) error  { return nil }
func (c *slowCloseConn) SetWriteDeadline(time.Time) error { return nil }

// fixedAddrConn is a slow-closing conn that reports a fixed (SSU2) remote address
// regardless of its own type, so the router selects the SSU2 branch and then fails
// to unwrap it to a concrete SSU2Conn.
type fixedAddrConn struct {
	remoteAddr   net.Addr
	closeDelay   time.Duration
	closeStarted chan struct{}
	closeOnce    atomic.Bool
}

func (c *fixedAddrConn) Read(_ []byte) (int, error)  { return 0, net.ErrClosed }
func (c *fixedAddrConn) Write(b []byte) (int, error) { return len(b), nil }
func (c *fixedAddrConn) Close() error {
	if c.closeOnce.CompareAndSwap(false, true) {
		close(c.closeStarted)
	}
	time.Sleep(c.closeDelay)
	return nil
}

func (c *fixedAddrConn) LocalAddr() net.Addr {
	return &mockAddr{network: "udp", address: "127.0.0.1:0"}
}
func (c *fixedAddrConn) RemoteAddr() net.Addr             { return c.remoteAddr }
func (c *fixedAddrConn) SetDeadline(time.Time) error      { return nil }
func (c *fixedAddrConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fixedAddrConn) SetWriteDeadline(time.Time) error { return nil }

var (
	_ net.Conn = (*slowCloseConn)(nil)
	_ net.Conn = (*fixedAddrConn)(nil)
)
