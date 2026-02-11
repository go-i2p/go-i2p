package ntcp2

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// acceptMockConn is a net.Conn with configurable addresses for accept tests.
// It is separate from the mockConn in ntcp2_test.go which has hardcoded addresses.
type acceptMockConn struct {
	data    []byte
	offset  int
	local   net.Addr
	remote  net.Addr
	closeMu sync.Mutex
	closed  bool
}

func newAcceptMockConn(remoteAddr string) *acceptMockConn {
	return &acceptMockConn{
		data:   []byte{},
		local:  &mockAddr{"127.0.0.1:0"},
		remote: &mockAddr{remoteAddr},
	}
}

func (c *acceptMockConn) Read(p []byte) (n int, err error) {
	if c.offset >= len(c.data) {
		return 0, fmt.Errorf("EOF")
	}
	n = copy(p, c.data[c.offset:])
	c.offset += n
	return n, nil
}

func (c *acceptMockConn) Write(p []byte) (n int, err error)  { return len(p), nil }
func (c *acceptMockConn) LocalAddr() net.Addr                { return c.local }
func (c *acceptMockConn) RemoteAddr() net.Addr               { return c.remote }
func (c *acceptMockConn) SetDeadline(t time.Time) error      { return nil }
func (c *acceptMockConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *acceptMockConn) SetWriteDeadline(t time.Time) error { return nil }
func (c *acceptMockConn) Close() error {
	c.closeMu.Lock()
	defer c.closeMu.Unlock()
	c.closed = true
	return nil
}

// mockListener implements net.Listener for testing Accept().
type mockListener struct {
	conns   chan net.Conn
	closed  bool
	closeMu sync.Mutex
}

func newMockListener(conns ...net.Conn) *mockListener {
	ch := make(chan net.Conn, len(conns)+10)
	for _, c := range conns {
		ch <- c
	}
	return &mockListener{conns: ch}
}

func (l *mockListener) Accept() (net.Conn, error) {
	l.closeMu.Lock()
	closed := l.closed
	l.closeMu.Unlock()
	if closed {
		return nil, net.ErrClosed
	}
	select {
	case c := <-l.conns:
		return c, nil
	default:
		return nil, net.ErrClosed
	}
}

func (l *mockListener) Close() error {
	l.closeMu.Lock()
	l.closed = true
	l.closeMu.Unlock()
	return nil
}

func (l *mockListener) Addr() net.Addr {
	return &mockAddr{"mock-listener"}
}

// newTestTransport creates a minimal NTCP2Transport for testing Accept().
func newTestTransport(listener net.Listener, maxSessions int) *NTCP2Transport {
	ctx, cancel := context.WithCancel(context.Background())
	cfg := &Config{
		ListenerAddress: "127.0.0.1:0",
		MaxSessions:     maxSessions,
	}
	return &NTCP2Transport{
		listener: listener,
		config:   cfg,
		ctx:      ctx,
		cancel:   cancel,
		logger:   logger.WithField("test", "accept"),
		sessions: sync.Map{},
	}
}

// TestAccept_TracksInboundSession verifies that Accept() stores the inbound
// connection in the transport's session map so GetSessionCount() is accurate.
func TestAccept_TracksInboundSession(t *testing.T) {
	conn := newAcceptMockConn("10.0.0.1:5001")
	listener := newMockListener(conn)
	transport := newTestTransport(listener, 10)
	defer transport.cancel()

	// Session count should start at 0
	assert.Equal(t, 0, transport.GetSessionCount(), "initial session count should be 0")

	accepted, err := transport.Accept()
	require.NoError(t, err)
	require.NotNil(t, accepted)

	// Session count should now be 1
	assert.Equal(t, 1, transport.GetSessionCount(), "session count should be 1 after Accept()")
}

// TestAccept_SessionCountDecrementsOnClose verifies that closing the accepted
// connection removes it from the session map via the trackedConn wrapper.
func TestAccept_SessionCountDecrementsOnClose(t *testing.T) {
	conn := newAcceptMockConn("10.0.0.1:5001")
	listener := newMockListener(conn)
	transport := newTestTransport(listener, 10)
	defer transport.cancel()

	accepted, err := transport.Accept()
	require.NoError(t, err)

	assert.Equal(t, 1, transport.GetSessionCount())

	// Close the accepted connection
	err = accepted.Close()
	require.NoError(t, err)

	// Session count should return to 0
	assert.Equal(t, 0, transport.GetSessionCount(),
		"session count should be 0 after closing the accepted connection")
}

// TestAccept_DoubleCloseIsIdempotent verifies that closing a tracked connection
// twice does not panic or double-decrement the session count.
func TestAccept_DoubleCloseIsIdempotent(t *testing.T) {
	conn := newAcceptMockConn("10.0.0.1:5001")
	listener := newMockListener(conn)
	transport := newTestTransport(listener, 10)
	defer transport.cancel()

	accepted, err := transport.Accept()
	require.NoError(t, err)

	// Close twice — should not panic
	require.NotPanics(t, func() {
		_ = accepted.Close()
		_ = accepted.Close()
	})

	assert.Equal(t, 0, transport.GetSessionCount(),
		"session count should be 0 after double-close")
}

// TestAccept_EnforcesSessionLimit verifies that Accept() returns
// ErrConnectionPoolFull when the maximum session count is reached.
func TestAccept_EnforcesSessionLimit(t *testing.T) {
	conn1 := newAcceptMockConn("10.0.0.1:5001")
	conn2 := newAcceptMockConn("10.0.0.2:5002")

	listener := newMockListener(conn1, conn2)
	transport := newTestTransport(listener, 2)
	defer transport.cancel()

	// Accept two connections
	accepted1, err := transport.Accept()
	require.NoError(t, err)
	require.NotNil(t, accepted1)

	accepted2, err := transport.Accept()
	require.NoError(t, err)
	require.NotNil(t, accepted2)

	assert.Equal(t, 2, transport.GetSessionCount())

	// Third Accept should fail with pool full
	conn3 := newAcceptMockConn("10.0.0.3:5003")
	listener.conns <- conn3

	_, err = transport.Accept()
	assert.Error(t, err, "Accept should fail when session limit is reached")
	assert.Contains(t, err.Error(), "pool full",
		"error should indicate connection pool is full")

	_ = accepted1.Close()
	_ = accepted2.Close()
}

// TestAccept_SessionLimitRecovery verifies that closing a session frees a slot
// for new inbound connections.
func TestAccept_SessionLimitRecovery(t *testing.T) {
	conn1 := newAcceptMockConn("10.0.0.1:5001")
	listener := newMockListener(conn1)
	transport := newTestTransport(listener, 1)
	defer transport.cancel()

	// Fill the pool
	accepted1, err := transport.Accept()
	require.NoError(t, err)
	assert.Equal(t, 1, transport.GetSessionCount())

	// Close the first connection to free the slot
	_ = accepted1.Close()
	assert.Equal(t, 0, transport.GetSessionCount())

	// Now a new connection should be accepted
	conn2 := newAcceptMockConn("10.0.0.2:5002")
	listener.conns <- conn2

	accepted2, err := transport.Accept()
	require.NoError(t, err)
	require.NotNil(t, accepted2)
	assert.Equal(t, 1, transport.GetSessionCount())

	_ = accepted2.Close()
}

// TestAccept_NilListener verifies that Accept() returns an error
// when the listener is nil.
func TestAccept_NilListener(t *testing.T) {
	transport := newTestTransport(nil, 10)
	transport.listener = nil
	defer transport.cancel()

	_, err := transport.Accept()
	assert.Error(t, err)
}

// TestExtractPeerHash_FallbackToAddress verifies that extractPeerHash returns
// a unique hash derived from the remote address when NTCP2Addr is not available.
func TestExtractPeerHash_FallbackToAddress(t *testing.T) {
	transport := newTestTransport(nil, 10)
	defer transport.cancel()

	conn1 := newAcceptMockConn("10.0.0.1:5001")
	conn2 := newAcceptMockConn("10.0.0.2:5002")

	hash1 := transport.extractPeerHash(conn1)
	hash2 := transport.extractPeerHash(conn2)

	// Different addresses should produce different hashes
	assert.NotEqual(t, hash1, hash2,
		"different remote addresses should produce different peer hashes")

	// Same address should produce the same hash
	hash1Again := transport.extractPeerHash(conn1)
	assert.Equal(t, hash1, hash1Again,
		"same remote address should produce the same peer hash")
}

// TestTrackedConn_PreservesConnBehavior verifies that trackedConn delegates
// all net.Conn methods to the wrapped connection.
func TestTrackedConn_PreservesConnBehavior(t *testing.T) {
	inner := &acceptMockConn{
		data:   []byte("hello"),
		local:  &mockAddr{"127.0.0.1:8080"},
		remote: &mockAddr{"10.0.0.1:5001"},
	}

	called := false
	tc := &trackedConn{
		Conn:    inner,
		onClose: func() { called = true },
	}

	// RemoteAddr and LocalAddr should delegate
	assert.Equal(t, "10.0.0.1:5001", tc.RemoteAddr().String())
	assert.Equal(t, "127.0.0.1:8080", tc.LocalAddr().String())

	// Read should delegate
	buf := make([]byte, 5)
	n, err := tc.Read(buf)
	assert.Equal(t, 5, n)
	assert.NoError(t, err)
	assert.Equal(t, "hello", string(buf))

	// Write should delegate
	n, err = tc.Write([]byte("world"))
	assert.Equal(t, 5, n)
	assert.NoError(t, err)

	// Close should call onClose
	assert.False(t, called)
	_ = tc.Close()
	assert.True(t, called)
}

// TestAccept_MixedInboundOutbound verifies that session count reflects both
// inbound (Accept) and outbound (setupSession) sessions.
func TestAccept_MixedInboundOutbound(t *testing.T) {
	conn := newAcceptMockConn("10.0.0.1:5001")
	listener := newMockListener(conn)
	transport := newTestTransport(listener, 10)
	defer transport.cancel()

	// Simulate an outbound session by storing directly in sessions map
	var outboundHash data.Hash
	copy(outboundHash[:], []byte("outbound-peer-hash-for-testing!!"))
	transport.sessions.Store(outboundHash, "outbound-placeholder")
	assert.Equal(t, 1, transport.GetSessionCount())

	// Accept an inbound connection
	accepted, err := transport.Accept()
	require.NoError(t, err)
	assert.Equal(t, 2, transport.GetSessionCount(),
		"session count should include both inbound and outbound sessions")

	// Close inbound
	_ = accepted.Close()
	assert.Equal(t, 1, transport.GetSessionCount(),
		"closing inbound should only decrement inbound session")

	// Remove outbound
	transport.sessions.Delete(outboundHash)
	assert.Equal(t, 0, transport.GetSessionCount())
}

// TestAccept_ConcurrentAcceptAndClose verifies thread safety of session tracking
// under concurrent accept/close operations.
func TestAccept_ConcurrentAcceptAndClose(t *testing.T) {
	const numConns = 20
	conns := make([]net.Conn, numConns)
	for i := 0; i < numConns; i++ {
		conns[i] = newAcceptMockConn(fmt.Sprintf("10.0.%d.%d:5001", i/256, i%256))
	}
	listener := newMockListener(conns...)
	transport := newTestTransport(listener, numConns+10)
	defer transport.cancel()

	// Accept all connections concurrently
	accepted := make([]net.Conn, numConns)
	var wg sync.WaitGroup
	for i := 0; i < numConns; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			conn, err := transport.Accept()
			if err == nil {
				accepted[idx] = conn
			}
		}(i)
	}
	wg.Wait()

	// Close all concurrently
	for i := 0; i < numConns; i++ {
		if accepted[i] != nil {
			wg.Add(1)
			go func(conn net.Conn) {
				defer wg.Done()
				_ = conn.Close()
			}(accepted[i])
		}
	}
	wg.Wait()

	// All should be cleaned up eventually
	time.Sleep(10 * time.Millisecond)
	assert.Equal(t, 0, transport.GetSessionCount(),
		"all sessions should be cleaned up after concurrent close")
}
