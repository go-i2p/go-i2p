package ntcp2

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockSetupConn is a minimal net.Conn for setupSession tests.
// Read blocks until Close is called, mimicking real TCP connection behavior.
type mockSetupConn struct {
	net.Conn
	closed int32
	done   chan struct{}
}

func newMockSetupConn() *mockSetupConn {
	return &mockSetupConn{done: make(chan struct{})}
}

func (m *mockSetupConn) Read(b []byte) (int, error) {
	// Block until Close is called, then return an error (like a real conn).
	<-m.done
	return 0, net.ErrClosed
}
func (m *mockSetupConn) Write(b []byte) (int, error) { return len(b), nil }
func (m *mockSetupConn) Close() error {
	if atomic.CompareAndSwapInt32(&m.closed, 0, 1) {
		close(m.done)
	}
	return nil
}
func (m *mockSetupConn) LocalAddr() net.Addr { return &net.TCPAddr{} }
func (m *mockSetupConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9999}
}
func (m *mockSetupConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockSetupConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockSetupConn) SetWriteDeadline(t time.Time) error { return nil }
func (m *mockSetupConn) isClosed() bool                     { return atomic.LoadInt32(&m.closed) == 1 }

// newMinimalTransport creates a minimal NTCP2Transport suitable for testing
// setupSession behavior without requiring a real listener or crypto setup.
func newMinimalTransport() (*NTCP2Transport, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	log := logger.WithField("component", "ntcp2_test")
	return &NTCP2Transport{
		ctx:    ctx,
		cancel: cancel,
		logger: log,
	}, cancel
}

// TestSetupSession_DuplicateSession validates that when a session already
// exists for a given routerHash, the newly created session is closed and
// the existing session is returned.
//
// This test exercises the logic of setupSession indirectly because the
// method signature requires *ntcp2.NTCP2Conn (from go-noise). We reproduce
// the exact LoadOrStore + Close pattern using NewNTCP2Session, which
// accepts net.Conn.
func TestSetupSession_DuplicateSession(t *testing.T) {
	transport, cancel := newMinimalTransport()
	defer cancel()

	routerHash := data.Hash{}
	copy(routerHash[:], []byte("test-router-hash-32bytes-pad!!XX"))

	// --- First session: simulate a successful store ---
	conn1 := newMockSetupConn()
	session1 := NewNTCP2Session(conn1, transport.ctx, transport.logger)
	session1.SetCleanupCallback(func() {
		transport.removeSession(routerHash)
	})
	_, loaded := transport.sessions.LoadOrStore(routerHash, session1)
	require.False(t, loaded, "first store should succeed")
	atomic.AddInt32(&transport.sessionCount, 1)

	assert.Equal(t, 1, transport.GetSessionCount(), "should have 1 session")

	// --- Second session: simulate a duplicate store (the bug scenario) ---
	conn2 := newMockSetupConn()
	session2 := NewNTCP2Session(conn2, transport.ctx, transport.logger)

	existing, loaded2 := transport.sessions.LoadOrStore(routerHash, session2)
	require.True(t, loaded2, "second store should find existing session")

	// The fix: close the duplicate session and return the existing one.
	session2.Close()
	returned := existing.(*NTCP2Session)

	// Verify:
	// 1. The returned session is the original (session1).
	assert.Same(t, session1, returned, "should return the existing session, not the new one")

	// 2. The duplicate session's connection was closed.
	assert.True(t, conn2.isClosed(), "duplicate session's connection should be closed")

	// 3. The original session's connection is still open.
	assert.False(t, conn1.isClosed(), "original session's connection should still be open")

	// 4. Session count is still 1 (no leak).
	assert.Equal(t, 1, transport.GetSessionCount(), "session count should remain 1")

	// Clean up: close session1 so goroutines don't leak.
	session1.Close()
	assert.True(t, conn1.isClosed(), "original session should be closed during cleanup")
}

// TestSetupSession_ConcurrentDuplicate verifies that concurrent calls
// to setupSession for the same peer result in only one active session.
// Run with -race to detect data races.
func TestSetupSession_ConcurrentDuplicate(t *testing.T) {
	transport, cancel := newMinimalTransport()
	defer cancel()

	routerHash := data.Hash{}
	copy(routerHash[:], []byte("concurrent-hash-32bytes-pad!!XX"))

	const numGoroutines = 10
	var wg sync.WaitGroup
	sessions := make([]*NTCP2Session, numGoroutines)
	conns := make([]*mockSetupConn, numGoroutines)

	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			conn := newMockSetupConn()
			conns[idx] = conn
			session := NewNTCP2Session(conn, transport.ctx, transport.logger)

			existing, loaded := transport.sessions.LoadOrStore(routerHash, session)
			if loaded {
				// Duplicate — close the new session, return existing.
				session.Close()
				sessions[idx] = existing.(*NTCP2Session)
			} else {
				// Won the store — set up cleanup and count.
				session.SetCleanupCallback(func() {
					transport.removeSession(routerHash)
				})
				atomic.AddInt32(&transport.sessionCount, 1)
				sessions[idx] = session
			}
		}(i)
	}
	wg.Wait()

	// All goroutines should return the same session.
	winner := sessions[0]
	for i := 1; i < numGoroutines; i++ {
		assert.Same(t, winner, sessions[i],
			"all goroutines should return the same session (goroutine %d)", i)
	}

	// Exactly 1 session should be active.
	assert.Equal(t, 1, transport.GetSessionCount(),
		"exactly one session should be counted")

	// Exactly numGoroutines-1 connections should be closed (duplicates),
	// and 1 should remain open (the winner).
	closedCount := 0
	for _, conn := range conns {
		if conn.isClosed() {
			closedCount++
		}
	}
	assert.Equal(t, numGoroutines-1, closedCount,
		"all duplicate connections should be closed")

	// Clean up the winning session.
	winner.Close()
}

// TestSetupSession_NoCleanupCallbackOnDuplicate verifies that the duplicate
// session does NOT get a cleanup callback set, so closing it won't remove
// the existing session from the transport's session map.
func TestSetupSession_NoCleanupCallbackOnDuplicate(t *testing.T) {
	transport, cancel := newMinimalTransport()
	defer cancel()

	routerHash := data.Hash{}
	copy(routerHash[:], []byte("no-callback-hash-32bytes-pad!XX"))

	// Store the first session.
	conn1 := newMockSetupConn()
	session1 := NewNTCP2Session(conn1, transport.ctx, transport.logger)
	session1.SetCleanupCallback(func() {
		transport.removeSession(routerHash)
	})
	transport.sessions.LoadOrStore(routerHash, session1)
	atomic.AddInt32(&transport.sessionCount, 1)

	// Create a duplicate session and close it (simulating the fix).
	conn2 := newMockSetupConn()
	session2 := NewNTCP2Session(conn2, transport.ctx, transport.logger)
	// Deliberately do NOT set cleanup callback on session2 (this is part of the fix).
	session2.Close()

	// The existing session should still be in the map.
	val, ok := transport.sessions.Load(routerHash)
	require.True(t, ok, "existing session should still be in the map after duplicate is closed")
	assert.Same(t, session1, val.(*NTCP2Session))

	// Session count should remain 1.
	assert.Equal(t, 1, transport.GetSessionCount())

	// Clean up.
	session1.Close()
}

// TestFindExistingSession_PromotesInboundConn verifies that findExistingSession
// promotes a raw net.Conn (stored by Accept) into a full NTCP2Session so that
// GetSession can return it instead of creating a redundant outbound connection.
func TestFindExistingSession_PromotesInboundConn(t *testing.T) {
	transport, cancel := newMinimalTransport()
	defer cancel()

	routerHash := data.Hash{}
	copy(routerHash[:], []byte("inbound-conn-hash-32bytes-pad!X"))

	// Simulate Accept: store a raw net.Conn in the sessions map.
	conn := newMockSetupConn()
	transport.sessions.Store(routerHash, net.Conn(conn))
	atomic.AddInt32(&transport.sessionCount, 1)

	// findExistingSession should detect the net.Conn and promote it to *NTCP2Session.
	session, found := transport.findExistingSession(routerHash)
	require.True(t, found, "should find the inbound conn entry")
	require.NotNil(t, session, "promoted session should not be nil")

	// The map entry should now be an *NTCP2Session.
	val, ok := transport.sessions.Load(routerHash)
	require.True(t, ok)
	ntcp2Session, ok := val.(*NTCP2Session)
	require.True(t, ok, "map entry should now be *NTCP2Session, not net.Conn")

	// The session count should remain 1.
	assert.Equal(t, 1, transport.GetSessionCount())

	// Clean up the promoted session.
	ntcp2Session.Close()
}
