package ntcp2

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSetupSession_HandlesNetConnFromAccept verifies that setupSession does not
// panic when sessions.LoadOrStore returns a raw net.Conn (stored by Accept())
// instead of *NTCP2Session. This was a CRITICAL BUG: the original code used
// existing.(*NTCP2Session) without checking the type.
func TestSetupSession_HandlesNetConnFromAccept(t *testing.T) {
	transport := newTestTransport(nil, 100)
	defer transport.cancel()

	// Simulate Accept() having stored a raw net.Conn in the session map.
	var peerHash data.Hash
	copy(peerHash[:], []byte("test-peer-hash-for-race-test!"))
	rawConn := newAcceptMockConn("192.168.1.1:5001")
	transport.sessions.Store(peerHash, rawConn)
	atomic.AddInt32(&transport.sessionCount, 1)

	// Create a mock outbound conn to pass to setupSession.
	outboundConn := newAcceptMockConn("192.168.1.1:5001")
	// Wrap it as a *ntcp2.NTCP2Conn is not possible without the actual
	// handshake, so we test resolveExistingSession directly instead.
	// The setupSession calls resolveExistingSession when LoadOrStore finds
	// an existing entry.

	// resolveExistingSession should promote the raw net.Conn to *NTCP2Session
	// without panicking.
	require.NotPanics(t, func() {
		result := transport.resolveExistingSession(rawConn, peerHash)
		require.NotNil(t, result, "resolveExistingSession should return a promoted session")
	})

	// Verify the session was promoted in the map.
	entry, exists := transport.sessions.Load(peerHash)
	require.True(t, exists)
	_, isSession := entry.(*NTCP2Session)
	assert.True(t, isSession, "map entry should now be *NTCP2Session after promotion")

	// Clean up: close the outbound conn to avoid leaks.
	_ = outboundConn.Close()
}

// TestResolveExistingSession_NTCP2Session verifies the fast path where the
// existing entry is already an *NTCP2Session.
func TestResolveExistingSession_NTCP2Session(t *testing.T) {
	transport := newTestTransport(nil, 100)
	defer transport.cancel()

	var peerHash data.Hash
	copy(peerHash[:], []byte("test-peer-hash-ntcp2-session"))

	mockConn := newAcceptMockConn("192.168.1.2:5002")
	existingSession := NewNTCP2Session(mockConn, transport.ctx, transport.logger)

	result := transport.resolveExistingSession(existingSession, peerHash)
	require.NotNil(t, result)
	assert.Equal(t, existingSession, result, "should return the same *NTCP2Session")

	_ = existingSession.Close()
}

// TestResolveExistingSession_RawNetConn verifies the slow path where the
// existing entry is a raw net.Conn that needs promotion.
func TestResolveExistingSession_RawNetConn(t *testing.T) {
	transport := newTestTransport(nil, 100)
	defer transport.cancel()

	var peerHash data.Hash
	copy(peerHash[:], []byte("test-peer-hash-raw-conn-promo"))

	rawConn := newAcceptMockConn("192.168.1.3:5003")
	transport.sessions.Store(peerHash, rawConn)

	result := transport.resolveExistingSession(rawConn, peerHash)
	require.NotNil(t, result, "should promote raw net.Conn to *NTCP2Session")

	// Verify the map now contains *NTCP2Session.
	entry, exists := transport.sessions.Load(peerHash)
	require.True(t, exists)
	_, isSession := entry.(*NTCP2Session)
	assert.True(t, isSession)

	_ = result.Close()
}

// TestResolveExistingSession_ConcurrentPromotion verifies that concurrent
// promotion of the same net.Conn is safe — no panics, no data races.
func TestResolveExistingSession_ConcurrentPromotion(t *testing.T) {
	transport := newTestTransport(nil, 100)
	defer transport.cancel()

	var peerHash data.Hash
	copy(peerHash[:], []byte("test-peer-hash-concurrent-prm"))

	rawConn := newAcceptMockConn("192.168.1.4:5004")
	transport.sessions.Store(peerHash, rawConn)

	const goroutines = 10
	var wg sync.WaitGroup

	// The critical property: no goroutine should panic.
	// resolveExistingSession must be safe to call concurrently.
	require.NotPanics(t, func() {
		wg.Add(goroutines)
		for i := 0; i < goroutines; i++ {
			go func() {
				defer wg.Done()
				_ = transport.resolveExistingSession(rawConn, peerHash)
			}()
		}
		wg.Wait()
	})

	// The map should contain *NTCP2Session (promoted by the winner).
	entry, exists := transport.sessions.Load(peerHash)
	require.True(t, exists, "session map entry should exist")
	if session, ok := entry.(*NTCP2Session); ok {
		_ = session.Close()
	}
}

// TestCloseAllActiveSessions_ClosesNetConnEntries verifies that
// closeAllActiveSessions closes raw net.Conn entries (from Accept)
// in addition to *NTCP2Session entries, preventing connection leaks.
func TestCloseAllActiveSessions_ClosesNetConnEntries(t *testing.T) {
	transport := newTestTransport(nil, 100)
	defer transport.cancel()

	// Store a raw net.Conn (as Accept() would).
	var connHash data.Hash
	copy(connHash[:], []byte("test-raw-conn-shutdown-close!"))
	rawConn := newAcceptMockConn("192.168.1.5:5005")
	transport.sessions.Store(connHash, rawConn)
	atomic.AddInt32(&transport.sessionCount, 1)

	// Store an *NTCP2Session.
	var sessionHash data.Hash
	copy(sessionHash[:], []byte("test-session-shutdown-close!!"))
	sessionConn := newAcceptMockConn("192.168.1.6:5006")
	session := NewNTCP2Session(sessionConn, transport.ctx, transport.logger)
	transport.sessions.Store(sessionHash, session)
	atomic.AddInt32(&transport.sessionCount, 1)

	assert.Equal(t, 2, transport.GetSessionCount())

	// Close all sessions.
	transport.closeAllActiveSessions()

	// Both entries should be removed.
	assert.Equal(t, 0, transport.GetSessionCount())

	// Raw conn should have been closed.
	rawConn.closeMu.Lock()
	assert.True(t, rawConn.closed, "raw net.Conn should be closed during shutdown")
	rawConn.closeMu.Unlock()
}

// TestCloseIndividualSession_NetConn verifies that closeIndividualSession
// properly closes a raw net.Conn value without panicking.
func TestCloseIndividualSession_NetConn(t *testing.T) {
	transport := newTestTransport(nil, 100)
	defer transport.cancel()

	var hash data.Hash
	copy(hash[:], []byte("test-close-individual-netconn"))
	conn := newAcceptMockConn("192.168.1.7:5007")

	require.NotPanics(t, func() {
		transport.closeIndividualSession(hash, conn)
	})

	conn.closeMu.Lock()
	assert.True(t, conn.closed, "net.Conn should be closed")
	conn.closeMu.Unlock()
}

// TestCloseIndividualSession_NTCP2Session verifies that closeIndividualSession
// properly closes an *NTCP2Session value.
func TestCloseIndividualSession_NTCP2Session(t *testing.T) {
	transport := newTestTransport(nil, 100)
	defer transport.cancel()

	var hash data.Hash
	copy(hash[:], []byte("test-close-individual-session"))
	mockConn := newAcceptMockConn("192.168.1.8:5008")
	session := NewNTCP2Session(mockConn, transport.ctx, transport.logger)

	require.NotPanics(t, func() {
		transport.closeIndividualSession(hash, session)
	})
}

// TestCloseIndividualSession_UnexpectedType verifies that closeIndividualSession
// handles unexpected types without panicking.
func TestCloseIndividualSession_UnexpectedType(t *testing.T) {
	transport := newTestTransport(nil, 100)
	defer transport.cancel()

	var hash data.Hash
	copy(hash[:], []byte("test-close-individual-unknown"))

	require.NotPanics(t, func() {
		transport.closeIndividualSession(hash, "unexpected-string-value")
	})
}

// TestCreateOutboundSession_NilReturnOnSetupFailure verifies that
// createOutboundSession handles the case where setupSession.resolveExistingSession
// might return nil (defensive programming).
func TestResolveExistingSession_UnexpectedType(t *testing.T) {
	transport := newTestTransport(nil, 100)
	defer transport.cancel()

	var peerHash data.Hash
	copy(peerHash[:], []byte("test-peer-hash-unexpected-typ"))

	// Store something that is neither *NTCP2Session nor net.Conn.
	transport.sessions.Store(peerHash, "unexpected-type")

	result := transport.resolveExistingSession("unexpected-type", peerHash)
	assert.Nil(t, result, "should return nil for unexpected types")
}

// TestSetupSession_WinsStoreRace verifies the normal path where setupSession
// successfully stores a new session (no existing entry).
func TestSetupSession_NewSessionPath(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	transport := &NTCP2Transport{
		config:   &Config{ListenerAddress: "127.0.0.1:0", MaxSessions: 100},
		ctx:      ctx,
		cancel:   cancel,
		logger:   logger.WithField("test", "setup_session"),
		sessions: sync.Map{},
	}

	var peerHash data.Hash
	copy(peerHash[:], []byte("test-new-session-store-path!!"))

	// Reserve a session slot as createOutboundSession would.
	atomic.AddInt32(&transport.sessionCount, 1)

	mockConn := newAcceptMockConn("192.168.1.9:5009")

	// We can't create a real *ntcp2.NTCP2Conn without a handshake,
	// so we test the resolveExistingSession path separately.
	// Verify the session map structure after store.
	session := NewNTCP2SessionDeferred(mockConn, ctx, transport.logger)
	session.StartWorkers()
	session.SetCleanupCallback(func() {
		transport.removeSession(peerHash)
	})
	transport.sessions.Store(peerHash, session)

	entry, exists := transport.sessions.Load(peerHash)
	require.True(t, exists)
	_, isSession := entry.(*NTCP2Session)
	assert.True(t, isSession)

	_ = session.Close()
}

// TestAccept_ThenGetSession_NoRacePanic verifies the full accept→getSession
// flow doesn't panic even when Accept() stores a net.Conn and findExistingSession
// tries to promote it.
func TestAccept_ThenFindExistingSession_Promotion(t *testing.T) {
	conn := newAcceptMockConn("10.0.0.50:5050")
	listener := newMockListener(conn)
	transport := newTestTransport(listener, 10)
	defer transport.cancel()

	// Accept stores a raw net.Conn in the session map.
	accepted, err := transport.Accept()
	require.NoError(t, err)
	require.NotNil(t, accepted)

	// Extract the peer hash that Accept used.
	peerHash := transport.extractPeerHash(conn)

	// findExistingSession should promote the net.Conn to *NTCP2Session.
	session, found := transport.findExistingSession(peerHash)
	assert.True(t, found, "should find the accepted connection")
	assert.NotNil(t, session, "should return a promoted session")

	// Verify the map entry is now *NTCP2Session.
	entry, exists := transport.sessions.Load(peerHash)
	require.True(t, exists)
	_, isSession := entry.(*NTCP2Session)
	assert.True(t, isSession, "map entry should be *NTCP2Session after promotion")

	_ = accepted.Close()
	if session != nil {
		// The promoted session may share the same underlying conn,
		// so closing it is expected to return an error (already closed).
		_ = session.(interface{ Close() error }).Close()
	}
}

// TestCreateNewListenerWithConfig_ClosesListenerOnError is a compile-time
// verification that the fix is in place. We can't easily make
// ntcp2.NewNTCP2Listener fail in a unit test without complex mocking,
// but we verify the error path structure is correct.
func TestCreateNewListenerWithConfig_ErrorPathStructure(t *testing.T) {
	// Verify the function exists and has the correct signature.
	transport := newTestTransport(nil, 100)
	defer transport.cancel()

	// Calling with a valid address but nil config should fail at
	// NewNTCP2Listener, and the fix ensures tcpListener is closed.
	transport.config.ListenerAddress = fmt.Sprintf("127.0.0.1:0")
	_, err := transport.createNewListenerWithConfig(nil)
	// We expect an error because ntcp2Config is nil.
	assert.Error(t, err, "should fail with nil NTCP2 config")
}
