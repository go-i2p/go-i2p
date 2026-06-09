package ntcp2

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSetCleanupCallback_CalledSynchronouslyOnClose verifies that cleanup callbacks fire
// synchronously when Close() completes, not deferred.
// SA-1 FIX: Confirms callback timing is correct with HIGH-8.2 fix
// (SetCleanupCallback before StartWorkers).
func TestSetCleanupCallback_CalledSynchronouslyOnClose(t *testing.T) {
	transport := newNilListenerTestTransport(t, 100)

	// Create a session with cleanup callback
	peerHash := newTestPeerHash("callback-test")
	conn := newAcceptMockConn("10.0.0.1:5001")
	session := NewNTCP2Session(conn, transport.ctx, transport.logger)

	var callbackFired atomic.Bool

	// Set callback BEFORE starting workers (HIGH-8.2 fix)
	session.SetCleanupCallback(func() {
		callbackFired.Store(true)
	})

	session.StartWorkers()

	// Store in transport map to simulate real usage
	transport.sessions.Store(peerHash, session)
	atomic.AddInt32(&transport.sessionCount, 1)

	// Close the session
	err := session.Close()
	require.NoError(t, err)

	// Verify callback fired synchronously (not deferred)
	assert.True(t, callbackFired.Load(), "cleanup callback should have fired during Close()")

	// Close transport
	err = transport.Close()
	require.NoError(t, err)
}

// TestSetCleanupCallback_FiresExactlyOnce verifies that cleanup callbacks
// are called exactly once, even under concurrent Close() attempts.
// SA-1 FIX: sync.Once protection prevents double-decrement.
func TestSetCleanupCallback_FiresExactlyOnce(t *testing.T) {
	transport := newNilListenerTestTransport(t, 100)

	peerHash := newTestPeerHash("once-test")
	conn := newAcceptMockConn("10.0.0.1:5001")
	session := NewNTCP2Session(conn, transport.ctx, transport.logger)

	var callbackCount int32

	session.SetCleanupCallback(func() {
		atomic.AddInt32(&callbackCount, 1)
	})
	session.StartWorkers()

	transport.sessions.Store(peerHash, session)
	atomic.AddInt32(&transport.sessionCount, 1)

	// Attempt concurrent Close() calls
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = session.Close()
		}()
	}
	wg.Wait()

	// Verify callback fired exactly once
	finalCount := atomic.LoadInt32(&callbackCount)
	assert.Equal(t, int32(1), finalCount, "callback should fire exactly once despite concurrent Close() calls")

	// Close transport
	err := transport.Close()
	require.NoError(t, err)
}

// TestPromoteInboundConnection_CallbackFiresBeforeMapRemoval verifies that
// promoted sessions have cleanup callbacks installed BEFORE workers start.
// SA-1 FIX: Ensures HIGH-8.2 fix (callback before StartWorkers) prevents orphaned sessions.
func TestPromoteInboundConnection_CallbackFiresBeforeMapRemoval(t *testing.T) {
	transport := newNilListenerTestTransport(t, 100)

	// Create an accepted connection
	peerHash := newTestPeerHash("promote-test")
	conn := newAcceptMockConn("10.0.0.1:5001")
	tracked, fresh := transport.trackInboundConnection(conn)
	require.True(t, fresh)

	// Store in map as accepted connection
	transport.sessions.Store(peerHash, tracked)
	atomic.AddInt32(&transport.sessionCount, 1)

	// Create and promote a session
	session := NewNTCP2Session(tracked, transport.ctx, transport.logger)

	// Simulate promotion with callback installation BEFORE StartWorkers
	var callbackExecuted atomic.Bool
	session.SetCleanupCallback(func() {
		callbackExecuted.Store(true)
		// Actually remove from map and decrement count like removeSession does
		if _, loaded := transport.sessions.LoadAndDelete(peerHash); loaded {
			transport.decrementSessionCountSafe()
		}
	})
	session.StartWorkers()

	// Replace in map with promoted session
	transport.sessions.Store(peerHash, session)

	// Close the session
	err := session.Close()
	require.NoError(t, err)

	// Verify callback executed and session was removed from map
	assert.True(t, callbackExecuted.Load(), "callback should execute on session close")

	_, exists := transport.sessions.Load(peerHash)
	assert.False(t, exists, "session should be removed from map after callback")

	// Verify sessionCount was decremented
	assert.Equal(t, 0, transport.GetSessionCount())

	// Close transport
	err = transport.Close()
	require.NoError(t, err)
}

// TestCloseAllActiveSessions_AllCallbacksFire verifies that during transport
// Close(), all session cleanup callbacks fire before the transport finishes closing.
// SA-1 FIX: Verifies that reconciliation doesn't find stale sessions (callbacks fired).
func TestCloseAllActiveSessions_AllCallbacksFire(t *testing.T) {
	transport := newNilListenerTestTransport(t, 100)

	const numSessions = 20
	var callbacksFired int32

	// Create multiple sessions with tracked callbacks
	for i := 0; i < numSessions; i++ {
		peerHash := newTestPeerHash("multi-callback-" + string(rune(i)))
		conn := newAcceptMockConn("10.0.0.1:5001")
		session := NewNTCP2Session(conn, transport.ctx, transport.logger)

		session.SetCleanupCallback(func() {
			atomic.AddInt32(&callbacksFired, 1)
		})
		session.StartWorkers()

		transport.sessions.Store(peerHash, session)
		atomic.AddInt32(&transport.sessionCount, 1)
	}

	assert.Equal(t, numSessions, int(transport.GetSessionCount()))

	// Close all sessions
	transport.closeAllActiveSessions()

	// Verify all callbacks fired
	finalCallbackCount := atomic.LoadInt32(&callbacksFired)
	assert.Equal(t, int32(numSessions), finalCallbackCount,
		"all cleanup callbacks should fire during closeAllActiveSessions()")

	// Verify sessionCount is 0 after close
	assert.Equal(t, 0, transport.GetSessionCount(), "sessionCount should be 0 after closeAllActiveSessions()")

	// Verify no stale sessions remain
	staleSessions := 0
	transport.sessions.Range(func(key, value interface{}) bool {
		staleSessions++
		return true
	})
	assert.Equal(t, 0, staleSessions, "no sessions should remain in map")

	// Close transport
	err := transport.Close()
	require.NoError(t, err)
}
