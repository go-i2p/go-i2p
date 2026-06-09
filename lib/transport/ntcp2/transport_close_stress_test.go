package ntcp2

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCloseWithHighConnectionChurn verifies that sessionCount remains correct
// under high concurrency with rapid session creation and destruction.
// RC-4 FIX: Tests that cleanup callbacks fire correctly and sessionCount
// doesn't go negative or accumulate stale entries.
func TestCloseWithHighConnectionChurn(t *testing.T) {
	transport := newNilListenerTestTransport(t, 2000) // Allow up to 2000 concurrent sessions

	// Phase 1: Create many sessions rapidly
	const numSessions = 500
	var createdSessions int32
	var createdErrors int32

	wg := sync.WaitGroup{}
	for i := 0; i < numSessions; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			// Reserve slot
			err := transport.checkSessionLimit()
			if err != nil {
				atomic.AddInt32(&createdErrors, 1)
				return
			}
			atomic.AddInt32(&createdSessions, 1)

			// Track inbound connection
			conn := newAcceptMockConn("10.0.0.1:5001")
			tracked, fresh := transport.trackInboundConnection(conn)
			if !fresh {
				_ = tracked.Close()
				return
			}

			// Simulate session creation and cleanup
			peerHash := newTestPeerHash("churn-test-" + string(rune(id)))
			session := NewNTCP2Session(tracked, transport.ctx, transport.logger)
			session.SetCleanupCallback(func() {
				transport.removeSession(peerHash)
			})

			// Store and close after a brief moment to simulate real lifecycle
			transport.sessions.Store(peerHash, session)
			atomic.AddInt32(&transport.sessionCount, 1)

			// Simulate work and cleanup
			_ = session.Close()
		}(i)
	}

	// Wait for all session creations to complete
	wg.Wait()

	createdVal := atomic.LoadInt32(&createdSessions)
	errorsVal := atomic.LoadInt32(&createdErrors)

	t.Logf("Created %d sessions, %d errors", createdVal, errorsVal)

	// Allow cleanup callbacks to complete
	transport.closeAllActiveSessions()

	// Verify final state
	finalCount := transport.GetSessionCount()
	assert.Equal(t, 0, finalCount, "sessionCount should be 0 after all sessions closed")

	// Verify no stale sessions remain in map
	staleSessions := 0
	transport.sessions.Range(func(key, value interface{}) bool {
		staleSessions++
		return true
	})
	assert.Equal(t, 0, staleSessions, "no sessions should remain in map after close")

	// Close the transport
	err := transport.Close()
	require.NoError(t, err)
}

// TestConcurrentCreationAndClosureIntegration verifies that sessionCount
// stays consistent when sessions are created and destroyed concurrently
// with transport Close() being called.
// RC-4 FIX: Ensures the reconciliation loop doesn't double-decrement.
func TestConcurrentCreationAndClosureIntegration(t *testing.T) {
	transport := newNilListenerTestTransport(t, 1000)

	// Phase 1: Start background goroutines that continuously create/destroy sessions
	const duration = 100 // iterations
	var createdCount int32

	wg := sync.WaitGroup{}

	// Creator workers
	for w := 0; w < 5; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for i := 0; i < duration; i++ {
				if transport.checkSessionLimit() != nil {
					// Skip if limit reached
					continue
				}

				conn := newAcceptMockConn("10.0.0.1:5001")
				tracked, fresh := transport.trackInboundConnection(conn)
				if !fresh {
					_ = tracked.Close()
					continue
				}

				atomic.AddInt32(&createdCount, 1)

				// Immediately close to simulate rapid churn
				_ = tracked.Close()
			}
		}(w)
	}

	// Wait for all creations to complete
	wg.Wait()

	// Phase 2: Close transport while verifying no crashes or negative counts
	preCloseCount := transport.GetSessionCount()
	t.Logf("Session count before close: %d (created: %d)", preCloseCount, atomic.LoadInt32(&createdCount))

	err := transport.Close()
	require.NoError(t, err)

	postCloseCount := transport.GetSessionCount()
	assert.Equal(t, 0, postCloseCount, "sessionCount should be 0 after transport.Close()")
}

// TestDecrementSessionCountSafe_DoesNotGoNegative verifies the safe decrement
// helper catches and prevents negative sessionCount.
// RC-4 FIX: Runtime assertion that catches double-decrements.
func TestDecrementSessionCountSafe_DoesNotGoNegative(t *testing.T) {
	transport := newNilListenerTestTransport(t, 100)

	// Manually test safe decrement behavior
	assert.Equal(t, 0, transport.GetSessionCount())

	// Attempt to decrement from 0 (should fail and force-reset)
	result := transport.decrementSessionCountSafe()
	assert.False(t, result, "decrement should return false when count is 0")

	// Verify it stayed at 0 (force-reset, not negative)
	assert.Equal(t, 0, transport.GetSessionCount())

	// Now properly increment, then decrement
	atomic.AddInt32(&transport.sessionCount, 1)
	assert.Equal(t, 1, transport.GetSessionCount())

	result = transport.decrementSessionCountSafe()
	assert.True(t, result, "decrement should return true with count > 0")
	assert.Equal(t, 0, transport.GetSessionCount())
}

// TestSessionCountReconciliation verifies the reconciliation loop in closeAllActiveSessions
// properly handles both cleanup-callback-removed sessions and stale sessions.
// RC-4 FIX: Ensures stale sessions are decremented exactly once.
func TestSessionCountReconciliation(t *testing.T) {
	transport := newNilListenerTestTransport(t, 100)

	// Create a session with no cleanup callback (simulating a stale session)
	peerHash := newTestPeerHash("stale-session-test")
	conn := newAcceptMockConn("10.0.0.1:5001")
	session := NewNTCP2Session(conn, transport.ctx, transport.logger)

	// Store in map but DON'T set cleanup callback
	transport.sessions.Store(peerHash, session)
	atomic.AddInt32(&transport.sessionCount, 1)

	assert.Equal(t, 1, transport.GetSessionCount())

	// Close all sessions - reconciliation loop should find and decrement this stale entry
	transport.closeAllActiveSessions()

	finalCount := transport.GetSessionCount()
	assert.Equal(t, 0, finalCount, "reconciliation should decrement the stale session")

	// Close transport
	err := transport.Close()
	require.NoError(t, err)
}
