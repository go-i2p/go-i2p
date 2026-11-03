// Tests for router session management. Validates that sessions are added,
// looked up, and removed correctly.
package router

import (
	"fmt"
	"sync"
	"testing"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/go-i2p/go-i2p/lib/netdb"
	"github.com/go-i2p/go-i2p/lib/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRouterSessionTracking tests basic session add/remove operations
func TestRouterSessionTracking(t *testing.T) {
	// Create a router with minimal setup for session testing
	router := &Router{
		activeSessions: make(map[common.Hash]transport.TransportSession),
	}

	// Create mock peer hashes
	peer1Hash := common.Hash{}
	peer2Hash := common.Hash{}
	copy(peer1Hash[:], "peer1_hash_12345678901234567890123")
	copy(peer2Hash[:], "peer2_hash_12345678901234567890123")

	// For unit testing session tracking logic, we don't need actual sessions.
	// They do need to be live ones: the router evicts a session whose transport
	// context is gone (finding 006), so a typed nil would be treated as dead.
	session1 := newFakeTransportSession()
	session2 := newFakeTransportSession()

	// Note: In real usage, these would be actual NTCP2Session instances
	// For this unit test, we're only testing map operations, not session functionality

	// Test adding sessions
	addAndAssertSession(t, router, peer1Hash, session1)
	addAndAssertSession(t, router, peer2Hash, session2)

	// Verify sessions were added
	assert.Equal(t, 2, len(router.activeSessions), "Should have 2 active sessions")

	// Test removing a session
	router.removeSession(peer1Hash)
	assert.Equal(t, 1, len(router.activeSessions), "Should have 1 active session after removal")

	// Verify removed session can't be retrieved
	_, err := router.getSessionByHash(peer1Hash)
	assert.Error(t, err, "Should return error for removed session")
	assert.Contains(t, err.Error(), "no session found", "Error should indicate session not found")

	// Test removing the last session
	router.removeSession(peer2Hash)
	assert.Equal(t, 0, len(router.activeSessions), "Should have 0 active sessions")
}

// TestGetSessionByHash tests session retrieval scenarios
func TestGetSessionByHash(t *testing.T) {
	router := &Router{
		activeSessions: make(map[common.Hash]transport.TransportSession),
	}

	// Test retrieving non-existent session
	nonExistentHash := common.Hash{}
	copy(nonExistentHash[:], "nonexistent_hash_12345678901234567")

	_, err := router.getSessionByHash(nonExistentHash)
	assert.Error(t, err, "Should return error for non-existent session")
	assert.Contains(t, err.Error(), "no session found", "Error should indicate session not found")

	// Add a session and verify retrieval
	peerHash := common.Hash{}
	copy(peerHash[:], "test_peer_hash_1234567890123456789")

	// A live placeholder session: the router only returns sessions that are alive.
	session := newFakeTransportSession()
	addAndAssertSession(t, router, peerHash, session)
}

// TestSessionThreadSafety tests concurrent session operations
func TestSessionThreadSafety(t *testing.T) {
	router := &Router{
		activeSessions: make(map[common.Hash]transport.TransportSession),
	}

	const numGoroutines = 10
	const operationsPerGoroutine = 100

	var wg sync.WaitGroup
	wg.Add(numGoroutines * 3) // 3 operation types: add, get, remove

	// Concurrent add operations
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < operationsPerGoroutine; j++ {
				peerHash := common.Hash{}
				hashStr := fmt.Sprintf("peer_%d_%d_hash_1234567890123456", id, j)
				copy(peerHash[:], hashStr)
				// Live placeholder sessions for testing concurrent map operations
				session := newFakeTransportSession()
				router.addSession(peerHash, session)
			}
		}(i)
	}

	// Concurrent get operations
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < operationsPerGoroutine; j++ {
				peerHash := common.Hash{}
				hashStr := fmt.Sprintf("peer_%d_%d_hash_1234567890123456", id, j)
				copy(peerHash[:], hashStr)
				// Ignore errors since the session might not exist yet
				_, _ = router.getSessionByHash(peerHash)
			}
		}(i)
	}

	// Concurrent remove operations
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < operationsPerGoroutine; j++ {
				peerHash := common.Hash{}
				hashStr := fmt.Sprintf("peer_%d_%d_hash_1234567890123456", id, j)
				copy(peerHash[:], hashStr)
				router.removeSession(peerHash)
			}
		}(i)
	}

	// Wait for all goroutines to complete
	wg.Wait()

	// Verify the router is still in a valid state (no panics occurred)
	assert.NotNil(t, router.activeSessions, "Active sessions map should still exist")
}

// TestRouterImplementsSessionProvider verifies Router implements SessionProvider interface
func TestRouterImplementsSessionProvider(t *testing.T) {
	router := &Router{
		activeSessions: make(map[common.Hash]transport.TransportSession),
		running:        true, // Mark as running to allow session operations
	}

	// Compile-time check that Router implements SessionProvider
	var _ i2np.SessionProvider = router

	// Runtime verification
	peerHash := common.Hash{}
	copy(peerHash[:], "test_peer_for_interface_12345678901")

	// We're only testing the interface, not actual session functionality.
	session := newFakeTransportSession()
	router.addSession(peerHash, session)

	// Test GetSessionByHash (SessionProvider method)
	transportSession, err := router.GetSessionByHash(peerHash)
	require.NoError(t, err, "GetSessionByHash should succeed")
	assert.Equal(t, session, transportSession, "Should return the stored session")
}

// TestGetSessionByHashWithNonExistentPeer tests SessionProvider interface with missing peer
func TestGetSessionByHashWithNonExistentPeer(t *testing.T) {
	// Create temporary directory for NetDB
	tempDir := t.TempDir()

	router := &Router{
		activeSessions: make(map[common.Hash]transport.TransportSession),
		netdb:          netdb.NewStdNetDB(tempDir),
		running:        true, // Mark as running to allow session operations
	}

	// Ensure NetDB is initialized
	err := router.netdb.Ensure()
	require.NoError(t, err, "NetDB initialization should succeed")

	// Test with non-existent peer
	nonExistentHash := common.Hash{}
	copy(nonExistentHash[:], "does_not_exist_hash_123456789012345")

	transportSession, err := router.GetSessionByHash(nonExistentHash)
	assert.Error(t, err, "Should return error for non-existent peer")
	assert.Nil(t, transportSession, "TransportSession should be nil on error")
	assert.Contains(t, err.Error(), "RouterInfo", "Error message should indicate RouterInfo not found")
}

// TestSessionReplacement tests that adding a session with the same hash replaces the old one
func TestSessionReplacement(t *testing.T) {
	router := &Router{
		activeSessions: make(map[common.Hash]transport.TransportSession),
	}

	peerHash := common.Hash{}
	copy(peerHash[:], "test_peer_replacement_1234567890123")

	// Create two distinct sessions for testing replacement
	session1 := newFakeTransportSession()
	session2 := newFakeTransportSession()

	// Verify they're different pointers (compare addresses, not values)
	require.NotSame(t, session1, session2, "Sessions should have different addresses")

	// Add first session
	router.addSession(peerHash, session1)

	// Verify first session
	retrieved1, err := router.getSessionByHash(peerHash)
	require.NoError(t, err)
	assert.Equal(t, session1, retrieved1)

	// Add second session with same hash (should replace)
	router.addSession(peerHash, session2)

	// Verify second session replaced the first (compare pointers)
	retrieved2, err := router.getSessionByHash(peerHash)
	require.NoError(t, err)
	assert.Same(t, session2, retrieved2, "Should retrieve session2")
	assert.NotSame(t, session1, retrieved2, "Old session should be replaced")

	// Verify only one session exists
	assert.Equal(t, 1, len(router.activeSessions), "Should still have only 1 session")
}

// TestMultipleSessionRemoval tests that removing a session multiple times is safe
func TestMultipleSessionRemoval(t *testing.T) {
	router := &Router{
		activeSessions: make(map[common.Hash]transport.TransportSession),
	}

	peerHash := common.Hash{}
	copy(peerHash[:], "test_multiple_removal_123456789012")

	// Use a live placeholder session for testing
	session := newFakeTransportSession()

	// Add and remove session
	router.addSession(peerHash, session)
	assert.Equal(t, 1, len(router.activeSessions))

	router.removeSession(peerHash)
	assert.Equal(t, 0, len(router.activeSessions))

	// Remove again - should not panic
	router.removeSession(peerHash)
	assert.Equal(t, 0, len(router.activeSessions))

	// Remove one more time for good measure
	router.removeSession(peerHash)
	assert.Equal(t, 0, len(router.activeSessions))
}

// TestWireInboundHandler_WithoutI2CP ensures tunnel-data processing stays wired
// even when I2CP is disabled and no session manager is available.
func TestWireInboundHandler_WithoutI2CP(t *testing.T) {
	router := &Router{}

	router.wireInboundHandler()

	require.NotNil(t, router.inboundHandler, "inbound handler should always be initialized")
	assert.Nil(t, router.inboundHandler.sessionManager, "session manager should be nil when I2CP is disabled")
}

// TestSessionMapInitialization tests that activeSessions map must be initialized
func TestSessionMapInitialization(t *testing.T) {
	// Router with nil activeSessions map (testing edge case)
	router := &Router{
		activeSessions: nil,
	}

	// This would panic if code doesn't handle nil map, but our implementation
	// requires proper initialization. Document this requirement.
	assert.Nil(t, router.activeSessions, "activeSessions can be nil initially")

	// Initialize the map properly
	router.activeSessions = make(map[common.Hash]transport.TransportSession)
	assert.NotNil(t, router.activeSessions, "activeSessions should be initialized")

	// Now operations should work
	peerHash := common.Hash{}
	copy(peerHash[:], "test_init_hash_123456789012345678")

	// Use a live placeholder session for testing
	session := newFakeTransportSession()
	router.addSession(peerHash, session)

	assert.Equal(t, 1, len(router.activeSessions), "Should have 1 session after initialization")
}

// BenchmarkAddSession benchmarks session addition performance
func BenchmarkAddSession(b *testing.B) {
	router := &Router{
		activeSessions: make(map[common.Hash]transport.TransportSession),
	}

	// Use live placeholder sessions - we're benchmarking map operations, not
	// session functionality. Dead entries would be evicted on lookup.
	sessions := make([]*fakeTransportSession, b.N)
	hashes := make([]common.Hash, b.N)

	// Pre-create hashes
	for i := 0; i < b.N; i++ {
		sessions[i] = newFakeTransportSession()
		hashStr := fmt.Sprintf("bench_peer_%d_hash_12345678901234", i)
		copy(hashes[i][:], hashStr)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		router.addSession(hashes[i], sessions[i])
	}
}

// BenchmarkGetSession benchmarks session retrieval performance
func BenchmarkGetSession(b *testing.B) {
	router := &Router{
		activeSessions: make(map[common.Hash]transport.TransportSession),
	}

	// Add 1000 live placeholder sessions for benchmarking map retrieval
	const numSessions = 1000
	hashes := make([]common.Hash, numSessions)
	for i := 0; i < numSessions; i++ {
		session := newFakeTransportSession()
		hashStr := fmt.Sprintf("bench_get_%d_hash_123456789012345", i)
		copy(hashes[i][:], hashStr)
		router.addSession(hashes[i], session)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = router.getSessionByHash(hashes[i%numSessions])
	}
}

// BenchmarkRemoveSession benchmarks session removal performance
func BenchmarkRemoveSession(b *testing.B) {
	router := &Router{
		activeSessions: make(map[common.Hash]transport.TransportSession),
	}

	hashes := make([]common.Hash, b.N)

	// Add live placeholder sessions for benchmarking map removal
	for i := 0; i < b.N; i++ {
		session := newFakeTransportSession()
		hashStr := fmt.Sprintf("bench_remove_%d_hash_1234567890123", i)
		copy(hashes[i][:], hashStr)
		router.addSession(hashes[i], session)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		router.removeSession(hashes[i])
	}
}

// --- finding 006: a dead session must not be handed out, and must not block re-dial ---

// TestGetSessionByHashEvictsDeadSession pins the router half of finding 006.
// Before the fix the lookup returned whatever was in activeSessions with no
// liveness check, so tunnel forwarding, build replies and I2CP kept queueing
// onto a session whose transport workers were already gone — and because a
// session was "present", the router never re-dialled the peer. The link stayed
// dead until restart.
func TestGetSessionByHashEvictsDeadSession(t *testing.T) {
	router := &Router{
		activeSessions: make(map[common.Hash]transport.TransportSession),
	}

	peerHash := common.Hash{}
	copy(peerHash[:], "finding006_evict_dead_123456789012")

	session := newFakeTransportSession()
	router.addSession(peerHash, session)

	// A transport worker hits a fatal read/write error: the context is gone.
	session.setAlive(false)

	_, err := router.getSessionByHash(peerHash)
	require.Error(t, err, "a dead session must not be returned")
	assert.Contains(t, err.Error(), "is closed")

	// It must also be gone from the registry, so the next lookup goes on to
	// establish a new session rather than finding the corpse again.
	router.sessionMutex.RLock()
	_, exists := router.activeSessions[peerHash]
	router.sessionMutex.RUnlock()
	assert.False(t, exists, "the dead session must be evicted from activeSessions")

	// A second lookup reports the plain "no session" case.
	_, err = router.getSessionByHash(peerHash)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no session found")
}

// TestGetSessionByHashKeepsLiveSession is the negative control: liveness gating
// must not disturb the normal path.
func TestGetSessionByHashKeepsLiveSession(t *testing.T) {
	router := &Router{
		activeSessions: make(map[common.Hash]transport.TransportSession),
	}

	peerHash := common.Hash{}
	copy(peerHash[:], "finding006_keep_live_1234567890123")

	session := newFakeTransportSession()
	router.addSession(peerHash, session)

	retrieved, err := router.getSessionByHash(peerHash)
	require.NoError(t, err)
	assert.Same(t, session, retrieved, "a live session must be returned unchanged")
}

// TestGetSessionByHashAttemptsRedialAfterDeath is the end-to-end router
// behaviour: once the dead session is gone, the public SessionProvider entry
// point proceeds to establish a new session instead of returning the corpse.
// The peer has no RouterInfo here, so the re-dial fails — which is exactly the
// proof that the router tried to reconnect rather than reusing the dead link.
func TestGetSessionByHashAttemptsRedialAfterDeath(t *testing.T) {
	tempDir := t.TempDir()
	router := &Router{
		activeSessions: make(map[common.Hash]transport.TransportSession),
		netdb:          netdb.NewStdNetDB(tempDir),
		running:        true,
	}
	require.NoError(t, router.netdb.Ensure())

	peerHash := common.Hash{}
	copy(peerHash[:], "finding006_redial_attempt_12345678")

	session := newFakeTransportSession()
	router.addSession(peerHash, session)
	session.setAlive(false)

	got, err := router.GetSessionByHash(peerHash)
	assert.Error(t, err, "the dead session must not be returned")
	assert.Nil(t, got)
	assert.NotContains(t, err.Error(), "is closed",
		"the lookup must have moved past eviction to the establish-new-session path")
	assert.Contains(t, err.Error(), "RouterInfo",
		"expected the re-dial path's RouterInfo lookup to fail for an unknown peer")
}

// TestRemoveSessionIfCurrentDoesNotEvictReplacement pins the re-dial race the
// fix introduces: a dead session whose cleanup runs late must not delete the
// replacement session the router already registered for the same peer.
func TestRemoveSessionIfCurrentDoesNotEvictReplacement(t *testing.T) {
	router := &Router{
		activeSessions: make(map[common.Hash]transport.TransportSession),
	}

	peerHash := common.Hash{}
	copy(peerHash[:], "finding006_replacement_race_123456")

	oldSession := newFakeTransportSession()
	router.addSession(peerHash, oldSession)

	// The router re-dials and registers a replacement under the same hash.
	newSession := newFakeTransportSession()
	router.addSession(peerHash, newSession)

	// The old session's cleanup fires late.
	assert.False(t, router.removeSessionIfCurrent(peerHash, oldSession),
		"the old session must not remove an entry it no longer owns")

	retrieved, err := router.getSessionByHash(peerHash)
	require.NoError(t, err, "the replacement must still be registered")
	assert.Same(t, newSession, retrieved)

	// The replacement's own cleanup does remove it.
	assert.True(t, router.removeSessionIfCurrent(peerHash, newSession))
	_, err = router.getSessionByHash(peerHash)
	require.Error(t, err)
}

// TestConnectedPeerHashesExcludesDeadSessions keeps hop-selection honest: a peer
// whose session just died must not be reported as already reachable, or new
// tunnels keep getting placed on dead links.
func TestConnectedPeerHashesExcludesDeadSessions(t *testing.T) {
	router := &Router{
		activeSessions: make(map[common.Hash]transport.TransportSession),
	}

	liveHash := common.Hash{}
	copy(liveHash[:], "finding006_connected_live_123456789")
	deadHash := common.Hash{}
	copy(deadHash[:], "finding006_connected_dead_123456789")

	live := newFakeTransportSession()
	dead := newFakeTransportSession()
	dead.setAlive(false)

	router.addSession(liveHash, live)
	router.addSession(deadHash, dead)

	connected := router.connectedPeerHashes()
	require.NotNil(t, connected)
	_, hasLive := connected[liveHash]
	_, hasDead := connected[deadHash]
	assert.True(t, hasLive, "a live session means the peer is connected")
	assert.False(t, hasDead, "a dead session must not count as connected")
}

// TestConnectedPeerHashesNilWhenAllDead checks the provider reports "nothing
// connected" rather than an empty-but-present map, so callers fall back cleanly.
func TestConnectedPeerHashesNilWhenAllDead(t *testing.T) {
	router := &Router{
		activeSessions: make(map[common.Hash]transport.TransportSession),
	}

	hash := common.Hash{}
	copy(hash[:], "finding006_all_dead_1234567890123")
	dead := newFakeTransportSession()
	dead.setAlive(false)
	router.addSession(hash, dead)

	assert.Nil(t, router.connectedPeerHashes(), "no live peers should yield nil")
}
