package router

import (
	"fmt"
	"sync"
	"testing"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/go-i2p/lib/i2np"
	ntcp "github.com/go-i2p/go-i2p/lib/transport/ntcp2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRouterSessionTracking tests basic session add/remove operations
func TestRouterSessionTracking(t *testing.T) {
	// Create a router with minimal setup for session testing
	router := &Router{
		activeSessions: make(map[common.Hash]*ntcp.NTCP2Session),
	}

	// Create mock peer hashes
	peer1Hash := common.Hash{}
	peer2Hash := common.Hash{}
	copy(peer1Hash[:], "peer1_hash_12345678901234567890123")
	copy(peer2Hash[:], "peer2_hash_12345678901234567890123")

	// For unit testing session tracking logic, we don't need actual sessions
	// We just need non-nil pointers that can be stored in the map
	// Using type assertions to store nil pointers of correct type
	session1 := (*ntcp.NTCP2Session)(nil)
	session2 := (*ntcp.NTCP2Session)(nil)

	// Note: In real usage, these would be actual NTCP2Session instances
	// For this unit test, we're only testing map operations, not session functionality

	// Test adding sessions
	router.addSession(peer1Hash, session1)
	router.addSession(peer2Hash, session2)

	// Verify sessions were added
	assert.Equal(t, 2, len(router.activeSessions), "Should have 2 active sessions")

	// Test retrieving sessions
	retrievedSession1, err := router.getSessionByHash(peer1Hash)
	require.NoError(t, err, "Should retrieve session1 without error")
	assert.Equal(t, session1, retrievedSession1, "Should retrieve correct session1")

	retrievedSession2, err := router.getSessionByHash(peer2Hash)
	require.NoError(t, err, "Should retrieve session2 without error")
	assert.Equal(t, session2, retrievedSession2, "Should retrieve correct session2")

	// Test removing a session
	router.removeSession(peer1Hash)
	assert.Equal(t, 1, len(router.activeSessions), "Should have 1 active session after removal")

	// Verify removed session can't be retrieved
	_, err = router.getSessionByHash(peer1Hash)
	assert.Error(t, err, "Should return error for removed session")
	assert.Contains(t, err.Error(), "no session found", "Error should indicate session not found")

	// Test removing the last session
	router.removeSession(peer2Hash)
	assert.Equal(t, 0, len(router.activeSessions), "Should have 0 active sessions")
}

// TestGetSessionByHash tests session retrieval scenarios
func TestGetSessionByHash(t *testing.T) {
	router := &Router{
		activeSessions: make(map[common.Hash]*ntcp.NTCP2Session),
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

	// Use nil session for testing map operations only
	session := (*ntcp.NTCP2Session)(nil)
	router.addSession(peerHash, session)

	retrievedSession, err := router.getSessionByHash(peerHash)
	require.NoError(t, err, "Should retrieve existing session without error")
	assert.Equal(t, session, retrievedSession, "Should retrieve the correct session")
}

// TestSessionThreadSafety tests concurrent session operations
func TestSessionThreadSafety(t *testing.T) {
	router := &Router{
		activeSessions: make(map[common.Hash]*ntcp.NTCP2Session),
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
				// Use nil session for testing concurrent map operations
				session := (*ntcp.NTCP2Session)(nil)
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
		activeSessions: make(map[common.Hash]*ntcp.NTCP2Session),
	}

	// Compile-time check that Router implements SessionProvider
	var _ i2np.SessionProvider = router

	// Runtime verification
	peerHash := common.Hash{}
	copy(peerHash[:], "test_peer_for_interface_12345678901")

	// Use nil session - we're only testing the interface, not actual functionality
	session := (*ntcp.NTCP2Session)(nil)
	router.addSession(peerHash, session)

	// Test GetSessionByHash (SessionProvider method)
	transportSession, err := router.GetSessionByHash(peerHash)
	require.NoError(t, err, "GetSessionByHash should succeed")
	// Note: transportSession will be nil in this test since we used a nil session,
	// but in real usage it would be a valid NTCP2Session that implements TransportSession
	assert.Equal(t, session, transportSession, "Should return the stored session")
}

// TestGetSessionByHashWithNonExistentPeer tests SessionProvider interface with missing peer
func TestGetSessionByHashWithNonExistentPeer(t *testing.T) {
	router := &Router{
		activeSessions: make(map[common.Hash]*ntcp.NTCP2Session),
	}

	// Test with non-existent peer
	nonExistentHash := common.Hash{}
	copy(nonExistentHash[:], "does_not_exist_hash_123456789012345")

	transportSession, err := router.GetSessionByHash(nonExistentHash)
	assert.Error(t, err, "Should return error for non-existent peer")
	assert.Nil(t, transportSession, "TransportSession should be nil on error")
	assert.Contains(t, err.Error(), "no session found", "Error message should indicate session not found")
}

// TestSessionReplacement tests that adding a session with the same hash replaces the old one
func TestSessionReplacement(t *testing.T) {
	router := &Router{
		activeSessions: make(map[common.Hash]*ntcp.NTCP2Session),
	}

	peerHash := common.Hash{}
	copy(peerHash[:], "test_peer_replacement_1234567890123")

	// Create two distinct session pointers for testing replacement
	// Using new() ensures we get different memory addresses
	session1 := new(ntcp.NTCP2Session)
	session2 := new(ntcp.NTCP2Session)

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
		activeSessions: make(map[common.Hash]*ntcp.NTCP2Session),
	}

	peerHash := common.Hash{}
	copy(peerHash[:], "test_multiple_removal_123456789012")

	// Use nil session for testing
	session := (*ntcp.NTCP2Session)(nil)

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
	router.activeSessions = make(map[common.Hash]*ntcp.NTCP2Session)
	assert.NotNil(t, router.activeSessions, "activeSessions should be initialized")

	// Now operations should work
	peerHash := common.Hash{}
	copy(peerHash[:], "test_init_hash_123456789012345678")

	// Use nil session for testing
	session := (*ntcp.NTCP2Session)(nil)
	router.addSession(peerHash, session)

	assert.Equal(t, 1, len(router.activeSessions), "Should have 1 session after initialization")
}

// BenchmarkAddSession benchmarks session addition performance
func BenchmarkAddSession(b *testing.B) {
	router := &Router{
		activeSessions: make(map[common.Hash]*ntcp.NTCP2Session),
	}

	// Use nil sessions for benchmarking - we're testing map operations, not session functionality
	sessions := make([]*ntcp.NTCP2Session, b.N)
	hashes := make([]common.Hash, b.N)

	// Pre-create hashes
	for i := 0; i < b.N; i++ {
		sessions[i] = (*ntcp.NTCP2Session)(nil)
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
		activeSessions: make(map[common.Hash]*ntcp.NTCP2Session),
	}

	// Add 1000 nil sessions for benchmarking map retrieval
	const numSessions = 1000
	hashes := make([]common.Hash, numSessions)
	for i := 0; i < numSessions; i++ {
		session := (*ntcp.NTCP2Session)(nil)
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
		activeSessions: make(map[common.Hash]*ntcp.NTCP2Session),
	}

	hashes := make([]common.Hash, b.N)

	// Add nil sessions for benchmarking map removal
	for i := 0; i < b.N; i++ {
		session := (*ntcp.NTCP2Session)(nil)
		hashStr := fmt.Sprintf("bench_remove_%d_hash_1234567890123", i)
		copy(hashes[i][:], hashStr)
		router.addSession(hashes[i], session)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		router.removeSession(hashes[i])
	}
}
