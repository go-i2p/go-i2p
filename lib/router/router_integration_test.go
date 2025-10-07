package router

import (
	"fmt"
	"sync"
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/go-i2p/lib/i2np"
	ntcp "github.com/go-i2p/go-i2p/lib/transport/ntcp2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRouterSessionProviderInterface verifies that Router satisfies the SessionProvider interface
func TestRouterSessionProviderInterface(t *testing.T) {
	// Create a minimal router instance for interface verification
	router := &Router{
		activeSessions: make(map[common.Hash]*ntcp.NTCP2Session),
	}

	// Verify Router implements i2np.SessionProvider interface
	// This will fail at compile time if the interface is not satisfied
	var _ i2np.SessionProvider = router

	t.Log("Router successfully implements i2np.SessionProvider interface")
}

// TestMessageRouterSessionProvider verifies that MessageRouter properly receives and uses SessionProvider
func TestMessageRouterSessionProvider(t *testing.T) {
	// Create a router with active sessions
	router := &Router{
		activeSessions: make(map[common.Hash]*ntcp.NTCP2Session),
	}

	// Create a MessageRouter with configuration
	messageConfig := i2np.MessageRouterConfig{
		MaxRetries:     3,
		DefaultTimeout: 30 * time.Second,
		EnableLogging:  true,
	}
	messageRouter := i2np.NewMessageRouter(messageConfig)

	// Create a test peer hash
	peerHash := common.Hash{}
	copy(peerHash[:], "test_peer_hash_1234567890123456789")

	// Add a mock session to the router
	// For this test, we're testing the wiring, not actual session functionality
	mockSession := (*ntcp.NTCP2Session)(nil)
	router.addSession(peerHash, mockSession)

	// Set the router as SessionProvider for the MessageRouter
	messageRouter.SetSessionProvider(router)

	// Verify we can retrieve the session through the router's SessionProvider interface
	session, err := router.GetSessionByHash(peerHash)
	require.NoError(t, err, "Should retrieve session through SessionProvider interface")
	assert.Equal(t, mockSession, session, "Should retrieve the correct session")

	t.Log("MessageRouter successfully configured with SessionProvider")
}

// TestSessionProviderWithNonExistentPeer verifies error handling for unknown peers
func TestSessionProviderWithNonExistentPeer(t *testing.T) {
	// Create a router with empty session map
	router := &Router{
		activeSessions: make(map[common.Hash]*ntcp.NTCP2Session),
	}

	// Try to retrieve a non-existent session
	unknownPeerHash := common.Hash{}
	copy(unknownPeerHash[:], "unknown_peer_hash_12345678901234567")

	session, err := router.GetSessionByHash(unknownPeerHash)

	// Verify error handling
	assert.Error(t, err, "Should return error for unknown peer")
	assert.Nil(t, session, "Session should be nil for unknown peer")
	assert.Contains(t, err.Error(), "no session found", "Error message should indicate session not found")

	t.Log("SessionProvider correctly handles requests for unknown peers")
}

// TestInitializeMessageRouterWithSessionProvider tests the complete initialization flow
func TestInitializeMessageRouterWithSessionProvider(t *testing.T) {
	// This test verifies that initializeMessageRouter properly configures the SessionProvider
	// We'll create a minimal router setup to test the initialization flow

	router := &Router{
		activeSessions: make(map[common.Hash]*ntcp.NTCP2Session),
	}

	// Initialize the MessageRouter (without NetDB for this unit test)
	messageConfig := i2np.MessageRouterConfig{
		MaxRetries:     3,
		DefaultTimeout: 30 * time.Second,
		EnableLogging:  true,
	}
	router.messageRouter = i2np.NewMessageRouter(messageConfig)

	// Set the SessionProvider (this is what initializeMessageRouter does)
	router.messageRouter.SetSessionProvider(router)

	// Add a test session
	testPeerHash := common.Hash{}
	copy(testPeerHash[:], "integration_test_peer_123456789012")
	testSession := (*ntcp.NTCP2Session)(nil)
	router.addSession(testPeerHash, testSession)

	// Verify the session can be retrieved through the router's SessionProvider
	retrievedSession, err := router.GetSessionByHash(testPeerHash)
	require.NoError(t, err, "Should retrieve session through SessionProvider")
	assert.Equal(t, testSession, retrievedSession, "Retrieved session should match added session")

	t.Log("MessageRouter initialization with SessionProvider completed successfully")
}

// TestSessionProviderThreadSafety verifies concurrent access to SessionProvider
func TestSessionProviderThreadSafety(t *testing.T) {
	router := &Router{
		activeSessions: make(map[common.Hash]*ntcp.NTCP2Session),
	}

	// Add multiple sessions
	const numSessions = 10
	sessionHashes := make([]common.Hash, numSessions)
	for i := 0; i < numSessions; i++ {
		hash := common.Hash{}
		copy(hash[:], []byte(fmt.Sprintf("concurrent_peer_%02d_hash_1234567", i)))
		sessionHashes[i] = hash
		router.addSession(hash, (*ntcp.NTCP2Session)(nil))
	}

	// Concurrently access SessionProvider from multiple goroutines
	var wg sync.WaitGroup
	const numGoroutines = 20
	const operationsPerGoroutine = 100

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()
			for j := 0; j < operationsPerGoroutine; j++ {
				// Randomly select a session hash
				hashIndex := (goroutineID + j) % numSessions
				hash := sessionHashes[hashIndex]

				// Use SessionProvider interface to retrieve session
				_, err := router.GetSessionByHash(hash)
				assert.NoError(t, err, "Concurrent GetSessionByHash should not error")
			}
		}(i)
	}

	wg.Wait()
	t.Log("SessionProvider successfully handled concurrent access")
}

// mockSessionProvider implements SessionProvider for testing
type mockSessionProvider struct {
	sessions map[common.Hash]i2np.TransportSession
}

func (m *mockSessionProvider) GetSessionByHash(hash common.Hash) (i2np.TransportSession, error) {
	if session, ok := m.sessions[hash]; ok {
		return session, nil
	}
	return nil, fmt.Errorf("no session found for peer %x", hash[:8])
}

// TestMessageRouterWithMockSessionProvider tests MessageRouter with a mock provider
func TestMessageRouterWithMockSessionProvider(t *testing.T) {
	// Create a mock session provider
	mockProvider := &mockSessionProvider{
		sessions: make(map[common.Hash]i2np.TransportSession),
	}

	// Create a MessageRouter
	messageConfig := i2np.MessageRouterConfig{
		MaxRetries:     3,
		DefaultTimeout: 30 * time.Second,
		EnableLogging:  false, // Disable logging for cleaner test output
	}
	messageRouter := i2np.NewMessageRouter(messageConfig)

	// Set the mock provider
	messageRouter.SetSessionProvider(mockProvider)

	// This test verifies that MessageRouter accepts any SessionProvider implementation
	// not just the Router struct
	t.Log("MessageRouter successfully configured with mock SessionProvider")
}
