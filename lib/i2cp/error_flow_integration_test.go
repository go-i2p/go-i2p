package i2cp

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestErrorFlowIntegration_SessionCreationWithErrorHandling tests that session creation
// properly handles all error returns from IdentHash(), Bytes(), PublicKey(), SigningPublicKey()
// This is an integration test for Phase 2: Proper Error Handling
func TestErrorFlowIntegration_SessionCreationWithErrorHandling(t *testing.T) {
	// Create server
	serverConfig := &ServerConfig{
		ListenAddr:  "localhost:0",
		Network:     "tcp",
		MaxSessions: 10,
	}

	server, err := NewServer(serverConfig)
	require.NoError(t, err)

	err = server.Start()
	require.NoError(t, err)
	defer server.Stop()

	// Create session - exercises error handling in destination/keys creation
	session, err := server.manager.CreateSession(nil, nil)
	require.NoError(t, err, "session creation should handle all error paths properly")
	require.NotNil(t, session)
	defer session.Stop()

	// Verify destination is valid and error handling works
	dest := session.Destination()
	require.NotNil(t, dest)

	// Test 1: Bytes() should work without error - exercises error handling from Phase 2
	bytes, err := dest.Bytes()
	assert.NoError(t, err, "Bytes() should succeed with proper error handling")
	assert.NotEmpty(t, bytes)

	// Test 2: Validate() should work without error
	err = dest.Validate()
	assert.NoError(t, err, "Validate() should succeed with proper error handling")

	// Test 3: Base64() should work without error - exercises Bytes() internally
	base64Str, err := dest.Base64()
	assert.NoError(t, err, "Base64() should succeed with proper error handling")
	assert.NotEmpty(t, base64Str)

	// Test 4: Base32Address() should work without error
	base32Addr, err := dest.Base32Address()
	assert.NoError(t, err, "Base32Address() should succeed with proper error handling")
	assert.NotEmpty(t, base32Addr)
}

// TestErrorFlowIntegration_LeaseSetCreationWithErrorHandling tests that LeaseSet creation
// properly handles errors from destination methods
func TestErrorFlowIntegration_LeaseSetCreationWithErrorHandling(t *testing.T) {
	_, session, inboundPool, _, cleanup := setupTestEnvironment(t)
	defer cleanup()

	// Verify we have active tunnels
	activeTunnels := inboundPool.GetActiveTunnels()
	require.Greater(t, len(activeTunnels), 0, "should have at least one active tunnel")

	// Create LeaseSet - exercises Bytes() and other error-returning methods
	leaseSetBytes, err := session.CreateLeaseSet()
	require.NoError(t, err, "LeaseSet creation should handle all error paths")
	require.NotNil(t, leaseSetBytes)
	require.Greater(t, len(leaseSetBytes), 0)

	// Verify LeaseSet is cached
	cachedLS := session.CurrentLeaseSet()
	assert.Equal(t, leaseSetBytes, cachedLS)

	// Verify destination can be serialized repeatedly without errors
	dest := session.Destination()
	for i := 0; i < 5; i++ {
		bytes, err := dest.Bytes()
		assert.NoError(t, err, "iteration %d: Bytes() should not fail", i)
		assert.NotEmpty(t, bytes)
	}
}

// TestErrorFlowIntegration_ConcurrentSessionsWithErrorHandling tests that error handling
// is thread-safe under concurrent session operations
func TestErrorFlowIntegration_ConcurrentSessionsWithErrorHandling(t *testing.T) {
	serverConfig := &ServerConfig{
		ListenAddr:  "localhost:0",
		Network:     "tcp",
		MaxSessions: 50,
	}

	server, err := NewServer(serverConfig)
	require.NoError(t, err)

	err = server.Start()
	require.NoError(t, err)
	defer server.Stop()

	// Create multiple concurrent sessions
	numSessions := 10
	var wg sync.WaitGroup
	errors := make(chan error, numSessions*4) // 4 error checks per session
	successCount := make(chan int, numSessions)

	for i := 0; i < numSessions; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			// Create session
			session, err := server.manager.CreateSession(nil, nil)
			if err != nil {
				errors <- err
				return
			}
			defer session.Stop()

			dest := session.Destination()
			if dest == nil {
				errors <- assert.AnError
				return
			}

			checks := 0

			// Test Bytes() error handling
			if bytes, err := dest.Bytes(); err == nil && len(bytes) > 0 {
				checks++
			} else if err != nil {
				errors <- err
			}

			// Test Validate() error handling
			if err := dest.Validate(); err == nil {
				checks++
			} else {
				errors <- err
			}

			// Test Base64() error handling
			if base64, err := dest.Base64(); err == nil && len(base64) > 0 {
				checks++
			} else if err != nil {
				errors <- err
			}

			// Test Base32Address() error handling
			if addr, err := dest.Base32Address(); err == nil && len(addr) > 0 {
				checks++
			} else if err != nil {
				errors <- err
			}

			successCount <- checks
		}(i)
	}

	wg.Wait()
	close(errors)
	close(successCount)

	// Verify no errors occurred
	errorList := make([]error, 0)
	for err := range errors {
		errorList = append(errorList, err)
	}
	assert.Empty(t, errorList, "all concurrent operations should succeed without errors")

	// Verify all checks passed
	totalSuccesses := 0
	for count := range successCount {
		totalSuccesses += count
	}
	assert.Equal(t, numSessions*4, totalSuccesses,
		"all concurrent sessions should pass all error handling checks")
}

// TestErrorFlowIntegration_MessageQueueingWithErrorHandling tests that message
// operations handle errors properly
func TestErrorFlowIntegration_MessageQueueingWithErrorHandling(t *testing.T) {
	_, session, _, _, cleanup := setupTestEnvironment(t)
	defer cleanup()

	// Queue multiple messages and verify no errors
	messages := [][]byte{
		[]byte("Message 1"),
		[]byte("Message 2"),
		[]byte("Message 3"),
		[]byte("Message 4"),
		[]byte("Message 5"),
	}

	// Queue messages - should not fail
	for i, msg := range messages {
		err := session.QueueIncomingMessage(msg)
		assert.NoError(t, err, "queueing message %d should not fail", i)
	}

	// Receive messages - should not fail
	for i := range messages {
		msg, err := session.ReceiveMessage()
		assert.NoError(t, err, "receiving message %d should not fail", i)
		assert.NotNil(t, msg)
	}

	// Verify session can still create LeaseSet after message operations
	leaseSet, err := session.CreateLeaseSet()
	assert.NoError(t, err, "LeaseSet creation after messages should not fail")
	assert.NotNil(t, leaseSet)

	// Verify destination methods still work
	dest := session.Destination()
	bytes, err := dest.Bytes()
	assert.NoError(t, err, "Bytes() after messages should not fail")
	assert.NotEmpty(t, bytes)
}

// TestErrorFlowIntegration_SessionLifecycleErrorRecovery tests that sessions
// can recover from and handle errors throughout their lifecycle
func TestErrorFlowIntegration_SessionLifecycleErrorRecovery(t *testing.T) {
	_, session, _, _, cleanup := setupTestEnvironment(t)
	defer cleanup()

	// Perform multiple operations in sequence, verifying error handling works
	// throughout the session lifecycle

	// 1. Initial LeaseSet creation
	leaseSet1, err := session.CreateLeaseSet()
	assert.NoError(t, err, "initial LeaseSet creation should succeed")
	assert.NotNil(t, leaseSet1)

	// 2. Queue and receive messages
	err = session.QueueIncomingMessage([]byte("test 1"))
	assert.NoError(t, err, "first message queue should succeed")

	msg1, err := session.ReceiveMessage()
	assert.NoError(t, err, "first message receive should succeed")
	assert.NotNil(t, msg1)

	// 3. Create LeaseSet again
	leaseSet2, err := session.CreateLeaseSet()
	assert.NoError(t, err, "second LeaseSet creation should succeed")
	assert.NotNil(t, leaseSet2)

	// 4. More message operations
	err = session.QueueIncomingMessage([]byte("test 2"))
	assert.NoError(t, err, "second message queue should succeed")

	msg2, err := session.ReceiveMessage()
	assert.NoError(t, err, "second message receive should succeed")
	assert.NotNil(t, msg2)

	// 5. Verify destination methods still work correctly
	dest := session.Destination()

	bytes, err := dest.Bytes()
	assert.NoError(t, err, "Bytes() after lifecycle operations should succeed")
	assert.NotEmpty(t, bytes)

	base64Str, err := dest.Base64()
	assert.NoError(t, err, "Base64() after lifecycle operations should succeed")
	assert.NotEmpty(t, base64Str)

	base32Addr, err := dest.Base32Address()
	assert.NoError(t, err, "Base32Address() after lifecycle operations should succeed")
	assert.NotEmpty(t, base32Addr)

	err = dest.Validate()
	assert.NoError(t, err, "Validate() after lifecycle operations should succeed")

	// 6. Verify we can still create LeaseSet at the end
	leaseSet3, err := session.CreateLeaseSet()
	assert.NoError(t, err, "final LeaseSet creation should succeed")
	assert.NotNil(t, leaseSet3)

	// All operations should have succeeded without any error handling issues
}
