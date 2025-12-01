package i2cp

import (
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHandleCreateLeaseSetWithPublisher tests that handleCreateLeaseSet
// publishes to the network when a LeaseSetPublisher is configured
func TestHandleCreateLeaseSetWithPublisher(t *testing.T) {
	// Create a mock publisher to track publication calls
	publisher := newMockLeaseSetPublisher()

	// Create session with publisher configured
	session, err := NewSession(1, nil, nil)
	require.NoError(t, err, "Failed to create session")
	defer session.Stop()

	session.SetLeaseSetPublisher(publisher)

	// Setup inbound tunnel pool with active tunnel
	selector := &mockPeerSelector{}
	pool := tunnel.NewTunnelPool(selector)
	session.SetInboundPool(pool)

	var gatewayHash common.Hash
	copy(gatewayHash[:], []byte("gateway-router-hash-12345678"))

	tunnelState := &tunnel.TunnelState{
		ID:        tunnel.TunnelID(12345),
		Hops:      []common.Hash{gatewayHash},
		State:     tunnel.TunnelReady,
		CreatedAt: time.Now(),
	}
	pool.AddTunnel(tunnelState)

	// Create message with empty payload (CreateLeaseSet doesn't use payload)
	msg := &Message{
		Type:      MessageTypeCreateLeaseSet,
		SessionID: session.ID(),
		Payload:   []byte{},
	}

	// Create a mock server to call handleCreateLeaseSet
	config := DefaultServerConfig()
	config.LeaseSetPublisher = publisher
	server, err := NewServer(config)
	require.NoError(t, err, "Failed to create server")

	// Call handleCreateLeaseSet through the server
	sessionPtr := session
	response, err := server.handleCreateLeaseSet(msg, &sessionPtr)

	// Verify no error and no response (per I2CP protocol)
	assert.NoError(t, err, "handleCreateLeaseSet should succeed")
	assert.Nil(t, response, "CreateLeaseSet should not return a response")

	// Verify publisher was called exactly once
	assert.Equal(t, 1, publisher.publishCalled, "Publisher should be called once")
	assert.Equal(t, 1, len(publisher.published), "Should have published 1 LeaseSet")

	// Verify the published key matches destination hash
	destBytes, err := session.Destination().Bytes()
	require.NoError(t, err, "Failed to get destination bytes")
	destHash := common.HashData(destBytes)

	publishedData, exists := publisher.published[destHash]
	assert.True(t, exists, "Should have published LeaseSet for destination hash %x", destHash[:8])
	assert.NotEmpty(t, publishedData, "Published LeaseSet data should not be empty")
	assert.Greater(t, len(publishedData), 100, "LeaseSet should be substantial in size")
}

// TestHandleCreateLeaseSetWithoutPublisher tests that handleCreateLeaseSet
// succeeds even when no publisher is configured (local-only mode)
func TestHandleCreateLeaseSetWithoutPublisher(t *testing.T) {
	// Create session without publisher (nil)
	session, err := NewSession(1, nil, nil)
	require.NoError(t, err, "Failed to create session")
	defer session.Stop()

	// Don't set publisher - leave it nil

	// Setup inbound tunnel pool with active tunnel
	selector := &mockPeerSelector{}
	pool := tunnel.NewTunnelPool(selector)
	session.SetInboundPool(pool)

	var gatewayHash common.Hash
	copy(gatewayHash[:], []byte("gateway-router-hash-12345678"))

	tunnelState := &tunnel.TunnelState{
		ID:        tunnel.TunnelID(12345),
		Hops:      []common.Hash{gatewayHash},
		State:     tunnel.TunnelReady,
		CreatedAt: time.Now(),
	}
	pool.AddTunnel(tunnelState)

	// Create message
	msg := &Message{
		Type:      MessageTypeCreateLeaseSet,
		SessionID: session.ID(),
		Payload:   []byte{},
	}

	// Create server without publisher
	config := DefaultServerConfig()
	config.LeaseSetPublisher = nil
	server, err := NewServer(config)
	require.NoError(t, err, "Failed to create server")

	// Call handleCreateLeaseSet
	sessionPtr := session
	response, err := server.handleCreateLeaseSet(msg, &sessionPtr)

	// Should succeed even without publisher
	assert.NoError(t, err, "handleCreateLeaseSet should succeed without publisher")
	assert.Nil(t, response, "CreateLeaseSet should not return a response")

	// Verify LeaseSet was created and cached locally
	leaseSet := session.CurrentLeaseSet()
	assert.NotEmpty(t, leaseSet, "LeaseSet should be cached in session")
}

// TestHandleCreateLeaseSetPublisherError tests that handleCreateLeaseSet
// continues successfully even when the publisher returns an error
func TestHandleCreateLeaseSetPublisherError(t *testing.T) {
	// Create a mock publisher that returns errors
	publisher := newMockLeaseSetPublisher()
	publisher.publishErr = assert.AnError

	// Create session with failing publisher
	session, err := NewSession(1, nil, nil)
	require.NoError(t, err, "Failed to create session")
	defer session.Stop()

	session.SetLeaseSetPublisher(publisher)

	// Setup inbound tunnel pool
	selector := &mockPeerSelector{}
	pool := tunnel.NewTunnelPool(selector)
	session.SetInboundPool(pool)

	var gatewayHash common.Hash
	copy(gatewayHash[:], []byte("gateway-router-hash-12345678"))

	tunnelState := &tunnel.TunnelState{
		ID:        tunnel.TunnelID(12345),
		Hops:      []common.Hash{gatewayHash},
		State:     tunnel.TunnelReady,
		CreatedAt: time.Now(),
	}
	pool.AddTunnel(tunnelState)

	// Create message
	msg := &Message{
		Type:      MessageTypeCreateLeaseSet,
		SessionID: session.ID(),
		Payload:   []byte{},
	}

	// Create server
	config := DefaultServerConfig()
	config.LeaseSetPublisher = publisher
	server, err := NewServer(config)
	require.NoError(t, err, "Failed to create server")

	// Call handleCreateLeaseSet
	sessionPtr := session
	response, err := server.handleCreateLeaseSet(msg, &sessionPtr)

	// Should succeed even though publisher failed (error is logged, not returned)
	assert.NoError(t, err, "handleCreateLeaseSet should succeed even when publisher fails")
	assert.Nil(t, response, "CreateLeaseSet should not return a response")

	// Verify publisher was called
	assert.Equal(t, 1, publisher.publishCalled, "Publisher should be called")

	// Verify LeaseSet is still cached locally despite publisher error
	leaseSet := session.CurrentLeaseSet()
	assert.NotEmpty(t, leaseSet, "LeaseSet should be cached even if publishing fails")
}

// TestHandleCreateLeaseSetNoActiveTunnels tests error handling when
// session has no active tunnels (cannot create LeaseSet)
func TestHandleCreateLeaseSetNoActiveTunnels(t *testing.T) {
	publisher := newMockLeaseSetPublisher()

	// Create session
	session, err := NewSession(1, nil, nil)
	require.NoError(t, err, "Failed to create session")
	defer session.Stop()

	session.SetLeaseSetPublisher(publisher)

	// Setup empty inbound tunnel pool (no active tunnels)
	selector := &mockPeerSelector{}
	pool := tunnel.NewTunnelPool(selector)
	session.SetInboundPool(pool)
	// Don't add any tunnels

	// Create message
	msg := &Message{
		Type:      MessageTypeCreateLeaseSet,
		SessionID: session.ID(),
		Payload:   []byte{},
	}

	// Create server
	config := DefaultServerConfig()
	config.LeaseSetPublisher = publisher
	server, err := NewServer(config)
	require.NoError(t, err, "Failed to create server")

	// Call handleCreateLeaseSet
	sessionPtr := session
	response, err := server.handleCreateLeaseSet(msg, &sessionPtr)

	// Should fail because no active tunnels
	assert.Error(t, err, "handleCreateLeaseSet should fail with no active tunnels")
	assert.Nil(t, response, "Should not return response on error")
	assert.Contains(t, err.Error(), "no active", "Error should mention no active tunnels")

	// Publisher should not be called if LeaseSet creation failed
	assert.Equal(t, 0, publisher.publishCalled, "Publisher should not be called on creation failure")
}

// TestHandleCreateLeaseSetMultipleCalls tests that multiple calls to
// handleCreateLeaseSet result in multiple publications
func TestHandleCreateLeaseSetMultipleCalls(t *testing.T) {
	publisher := newMockLeaseSetPublisher()

	// Create session
	session, err := NewSession(1, nil, nil)
	require.NoError(t, err, "Failed to create session")
	defer session.Stop()

	session.SetLeaseSetPublisher(publisher)

	// Setup inbound tunnel pool
	selector := &mockPeerSelector{}
	pool := tunnel.NewTunnelPool(selector)
	session.SetInboundPool(pool)

	var gatewayHash common.Hash
	copy(gatewayHash[:], []byte("gateway-router-hash-12345678"))

	tunnelState := &tunnel.TunnelState{
		ID:        tunnel.TunnelID(12345),
		Hops:      []common.Hash{gatewayHash},
		State:     tunnel.TunnelReady,
		CreatedAt: time.Now(),
	}
	pool.AddTunnel(tunnelState)

	// Create message
	msg := &Message{
		Type:      MessageTypeCreateLeaseSet,
		SessionID: session.ID(),
		Payload:   []byte{},
	}

	// Create server
	config := DefaultServerConfig()
	config.LeaseSetPublisher = publisher
	server, err := NewServer(config)
	require.NoError(t, err, "Failed to create server")

	sessionPtr := session

	// Call handleCreateLeaseSet 3 times
	for i := 0; i < 3; i++ {
		response, err := server.handleCreateLeaseSet(msg, &sessionPtr)
		assert.NoError(t, err, "Call %d should succeed", i+1)
		assert.Nil(t, response, "Call %d should not return response", i+1)
	}

	// Verify publisher was called 3 times
	assert.Equal(t, 3, publisher.publishCalled, "Publisher should be called 3 times")
}

// TestHandleCreateLeaseSetNilSession tests error handling when session is nil
func TestHandleCreateLeaseSetNilSession(t *testing.T) {
	// Create message
	msg := &Message{
		Type:      MessageTypeCreateLeaseSet,
		SessionID: 1,
		Payload:   []byte{},
	}

	// Create server
	config := DefaultServerConfig()
	server, err := NewServer(config)
	require.NoError(t, err, "Failed to create server")

	// Call handleCreateLeaseSet with nil session
	var sessionPtr *Session = nil
	response, err := server.handleCreateLeaseSet(msg, &sessionPtr)

	// Should fail with nil session
	assert.Error(t, err, "handleCreateLeaseSet should fail with nil session")
	assert.Contains(t, err.Error(), "no active session", "Error should mention no active session")
	assert.Nil(t, response, "Should not return response on error")
}

// TestLeaseSetPublishedDataIntegrity verifies that the published LeaseSet
// data matches what the session created
func TestLeaseSetPublishedDataIntegrity(t *testing.T) {
	publisher := newMockLeaseSetPublisher()

	// Create session
	session, err := NewSession(1, nil, nil)
	require.NoError(t, err, "Failed to create session")
	defer session.Stop()

	session.SetLeaseSetPublisher(publisher)

	// Setup inbound tunnel pool
	selector := &mockPeerSelector{}
	pool := tunnel.NewTunnelPool(selector)
	session.SetInboundPool(pool)

	var gatewayHash common.Hash
	copy(gatewayHash[:], []byte("gateway-router-hash-12345678"))

	tunnelState := &tunnel.TunnelState{
		ID:        tunnel.TunnelID(12345),
		Hops:      []common.Hash{gatewayHash},
		State:     tunnel.TunnelReady,
		CreatedAt: time.Now(),
	}
	pool.AddTunnel(tunnelState)

	// Create message
	msg := &Message{
		Type:      MessageTypeCreateLeaseSet,
		SessionID: session.ID(),
		Payload:   []byte{},
	}

	// Create server
	config := DefaultServerConfig()
	config.LeaseSetPublisher = publisher
	server, err := NewServer(config)
	require.NoError(t, err, "Failed to create server")

	// Call handleCreateLeaseSet
	sessionPtr := session
	_, err = server.handleCreateLeaseSet(msg, &sessionPtr)
	require.NoError(t, err, "handleCreateLeaseSet should succeed")

	// Get the cached LeaseSet from session
	cachedLeaseSet := session.CurrentLeaseSet()
	require.NotEmpty(t, cachedLeaseSet, "Session should have cached LeaseSet")

	// Get the published LeaseSet from publisher
	destBytes, err := session.Destination().Bytes()
	require.NoError(t, err, "Failed to get destination bytes")
	destHash := common.HashData(destBytes)

	publishedLeaseSet, exists := publisher.published[destHash]
	require.True(t, exists, "Publisher should have LeaseSet for this destination")

	// Verify data integrity - published data should match cached data
	assert.Equal(t, cachedLeaseSet, publishedLeaseSet, "Published LeaseSet should match cached LeaseSet")
}

// BenchmarkHandleCreateLeaseSetWithPublisher benchmarks the performance
// of creating and publishing LeaseSets
func BenchmarkHandleCreateLeaseSetWithPublisher(b *testing.B) {
	publisher := newMockLeaseSetPublisher()

	// Create session
	session, err := NewSession(1, nil, nil)
	if err != nil {
		b.Fatalf("Failed to create session: %v", err)
	}
	defer session.Stop()

	session.SetLeaseSetPublisher(publisher)

	// Setup inbound tunnel pool
	selector := &mockPeerSelector{}
	pool := tunnel.NewTunnelPool(selector)
	session.SetInboundPool(pool)

	var gatewayHash common.Hash
	copy(gatewayHash[:], []byte("gateway-router-hash-12345678"))

	tunnelState := &tunnel.TunnelState{
		ID:        tunnel.TunnelID(12345),
		Hops:      []common.Hash{gatewayHash},
		State:     tunnel.TunnelReady,
		CreatedAt: time.Now(),
	}
	pool.AddTunnel(tunnelState)

	// Create message
	msg := &Message{
		Type:      MessageTypeCreateLeaseSet,
		SessionID: session.ID(),
		Payload:   []byte{},
	}

	// Create server
	config := DefaultServerConfig()
	config.LeaseSetPublisher = publisher
	server, _ := NewServer(config)

	sessionPtr := session

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = server.handleCreateLeaseSet(msg, &sessionPtr)
	}
}

// BenchmarkHandleCreateLeaseSetWithoutPublisher benchmarks the performance
// of creating LeaseSets without network publication
func BenchmarkHandleCreateLeaseSetWithoutPublisher(b *testing.B) {
	// Create session without publisher
	session, err := NewSession(1, nil, nil)
	if err != nil {
		b.Fatalf("Failed to create session: %v", err)
	}
	defer session.Stop()

	// Setup inbound tunnel pool
	selector := &mockPeerSelector{}
	pool := tunnel.NewTunnelPool(selector)
	session.SetInboundPool(pool)

	var gatewayHash common.Hash
	copy(gatewayHash[:], []byte("gateway-router-hash-12345678"))

	tunnelState := &tunnel.TunnelState{
		ID:        tunnel.TunnelID(12345),
		Hops:      []common.Hash{gatewayHash},
		State:     tunnel.TunnelReady,
		CreatedAt: time.Now(),
	}
	pool.AddTunnel(tunnelState)

	// Create message
	msg := &Message{
		Type:      MessageTypeCreateLeaseSet,
		SessionID: session.ID(),
		Payload:   []byte{},
	}

	// Create server without publisher
	config := DefaultServerConfig()
	config.LeaseSetPublisher = nil
	server, _ := NewServer(config)

	sessionPtr := session

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = server.handleCreateLeaseSet(msg, &sessionPtr)
	}
}
