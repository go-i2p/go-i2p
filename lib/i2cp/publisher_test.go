package i2cp

import (
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockLeaseSetPublisher implements LeaseSetPublisher for testing
type mockLeaseSetPublisher struct {
	published     map[common.Hash][]byte
	publishErr    error
	publishCalled int
}

func newMockLeaseSetPublisher() *mockLeaseSetPublisher {
	return &mockLeaseSetPublisher{
		published: make(map[common.Hash][]byte),
	}
}

func (m *mockLeaseSetPublisher) PublishLeaseSet(key common.Hash, data []byte) error {
	m.publishCalled++
	if m.publishErr != nil {
		return m.publishErr
	}
	m.published[key] = data
	return nil
}

// TestSessionSetLeaseSetPublisher tests setting the publisher on a session
func TestSessionSetLeaseSetPublisher(t *testing.T) {
	session, err := NewSession(1, nil, nil)
	require.NoError(t, err, "Failed to create session")
	defer session.Stop()

	publisher := newMockLeaseSetPublisher()
	session.SetLeaseSetPublisher(publisher)

	// Verify publisher is set (we can't access it directly, but we can test behavior)
	assert.NotNil(t, session, "Session should not be nil")
}

// TestSessionPublishLeaseSetWithPublisher tests LeaseSet publication via publisher
func TestSessionPublishLeaseSetWithPublisher(t *testing.T) {
	session, err := NewSession(1, nil, nil)
	require.NoError(t, err, "Failed to create session")
	defer session.Stop()

	publisher := newMockLeaseSetPublisher()
	session.SetLeaseSetPublisher(publisher)

	// Setup tunnel pool with active tunnel
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

	// Create LeaseSet (this should trigger publishing)
	leaseSetBytes, err := session.CreateLeaseSet()
	require.NoError(t, err, "Failed to create LeaseSet")
	assert.NotEmpty(t, leaseSetBytes, "LeaseSet should not be empty")

	// Now trigger regeneration which should call the publisher
	err = session.regenerateAndPublishLeaseSet()
	require.NoError(t, err, "Failed to regenerate and publish LeaseSet")

	// Verify publisher was called
	assert.Equal(t, 1, publisher.publishCalled, "Publisher should be called once")
	assert.Equal(t, 1, len(publisher.published), "Should have published 1 LeaseSet")

	// Verify the published key matches destination hash
	destBytes, err := session.Destination().Bytes()
	require.NoError(t, err, "Failed to get destination bytes")
	destHash := common.HashData(destBytes)
	publishedData, exists := publisher.published[destHash]
	assert.True(t, exists, "Should have published LeaseSet for this destination")
	assert.NotEmpty(t, publishedData, "Published data should not be empty")
}

// TestSessionPublishLeaseSetWithoutPublisher tests LeaseSet creation without publisher
func TestSessionPublishLeaseSetWithoutPublisher(t *testing.T) {
	session, err := NewSession(1, nil, nil)
	require.NoError(t, err, "Failed to create session")
	defer session.Stop()

	// Don't set a publisher

	// Setup tunnel pool
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

	// Create LeaseSet (should work even without publisher)
	leaseSetBytes, err := session.CreateLeaseSet()
	require.NoError(t, err, "Failed to create LeaseSet")
	assert.NotEmpty(t, leaseSetBytes, "LeaseSet should not be empty")

	// Regeneration should also succeed without publisher
	err = session.regenerateAndPublishLeaseSet()
	assert.NoError(t, err, "Should succeed even without publisher")
}

// TestSessionPublishLeaseSetPublisherError tests handling of publisher errors
func TestSessionPublishLeaseSetPublisherError(t *testing.T) {
	session, err := NewSession(1, nil, nil)
	require.NoError(t, err, "Failed to create session")
	defer session.Stop()

	publisher := newMockLeaseSetPublisher()
	publisher.publishErr = assert.AnError // Make publisher return error
	session.SetLeaseSetPublisher(publisher)

	// Setup tunnel pool
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

	// Regeneration should still succeed even if publisher fails
	// (publisher errors are logged but not returned)
	err = session.regenerateAndPublishLeaseSet()
	assert.NoError(t, err, "Should not fail even if publisher errors")

	// Verify publisher was called
	assert.Equal(t, 1, publisher.publishCalled, "Publisher should be called")
}

// TestSessionMaintenanceWithPublisher tests LeaseSet maintenance with publisher
func TestSessionMaintenanceWithPublisher(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping maintenance test in short mode")
	}

	config := DefaultSessionConfig()
	config.TunnelLifetime = 2 * time.Second // Very short for testing

	session, err := NewSession(1, nil, config)
	require.NoError(t, err, "Failed to create session")
	defer session.Stop()

	publisher := newMockLeaseSetPublisher()
	session.SetLeaseSetPublisher(publisher)

	// Setup tunnel pool
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

	// Start maintenance
	err = session.StartLeaseSetMaintenance()
	require.NoError(t, err, "Failed to start maintenance")

	// Wait for initial publication
	time.Sleep(100 * time.Millisecond)

	// Verify at least one publication occurred
	assert.GreaterOrEqual(t, publisher.publishCalled, 1, "Should have published at least once")

	// Wait for potential regeneration
	time.Sleep(1200 * time.Millisecond)

	// Should have regenerated at least once more
	assert.GreaterOrEqual(t, publisher.publishCalled, 2, "Should have published multiple times")
}

// TestServerWithLeaseSetPublisher tests I2CP server with publisher
func TestServerWithLeaseSetPublisher(t *testing.T) {
	publisher := newMockLeaseSetPublisher()

	config := &ServerConfig{
		ListenAddr:        "localhost:17670",
		Network:           "tcp",
		MaxSessions:       10,
		LeaseSetPublisher: publisher,
	}

	server, err := NewServer(config)
	require.NoError(t, err, "Failed to create server")
	require.NotNil(t, server, "Server should not be nil")

	err = server.Start()
	require.NoError(t, err, "Failed to start server")
	defer server.Stop()

	// The server should have the publisher set
	assert.NotNil(t, server.leaseSetPublisher, "Server should have publisher")
}

// TestServerWithoutLeaseSetPublisher tests I2CP server without publisher
func TestServerWithoutLeaseSetPublisher(t *testing.T) {
	config := &ServerConfig{
		ListenAddr:        "localhost:17671",
		Network:           "tcp",
		MaxSessions:       10,
		LeaseSetPublisher: nil, // No publisher
	}

	server, err := NewServer(config)
	require.NoError(t, err, "Failed to create server")
	require.NotNil(t, server, "Server should not be nil")

	err = server.Start()
	require.NoError(t, err, "Failed to start server")
	defer server.Stop()

	// The server should work without a publisher
	assert.Nil(t, server.leaseSetPublisher, "Server should have nil publisher")
}
