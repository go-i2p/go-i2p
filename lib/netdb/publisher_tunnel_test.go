package netdb

import (
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/go-i2p/go-i2p/lib/keys"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createValidRouterInfo creates a truly valid RouterInfo for testing.
// Uses the actual keystore to generate proper keys and RouterInfo.
func createValidRouterInfo(t *testing.T) router_info.RouterInfo {
	// Create temporary directory for keystore
	tmpDir, err := os.MkdirTemp("", "netdb-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create keystore
	keystore, err := keys.NewRouterInfoKeystore(tmpDir, "test-router")
	require.NoError(t, err)

	// Construct RouterInfo (this creates valid keys and identity)
	ri, err := keystore.ConstructRouterInfo(nil)
	require.NoError(t, err)
	require.NotNil(t, ri)

	return *ri
}

// mockTransportManager implements TransportManager for testing
type mockTransportManager struct {
	mu       sync.Mutex
	sessions map[string]*mockTransportSession // keyed by router hash
}

func newMockTransportManager() *mockTransportManager {
	return &mockTransportManager{
		sessions: make(map[string]*mockTransportSession),
	}
}

func (m *mockTransportManager) GetSession(routerInfo router_info.RouterInfo) (TransportSession, error) {
	hash, err := routerInfo.IdentHash()
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	key := string(hash[:])
	if session, exists := m.sessions[key]; exists {
		return session, nil
	}

	// Create new session
	session := newMockTransportSession()
	m.sessions[key] = session
	return session, nil
}

func (m *mockTransportManager) GetSentMessages(hash common.Hash) []i2np.I2NPMessage {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := string(hash[:])
	if session, exists := m.sessions[key]; exists {
		return session.GetSentMessages()
	}
	return nil
}

// mockTransportSession implements TransportSession for testing
type mockTransportSession struct {
	mu           sync.Mutex
	sentMessages []i2np.I2NPMessage
}

func newMockTransportSession() *mockTransportSession {
	return &mockTransportSession{
		sentMessages: make([]i2np.I2NPMessage, 0),
	}
}

func (m *mockTransportSession) QueueSendI2NP(msg i2np.I2NPMessage) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sentMessages = append(m.sentMessages, msg)
}

func (m *mockTransportSession) GetSentMessages() []i2np.I2NPMessage {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]i2np.I2NPMessage{}, m.sentMessages...)
}

// TestSendDatabaseStoreToFloodfill_NoActiveTunnels tests the error case when no tunnels are available
func TestSendDatabaseStoreToFloodfill_NoActiveTunnels(t *testing.T) {
	db := newMockNetDB()
	transport := newMockTransportManager()
	selector := &mockPeerSelector{}
	pool := tunnel.NewTunnelPool(selector)
	publisher := NewPublisher(db, pool, transport, nil, DefaultPublisherConfig())

	// Create test data
	hash := common.Hash{1, 2, 3, 4, 5, 6, 7, 8}
	data := []byte("test leaseset data")
	floodfill := createValidRouterInfo(t)

	// Should fail with no tunnels
	err := publisher.sendDatabaseStoreToFloodfill(hash, data, i2np.DATABASE_STORE_TYPE_LEASESET2, floodfill)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no active outbound tunnels")
}

// TestSendDatabaseStoreToFloodfill_WithActiveTunnel tests successful tunnel selection and message transmission
func TestSendDatabaseStoreToFloodfill_WithActiveTunnel(t *testing.T) {
	db := newMockNetDB()
	transport := newMockTransportManager()

	// Create pool
	selector := &mockPeerSelector{}
	pool := tunnel.NewTunnelPool(selector)

	// Add an active tunnel to the pool with valid gateway router
	tunnelID := tunnel.TunnelID(12345)

	// Add gateway router to NetDB first
	gatewayRI := createValidRouterInfo(t)
	gatewayHash, _ := gatewayRI.IdentHash()
	db.StoreRouterInfo(gatewayRI)

	// Create hops with actual gateway hash
	hop1 := gatewayHash // Use gateway hash directly
	hop2 := common.Hash{0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18}
	hop3 := common.Hash{0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28}

	tunnelState := &tunnel.TunnelState{
		ID:        tunnelID,
		Hops:      []common.Hash{hop1, hop2, hop3},
		State:     tunnel.TunnelReady,
		CreatedAt: time.Now(),
	}
	pool.AddTunnel(tunnelState)

	publisher := NewPublisher(db, pool, transport, nil, DefaultPublisherConfig())

	// Create test data
	hash := common.Hash{9, 10, 11, 12, 13, 14, 15, 16}
	data := []byte("test leaseset data for tunnel transmission")
	floodfill := createValidRouterInfo(t)

	// Should succeed with active tunnel and transport
	err := publisher.sendDatabaseStoreToFloodfill(hash, data, i2np.DATABASE_STORE_TYPE_LEASESET2, floodfill)
	assert.NoError(t, err)

	// Verify message was sent through transport
	sentMessages := transport.GetSentMessages(hop1)
	require.NotNil(t, sentMessages, "Expected messages sent to gateway")
	require.Len(t, sentMessages, 1, "Expected exactly one message sent")

	// Verify message is a TunnelGateway message
	msg := sentMessages[0]
	assert.Equal(t, i2np.I2NP_MESSAGE_TYPE_TUNNEL_GATEWAY, msg.Type(), "Expected TunnelGateway message type")
}

// TestSendDatabaseStoreToFloodfill_TunnelWithNoHops tests error handling for invalid tunnels
func TestSendDatabaseStoreToFloodfill_TunnelWithNoHops(t *testing.T) {
	db := newMockNetDB()
	transport := newMockTransportManager()

	selector := &mockPeerSelector{}
	pool := tunnel.NewTunnelPool(selector)

	// Add a tunnel with no hops (invalid state)
	tunnelID := tunnel.TunnelID(12345)
	tunnelState := &tunnel.TunnelState{
		ID:        tunnelID,
		Hops:      []common.Hash{}, // Empty hops - invalid
		State:     tunnel.TunnelReady,
		CreatedAt: time.Now(),
	}
	pool.AddTunnel(tunnelState)

	publisher := NewPublisher(db, pool, transport, nil, DefaultPublisherConfig())

	// Create test data
	hash := common.Hash{17, 18, 19, 20, 21, 22, 23, 24}
	data := []byte("test data")
	floodfill := createValidRouterInfo(t)

	// Should fail with tunnel that has no hops
	err := publisher.sendDatabaseStoreToFloodfill(hash, data, i2np.DATABASE_STORE_TYPE_LEASESET2, floodfill)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "tunnel has no hops")
}

// TestSendDatabaseStoreToFloodfill_GatewayNotInNetDB tests error when gateway RouterInfo is missing
func TestSendDatabaseStoreToFloodfill_GatewayNotInNetDB(t *testing.T) {
	db := newMockNetDB()
	transport := newMockTransportManager()

	selector := &mockPeerSelector{}
	pool := tunnel.NewTunnelPool(selector)

	// Add tunnel with gateway not in NetDB
	tunnelID := tunnel.TunnelID(12345)
	hop1 := common.Hash{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08} // Unknown gateway

	tunnelState := &tunnel.TunnelState{
		ID:        tunnelID,
		Hops:      []common.Hash{hop1},
		State:     tunnel.TunnelReady,
		CreatedAt: time.Now(),
	}
	pool.AddTunnel(tunnelState)

	publisher := NewPublisher(db, pool, transport, nil, DefaultPublisherConfig())

	// Create test data
	hash := common.Hash{25, 26, 27, 28, 29, 30, 31, 32}
	data := []byte("test data")
	floodfill := createValidRouterInfo(t)

	// Should fail when gateway not found in NetDB
	err := publisher.sendDatabaseStoreToFloodfill(hash, data, i2np.DATABASE_STORE_TYPE_LEASESET2, floodfill)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found in NetDB")
}

// TestSendDatabaseStoreToFloodfill_MultipleTunnelsRoundRobin tests round-robin tunnel selection
func TestSendDatabaseStoreToFloodfill_MultipleTunnelsRoundRobin(t *testing.T) {
	db := newMockNetDB()
	transport := newMockTransportManager()

	selector := &mockPeerSelector{}
	pool := tunnel.NewTunnelPool(selector)

	// Add multiple active tunnels with gateways in NetDB
	gatewayHashes := make([]common.Hash, 3)
	for i := 0; i < 3; i++ {
		tunnelID := tunnel.TunnelID(1000 + i)

		// Create and store gateway RouterInfo
		gatewayRI := createValidRouterInfo(t)
		gatewayHash, _ := gatewayRI.IdentHash()
		gatewayHashes[i] = gatewayHash
		db.StoreRouterInfo(gatewayRI)

		hop2 := common.Hash{byte(i + 10), 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17}

		tunnelState := &tunnel.TunnelState{
			ID:        tunnelID,
			Hops:      []common.Hash{gatewayHash, hop2},
			State:     tunnel.TunnelReady,
			CreatedAt: time.Now(),
		}
		pool.AddTunnel(tunnelState)
	}

	publisher := NewPublisher(db, pool, transport, nil, DefaultPublisherConfig())

	// Create test data
	hash := common.Hash{25, 26, 27, 28, 29, 30, 31, 32}
	data := []byte("test data")
	floodfill := createValidRouterInfo(t)

	// Send multiple times and verify messages distributed across gateways
	sends := 6
	for i := 0; i < sends; i++ {
		err := publisher.sendDatabaseStoreToFloodfill(hash, data, i2np.DATABASE_STORE_TYPE_LEASESET2, floodfill)
		assert.NoError(t, err, "Send %d should succeed", i+1)
	}

	// Verify messages were sent (round-robin distributes across tunnels)
	totalMessages := 0
	for _, gwHash := range gatewayHashes {
		messages := transport.GetSentMessages(gwHash)
		totalMessages += len(messages)
	}
	assert.Equal(t, sends, totalMessages, "Expected all sends to complete")
}

// TestSendDatabaseStoreToFloodfill_LargeData tests handling of large DatabaseStore payloads
func TestSendDatabaseStoreToFloodfill_LargeData(t *testing.T) {
	db := newMockNetDB()
	transport := newMockTransportManager()

	selector := &mockPeerSelector{}
	pool := tunnel.NewTunnelPool(selector)

	// Add tunnel with gateway in NetDB
	tunnelID := tunnel.TunnelID(99999)
	gatewayRI := createValidRouterInfo(t)
	gatewayHash, _ := gatewayRI.IdentHash()
	db.StoreRouterInfo(gatewayRI)

	hop2 := common.Hash{0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99}
	hop3 := common.Hash{0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18}

	tunnelState := &tunnel.TunnelState{
		ID:        tunnelID,
		Hops:      []common.Hash{gatewayHash, hop2, hop3},
		State:     tunnel.TunnelReady,
		CreatedAt: time.Now(),
	}
	pool.AddTunnel(tunnelState)

	publisher := NewPublisher(db, pool, transport, nil, DefaultPublisherConfig())

	// Create large test data (simulating large RouterInfo with many router addresses)
	hash := common.Hash{33, 34, 35, 36, 37, 38, 39, 40}
	data := make([]byte, 10*1024) // 10KB payload
	for i := range data {
		data[i] = byte(i % 256)
	}
	floodfill := createValidRouterInfo(t)

	// Should handle large payloads without error
	err := publisher.sendDatabaseStoreToFloodfill(hash, data, i2np.DATABASE_STORE_TYPE_LEASESET2, floodfill)
	assert.NoError(t, err)

	// Verify message was sent
	sentMessages := transport.GetSentMessages(gatewayHash)
	require.Len(t, sentMessages, 1, "Expected large message to be sent")
}

// TestSendDatabaseStoreToFloodfill_EmptyData tests handling of empty data payload
func TestSendDatabaseStoreToFloodfill_EmptyData(t *testing.T) {
	db := newMockNetDB()
	transport := newMockTransportManager()

	selector := &mockPeerSelector{}
	pool := tunnel.NewTunnelPool(selector)

	// Add tunnel with gateway in NetDB
	tunnelID := tunnel.TunnelID(555)
	gatewayRI := createValidRouterInfo(t)
	gatewayHash, _ := gatewayRI.IdentHash()
	db.StoreRouterInfo(gatewayRI)

	hop2 := common.Hash{0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C}

	tunnelState := &tunnel.TunnelState{
		ID:        tunnelID,
		Hops:      []common.Hash{gatewayHash, hop2},
		State:     tunnel.TunnelReady,
		CreatedAt: time.Now(),
	}
	pool.AddTunnel(tunnelState)

	publisher := NewPublisher(db, pool, transport, nil, DefaultPublisherConfig())

	// Create test with empty data
	hash := common.Hash{41, 42, 43, 44, 45, 46, 47, 48}
	data := []byte{} // Empty payload
	floodfill := createValidRouterInfo(t)

	// Should handle empty data (may represent deletion or placeholder)
	err := publisher.sendDatabaseStoreToFloodfill(hash, data, i2np.DATABASE_STORE_TYPE_LEASESET2, floodfill)
	assert.NoError(t, err)

	// Verify message was sent
	sentMessages := transport.GetSentMessages(gatewayHash)
	require.Len(t, sentMessages, 1, "Expected empty data message to be sent")
}

// TestSendDatabaseStoreToFloodfill_ConcurrentSends tests thread-safety of concurrent sends
func TestSendDatabaseStoreToFloodfill_ConcurrentSends(t *testing.T) {
	db := newMockNetDB()
	transport := newMockTransportManager()

	selector := &mockPeerSelector{}
	pool := tunnel.NewTunnelPool(selector)

	// Add tunnel with gateway in NetDB
	tunnelID := tunnel.TunnelID(777)
	gatewayRI := createValidRouterInfo(t)
	gatewayHash, _ := gatewayRI.IdentHash()
	db.StoreRouterInfo(gatewayRI)

	tunnelState := &tunnel.TunnelState{
		ID:        tunnelID,
		Hops:      []common.Hash{gatewayHash},
		State:     tunnel.TunnelReady,
		CreatedAt: time.Now(),
	}
	pool.AddTunnel(tunnelState)

	publisher := NewPublisher(db, pool, transport, nil, DefaultPublisherConfig())

	// Create test data
	floodfill := createValidRouterInfo(t)

	// Send concurrently from multiple goroutines
	concurrency := 10
	var wg sync.WaitGroup
	errors := make(chan error, concurrency)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			hash := common.Hash{byte(index), byte(index + 1), byte(index + 2)}
			data := []byte(fmt.Sprintf("concurrent send %d", index))
			err := publisher.sendDatabaseStoreToFloodfill(hash, data, i2np.DATABASE_STORE_TYPE_LEASESET2, floodfill)
			if err != nil {
				errors <- err
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	// Check for errors
	for err := range errors {
		t.Errorf("Concurrent send failed: %v", err)
	}

	// Verify all messages were sent
	sentMessages := transport.GetSentMessages(gatewayHash)
	assert.Equal(t, concurrency, len(sentMessages), "Expected all concurrent sends to complete")
}

// TestPublisher_SetTransport tests setting transport after publisher creation
func TestPublisher_SetTransport(t *testing.T) {
	db := newMockNetDB()
	selector := &mockPeerSelector{}
	pool := tunnel.NewTunnelPool(selector)

	// Create publisher without transport
	publisher := NewPublisher(db, pool, nil, nil, DefaultPublisherConfig())
	assert.Nil(t, publisher.transport)

	// Set transport
	transport := newMockTransportManager()
	publisher.SetTransport(transport)
	assert.NotNil(t, publisher.transport)

	// Verify transport is usable
	gatewayRI := createValidRouterInfo(t)
	session, err := publisher.transport.GetSession(gatewayRI)
	assert.NoError(t, err)
	assert.NotNil(t, session)
}

// TestPublisher_StartWithoutTransport tests that Start() fails when transport is not set
func TestPublisher_StartWithoutTransport(t *testing.T) {
	db := newMockNetDB()
	selector := &mockPeerSelector{}
	pool := tunnel.NewTunnelPool(selector)

	// Create publisher without transport
	publisher := NewPublisher(db, pool, nil, nil, DefaultPublisherConfig())

	// Start should fail without transport
	err := publisher.Start()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "transport manager required")
}

// mockPeerSelector implements PeerSelector for testing
type mockPeerSelector struct{}

func (m *mockPeerSelector) SelectPeers(count int, exclude []common.Hash) ([]router_info.RouterInfo, error) {
	// Not needed for these tests
	return nil, nil
}
