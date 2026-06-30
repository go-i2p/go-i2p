package netdb

import (
	"encoding/binary"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/go-i2p/go-i2p/lib/keys"
	"github.com/go-i2p/go-i2p/lib/transport"
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

func (m *mockTransportManager) GetSession(routerInfo router_info.RouterInfo) (I2NPSender, error) {
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

func (m *mockTransportManager) GetSentMessages(hash common.Hash) []i2np.Message {
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
	sentMessages []i2np.Message
}

func newMockTransportSession() *mockTransportSession {
	return &mockTransportSession{
		sentMessages: make([]i2np.Message, 0),
	}
}

func (m *mockTransportSession) QueueSendI2NP(msg i2np.Message) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sentMessages = append(m.sentMessages, msg)
	return nil
}

func (m *mockTransportSession) GetSentMessages() []i2np.Message {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]i2np.Message{}, m.sentMessages...)
}

// publisherTestEnv holds the common test fixtures for publisher tunnel tests.
type publisherTestEnv struct {
	db          *mockNetDB
	transport   *mockTransportManager
	pool        *tunnel.Pool
	publisher   *Publisher
	gatewayHash common.Hash
}

type staticRouterInfoProvider struct {
	ri *router_info.RouterInfo
}

func (p staticRouterInfoProvider) GetRouterInfo() (*router_info.RouterInfo, error) {
	return p.ri, nil
}

// setupPublisherWithTunnel creates a publisher test environment with an active
// tunnel whose gateway is stored in the mock NetDB. The caller specifies the
// tunnel ID and any extra hops beyond the gateway.
func setupPublisherWithTunnel(t *testing.T, tunnelID tunnel.TunnelID, extraHops []common.Hash) *publisherTestEnv {
	t.Helper()
	db := newMockNetDB()
	transport := newMockTransportManager()

	selector := &mockPeerSelector{}
	pool := tunnel.NewTunnelPool(selector)

	gatewayRI := createValidRouterInfo(t)
	gatewayHash, _ := gatewayRI.IdentHash()
	db.StoreRouterInfo(gatewayRI)

	hops := append([]common.Hash{gatewayHash}, extraHops...)
	tunnelState := &tunnel.TunnelState{
		ID:        tunnelID,
		Hops:      hops,
		State:     tunnel.TunnelReady,
		CreatedAt: time.Now(),
	}
	pool.AddTunnel(tunnelState)

	publisher := NewPublisher(db, pool, transport, nil, DefaultPublisherConfig())

	return &publisherTestEnv{
		db:          db,
		transport:   transport,
		pool:        pool,
		publisher:   publisher,
		gatewayHash: gatewayHash,
	}
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
	_, err := publisher.sendDatabaseStoreToFloodfill(hash, data, i2np.DatabaseStoreTypeLeaseSet2, floodfill)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no active outbound tunnels")
}

func TestSendDatabaseStoreToFloodfill_RouterInfoFallsBackToDirectTransport(t *testing.T) {
	db := newMockNetDB()
	transport := newMockTransportManager()
	selector := &mockPeerSelector{}
	pool := tunnel.NewTunnelPool(selector)
	publisher := NewPublisher(db, pool, transport, nil, DefaultPublisherConfig())

	hash := common.Hash{1, 2, 3, 4, 5, 6, 7, 8}
	data := []byte("compressed routerinfo bytes")
	floodfill := createValidRouterInfo(t)
	floodfillHash, err := floodfill.IdentHash()
	require.NoError(t, err)

	_, err = publisher.sendDatabaseStoreToFloodfill(hash, data, i2np.DatabaseStoreTypeRouterInfo, floodfill)
	assert.NoError(t, err)

	sentMessages := transport.GetSentMessages(floodfillHash)
	require.Len(t, sentMessages, 1, "Expected direct DatabaseStore message to floodfill")
	assert.Equal(t, i2np.I2NPMessageTypeDatabaseStore, sentMessages[0].Type(), "Expected direct DatabaseStore message type")
}

func TestSendDatabaseStoreToFloodfill_RouterInfoDirectSendFailsWhenTransportUnavailable(t *testing.T) {
	db := newMockNetDB()
	transport := &routingMockTransportManager{sessions: make(map[string]*mockTransportSession)}
	selector := &mockPeerSelector{}
	pool := tunnel.NewTunnelPool(selector)

	publisher := NewPublisher(db, pool, transport, nil, DefaultPublisherConfig())

	// Add a valid outbound tunnel and gateway RouterInfo so the fallback path can succeed.
	gatewayRI := createValidRouterInfo(t)
	gatewayHash, err := gatewayRI.IdentHash()
	require.NoError(t, err)
	db.StoreRouterInfo(gatewayRI)

	pool.AddTunnel(&tunnel.TunnelState{
		ID:        tunnel.TunnelID(12345),
		Hops:      []common.Hash{gatewayHash},
		State:     tunnel.TunnelReady,
		CreatedAt: time.Now(),
	})

	directFloodfill := createValidRouterInfo(t)
	directFloodfillHash, err := directFloodfill.IdentHash()
	require.NoError(t, err)

	transport.failForHash(directFloodfillHash)
	transport.allowForHash(gatewayHash)

	hash := common.Hash{1, 2, 3, 4, 5, 6, 7, 8}
	data := []byte("compressed routerinfo bytes")
	floodfill := directFloodfill

	_, err = publisher.sendDatabaseStoreToFloodfill(hash, data, i2np.DatabaseStoreTypeRouterInfo, floodfill)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get transport session to floodfill")

	sentMessages := transport.GetSentMessages(gatewayHash)
	require.Len(t, sentMessages, 0, "RouterInfo publish should not fallback to tunnel gateway when direct transport is unavailable")
}

type routingMockTransportManager struct {
	mu          sync.Mutex
	sessions    map[string]*mockTransportSession
	failHashes  map[string]struct{}
	allowHashes map[string]struct{}
}

func (m *routingMockTransportManager) failForHash(hash common.Hash) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failHashes == nil {
		m.failHashes = make(map[string]struct{})
	}
	m.failHashes[string(hash[:])] = struct{}{}
}

func (m *routingMockTransportManager) allowForHash(hash common.Hash) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.allowHashes == nil {
		m.allowHashes = make(map[string]struct{})
	}
	m.allowHashes[string(hash[:])] = struct{}{}
}

func (m *routingMockTransportManager) GetSession(routerInfo router_info.RouterInfo) (I2NPSender, error) {
	hash, err := routerInfo.IdentHash()
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	key := string(hash[:])
	if _, blocked := m.failHashes[key]; blocked {
		return nil, transport.ErrNoTransportAvailable
	}
	if session, ok := m.sessions[key]; ok {
		return session, nil
	}
	session := newMockTransportSession()
	m.sessions[key] = session
	return session, nil
}

func (m *routingMockTransportManager) GetSentMessages(hash common.Hash) []i2np.Message {
	m.mu.Lock()
	defer m.mu.Unlock()
	if session, ok := m.sessions[string(hash[:])]; ok {
		return session.GetSentMessages()
	}
	return nil
}

func TestCreateDatabaseStoreMessage_IncludesNonZeroReplyToken(t *testing.T) {
	db := newMockNetDB()
	transport := newMockTransportManager()
	selector := &mockPeerSelector{}
	pool := tunnel.NewTunnelPool(selector)
	publisher := NewPublisher(db, pool, transport, nil, DefaultPublisherConfig())

	hash := common.Hash{1, 2, 3, 4, 5, 6, 7, 8}
	data := []byte("dbstore payload")

	msg, err := publisher.createDatabaseStoreMessage(hash, data, i2np.DatabaseStoreTypeLeaseSet2)
	require.NoError(t, err)
	require.Equal(t, i2np.I2NPMessageTypeDatabaseStore, msg.Type())

	parsed, ok := msg.(*i2np.DatabaseStore)
	require.True(t, ok, "createDatabaseStoreMessage should return DatabaseStore message")

	replyToken := binary.BigEndian.Uint32(parsed.ReplyToken[:])
	assert.Zero(t, replyToken, "reply token must remain zero when no inbound reply route is available")
}

func TestCreateDatabaseStoreMessage_TracksReplyTokenOnlyWhenReplyRouteAvailable(t *testing.T) {
	db := newMockNetDB()
	transport := newMockTransportManager()
	selector := &mockPeerSelector{}
	outboundPool := tunnel.NewTunnelPool(selector)
	inboundPool := tunnel.NewTunnelPool(selector)

	providerRI := createValidRouterInfo(t)
	publisher := NewPublisher(db, outboundPool, transport, staticRouterInfoProvider{ri: &providerRI}, DefaultPublisherConfig())

	hash := common.Hash{9, 8, 7, 6, 5, 4, 3, 2}
	msg, err := publisher.createDatabaseStoreMessage(hash, []byte("dbstore payload"), i2np.DatabaseStoreTypeRouterInfo)
	require.NoError(t, err)
	parsed, ok := msg.(*i2np.DatabaseStore)
	require.True(t, ok)
	assert.NotZero(t, binary.BigEndian.Uint32(parsed.ReplyToken[:]), "RouterInfo should carry a reply token even without inbound reply tunnel")
	assert.NotEqual(t, common.Hash{}, parsed.ReplyGateway, "RouterInfo should include direct reply gateway when no inbound reply tunnel exists")
	assert.Zero(t, binary.BigEndian.Uint32(parsed.ReplyTunnelID[:]), "RouterInfo direct reply should not set reply tunnel ID without inbound reply tunnel")
	token := binary.BigEndian.Uint32(parsed.ReplyToken[:])
	_, pending := publisher.pendingReplyTokens.Load(token)
	assert.True(t, pending, "reply token should be tracked for RouterInfo direct reply route")

	inboundPool.AddTunnel(&tunnel.TunnelState{
		ID:        tunnel.TunnelID(0x01020304),
		Hops:      []common.Hash{{0xAA, 0xBB, 0xCC, 0xDD}},
		State:     tunnel.TunnelReady,
		CreatedAt: time.Now(),
		IsInbound: true,
	})
	publisher.SetInboundPool(inboundPool)

	msg, err = publisher.createDatabaseStoreMessage(hash, []byte("dbstore payload"), i2np.DatabaseStoreTypeRouterInfo)
	require.NoError(t, err)
	parsed, ok = msg.(*i2np.DatabaseStore)
	require.True(t, ok)
	token = binary.BigEndian.Uint32(parsed.ReplyToken[:])
	assert.NotZero(t, token, "reply token must be non-zero when a reply route is available")
	_, pending = publisher.pendingReplyTokens.Load(token)
	assert.True(t, pending, "reply token should be tracked when a reply route is available")
}

func TestCreateDatabaseStoreMessage_IncludesReplyRouteWhenInboundAvailable(t *testing.T) {
	db := newMockNetDB()
	transport := newMockTransportManager()
	selector := &mockPeerSelector{}
	outboundPool := tunnel.NewTunnelPool(selector)
	inboundPool := tunnel.NewTunnelPool(selector)

	ourRI := createValidRouterInfo(t)
	replyGateway := common.Hash{0xAA, 0xBB, 0xCC, 0xDD}

	// Add one active inbound tunnel for reply routing.
	inboundPool.AddTunnel(&tunnel.TunnelState{
		ID:        tunnel.TunnelID(0x10203040),
		Hops:      []common.Hash{replyGateway},
		State:     tunnel.TunnelReady,
		CreatedAt: time.Now(),
		IsInbound: true,
	})

	provider := staticRouterInfoProvider{ri: &ourRI}
	publisher := NewPublisher(db, outboundPool, transport, provider, DefaultPublisherConfig())
	publisher.SetInboundPool(inboundPool)

	hash := common.Hash{1, 2, 3, 4, 5, 6, 7, 8}
	data := []byte("dbstore payload")

	msg, err := publisher.createDatabaseStoreMessage(hash, data, i2np.DatabaseStoreTypeLeaseSet2)
	require.NoError(t, err)

	parsed, ok := msg.(*i2np.DatabaseStore)
	require.True(t, ok, "createDatabaseStoreMessage should return DatabaseStore message")

	assert.Equal(t, uint32(0x10203040), binary.BigEndian.Uint32(parsed.ReplyTunnelID[:]),
		"reply tunnel ID should be populated from active inbound tunnel")
	assert.Equal(t, replyGateway, parsed.ReplyGateway,
		"reply gateway should be the inbound tunnel gateway hop hash")
}

func TestCreateDatabaseStoreMessage_UsesInboundGatewayMetadataForReplyRoute(t *testing.T) {
	db := newMockNetDB()
	transport := newMockTransportManager()
	selector := &mockPeerSelector{}
	outboundPool := tunnel.NewTunnelPool(selector)
	inboundPool := tunnel.NewTunnelPool(selector)

	ourRI := createValidRouterInfo(t)
	gatewayHop := common.Hash{0x01, 0x02, 0x03, 0x04}
	middleHop := common.Hash{0x05, 0x06, 0x07, 0x08}
	endpointHop := common.Hash{0x09, 0x0A, 0x0B, 0x0C}

	inboundPool.AddTunnel(&tunnel.TunnelState{
		ID:              tunnel.TunnelID(0x01020304),
		GatewayTunnelID: tunnel.TunnelID(0xA1B2C3D4),
		Hops:            []common.Hash{gatewayHop, middleHop, endpointHop},
		State:           tunnel.TunnelReady,
		CreatedAt:       time.Now(),
		IsInbound:       true,
	})

	provider := staticRouterInfoProvider{ri: &ourRI}
	publisher := NewPublisher(db, outboundPool, transport, provider, DefaultPublisherConfig())
	publisher.SetInboundPool(inboundPool)

	msg, err := publisher.createDatabaseStoreMessage(common.Hash{1, 2, 3, 4}, []byte("dbstore payload"), i2np.DatabaseStoreTypeLeaseSet2)
	require.NoError(t, err)

	parsed, ok := msg.(*i2np.DatabaseStore)
	require.True(t, ok, "createDatabaseStoreMessage should return DatabaseStore message")

	assert.Equal(t, uint32(0xA1B2C3D4), binary.BigEndian.Uint32(parsed.ReplyTunnelID[:]),
		"reply tunnel ID should use inbound gateway tunnel metadata")
	assert.Equal(t, gatewayHop, parsed.ReplyGateway,
		"reply gateway should be derived from inbound gateway hop")
	assert.NotEqual(t, endpointHop, parsed.ReplyGateway,
		"reply gateway must not use inbound endpoint hop")
	assert.NotEqual(t, middleHop, parsed.ReplyGateway,
		"reply gateway must not use middle hop")
}

// TestSendDatabaseStoreToFloodfill_WithActiveTunnel tests successful tunnel selection and message transmission
func TestSendDatabaseStoreToFloodfill_WithActiveTunnel(t *testing.T) {
	env := setupPublisherWithTunnel(t, 12345, []common.Hash{
		{0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18},
		{0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28},
	})

	// Create test data
	hash := common.Hash{9, 10, 11, 12, 13, 14, 15, 16}
	data := []byte("test leaseset data for tunnel transmission")
	floodfill := createValidRouterInfo(t)

	// Should succeed with active tunnel and transport
	_, err := env.publisher.sendDatabaseStoreToFloodfill(hash, data, i2np.DatabaseStoreTypeLeaseSet2, floodfill)
	assert.NoError(t, err)

	// Verify message was sent through transport
	sentMessages := env.transport.GetSentMessages(env.gatewayHash)
	require.NotNil(t, sentMessages, "Expected messages sent to gateway")
	require.Len(t, sentMessages, 1, "Expected exactly one message sent")

	// Verify message is a TunnelGateway message
	msg := sentMessages[0]
	assert.Equal(t, i2np.I2NPMessageTypeTunnelGateway, msg.Type(), "Expected TunnelGateway message type")
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
	_, err := publisher.sendDatabaseStoreToFloodfill(hash, data, i2np.DatabaseStoreTypeLeaseSet2, floodfill)
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
	_, err := publisher.sendDatabaseStoreToFloodfill(hash, data, i2np.DatabaseStoreTypeLeaseSet2, floodfill)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to retrieve RouterInfo for gateway")
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
		_, err := publisher.sendDatabaseStoreToFloodfill(hash, data, i2np.DatabaseStoreTypeLeaseSet2, floodfill)
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
	env := setupPublisherWithTunnel(t, 99999, []common.Hash{
		{0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99},
		{0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18},
	})

	// Create large test data (simulating large RouterInfo with many router addresses)
	hash := common.Hash{33, 34, 35, 36, 37, 38, 39, 40}
	data := make([]byte, 10*1024) // 10KB payload
	for i := range data {
		data[i] = byte(i % 256)
	}
	floodfill := createValidRouterInfo(t)

	// Should handle large payloads without error
	_, err := env.publisher.sendDatabaseStoreToFloodfill(hash, data, i2np.DatabaseStoreTypeLeaseSet2, floodfill)
	assert.NoError(t, err)

	// Verify message was sent
	sentMessages := env.transport.GetSentMessages(env.gatewayHash)
	require.Len(t, sentMessages, 1, "Expected large message to be sent")
}

// TestSendDatabaseStoreToFloodfill_EmptyData tests handling of empty data payload
func TestSendDatabaseStoreToFloodfill_EmptyData(t *testing.T) {
	env := setupPublisherWithTunnel(t, 555, []common.Hash{
		{0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C},
	})

	// Create test with empty data
	hash := common.Hash{41, 42, 43, 44, 45, 46, 47, 48}
	data := []byte{} // Empty payload
	floodfill := createValidRouterInfo(t)

	// Should handle empty data (may represent deletion or placeholder)
	_, err := env.publisher.sendDatabaseStoreToFloodfill(hash, data, i2np.DatabaseStoreTypeLeaseSet2, floodfill)
	assert.NoError(t, err)

	// Verify message was sent
	sentMessages := env.transport.GetSentMessages(env.gatewayHash)
	require.Len(t, sentMessages, 1, "Expected empty data message to be sent")
}

// TestSendDatabaseStoreToFloodfill_ConcurrentSends tests thread-safety of concurrent sends
func TestSendDatabaseStoreToFloodfill_ConcurrentSends(t *testing.T) {
	env := setupPublisherWithTunnel(t, 777, nil)

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
			_, err := env.publisher.sendDatabaseStoreToFloodfill(hash, data, i2np.DatabaseStoreTypeLeaseSet2, floodfill)
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
	sentMessages := env.transport.GetSentMessages(env.gatewayHash)
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
