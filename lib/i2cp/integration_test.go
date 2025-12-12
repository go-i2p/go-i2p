package i2cp

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockTunnelBuilder implements tunnel.BuilderInterface for testing
type mockTunnelBuilder struct {
	nextID tunnel.TunnelID
}

func (m *mockTunnelBuilder) BuildTunnel(req tunnel.BuildTunnelRequest) (tunnel.TunnelID, error) {
	m.nextID++
	return m.nextID, nil
}

// setupTestEnvironment creates a complete test environment with server, session, and tunnel pools
func setupTestEnvironment(t *testing.T) (*Server, *Session, *tunnel.Pool, *tunnel.Pool, func()) {
	// Create server
	config := &ServerConfig{
		ListenAddr:  "localhost:0", // Use random port
		Network:     "tcp",
		MaxSessions: 100,
	}

	server, err := NewServer(config)
	require.NoError(t, err)

	err = server.Start()
	require.NoError(t, err)

	// Create session
	sessionConfig := DefaultSessionConfig()
	sessionConfig.TunnelLifetime = 1 * time.Minute // Shorter for testing
	sessionConfig.Nickname = "test-session"

	session, err := server.manager.CreateSession(nil, sessionConfig)
	require.NoError(t, err)
	require.NotNil(t, session)

	// Create tunnel pools
	selector := &mockPeerSelector{}
	inboundConfig := tunnel.DefaultPoolConfig()
	inboundConfig.IsInbound = true
	inboundConfig.MinTunnels = 2
	inboundConfig.MaxTunnels = 3
	inboundConfig.TunnelLifetime = 1 * time.Minute

	outboundConfig := tunnel.DefaultPoolConfig()
	outboundConfig.IsInbound = false
	outboundConfig.MinTunnels = 2
	outboundConfig.MaxTunnels = 3
	outboundConfig.TunnelLifetime = 1 * time.Minute

	inboundPool := tunnel.NewTunnelPoolWithConfig(selector, inboundConfig)
	outboundPool := tunnel.NewTunnelPoolWithConfig(selector, outboundConfig)

	// Set tunnel builder
	builder := &mockTunnelBuilder{}
	inboundPool.SetTunnelBuilder(builder)
	outboundPool.SetTunnelBuilder(builder)

	// Attach pools to session
	session.SetInboundPool(inboundPool)
	session.SetOutboundPool(outboundPool)

	// Add some mock tunnels to the inbound pool for LeaseSet generation
	for i := 0; i < 2; i++ {
		tunnelID := tunnel.TunnelID(1000 + i)
		var gateway data.Hash
		// Use a mock gateway hash
		copy(gateway[:], []byte("mock-gateway-router-hash-12345678901234567890"))

		tunnelState := &tunnel.TunnelState{
			ID:        tunnelID,
			Hops:      []data.Hash{gateway},
			State:     tunnel.TunnelReady,
			CreatedAt: time.Now(),
		}
		inboundPool.AddTunnel(tunnelState)
	}

	// Cleanup function
	cleanup := func() {
		session.Stop()
		inboundPool.Stop()
		outboundPool.Stop()
		if err := server.Stop(); err != nil {
			t.Logf("Error stopping server: %v", err)
		}
	}

	return server, session, inboundPool, outboundPool, cleanup
}

// TestE2E_SessionCreation tests the complete session creation flow
func TestE2E_SessionCreation(t *testing.T) {
	server, session, _, _, cleanup := setupTestEnvironment(t)
	defer cleanup()

	// Verify session was created
	assert.NotEqual(t, SessionIDReservedControl, session.ID())
	assert.NotEqual(t, SessionIDReservedBroadcast, session.ID())
	assert.True(t, session.IsActive())

	// Verify session is registered with server
	retrievedSession, exists := server.manager.GetSession(session.ID())
	assert.True(t, exists)
	assert.Equal(t, session, retrievedSession)

	// Verify session has a destination
	dest := session.Destination()
	assert.NotNil(t, dest)

	// Verify session has tunnel pools
	assert.NotNil(t, session.InboundPool())
	assert.NotNil(t, session.OutboundPool())
}

// TestE2E_LeaseSetCreation tests LeaseSet generation with active tunnels
func TestE2E_LeaseSetCreation(t *testing.T) {
	_, session, inboundPool, _, cleanup := setupTestEnvironment(t)
	defer cleanup()

	// Verify we have active tunnels
	activeTunnels := inboundPool.GetActiveTunnels()
	require.Greater(t, len(activeTunnels), 0, "should have at least one active tunnel")

	// Generate LeaseSet
	leaseSetBytes, err := session.CreateLeaseSet()
	require.NoError(t, err)
	require.NotNil(t, leaseSetBytes)
	require.Greater(t, len(leaseSetBytes), 0, "LeaseSet should not be empty")

	// Verify LeaseSet is cached
	cachedLS := session.CurrentLeaseSet()
	assert.Equal(t, leaseSetBytes, cachedLS)

	// Verify LeaseSet age
	age := session.LeaseSetAge()
	assert.Greater(t, age, time.Duration(0))
	assert.Less(t, age, 1*time.Second, "LeaseSet should be freshly created")
}

// TestE2E_LeaseSetMaintenance tests automatic LeaseSet maintenance
func TestE2E_LeaseSetMaintenance(t *testing.T) {
	_, session, _, _, cleanup := setupTestEnvironment(t)
	defer cleanup()

	// Start LeaseSet maintenance
	err := session.StartLeaseSetMaintenance()
	require.NoError(t, err)

	// Wait a short time for maintenance to run
	time.Sleep(200 * time.Millisecond)

	// Verify LeaseSet was created
	leaseSet := session.CurrentLeaseSet()
	assert.NotNil(t, leaseSet)
	assert.Greater(t, len(leaseSet), 0)

	// Verify age is recent
	age := session.LeaseSetAge()
	assert.Less(t, age, 1*time.Second)
}

// TestE2E_MessageQueueing tests message queueing and delivery
func TestE2E_MessageQueueing(t *testing.T) {
	_, session, _, _, cleanup := setupTestEnvironment(t)
	defer cleanup()

	// Test message payloads
	messages := [][]byte{
		[]byte("Hello, I2P!"),
		[]byte("Test message 2"),
		[]byte("Another message"),
	}

	// Queue messages
	for i, msg := range messages {
		err := session.QueueIncomingMessage(msg)
		require.NoError(t, err, "failed to queue message %d", i)
	}

	// Receive messages in order
	for i, expected := range messages {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()

		received, err := receiveMessageWithContext(ctx, session)
		require.NoError(t, err, "failed to receive message %d", i)
		require.NotNil(t, received)
		assert.Equal(t, expected, received.Payload)
	}
}

// receiveMessageWithContext receives a message with context timeout
func receiveMessageWithContext(ctx context.Context, session *Session) (*IncomingMessage, error) {
	msgChan := make(chan *IncomingMessage, 1)
	errChan := make(chan error, 1)

	go func() {
		msg, err := session.ReceiveMessage()
		if err != nil {
			errChan <- err
			return
		}
		msgChan <- msg
	}()

	select {
	case msg := <-msgChan:
		return msg, nil
	case err := <-errChan:
		return nil, err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// TestE2E_ClientProtocolFlow tests the complete I2CP protocol flow from client perspective
func TestE2E_ClientProtocolFlow(t *testing.T) {
	// Start server
	config := &ServerConfig{
		ListenAddr:  "localhost:17660",
		Network:     "tcp",
		MaxSessions: 100,
	}

	server, err := NewServer(config)
	require.NoError(t, err)

	err = server.Start()
	require.NoError(t, err)
	defer func() {
		if stopErr := server.Stop(); stopErr != nil {
			t.Logf("Error stopping server: %v", stopErr)
		}
	}()

	time.Sleep(10 * time.Millisecond)

	// Connect as a client
	conn, err := net.Dial("tcp", "localhost:17660")
	require.NoError(t, err)
	defer conn.Close()

	// Send protocol byte (0x2a) as required by I2CP spec
	protocolByte := []byte{0x2a}
	_, err = conn.Write(protocolByte)
	require.NoError(t, err)

	// Step 1: Create session
	createMsg := &Message{
		Type:      MessageTypeCreateSession,
		SessionID: SessionIDReservedControl,
		Payload:   []byte{},
	}

	err = WriteMessage(conn, createMsg)
	require.NoError(t, err)

	// Read SessionStatus response
	statusMsg, err := ReadMessage(conn)
	require.NoError(t, err)
	require.Equal(t, uint8(MessageTypeSessionStatus), uint8(statusMsg.Type))
	require.NotEqual(t, SessionIDReservedControl, statusMsg.SessionID)

	sessionID := statusMsg.SessionID

	// Verify session exists on server
	session, exists := server.manager.GetSession(sessionID)
	require.True(t, exists)
	require.NotNil(t, session)

	// Step 2: Send GetDate message
	getDateMsg := &Message{
		Type:      MessageTypeGetDate,
		SessionID: sessionID,
		Payload:   []byte{},
	}

	err = WriteMessage(conn, getDateMsg)
	require.NoError(t, err)

	// Read SetDate response
	setDateMsg, err := ReadMessage(conn)
	require.NoError(t, err)
	require.Equal(t, uint8(MessageTypeSetDate), uint8(setDateMsg.Type))

	// Step 3: Reconfigure session
	reconfigMsg := &Message{
		Type:      MessageTypeReconfigureSession,
		SessionID: sessionID,
		Payload:   []byte{}, // Empty config for now
	}

	err = WriteMessage(conn, reconfigMsg)
	require.NoError(t, err)

	// Step 4: Destroy session
	destroyMsg := &Message{
		Type:      MessageTypeDestroySession,
		SessionID: sessionID,
		Payload:   []byte{},
	}

	err = WriteMessage(conn, destroyMsg)
	require.NoError(t, err)

	// Wait for server to process
	time.Sleep(50 * time.Millisecond)

	// Verify session was destroyed
	_, exists = server.manager.GetSession(sessionID)
	assert.False(t, exists)
}

// TestE2E_MessageDeliveryToClient tests message delivery from server to client
func TestE2E_MessageDeliveryToClient(t *testing.T) {
	// Create in-memory pipe for bidirectional communication
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	// Create server and session
	server, err := NewServer(nil)
	require.NoError(t, err)

	session, err := server.manager.CreateSession(nil, nil)
	require.NoError(t, err)

	// Start message delivery goroutine
	server.wg.Add(1)
	go server.deliverMessagesToClient(session, serverConn)

	// Queue messages to the session
	testMessages := [][]byte{
		[]byte("Message 1"),
		[]byte("Message 2"),
		[]byte("Message 3"),
	}

	for _, msg := range testMessages {
		err := session.QueueIncomingMessage(msg)
		require.NoError(t, err)
	}

	// Read messages from client connection
	for i, expectedPayload := range testMessages {
		msg, err := ReadMessage(clientConn)
		require.NoError(t, err, "failed to read message %d", i)
		require.Equal(t, uint8(MessageTypeMessagePayload), uint8(msg.Type))
		require.Equal(t, session.ID(), msg.SessionID)

		// Parse MessagePayload
		payload, err := ParseMessagePayloadPayload(msg.Payload)
		require.NoError(t, err)
		assert.Equal(t, expectedPayload, payload.Payload)
	}

	// Stop session and wait for goroutine
	session.Stop()
	server.wg.Wait()
}

// TestE2E_SessionLifecycleWithTunnels tests complete session lifecycle with tunnel integration
func TestE2E_SessionLifecycleWithTunnels(t *testing.T) {
	server, session, inboundPool, _, cleanup := setupTestEnvironment(t)
	defer cleanup()

	// Verify initial state
	assert.True(t, session.IsActive())
	assert.NotNil(t, session.InboundPool())
	assert.NotNil(t, session.OutboundPool())

	// Generate LeaseSet
	leaseSet, err := session.CreateLeaseSet()
	require.NoError(t, err)
	require.NotNil(t, leaseSet)

	// Queue and receive a message
	testPayload := []byte("Test message through tunnels")
	err = session.QueueIncomingMessage(testPayload)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	received, err := receiveMessageWithContext(ctx, session)
	require.NoError(t, err)
	require.NotNil(t, received)
	assert.Equal(t, testPayload, received.Payload)

	// Verify pools are still active
	assert.Greater(t, len(inboundPool.GetActiveTunnels()), 0)

	// Destroy session
	err = server.manager.DestroySession(session.ID())
	require.NoError(t, err)

	// Verify session is inactive
	assert.False(t, session.IsActive())

	// Verify session is removed from manager
	_, exists := server.manager.GetSession(session.ID())
	assert.False(t, exists)
}

// TestE2E_MultipleSessionsConcurrent tests multiple concurrent sessions
func TestE2E_MultipleSessionsConcurrent(t *testing.T) {
	config := &ServerConfig{
		ListenAddr:  "localhost:17661",
		Network:     "tcp",
		MaxSessions: 10,
	}

	server, err := NewServer(config)
	require.NoError(t, err)

	err = server.Start()
	require.NoError(t, err)
	defer func() {
		if stopErr := server.Stop(); stopErr != nil {
			t.Logf("Error stopping server: %v", stopErr)
		}
	}()

	time.Sleep(10 * time.Millisecond)

	// Create multiple concurrent sessions
	numSessions := 5
	sessionIDs := make([]uint16, numSessions)
	conns := make([]net.Conn, numSessions)

	for i := 0; i < numSessions; i++ {
		conn, err := net.Dial("tcp", "localhost:17661")
		require.NoError(t, err)
		defer conn.Close()
		conns[i] = conn

		// Send protocol byte (0x2a)
		protocolByte := []byte{0x2a}
		_, err = conn.Write(protocolByte)
		require.NoError(t, err)

		// Create session
		createMsg := &Message{
			Type:      MessageTypeCreateSession,
			SessionID: SessionIDReservedControl,
			Payload:   []byte{},
		}

		err = WriteMessage(conn, createMsg)
		require.NoError(t, err)

		statusMsg, err := ReadMessage(conn)
		require.NoError(t, err)
		require.Equal(t, uint8(MessageTypeSessionStatus), uint8(statusMsg.Type))

		sessionIDs[i] = statusMsg.SessionID
	}

	// Verify all sessions are unique and exist
	uniqueIDs := make(map[uint16]bool)
	for _, id := range sessionIDs {
		uniqueIDs[id] = true
		session, exists := server.manager.GetSession(id)
		assert.True(t, exists)
		assert.NotNil(t, session)
	}
	assert.Equal(t, numSessions, len(uniqueIDs), "all session IDs should be unique")

	// Destroy all sessions
	for i, id := range sessionIDs {
		destroyMsg := &Message{
			Type:      MessageTypeDestroySession,
			SessionID: id,
			Payload:   []byte{},
		}

		err = WriteMessage(conns[i], destroyMsg)
		require.NoError(t, err)
	}

	time.Sleep(50 * time.Millisecond)

	// Verify all sessions are destroyed
	assert.Equal(t, 0, server.manager.SessionCount())
}

// TestE2E_LeaseSetRegenerationOnExpiry tests LeaseSet regeneration before expiry
func TestE2E_LeaseSetRegenerationOnExpiry(t *testing.T) {
	_, session, _, _, cleanup := setupTestEnvironment(t)
	defer cleanup()

	// Use very short lifetime for testing
	session.mu.Lock()
	session.config.TunnelLifetime = 500 * time.Millisecond
	session.mu.Unlock()

	// Start maintenance with shorter interval
	err := session.StartLeaseSetMaintenance()
	require.NoError(t, err)

	// Wait for initial LeaseSet
	time.Sleep(200 * time.Millisecond)
	initialLS := session.CurrentLeaseSet()
	require.NotNil(t, initialLS)

	// Wait past regeneration threshold (half of lifetime = 250ms)
	// Add maintenance check interval (125ms) + buffer
	time.Sleep(400 * time.Millisecond)

	// Verify LeaseSet was regenerated
	newLS := session.CurrentLeaseSet()
	require.NotNil(t, newLS)

	newAge := session.LeaseSetAge()
	// New age should be less than total elapsed time since initial creation
	// (it was regenerated sometime during the 400ms wait)
	assert.Less(t, newAge, 400*time.Millisecond, "LeaseSet should have been regenerated recently")
}

// TestE2E_SessionStopCleansUpResources tests that Stop() properly cleans up all resources
func TestE2E_SessionStopCleansUpResources(t *testing.T) {
	_, session, _, _, cleanup := setupTestEnvironment(t)
	// Don't defer cleanup since we're testing Stop explicitly

	// Start maintenance
	err := session.StartLeaseSetMaintenance()
	require.NoError(t, err)

	// Queue some messages
	for i := 0; i < 5; i++ {
		err := session.QueueIncomingMessage([]byte("test message"))
		require.NoError(t, err)
	}

	// Stop session
	session.Stop()

	// Verify session is inactive
	assert.False(t, session.IsActive())

	// Verify queueing new messages fails
	err = session.QueueIncomingMessage([]byte("should fail"))
	assert.Error(t, err)

	// Verify ReceiveMessage returns nil after stop
	msg, err := session.ReceiveMessage()
	assert.Nil(t, msg)
	assert.Nil(t, err)

	cleanup()
}

// BenchmarkE2E_MessageThroughput benchmarks message queuing and delivery throughput
func BenchmarkE2E_MessageThroughput(b *testing.B) {
	// Setup environment
	config := &ServerConfig{
		ListenAddr:  "localhost:27661",
		Network:     "tcp",
		MaxSessions: 100,
	}

	server, err := NewServer(config)
	if err != nil {
		b.Fatalf("Failed to create server: %v", err)
	}

	if err := server.Start(); err != nil {
		b.Fatalf("Failed to start server: %v", err)
	}
	defer func() {
		if stopErr := server.Stop(); stopErr != nil {
			b.Logf("Error stopping server: %v", stopErr)
		}
	}()

	session, err := server.manager.CreateSession(nil, nil)
	if err != nil {
		b.Fatalf("Failed to create session: %v", err)
	}
	defer session.Stop()

	testPayload := []byte("benchmark message payload")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = session.QueueIncomingMessage(testPayload)
		_, _ = session.ReceiveMessage()
	}
}

// BenchmarkE2E_SessionCreation benchmarks complete session creation and destruction
func BenchmarkE2E_SessionCreation(b *testing.B) {
	config := &ServerConfig{
		ListenAddr:  "localhost:27662",
		Network:     "tcp",
		MaxSessions: 10000,
	}

	server, err := NewServer(config)
	if err != nil {
		b.Fatalf("Failed to create server: %v", err)
	}

	if err := server.Start(); err != nil {
		b.Fatalf("Failed to start server: %v", err)
	}
	defer server.Stop()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		session, err := server.manager.CreateSession(nil, nil)
		if err != nil {
			b.Fatalf("Failed to create session: %v", err)
		}
		_ = server.manager.DestroySession(session.ID())
	}
}

// TestE2E_OutboundMessageRouting tests the complete outbound message routing flow
func TestE2E_OutboundMessageRouting(t *testing.T) {
	server, session, _, outboundPool, cleanup := setupTestEnvironment(t)
	defer cleanup()

	// Add outbound tunnels for routing
	for i := 0; i < 2; i++ {
		tunnelID := tunnel.TunnelID(3000 + i)
		var gateway data.Hash
		copy(gateway[:], []byte("test-outbound-gateway-hash-12345678901234567890"))
		gateway[31] = byte(i)

		tunnelState := &tunnel.TunnelState{
			ID:        tunnelID,
			Hops:      []data.Hash{gateway},
			State:     tunnel.TunnelReady,
			CreatedAt: time.Now(),
		}
		outboundPool.AddTunnel(tunnelState)
	}

	// Create garlic session manager
	var privKey [32]byte
	copy(privKey[:], "test-private-key-for-integration-test-32-bytes")
	garlicMgr, err := i2np.NewGarlicSessionManager(privKey)
	require.NoError(t, err)

	// Track sent messages
	sentMessages := make(map[string]i2np.I2NPMessage)
	var sentMutex sync.Mutex

	// Create transport send function
	transportSend := func(peerHash data.Hash, msg i2np.I2NPMessage) error {
		sentMutex.Lock()
		defer sentMutex.Unlock()
		sentMessages[string(peerHash[:])] = msg
		return nil
	}

	// Create and set message router on server
	router := NewMessageRouter(garlicMgr, transportSend)
	server.SetMessageRouter(router)

	// Create destination for routing
	var destHash data.Hash
	copy(destHash[:], "test-destination-hash-32-bytes-1234567890")

	var destPubKey [32]byte
	// Use a valid X25519 public key (generated once for testing)
	// This is a base point which is valid but obviously not secure
	copy(destPubKey[:], []byte{
		0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	})

	// Test payload
	payload := []byte("Hello from I2CP integration test!")

	// Route the message (messageID=0, no status callback for test)
	err = router.RouteOutboundMessage(session, 0, destHash, destPubKey, payload, nil)
	require.NoError(t, err)

	// Verify message was sent
	sentMutex.Lock()
	defer sentMutex.Unlock()
	assert.Len(t, sentMessages, 1, "should send one message to gateway")

	// Verify sent message is a Garlic message
	for _, msg := range sentMessages {
		assert.Equal(t, i2np.I2NP_MESSAGE_TYPE_GARLIC, msg.Type())
	}
}
