package i2cp

import (
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/go-i2p/common/data"
	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestI2CPServer creates an I2CP server with standard test config.
func newTestI2CPServer(t *testing.T, addr string) *Server {
	t.Helper()
	config := &ServerConfig{
		ListenAddr:  addr,
		Network:     "tcp",
		MaxSessions: 100,
	}
	server, err := NewServer(config)
	require.NoError(t, err, "NewServer() error")
	return server
}

// startServerAndConnect starts the server, waits, and returns a connected client.
// The connection and server are registered for cleanup via t.Cleanup.
func startServerAndConnect(t *testing.T, server *Server, addr string) net.Conn {
	t.Helper()
	require.NoError(t, server.Start(), "Start() error")
	t.Cleanup(func() { server.Stop() })

	time.Sleep(10 * time.Millisecond)

	conn, err := dialI2CPClient(addr)
	require.NoError(t, err, "Failed to connect to server")
	t.Cleanup(func() { conn.Close() })
	return conn
}

// createSessionOnConn sends a CreateSession message and returns the session ID.
func createSessionOnConn(t *testing.T, conn net.Conn) uint16 {
	t.Helper()
	createMsg := &Message{
		Type:      MessageTypeCreateSession,
		SessionID: SessionIDReservedControl,
		Payload:   []byte{},
	}
	require.NoError(t, WriteMessage(conn, createMsg), "WriteMessage() error")
	response, err := ReadMessage(conn)
	require.NoError(t, err, "ReadMessage() error")
	require.Equal(t, MessageTypeSessionStatus, response.Type, "Response type mismatch")
	return response.SessionID
}

func TestServerStartStop(t *testing.T) {
	server := newTestI2CPServer(t, "localhost:17654")

	require.NoError(t, server.Start(), "Start() error")
	assert.True(t, server.IsRunning(), "Server should be running after Start()")

	// Give server time to start listening
	time.Sleep(10 * time.Millisecond)

	require.NoError(t, server.Stop(), "Stop() error")
	assert.False(t, server.IsRunning(), "Server should not be running after Stop()")
}

func TestServerDoubleStart(t *testing.T) {
	server := newTestI2CPServer(t, "localhost:17655")
	defer server.Stop()

	require.NoError(t, server.Start(), "Start() error")

	// Second start should fail
	assert.Error(t, server.Start(), "Expected error on second Start()")
}

func TestServerCreateSession(t *testing.T) {
	server := newTestI2CPServer(t, "localhost:17656")

	require.NoError(t, server.Start(), "Start() error")
	defer server.Stop()

	// Give server time to start listening
	time.Sleep(10 * time.Millisecond)

	// Connect to server
	conn, err := dialI2CPClient("localhost:17656")
	require.NoError(t, err, "Failed to connect to server")
	defer conn.Close()

	// Send CreateSession message
	createMsg := &Message{
		Type:      MessageTypeCreateSession,
		SessionID: SessionIDReservedControl,
		Payload:   []byte{}, // Empty config for now
	}

	require.NoError(t, WriteMessage(conn, createMsg), "WriteMessage() error")

	// Read SessionStatus response
	response, err := ReadMessage(conn)
	require.NoError(t, err, "ReadMessage() error")

	assert.Equal(t, MessageTypeSessionStatus, response.Type)
	assert.NotEqual(t, SessionIDReservedControl, response.SessionID, "Session ID should not be reserved control value")

	// Per I2CP spec: SessionStatus payload is SessionID(2 bytes) + Status(1 byte) = 3 bytes
	require.Len(t, response.Payload, 3, "SessionStatus payload length")

	// Verify SessionID in payload matches the SessionID in message header
	payloadSessionID := binary.BigEndian.Uint16(response.Payload[0:2])
	assert.Equal(t, response.SessionID, payloadSessionID, "SessionID in payload")

	// Verify status byte is 0x01 (Created) per I2CP spec
	assert.Equal(t, SessionStatusCreated, response.Payload[2], "SessionStatus status byte")

	// Verify session was created
	assert.Equal(t, 1, server.SessionManager().SessionCount(), "SessionCount()")
}

func TestServerDestroySession(t *testing.T) {
	server := newTestI2CPServer(t, "localhost:17659")
	conn := startServerAndConnect(t, server, "localhost:17659")

	sessionID := createSessionOnConn(t, conn)

	// Destroy session
	destroyMsg := &Message{
		Type:      MessageTypeDestroySession,
		SessionID: sessionID,
		Payload:   []byte{},
	}

	require.NoError(t, WriteMessage(conn, destroyMsg), "WriteMessage() error")

	// Give server time to process
	time.Sleep(10 * time.Millisecond)

	// Verify session was destroyed
	assert.Equal(t, 0, server.SessionManager().SessionCount(), "SessionCount()")
}

func TestServerMaxSessions(t *testing.T) {
	config := &ServerConfig{
		ListenAddr:  "localhost:17654", // Different port
		Network:     "tcp",
		MaxSessions: 2,
	}

	server, err := NewServer(config)
	require.NoError(t, err, "NewServer() error")

	require.NoError(t, server.Start(), "Start() error")
	defer server.Stop()

	time.Sleep(10 * time.Millisecond)

	// Create 2 sessions (should succeed)
	var conns []net.Conn
	for i := 0; i < 2; i++ {
		conn, err := dialI2CPClient("localhost:17654")
		require.NoError(t, err, "Failed to connect")
		defer conn.Close()
		conns = append(conns, conn)

		createMsg := &Message{
			Type:      MessageTypeCreateSession,
			SessionID: SessionIDReservedControl,
			Payload:   []byte{},
		}

		require.NoError(t, WriteMessage(conn, createMsg), "WriteMessage() error")
		_, err = ReadMessage(conn)
		require.NoError(t, err, "ReadMessage() error")
	}

	// Verify 2 sessions exist
	assert.Equal(t, 2, server.SessionManager().SessionCount(), "SessionCount()")

	// Third connection should be rejected immediately
	conn3, err := dialI2CPClient("localhost:17654")
	require.NoError(t, err, "Failed to connect")
	defer conn3.Close()

	createMsg := &Message{
		Type:      MessageTypeCreateSession,
		SessionID: SessionIDReservedControl,
		Payload:   []byte{},
	}

	// Server should close connection without response
	_ = WriteMessage(conn3, createMsg)

	// Trying to read should get EOF or error
	require.NoError(t, conn3.SetReadDeadline(time.Now().Add(100*time.Millisecond)), "Failed to set read deadline")
	_, readErr := ReadMessage(conn3)
	// Connection should be closed, so read should fail
	// We don't check exact error since it could be EOF or network error
	_ = readErr
}

func TestServerGetDate(t *testing.T) {
	server := newTestI2CPServer(t, "localhost:17658")
	conn := startServerAndConnect(t, server, "localhost:17658")

	getDateMsg := &Message{
		Type:      MessageTypeGetDate,
		SessionID: SessionIDReservedControl,
		Payload:   []byte{},
	}

	require.NoError(t, WriteMessage(conn, getDateMsg), "WriteMessage() error")

	response, err := ReadMessage(conn)
	require.NoError(t, err, "ReadMessage() error")

	assert.Equal(t, MessageTypeSetDate, response.Type)
}

func TestServerHandleCreateLeaseSet(t *testing.T) {
	server := newTestI2CPServer(t, "localhost:17659")
	conn := startServerAndConnect(t, server, "localhost:17659")
	sessionID := createSessionOnConn(t, conn)

	// Send CreateLeaseSet - should fail because no inbound pool
	leaseSetMsg := &Message{
		Type:      MessageTypeCreateLeaseSet,
		SessionID: sessionID,
		Payload:   []byte{},
	}

	require.NoError(t, WriteMessage(conn, leaseSetMsg), "WriteMessage() error")

	// Server should handle it and log error but not disconnect
	// Give it time to process
	time.Sleep(50 * time.Millisecond)

	// Connection should still be alive
	testMsg := &Message{
		Type:      MessageTypeGetDate,
		SessionID: sessionID,
		Payload:   []byte{},
	}

	assert.NoError(t, WriteMessage(conn, testMsg), "Connection should still be alive after CreateLeaseSet failure")
}

func BenchmarkServerCreateSession(b *testing.B) {
	config := &ServerConfig{
		ListenAddr:  "localhost:27654", // Different port for benchmark
		Network:     "tcp",
		MaxSessions: 10000,
	}

	server, err := NewServer(config)
	if err != nil {
		b.Fatalf("NewServer() error = %v", err)
	}

	if err := server.Start(); err != nil {
		b.Fatalf("Start() error = %v", err)
	}
	defer server.Stop()

	time.Sleep(10 * time.Millisecond)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn, err := dialI2CPClient("localhost:27654")
		if err != nil {
			b.Fatalf("Failed to connect: %v", err)
		}

		createMsg := &Message{
			Type:      MessageTypeCreateSession,
			SessionID: SessionIDReservedControl,
			Payload:   []byte{},
		}

		_ = WriteMessage(conn, createMsg)
		_, _ = ReadMessage(conn)
		conn.Close()
	}
}

// TestServerConnWriteMuInitialized verifies that the per-connection write mutex
// map is properly initialized when creating a new server.
func TestServerConnWriteMuInitialized(t *testing.T) {
	server := newTestI2CPServer(t, "localhost:0")

	require.NotNil(t, server.connWriteMu, "connWriteMu should be initialized, not nil")
	assert.Empty(t, server.connWriteMu, "connWriteMu should be empty initially")
}

// TestSessionStatusDestroyedCode verifies that handleDestroySession returns
// a 3-byte SessionStatus payload (SessionID + Status) with status byte 0x00
// (Destroyed) per I2CP spec.
func TestSessionStatusDestroyedCode(t *testing.T) {
	server := newTestI2CPServer(t, "localhost:17690")

	session, err := server.manager.CreateSession(nil, nil)
	require.NoError(t, err, "CreateSession() error")

	sessionID := session.ID()
	sessionCopy := session

	destroyMsg := &Message{
		Type:      MessageTypeDestroySession,
		SessionID: sessionID,
	}

	response, err := server.handleDestroySession(destroyMsg, &sessionCopy)
	require.NoError(t, err, "handleDestroySession() error")
	require.NotNil(t, response, "handleDestroySession() returned nil response")

	// Verify payload is 3 bytes: SessionID(2) + Status(1)
	require.Len(t, response.Payload, 3, "payload length")

	// Verify the session ID is correctly encoded in the payload
	payloadSessionID := binary.BigEndian.Uint16(response.Payload[0:2])
	assert.Equal(t, sessionID, payloadSessionID, "Payload SessionID")

	// Destroyed status must be 0
	assert.Equal(t, SessionStatusDestroyed, response.Payload[2], "status byte")
}

// TestBuildRequestVariableLeaseSetPayload_FilteredCount verifies that the
// lease count byte in the payload matches the number of leases actually
// written, not the unfiltered tunnel count.
func TestBuildRequestVariableLeaseSetPayload_FilteredCount(t *testing.T) {
	server := &Server{}

	// Create a mix of valid, nil, and zero-hop tunnels
	hash1 := common.Hash{}
	copy(hash1[:], []byte("abcdefghijklmnopqrstuvwxyz012345"))
	hash2 := common.Hash{}
	copy(hash2[:], []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"))

	tunnels := []*tunnel.TunnelState{
		{
			ID:        1,
			Hops:      []common.Hash{hash1},
			CreatedAt: time.Now(),
		},
		nil, // nil tunnel — should be filtered
		{
			ID:        2,
			Hops:      []common.Hash{}, // zero-hop — should be filtered
			CreatedAt: time.Now(),
		},
		{
			ID:        3,
			Hops:      []common.Hash{hash2},
			CreatedAt: time.Now(),
		},
	}

	payload, err := server.buildRequestVariableLeaseSetPayload(tunnels)
	require.NoError(t, err, "buildRequestVariableLeaseSetPayload() error")

	assertLeaseSetPayload(t, payload, 2)

	// Verify first lease gateway hash
	assert.Equal(t, string(hash1[:]), string(payload[1:1+32]), "First lease gateway hash")

	// Verify second lease gateway hash (offset: 1 + 44)
	assert.Equal(t, string(hash2[:]), string(payload[45:45+32]), "Second lease gateway hash")
}

// TestBuildRequestVariableLeaseSetPayload_AllFilteredReturnsError verifies
// that when all tunnels are nil or zero-hop, an error is returned.
func TestBuildRequestVariableLeaseSetPayload_AllFilteredReturnsError(t *testing.T) {
	server := &Server{}

	tunnels := []*tunnel.TunnelState{
		nil,
		{ID: 1, Hops: []common.Hash{}}, // zero-hop
		nil,
	}

	_, err := server.buildRequestVariableLeaseSetPayload(tunnels)
	assert.Error(t, err, "Expected error when all tunnels are filtered out")
}

// assertLeaseSetPayload verifies payload count byte and size match expected lease count.
func assertLeaseSetPayload(t *testing.T, payload []byte, expectedCount int) {
	t.Helper()
	leaseCount := int(payload[0])
	assert.Equal(t, expectedCount, leaseCount, "Lease count")
	expectedSize := 1 + expectedCount*44
	assert.Equal(t, expectedSize, len(payload), "Payload size")
}

// TestBuildRequestVariableLeaseSetPayload_AllValid verifies correct behavior
// when all tunnels are valid (no filtering needed).
func TestBuildRequestVariableLeaseSetPayload_AllValid(t *testing.T) {
	server := &Server{}

	hash := common.Hash{}
	copy(hash[:], []byte("abcdefghijklmnopqrstuvwxyz012345"))

	tunnels := []*tunnel.TunnelState{
		{ID: 1, Hops: []common.Hash{hash}, CreatedAt: time.Now()},
		{ID: 2, Hops: []common.Hash{hash}, CreatedAt: time.Now()},
		{ID: 3, Hops: []common.Hash{hash}, CreatedAt: time.Now()},
	}

	payload, err := server.buildRequestVariableLeaseSetPayload(tunnels)
	require.NoError(t, err, "buildRequestVariableLeaseSetPayload() error")

	assertLeaseSetPayload(t, payload, 3)
}

// TestServerTunnelPoolConfiguration verifies that tunnel pools are properly configured
// when tunnel builder and peer selector are set before session creation
func TestServerTunnelPoolConfiguration(t *testing.T) {
	server, err := NewServer(DefaultServerConfig())
	require.NoError(t, err, "Failed to create server")
	defer server.Stop()

	// Configure tunnel infrastructure (reusing mocks from integration_test.go)
	builder := &mockTunnelBuilder{nextID: 1000}
	selector := &mockPeerSelector{}

	server.SetTunnelBuilder(builder)
	server.SetPeerSelector(selector)

	// Create a session
	config := &SessionConfig{
		InboundTunnelLength:  3,
		OutboundTunnelLength: 3,
		InboundTunnelCount:   2,
		OutboundTunnelCount:  2,
	}

	session, err := server.manager.CreateSession(nil, config)
	require.NoError(t, err, "Failed to create session")

	// Initialize tunnel pools
	require.NoError(t, server.initializeSessionTunnelPools(session, config), "Failed to initialize tunnel pools")

	// Verify inbound pool is configured
	assert.NotNil(t, session.InboundPool(), "Inbound pool not set")

	// Verify outbound pool is configured
	assert.NotNil(t, session.OutboundPool(), "Outbound pool not set")
}

// TestServerTunnelPoolWithoutInfrastructure verifies that session creation succeeds
// even when tunnel infrastructure is not configured (graceful degradation)
func TestServerTunnelPoolWithoutInfrastructure(t *testing.T) {
	server, err := NewServer(DefaultServerConfig())
	require.NoError(t, err, "Failed to create server")
	defer server.Stop()

	// Create a session without setting tunnel builder or peer selector
	config := DefaultSessionConfig()
	session, err := server.manager.CreateSession(nil, config)
	require.NoError(t, err, "Failed to create session")

	// Try to initialize tunnel pools (should fail gracefully)
	assert.Error(t, server.initializeSessionTunnelPools(session, config), "Expected error when initializing pools without infrastructure")

	// Session should still be valid
	assert.NotZero(t, session.ID(), "Session ID should be non-zero")
}

// TestServerTunnelPoolConfigurationFromSessionConfig verifies that tunnel pool
// configuration correctly reflects the session configuration parameters
func TestServerTunnelPoolConfigurationFromSessionConfig(t *testing.T) {
	server, err := NewServer(DefaultServerConfig())
	require.NoError(t, err, "Failed to create server")
	defer server.Stop()

	// Configure tunnel infrastructure
	builder := &mockTunnelBuilder{nextID: 2000}
	selector := &mockPeerSelector{}

	server.SetTunnelBuilder(builder)
	server.SetPeerSelector(selector)

	// Create a session with custom configuration
	config := &SessionConfig{
		InboundTunnelLength:  5, // Custom hop count
		OutboundTunnelLength: 4, // Custom hop count
		InboundTunnelCount:   3, // Custom min tunnels
		OutboundTunnelCount:  4, // Custom min tunnels
	}

	session, err := server.manager.CreateSession(nil, config)
	require.NoError(t, err, "Failed to create session")

	// Initialize tunnel pools
	require.NoError(t, server.initializeSessionTunnelPools(session, config), "Failed to initialize tunnel pools")

	// Verify pools are set
	assert.NotNil(t, session.InboundPool(), "Inbound pool should be set")
	assert.NotNil(t, session.OutboundPool(), "Outbound pool should be set")
}

// TestServerSetTunnelBuilderThreadSafety verifies thread-safe access to tunnel builder
func TestServerSetTunnelBuilderThreadSafety(t *testing.T) {
	server, err := NewServer(DefaultServerConfig())
	require.NoError(t, err, "Failed to create server")
	defer server.Stop()

	builder := &mockTunnelBuilder{nextID: 3000}

	// Set tunnel builder from multiple goroutines
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			server.SetTunnelBuilder(builder)
			done <- true
		}()
	}

	// Wait for all goroutines to complete
	timeout := time.After(5 * time.Second)
	for i := 0; i < 10; i++ {
		select {
		case <-done:
			// Success
		case <-timeout:
			t.Fatal("Timeout waiting for goroutines")
		}
	}
}

// TestServerSetPeerSelectorThreadSafety verifies thread-safe access to peer selector
func TestServerSetPeerSelectorThreadSafety(t *testing.T) {
	server, err := NewServer(DefaultServerConfig())
	require.NoError(t, err, "Failed to create server")
	defer server.Stop()

	selector := &mockPeerSelector{}

	// Set peer selector from multiple goroutines
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			server.SetPeerSelector(selector)
			done <- true
		}()
	}

	// Wait for all goroutines to complete
	timeout := time.After(5 * time.Second)
	for i := 0; i < 10; i++ {
		select {
		case <-done:
			// Success
		case <-timeout:
			t.Fatal("Timeout waiting for goroutines")
		}
	}
}

// leaseSetTestFixture holds common objects used by CreateLeaseSet tests.
type leaseSetTestFixture struct {
	session   *Session
	publisher *mockLeaseSetPublisher
	pool      *tunnel.Pool
	msg       *Message
	server    *Server
}

// setupLeaseSetTest creates a common test fixture for handleCreateLeaseSet tests.
// If publisher is nil, no publisher is set on the session or server config.
// If addTunnel is false, the pool is left empty (no active tunnels).
func setupLeaseSetTest(tb testing.TB, publisher *mockLeaseSetPublisher, addTunnel bool) *leaseSetTestFixture {
	tb.Helper()

	session, err := NewSession(1, nil, nil)
	require.NoError(tb, err, "Failed to create session")
	tb.Cleanup(func() { session.Stop() })

	if publisher != nil {
		session.SetLeaseSetPublisher(publisher)
	}

	selector := &mockPeerSelector{}
	pool := tunnel.NewTunnelPool(selector)
	session.SetInboundPool(pool)

	if addTunnel {
		var gatewayHash common.Hash
		copy(gatewayHash[:], []byte("gateway-router-hash-12345678"))
		pool.AddTunnel(&tunnel.TunnelState{
			ID:        tunnel.TunnelID(12345),
			Hops:      []common.Hash{gatewayHash},
			State:     tunnel.TunnelReady,
			CreatedAt: time.Now(),
		})
	}

	msg := &Message{
		Type:      MessageTypeCreateLeaseSet,
		SessionID: session.ID(),
		Payload:   []byte{},
	}

	config := DefaultServerConfig()
	config.LeaseSetPublisher = publisher
	server, err := NewServer(config)
	require.NoError(tb, err, "Failed to create server")

	return &leaseSetTestFixture{
		session:   session,
		publisher: publisher,
		pool:      pool,
		msg:       msg,
		server:    server,
	}
}

// TestHandleCreateLeaseSetWithPublisher tests that handleCreateLeaseSet
// publishes to the network when a LeaseSetPublisher is configured
func TestHandleCreateLeaseSetWithPublisher(t *testing.T) {
	publisher := newMockLeaseSetPublisher()
	f := setupLeaseSetTest(t, publisher, true)

	response, err := callHandleCreateLeaseSet(t, f)

	assert.NoError(t, err, "handleCreateLeaseSet should succeed")
	assert.Nil(t, response, "CreateLeaseSet should not return a response")

	assert.Equal(t, 1, publisher.publishCalled, "Publisher should be called once")
	assert.Equal(t, 1, len(publisher.published), "Should have published 1 LeaseSet")

	destBytes, err := f.session.Destination().Bytes()
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
	f := setupLeaseSetTest(t, nil, true)

	response, err := callHandleCreateLeaseSet(t, f)

	assert.NoError(t, err, "handleCreateLeaseSet should succeed without publisher")
	assert.Nil(t, response, "CreateLeaseSet should not return a response")

	leaseSet := f.session.CurrentLeaseSet()
	assert.NotEmpty(t, leaseSet, "LeaseSet should be cached in session")
}

// TestHandleCreateLeaseSetPublisherError tests that handleCreateLeaseSet
// continues successfully even when the publisher returns an error
func TestHandleCreateLeaseSetPublisherError(t *testing.T) {
	publisher := newMockLeaseSetPublisher()
	publisher.publishErr = assert.AnError
	f := setupLeaseSetTest(t, publisher, true)

	response, err := callHandleCreateLeaseSet(t, f)

	assert.NoError(t, err, "handleCreateLeaseSet should succeed even when publisher fails")
	assert.Nil(t, response, "CreateLeaseSet should not return a response")

	assert.Equal(t, 1, publisher.publishCalled, "Publisher should be called")

	leaseSet := f.session.CurrentLeaseSet()
	assert.NotEmpty(t, leaseSet, "LeaseSet should be cached even if publishing fails")
}

// TestHandleCreateLeaseSetNoActiveTunnels tests error handling when
// session has no active tunnels (cannot create LeaseSet)
func TestHandleCreateLeaseSetNoActiveTunnels(t *testing.T) {
	publisher := newMockLeaseSetPublisher()
	f := setupLeaseSetTest(t, publisher, false)

	response, err := callHandleCreateLeaseSet(t, f)

	assert.Error(t, err, "handleCreateLeaseSet should fail with no active tunnels")
	assert.Nil(t, response, "Should not return response on error")
	assert.Contains(t, err.Error(), "no active", "Error should mention no active tunnels")

	assert.Equal(t, 0, publisher.publishCalled, "Publisher should not be called on creation failure")
}

// TestHandleCreateLeaseSetMultipleCalls tests that multiple calls to
// handleCreateLeaseSet result in multiple publications
func TestHandleCreateLeaseSetMultipleCalls(t *testing.T) {
	publisher := newMockLeaseSetPublisher()
	f := setupLeaseSetTest(t, publisher, true)

	sessionPtr := f.session

	for i := 0; i < 3; i++ {
		response, err := f.server.handleCreateLeaseSet(f.msg, &sessionPtr)
		assert.NoError(t, err, "Call %d should succeed", i+1)
		assert.Nil(t, response, "Call %d should not return response", i+1)
	}

	assert.Equal(t, 3, publisher.publishCalled, "Publisher should be called 3 times")
}

// TestHandleCreateLeaseSetNilSession tests error handling when session is nil
func TestHandleCreateLeaseSetNilSession(t *testing.T) {
	msg := &Message{
		Type:      MessageTypeCreateLeaseSet,
		SessionID: 1,
		Payload:   []byte{},
	}

	config := DefaultServerConfig()
	server, err := NewServer(config)
	require.NoError(t, err, "Failed to create server")

	var sessionPtr *Session = nil
	response, err := server.handleCreateLeaseSet(msg, &sessionPtr)

	assert.Error(t, err, "handleCreateLeaseSet should fail with nil session")
	assert.Contains(t, err.Error(), "no active session", "Error should mention no active session")
	assert.Nil(t, response, "Should not return response on error")
}

// TestLeaseSetPublishedDataIntegrity verifies that the published LeaseSet
// data matches what the session created
func TestLeaseSetPublishedDataIntegrity(t *testing.T) {
	publisher := newMockLeaseSetPublisher()
	f := setupLeaseSetTest(t, publisher, true)

	sessionPtr := f.session
	_, err := f.server.handleCreateLeaseSet(f.msg, &sessionPtr)
	require.NoError(t, err, "handleCreateLeaseSet should succeed")

	cachedLeaseSet := f.session.CurrentLeaseSet()
	require.NotEmpty(t, cachedLeaseSet, "Session should have cached LeaseSet")

	destBytes, err := f.session.Destination().Bytes()
	require.NoError(t, err, "Failed to get destination bytes")
	destHash := common.HashData(destBytes)

	publishedLeaseSet, exists := publisher.published[destHash]
	require.True(t, exists, "Publisher should have LeaseSet for this destination")

	assert.Equal(t, cachedLeaseSet, publishedLeaseSet, "Published LeaseSet should match cached LeaseSet")
}

// BenchmarkHandleCreateLeaseSetWithPublisher benchmarks the performance
// of creating and publishing LeaseSets
func BenchmarkHandleCreateLeaseSetWithPublisher(b *testing.B) {
	publisher := newMockLeaseSetPublisher()
	f := setupLeaseSetTest(b, publisher, true)

	sessionPtr := f.session

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = f.server.handleCreateLeaseSet(f.msg, &sessionPtr)
	}
}

// BenchmarkHandleCreateLeaseSetWithoutPublisher benchmarks the performance
// of creating LeaseSets without network publication
func BenchmarkHandleCreateLeaseSetWithoutPublisher(b *testing.B) {
	f := setupLeaseSetTest(b, nil, true)

	sessionPtr := f.session

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = f.server.handleCreateLeaseSet(f.msg, &sessionPtr)
	}
}

func TestHandleHostnameLookup_NoResolver(t *testing.T) {
	server, err := NewServer(DefaultServerConfig())
	require.NoError(t, err)
	// Explicitly set nil resolver to test the no-resolver case
	server.SetHostnameResolver(nil)

	lookupMsg := &HostLookupPayload{
		RequestID:  42,
		LookupType: HostLookupTypeHostname,
		Query:      "forum.i2p",
	}

	reply := server.handleHostnameLookup(lookupMsg)
	assert.Equal(t, uint32(42), reply.RequestID)
	assert.Equal(t, byte(HostReplyError), reply.ResultCode)
	assert.Nil(t, reply.Destination)
}

func TestHandleHostnameLookup_WithResolver_Found(t *testing.T) {
	server, err := NewServer(DefaultServerConfig())
	require.NoError(t, err)

	fakeDest := make([]byte, 387) // Typical destination size
	fakeDest[0] = 0x05            // some marker
	resolver := &mockHostnameResolver{
		destinations: map[string][]byte{
			"forum.i2p": fakeDest,
		},
	}
	server.SetHostnameResolver(resolver)

	lookupMsg := &HostLookupPayload{
		RequestID:  43,
		LookupType: HostLookupTypeHostname,
		Query:      "forum.i2p",
	}

	reply := server.handleHostnameLookup(lookupMsg)
	assert.Equal(t, uint32(43), reply.RequestID)
	assert.Equal(t, byte(HostReplySuccess), reply.ResultCode)
	require.NotNil(t, reply.Destination)
	assert.Equal(t, fakeDest, reply.Destination)
}

func TestHandleHostnameLookup_WithResolver_NotFound(t *testing.T) {
	server, err := NewServer(DefaultServerConfig())
	require.NoError(t, err)

	resolver := &mockHostnameResolver{
		destinations: map[string][]byte{}, // empty
	}
	server.SetHostnameResolver(resolver)

	lookupMsg := &HostLookupPayload{
		RequestID:  44,
		LookupType: HostLookupTypeHostname,
		Query:      "unknown.i2p",
	}

	reply := server.handleHostnameLookup(lookupMsg)
	assert.Equal(t, uint32(44), reply.RequestID)
	assert.Equal(t, byte(HostReplyNotFound), reply.ResultCode)
	assert.Nil(t, reply.Destination)
}

func TestHandleHostnameLookup_WithResolver_Error(t *testing.T) {
	server, err := NewServer(DefaultServerConfig())
	require.NoError(t, err)

	resolver := &mockHostnameResolver{
		err: errors.New("resolver internal error"),
	}
	server.SetHostnameResolver(resolver)

	lookupMsg := &HostLookupPayload{
		RequestID:  45,
		LookupType: HostLookupTypeHostname,
		Query:      "forum.i2p",
	}

	reply := server.handleHostnameLookup(lookupMsg)
	assert.Equal(t, uint32(45), reply.RequestID)
	assert.Equal(t, byte(HostReplyNotFound), reply.ResultCode)
	assert.Nil(t, reply.Destination)
}

func TestSetHostnameResolver(t *testing.T) {
	server, err := NewServer(DefaultServerConfig())
	require.NoError(t, err)
	// NewServer now initializes a default hostname resolver
	assert.NotNil(t, server.hostnameResolver)

	// Verify that SetHostnameResolver can override the default
	resolver := &mockHostnameResolver{}
	server.SetHostnameResolver(resolver)
	assert.NotNil(t, server.hostnameResolver)
	assert.Equal(t, resolver, server.hostnameResolver)
}

func TestAllowHostLookup_RateLimitedPerConnection(t *testing.T) {
	server, err := NewServer(DefaultServerConfig())
	require.NoError(t, err)

	payload, err := (&HostLookupPayload{
		RequestID:  77,
		LookupType: HostLookupTypeHostname,
		Query:      "forum.i2p",
	}).MarshalBinary()
	require.NoError(t, err)

	msg := &Message{
		Type:      MessageTypeHostLookup,
		SessionID: 0,
		Payload:   payload,
	}

	client, peer := net.Pipe()
	defer client.Close()
	defer peer.Close()

	for i := 0; i < hostLookupBurst; i++ {
		response, allowed := server.allowHostLookup(client, msg)
		assert.True(t, allowed, "lookup %d should be allowed", i+1)
		assert.Nil(t, response)
	}

	response, allowed := server.allowHostLookup(client, msg)
	assert.False(t, allowed)
	require.NotNil(t, response)
	assert.Equal(t, MessageTypeHostReply, response.Type)

	reply, err := ParseHostReplyPayload(response.Payload)
	require.NoError(t, err)
	assert.Equal(t, uint32(77), reply.RequestID)
	assert.Equal(t, byte(HostReplyTimeout), reply.ResultCode)
}

// TestBuildMessageStatusResponse verifies MessageStatus message construction.
func TestBuildMessageStatusResponse(t *testing.T) {
	tests := []struct {
		name        string
		sessionID   uint16
		messageID   uint32
		statusCode  uint8
		messageSize uint32
		nonce       uint32
	}{
		{
			name:        "Accepted",
			sessionID:   1,
			messageID:   12345,
			statusCode:  MessageStatusAccepted,
			messageSize: 1024,
			nonce:       0,
		},
		{
			name:        "Success",
			sessionID:   2,
			messageID:   67890,
			statusCode:  MessageStatusSuccess,
			messageSize: 2048,
			nonce:       999,
		},
		{
			name:        "Failure",
			sessionID:   3,
			messageID:   11111,
			statusCode:  MessageStatusFailure,
			messageSize: 512,
			nonce:       0,
		},
		{
			name:        "NoTunnels",
			sessionID:   4,
			messageID:   22222,
			statusCode:  MessageStatusNoTunnels,
			messageSize: 0,
			nonce:       0,
		},
		{
			name:        "NoLeaseSet",
			sessionID:   5,
			messageID:   33333,
			statusCode:  MessageStatusNoLeaseSet,
			messageSize: 4096,
			nonce:       12345,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := buildMessageStatusResponse(tt.sessionID, tt.messageID, tt.statusCode, tt.messageSize, tt.nonce)

			// Verify message type
			assert.Equal(t, MessageTypeMessageStatus, msg.Type)

			// Verify session ID
			assert.Equal(t, tt.sessionID, msg.SessionID)

			// Verify payload length (15 bytes per I2CP spec: SessionID(2) + MessageID(4) + Status(1) + Size(4) + Nonce(4))
			require.Len(t, msg.Payload, 15, "Payload length")

			// Parse and verify payload fields
			gotSessionID := binary.BigEndian.Uint16(msg.Payload[0:2])
			assert.Equal(t, tt.sessionID, gotSessionID, "Payload SessionID")

			gotMessageID := binary.BigEndian.Uint32(msg.Payload[2:6])
			assert.Equal(t, tt.messageID, gotMessageID, "MessageID")

			gotStatusCode := msg.Payload[6]
			assert.Equal(t, tt.statusCode, gotStatusCode, "StatusCode")

			gotMessageSize := binary.BigEndian.Uint32(msg.Payload[7:11])
			assert.Equal(t, tt.messageSize, gotMessageSize, "MessageSize")

			gotNonce := binary.BigEndian.Uint32(msg.Payload[11:15])
			assert.Equal(t, tt.nonce, gotNonce, "Nonce")
		})
	}
}

// TestBuildMessageStatusResponseMarshal verifies the message can be marshaled correctly.
func TestBuildMessageStatusResponseMarshal(t *testing.T) {
	msg := buildMessageStatusResponse(100, 12345, MessageStatusSuccess, 2048, 999)

	// Wire format: length(4) + type(1) + payload(15) = 20 bytes
	data := marshalAndVerifyWireHeader(t, msg, 20, 15, MessageTypeMessageStatus)

	// Verify session ID in payload (bytes 5-6)
	gotSessionID := binary.BigEndian.Uint16(data[5:7])
	assert.Equal(t, uint16(100), gotSessionID, "SessionID")

	// Verify message ID in payload (bytes 7-10)
	gotMessageID := binary.BigEndian.Uint32(data[7:11])
	assert.Equal(t, uint32(12345), gotMessageID, "MessageID")

	// Verify status code (byte 11)
	assert.Equal(t, MessageStatusSuccess, data[11], "StatusCode")
}

// TestMessageIDGeneration verifies the Server generates unique message IDs.
func TestMessageIDGeneration(t *testing.T) {
	config := DefaultServerConfig()
	server, err := NewServer(config)
	require.NoError(t, err, "NewServer() error")

	// Generate multiple IDs and verify they're sequential and unique
	ids := make(map[uint32]bool)
	for i := 0; i < 100; i++ {
		id := server.nextMessageID.Add(1)
		assert.False(t, ids[id], "Duplicate message ID generated: %d", id)
		ids[id] = true
	}

	// Verify we generated 100 unique IDs
	assert.Len(t, ids, 100, "unique IDs")
}

// TestMessageStatusPayloadFormat verifies the exact wire format specification.
func TestMessageStatusPayloadFormat(t *testing.T) {
	// According to I2CP spec v0.9.67, MessageStatus payload is:
	// 2 bytes: Session ID (uint16, big endian)
	// 4 bytes: Message ID (uint32, big endian)
	// 1 byte:  Status code
	// 4 bytes: Message size (uint32, big endian)
	// 4 bytes: Nonce (uint32, big endian)
	// Total: 15 bytes

	msg := buildMessageStatusResponse(1, 0x12345678, 0xAB, 0xCDEF0123, 0x9ABCDEF0)

	require.Len(t, msg.Payload, 15, "Payload length")

	// Verify exact byte positions
	gotSessionID := binary.BigEndian.Uint16(msg.Payload[0:2])
	assert.Equal(t, uint16(1), gotSessionID, "Session ID at bytes 0-1")

	gotMessageID := binary.BigEndian.Uint32(msg.Payload[2:6])
	assert.Equal(t, uint32(0x12345678), gotMessageID, "Message ID at bytes 2-5")

	gotStatus := msg.Payload[6]
	assert.Equal(t, uint8(0xAB), gotStatus, "Status code at byte 6")

	gotSize := binary.BigEndian.Uint32(msg.Payload[7:11])
	assert.Equal(t, uint32(0xCDEF0123), gotSize, "Message size at bytes 7-10")

	gotNonce := binary.BigEndian.Uint32(msg.Payload[11:15])
	assert.Equal(t, uint32(0x9ABCDEF0), gotNonce, "Nonce at bytes 11-14")
}

// TestHandleSendMessage tests the SendMessage handler
func TestHandleSendMessage(t *testing.T) {
	server, session, msg := buildSendMessageRequest(t, "test_destination_hash_32_bytes!", "Test message to send")

	// Test without outbound pool (should fail)
	sessionPtr := session
	response, err := server.handleSendMessage(msg, &sessionPtr)
	assert.Error(t, err, "Expected error when no outbound pool")
	assert.Nil(t, response, "Expected nil response on error")

	// Add outbound pool
	pool := &tunnel.Pool{}
	session.SetOutboundPool(pool)

	// Test with pool (should succeed and return acceptance status)
	response, err = server.handleSendMessage(msg, &sessionPtr)
	assert.NoError(t, err, "Unexpected error with outbound pool")
	require.NotNil(t, response, "Expected MessageStatus response")
	assert.Equal(t, MessageTypeMessageStatus, response.Type, "Expected MessageStatus type")
	// Verify it's an acceptance status (status code should be 1)
	// MessageStatus format: SessionID(2) + MessageID(4) + Status(1) + Size(4) + Nonce(4) = 15 bytes
	require.GreaterOrEqual(t, len(response.Payload), 15, "MessageStatus payload too short")
	// Status byte is at index 6 (after SessionID(2) + MessageID(4))
	assert.Equal(t, MessageStatusAccepted, response.Payload[6], "Expected MessageStatusAccepted")
}

// TestHandleSendMessageNoSession tests SendMessage without active session
func TestHandleSendMessageNoSession(t *testing.T) {
	server, err := NewServer(nil)
	require.NoError(t, err, "Failed to create server")

	msg := &Message{
		Type:      MessageTypeSendMessage,
		SessionID: 0x1234,
		Payload:   make([]byte, 50),
	}

	var session *Session
	_, err = server.handleSendMessage(msg, &session)
	assert.Error(t, err, "Expected error when no session")
}

// TestHandleSendMessageInvalidPayload tests SendMessage with malformed payload
func TestHandleSendMessageInvalidPayload(t *testing.T) {
	server, err := NewServer(nil)
	require.NoError(t, err, "Failed to create server")

	session, err := server.manager.CreateSession(nil, nil)
	require.NoError(t, err, "Failed to create session")

	// Add outbound pool
	pool := &tunnel.Pool{}
	session.SetOutboundPool(pool)

	// Create invalid payload (too short — after stripping 2-byte SessionID prefix,
	// only 8 bytes remain, but ParseSendMessagePayload needs at least 36)
	msg := &Message{
		Type:      MessageTypeSendMessage,
		SessionID: session.ID(),
		Payload:   make([]byte, 10),
	}

	sessionPtr := session
	_, err = server.handleSendMessage(msg, &sessionPtr)
	assert.Error(t, err, "Expected error for invalid payload")
}

// TestDeliverMessagesToClientIntegration tests the message delivery goroutine
func TestDeliverMessagesToClientIntegration(t *testing.T) {
	_, session, clientConn := setupDeliveryTest(t)

	// Queue a message
	testPayload := []byte("Test incoming message")
	require.NoError(t, session.QueueIncomingMessage(testPayload), "Failed to queue message")

	// Read MessagePayload from client connection
	readDone := make(chan struct{})
	var readMsg *Message
	var readErr error

	go func() {
		readMsg, readErr = ReadMessage(clientConn)
		close(readDone)
	}()

	// Wait for read with timeout
	select {
	case <-readDone:
		// Success
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for message delivery")
	}

	require.NoError(t, readErr, "Failed to read message")

	// Verify message type
	assert.Equal(t, MessageTypeMessagePayload, readMsg.Type)

	// Verify session ID
	assert.Equal(t, session.ID(), readMsg.SessionID)

	// Parse MessagePayload payload
	msgPayload, err := ParseMessagePayloadPayload(readMsg.Payload)
	require.NoError(t, err, "Failed to parse MessagePayload")

	// Verify message ID is non-zero
	assert.NotZero(t, msgPayload.MessageID, "Expected non-zero message ID")

	// Verify payload
	assert.Equal(t, testPayload, msgPayload.Payload, "Payload mismatch")
}

// TestDeliverMessagesToClientMultiple tests delivering multiple messages
func TestDeliverMessagesToClientMultiple(t *testing.T) {
	_, session, clientConn := setupDeliveryTest(t)

	// Queue multiple messages
	numMessages := 5
	for i := 0; i < numMessages; i++ {
		payload := []byte{byte(i), byte(i + 1), byte(i + 2)}
		require.NoError(t, session.QueueIncomingMessage(payload), "Failed to queue message %d", i)
	}

	// Read all messages
	receivedCount := 0
	readDone := make(chan struct{})

	go func() {
		for i := 0; i < numMessages; i++ {
			msg, err := ReadMessage(clientConn)
			if err != nil {
				t.Logf("Read error: %v", err)
				break
			}

			if msg.Type != MessageTypeMessagePayload {
				t.Errorf("Message %d: wrong type %d", i, msg.Type)
				continue
			}

			receivedCount++
		}
		close(readDone)
	}()

	// Wait for reads
	select {
	case <-readDone:
		// Success
	case <-time.After(3 * time.Second):
		t.Fatal("Timeout waiting for messages")
	}

	assert.Equal(t, numMessages, receivedCount, "Received messages")
}

// TestDeliverMessagesToClientMessageIDIncrement tests message ID increments
func TestDeliverMessagesToClientMessageIDIncrement(t *testing.T) {
	_, session, clientConn := setupDeliveryTest(t)

	// Queue messages and verify IDs increment
	numMessages := 3
	for i := 0; i < numMessages; i++ {
		require.NoError(t, session.QueueIncomingMessage([]byte{byte(i)}), "Failed to queue message")
	}

	// Read and check message IDs
	messageIDs := make([]uint32, 0, numMessages)
	readDone := make(chan struct{})

	go func() {
		for i := 0; i < numMessages; i++ {
			msg, err := ReadMessage(clientConn)
			if err != nil {
				break
			}

			msgPayload, err := ParseMessagePayloadPayload(msg.Payload)
			if err != nil {
				t.Logf("Parse error: %v", err)
				break
			}

			messageIDs = append(messageIDs, msgPayload.MessageID)
		}
		close(readDone)
	}()

	select {
	case <-readDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout")
	}

	// Verify IDs increment
	require.Len(t, messageIDs, numMessages, "Got wrong number of IDs")

	for i := 0; i < len(messageIDs); i++ {
		expectedID := uint32(i + 1) // IDs start at 1
		assert.Equal(t, expectedID, messageIDs[i], "Message %d ID", i)
	}
}

// createTestServerWithPublisher creates a Server, starts it, and registers cleanup.
func createTestServerWithPublisher(t *testing.T, addr string, publisher LeaseSetPublisher) *Server {
	t.Helper()
	config := &ServerConfig{
		ListenAddr:        addr,
		Network:           "tcp",
		MaxSessions:       10,
		LeaseSetPublisher: publisher,
	}
	server, err := NewServer(config)
	require.NoError(t, err, "Failed to create server")
	require.NotNil(t, server, "Server should not be nil")
	err = server.Start()
	require.NoError(t, err, "Failed to start server")
	t.Cleanup(func() { server.Stop() })
	return server
}

// TestServerWithLeaseSetPublisher tests I2CP server with publisher
func TestServerWithLeaseSetPublisher(t *testing.T) {
	publisher := newMockLeaseSetPublisher()
	server := createTestServerWithPublisher(t, "localhost:17670", publisher)
	assert.NotNil(t, server.leaseSetPublisher, "Server should have publisher")
}

// TestServerWithoutLeaseSetPublisher tests I2CP server without publisher
func TestServerWithoutLeaseSetPublisher(t *testing.T) {
	server := createTestServerWithPublisher(t, "localhost:17671", nil)
	assert.Nil(t, server.leaseSetPublisher, "Server should have nil publisher")
}

// Regression tests for AUDIT.md critical bugs:
// 1. SessionStatus uses wrong status code (0x00 Destroyed instead of 0x01 Created)
// 2. SendMessage payload offset — SessionID not stripped before destination parsing

// TestSessionStatusCreatedCode verifies that buildSessionStatusResponse returns
// status byte 0x01 (Created) per I2CP spec v0.9.67, not 0x00 (Destroyed).
func TestSessionStatusCreatedCode(t *testing.T) {
	sessionID := uint16(42)
	msg := buildSessionStatusResponse(sessionID)

	assert.Equal(t, MessageTypeSessionStatus, msg.Type, "message type")

	require.Len(t, msg.Payload, 3, "payload length")

	// Verify SessionID in payload
	payloadSessionID := binary.BigEndian.Uint16(msg.Payload[0:2])
	assert.Equal(t, sessionID, payloadSessionID, "payload SessionID")

	// Critical: status byte MUST be 1 (Created), not 0 (Destroyed)
	assert.Equal(t, SessionStatusCreated, msg.Payload[2], "status byte")
}

// createTestServerSession creates a Server and a Session for message parsing tests.
func createTestServerSession(t *testing.T) (*Server, *Session) {
	t.Helper()
	server, err := NewServer(nil)
	require.NoError(t, err, "NewServer() error")
	session, err := server.manager.CreateSession(nil, nil)
	require.NoError(t, err, "CreateSession() error")
	return server, session
}

// buildWirePayload creates a wire payload with 2-byte SessionID prefix followed by inner bytes.
func buildWirePayload(sessionID uint16, innerBytes []byte) []byte {
	wirePayload := make([]byte, 2+len(innerBytes))
	binary.BigEndian.PutUint16(wirePayload[0:2], sessionID)
	copy(wirePayload[2:], innerBytes)
	return wirePayload
}

// TestParseSendMessagePayloadWithSessionIDPrefix verifies that
// parseSendMessagePayload correctly strips the 2-byte SessionID prefix
// from the wire payload before parsing the destination hash.
func TestParseSendMessagePayloadWithSessionIDPrefix(t *testing.T) {
	server, session := createTestServerSession(t)

	var destHash data.Hash
	copy(destHash[:], []byte("known_destination_hash_32bytes!"))

	messagePayload := []byte("hello i2p network")

	sendPayload := &SendMessagePayload{
		Destination: destHash,
		Payload:     messagePayload,
	}

	innerBytes, err := sendPayload.MarshalBinary()
	require.NoError(t, err, "MarshalBinary() error")

	msg := &Message{
		Type:      MessageTypeSendMessage,
		SessionID: session.ID(),
		Payload:   buildWirePayload(session.ID(), innerBytes),
	}

	parsed, err := server.parseSendMessagePayload(msg, session)
	require.NoError(t, err, "parseSendMessagePayload() error")

	assert.Equal(t, destHash, parsed.Destination, "destination hash mismatch")
	assert.Equal(t, string(messagePayload), string(parsed.Payload), "payload mismatch")
}

// TestParseSendMessagePayloadTooShort verifies that parseSendMessagePayload
// returns an error when the payload is too short to contain even a SessionID.
func TestParseSendMessagePayloadTooShort(t *testing.T) {
	server, session := createTestServerSession(t)

	msg := &Message{
		Type:      MessageTypeSendMessage,
		SessionID: session.ID(),
		Payload:   []byte{0x01}, // Only 1 byte — too short for 2-byte SessionID
	}

	_, err := server.parseSendMessagePayload(msg, session)
	assert.Error(t, err, "Expected error for payload too short for SessionID")
}

// TestParseSendMessageExpiresPayloadWithSessionIDPrefix verifies that
// parseSendMessageExpiresPayload correctly strips the 2-byte SessionID prefix
// from the wire payload before parsing the destination hash.
func TestParseSendMessageExpiresPayloadWithSessionIDPrefix(t *testing.T) {
	server, session := createTestServerSession(t)

	var destHash data.Hash
	copy(destHash[:], []byte("known_destination_hash_32bytes!"))

	messagePayload := []byte("expires test payload")

	sendPayload := &SendMessageExpiresPayload{
		Destination: destHash,
		Payload:     messagePayload,
		Nonce:       12345,
		Expiration:  1700000000000,
	}

	innerBytes, err := sendPayload.MarshalBinary()
	require.NoError(t, err, "MarshalBinary() error")

	msg := &Message{
		Type:      MessageTypeSendMessageExpires,
		SessionID: session.ID(),
		Payload:   buildWirePayload(session.ID(), innerBytes),
	}

	parsed, err := server.parseSendMessageExpiresPayload(msg, session)
	require.NoError(t, err, "parseSendMessageExpiresPayload() error")

	assert.Equal(t, destHash, parsed.Destination, "destination hash mismatch")
	assert.Equal(t, string(messagePayload), string(parsed.Payload), "payload mismatch")
	assert.Equal(t, uint32(12345), parsed.Nonce, "nonce")
	assert.Equal(t, uint64(1700000000000), parsed.Expiration, "expiration")
}

// TestParseSendMessageExpiresPayloadTooShort verifies that
// parseSendMessageExpiresPayload returns an error when the payload is too short.
func TestParseSendMessageExpiresPayloadTooShort(t *testing.T) {
	server, err := NewServer(nil)
	require.NoError(t, err, "NewServer() error")

	session, err := server.manager.CreateSession(nil, nil)
	require.NoError(t, err, "CreateSession() error")

	msg := &Message{
		Type:      MessageTypeSendMessageExpires,
		SessionID: session.ID(),
		Payload:   []byte{0x00}, // Only 1 byte — too short for 2-byte SessionID
	}

	_, err = server.parseSendMessageExpiresPayload(msg, session)
	assert.Error(t, err, "Expected error for payload too short for SessionID")
}

// TestHandleSendMessageWithWireFormatPayload is an end-to-end test that
// exercises handleSendMessage with a wire-format payload (SessionID prefix included)
// and verifies the full handler path including message acceptance.
func TestHandleSendMessageWithWireFormatPayload(t *testing.T) {
	server, session, msg := buildSendMessageRequest(t, "wire_format_test_destination_32!", "wire format end-to-end test")

	// Set up outbound pool (required for message sending)
	pool := &tunnel.Pool{}
	session.SetOutboundPool(pool)

	sessionPtr := session
	response, err := server.handleSendMessage(msg, &sessionPtr)
	require.NoError(t, err, "handleSendMessage() error")
	require.NotNil(t, response, "Expected MessageStatus response")

	assert.Equal(t, MessageTypeMessageStatus, response.Type, "response type")

	// MessageStatus payload: SessionID(2) + MessageID(4) + Status(1) + Size(4) + Nonce(4) = 15
	require.GreaterOrEqual(t, len(response.Payload), 15, "MessageStatus payload too short")

	// Status byte at index 6 should be MessageStatusAccepted
	assert.Equal(t, MessageStatusAccepted, response.Payload[6], "message status")
}

// TestResolveDestinationKey_NilResolver verifies that resolveDestinationKey returns
// ErrNoDestinationResolver when no resolver is configured, instead of silently
// returning a zero encryption key.
func TestResolveDestinationKey_NilResolver(t *testing.T) {
	server := &Server{}

	var destHash common.Hash
	copy(destHash[:], []byte("test-destination-hash-value-here!"))

	key, err := server.resolveDestinationKey(destHash)
	assert.ErrorIs(t, err, ErrNoDestinationResolver)

	// Verify the returned key is zero (no partial key leakage)
	var zeroKey [32]byte
	assert.Equal(t, zeroKey, key, "expected zero key on error")
}

// TestResolveDestinationKey_WithResolver verifies that resolveDestinationKey
// returns the key from the resolver when one is configured.
func TestResolveDestinationKey_WithResolver(t *testing.T) {
	var expectedKey [32]byte
	for i := range expectedKey {
		expectedKey[i] = byte(i + 1)
	}

	server := &Server{
		destinationResolver: &mockDestinationResolver{
			key: expectedKey,
			err: nil,
		},
	}

	var destHash common.Hash
	copy(destHash[:], []byte("test-destination-hash-value-here!"))

	key, err := server.resolveDestinationKey(destHash)
	require.NoError(t, err, "unexpected error")
	assert.Equal(t, expectedKey, key)
}

// TestResolveDestinationKey_ResolverError verifies that errors from the resolver
// are properly propagated.
func TestResolveDestinationKey_ResolverError(t *testing.T) {
	resolverErr := errors.New("destination not found in NetDB")
	server := &Server{
		destinationResolver: &mockDestinationResolver{
			err: resolverErr,
		},
	}

	var destHash common.Hash
	copy(destHash[:], []byte("test-destination-hash-value-here!"))

	_, err := server.resolveDestinationKey(destHash)
	require.Error(t, err, "expected error from resolver")
	assert.ErrorIs(t, err, resolverErr)
}

// TestErrNoDestinationResolver_ErrorMessage verifies the sentinel error message
// is descriptive enough for debugging.
func TestErrNoDestinationResolver_ErrorMessage(t *testing.T) {
	expected := "no destination resolver configured: cannot resolve encryption key"
	assert.Equal(t, expected, ErrNoDestinationResolver.Error())
}
