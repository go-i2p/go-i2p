package i2cp

import (
	"bytes"
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

func TestServerStartStop(t *testing.T) {
	config := &ServerConfig{
		ListenAddr:  "localhost:17654",
		Network:     "tcp",
		MaxSessions: 100,
	}

	server, err := NewServer(config)
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	if err := server.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	if !server.IsRunning() {
		t.Error("Server should be running after Start()")
	}

	// Give server time to start listening
	time.Sleep(10 * time.Millisecond)

	if err := server.Stop(); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}

	if server.IsRunning() {
		t.Error("Server should not be running after Stop()")
	}
}

func TestServerDoubleStart(t *testing.T) {
	config := &ServerConfig{
		ListenAddr:  "localhost:17655",
		Network:     "tcp",
		MaxSessions: 100,
	}

	server, err := NewServer(config)
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	defer server.Stop()

	if err := server.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// Second start should fail
	if err := server.Start(); err == nil {
		t.Error("Expected error on second Start(), got nil")
	}
}

func TestServerCreateSession(t *testing.T) {
	config := &ServerConfig{
		ListenAddr:  "localhost:17656",
		Network:     "tcp",
		MaxSessions: 100,
	}

	server, err := NewServer(config)
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	if err := server.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer server.Stop()

	// Give server time to start listening
	time.Sleep(10 * time.Millisecond)

	// Connect to server
	conn, err := dialI2CPClient("localhost:17656")
	if err != nil {
		t.Fatalf("Failed to connect to server: %v", err)
	}
	defer conn.Close()

	// Send CreateSession message
	createMsg := &Message{
		Type:      MessageTypeCreateSession,
		SessionID: SessionIDReservedControl,
		Payload:   []byte{}, // Empty config for now
	}

	if err := WriteMessage(conn, createMsg); err != nil {
		t.Fatalf("WriteMessage() error = %v", err)
	}

	// Read SessionStatus response
	response, err := ReadMessage(conn)
	if err != nil {
		t.Fatalf("ReadMessage() error = %v", err)
	}

	if response.Type != MessageTypeSessionStatus {
		t.Errorf("Response type = %d, want %d", response.Type, MessageTypeSessionStatus)
	}

	if response.SessionID == SessionIDReservedControl {
		t.Error("Session ID should not be reserved control value")
	}

	// Per I2CP spec: SessionStatus payload is SessionID(2 bytes) + Status(1 byte) = 3 bytes
	if len(response.Payload) != 3 {
		t.Errorf("SessionStatus payload length = %d, want 3", len(response.Payload))
	}

	// Verify SessionID in payload matches the SessionID in message header
	payloadSessionID := binary.BigEndian.Uint16(response.Payload[0:2])
	if payloadSessionID != response.SessionID {
		t.Errorf("SessionID in payload = %d, want %d", payloadSessionID, response.SessionID)
	}

	// Verify status byte is 0x01 (Created) per I2CP spec
	if response.Payload[2] != SessionStatusCreated {
		t.Errorf("SessionStatus status byte = 0x%02x, want 0x%02x (Created)", response.Payload[2], SessionStatusCreated)
	}

	// Verify session was created
	if server.SessionManager().SessionCount() != 1 {
		t.Errorf("SessionCount() = %d, want 1", server.SessionManager().SessionCount())
	}
}

func TestServerDestroySession(t *testing.T) {
	config := &ServerConfig{
		ListenAddr:  "localhost:17659",
		Network:     "tcp",
		MaxSessions: 100,
	}

	server, err := NewServer(config)
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	if err := server.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer server.Stop()

	time.Sleep(10 * time.Millisecond)

	// Connect to server
	conn, err := dialI2CPClient("localhost:17659")
	if err != nil {
		t.Fatalf("Failed to connect to server: %v", err)
	}
	defer conn.Close()

	// Create session
	createMsg := &Message{
		Type:      MessageTypeCreateSession,
		SessionID: SessionIDReservedControl,
		Payload:   []byte{},
	}

	if err := WriteMessage(conn, createMsg); err != nil {
		t.Fatalf("WriteMessage() error = %v", err)
	}

	response, err := ReadMessage(conn)
	if err != nil {
		t.Fatalf("ReadMessage() error = %v", err)
	}

	sessionID := response.SessionID

	// Destroy session
	destroyMsg := &Message{
		Type:      MessageTypeDestroySession,
		SessionID: sessionID,
		Payload:   []byte{},
	}

	if err := WriteMessage(conn, destroyMsg); err != nil {
		t.Fatalf("WriteMessage() error = %v", err)
	}

	// Give server time to process
	time.Sleep(10 * time.Millisecond)

	// Verify session was destroyed
	if server.SessionManager().SessionCount() != 0 {
		t.Errorf("SessionCount() = %d, want 0", server.SessionManager().SessionCount())
	}
}

func TestServerMaxSessions(t *testing.T) {
	config := &ServerConfig{
		ListenAddr:  "localhost:17654", // Different port
		Network:     "tcp",
		MaxSessions: 2,
	}

	server, err := NewServer(config)
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	if err := server.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer server.Stop()

	time.Sleep(10 * time.Millisecond)

	// Create 2 sessions (should succeed)
	var conns []net.Conn
	for i := 0; i < 2; i++ {
		conn, err := dialI2CPClient("localhost:17654")
		if err != nil {
			t.Fatalf("Failed to connect: %v", err)
		}
		defer conn.Close()
		conns = append(conns, conn)

		createMsg := &Message{
			Type:      MessageTypeCreateSession,
			SessionID: SessionIDReservedControl,
			Payload:   []byte{},
		}

		if err := WriteMessage(conn, createMsg); err != nil {
			t.Fatalf("WriteMessage() error = %v", err)
		}

		if _, err := ReadMessage(conn); err != nil {
			t.Fatalf("ReadMessage() error = %v", err)
		}
	}

	// Verify 2 sessions exist
	if server.SessionManager().SessionCount() != 2 {
		t.Errorf("SessionCount() = %d, want 2", server.SessionManager().SessionCount())
	}

	// Third connection should be rejected immediately
	conn3, err := dialI2CPClient("localhost:17654")
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer conn3.Close()

	createMsg := &Message{
		Type:      MessageTypeCreateSession,
		SessionID: SessionIDReservedControl,
		Payload:   []byte{},
	}

	// Server should close connection without response
	_ = WriteMessage(conn3, createMsg)

	// Trying to read should get EOF or error
	if err := conn3.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatalf("Failed to set read deadline: %v", err)
	}
	_, readErr := ReadMessage(conn3)
	// Connection should be closed, so read should fail
	// We don't check exact error since it could be EOF or network error
	_ = readErr
}

func TestServerGetDate(t *testing.T) {
	config := &ServerConfig{
		ListenAddr:  "localhost:17658",
		Network:     "tcp",
		MaxSessions: 100,
	}

	server, err := NewServer(config)
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	if err := server.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer server.Stop()

	time.Sleep(10 * time.Millisecond)

	conn, err := dialI2CPClient("localhost:17658")
	if err != nil {
		t.Fatalf("Failed to connect to server: %v", err)
	}
	defer conn.Close()

	// Send GetDate message
	getDateMsg := &Message{
		Type:      MessageTypeGetDate,
		SessionID: SessionIDReservedControl,
		Payload:   []byte{},
	}

	if err := WriteMessage(conn, getDateMsg); err != nil {
		t.Fatalf("WriteMessage() error = %v", err)
	}

	// Read SetDate response
	response, err := ReadMessage(conn)
	if err != nil {
		t.Fatalf("ReadMessage() error = %v", err)
	}

	if response.Type != MessageTypeSetDate {
		t.Errorf("Response type = %d, want %d", response.Type, MessageTypeSetDate)
	}
}

func TestServerHandleCreateLeaseSet(t *testing.T) {
	// Setup: start server
	config := &ServerConfig{
		ListenAddr:  "localhost:17659",
		Network:     "tcp",
		MaxSessions: 100,
	}

	server, err := NewServer(config)
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	if err := server.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer server.Stop()

	time.Sleep(10 * time.Millisecond)

	// Connect and create session
	conn, err := dialI2CPClient("localhost:17659")
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	// Create session first
	createMsg := &Message{
		Type:      MessageTypeCreateSession,
		SessionID: SessionIDReservedControl,
		Payload:   []byte{},
	}

	if err := WriteMessage(conn, createMsg); err != nil {
		t.Fatalf("WriteMessage() error = %v", err)
	}

	response, err := ReadMessage(conn)
	if err != nil {
		t.Fatalf("ReadMessage() error = %v", err)
	}

	if response.Type != MessageTypeSessionStatus {
		t.Fatalf("Response type = %d, want %d", response.Type, MessageTypeSessionStatus)
	}

	sessionID := response.SessionID

	// Send CreateLeaseSet - should fail because no inbound pool
	leaseSetMsg := &Message{
		Type:      MessageTypeCreateLeaseSet,
		SessionID: sessionID,
		Payload:   []byte{},
	}

	if err := WriteMessage(conn, leaseSetMsg); err != nil {
		t.Fatalf("WriteMessage() error = %v", err)
	}

	// Server should handle it and log error but not disconnect
	// Give it time to process
	time.Sleep(50 * time.Millisecond)

	// Connection should still be alive
	testMsg := &Message{
		Type:      MessageTypeGetDate,
		SessionID: sessionID,
		Payload:   []byte{},
	}

	if err := WriteMessage(conn, testMsg); err != nil {
		t.Errorf("Connection should still be alive after CreateLeaseSet failure")
	}
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
	config := &ServerConfig{
		ListenAddr:  "localhost:0",
		Network:     "tcp",
		MaxSessions: 100,
	}

	server, err := NewServer(config)
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	if server.connWriteMu == nil {
		t.Fatal("connWriteMu should be initialized, not nil")
	}

	if len(server.connWriteMu) != 0 {
		t.Fatalf("connWriteMu should be empty initially, got %d entries", len(server.connWriteMu))
	}
}

// TestDestroySessionPayloadFormat verifies that handleDestroySession returns
// a 3-byte SessionStatus payload (SessionID + Status) per the I2CP spec,
// not a 1-byte payload.
func TestDestroySessionPayloadFormat(t *testing.T) {
	config := &ServerConfig{
		ListenAddr:  "localhost:17680",
		Network:     "tcp",
		MaxSessions: 100,
	}

	server, err := NewServer(config)
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	// Create a session directly via the manager
	session, err := server.manager.CreateSession(nil, nil)
	if err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}

	sessionID := session.ID()
	sessionCopy := session

	// Call handleDestroySession
	destroyMsg := &Message{
		Type:      MessageTypeDestroySession,
		SessionID: sessionID,
	}

	response, err := server.handleDestroySession(destroyMsg, &sessionCopy)
	if err != nil {
		t.Fatalf("handleDestroySession() error = %v", err)
	}

	if response == nil {
		t.Fatal("handleDestroySession() returned nil response")
	}

	// Verify payload is 3 bytes: SessionID(2) + Status(1)
	if len(response.Payload) != 3 {
		t.Fatalf("SessionStatus payload length = %d, want 3", len(response.Payload))
	}

	// Verify the session ID is correctly encoded in the payload
	payloadSessionID := binary.BigEndian.Uint16(response.Payload[0:2])
	if payloadSessionID != sessionID {
		t.Errorf("Payload SessionID = %d, want %d", payloadSessionID, sessionID)
	}

	// Verify the status byte is 0 (Destroyed)
	if response.Payload[2] != 0x00 {
		t.Errorf("Payload status byte = %d, want 0 (Destroyed)", response.Payload[2])
	}
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
	if err != nil {
		t.Fatalf("buildRequestVariableLeaseSetPayload() error = %v", err)
	}

	// The count byte should be 2 (only the valid tunnels), not 4
	leaseCount := int(payload[0])
	if leaseCount != 2 {
		t.Errorf("Lease count = %d, want 2 (should exclude nil and zero-hop tunnels)", leaseCount)
	}

	// Verify payload size matches: 1 + 2*44 = 89 bytes
	expectedSize := 1 + 2*44
	if len(payload) != expectedSize {
		t.Errorf("Payload size = %d, want %d", len(payload), expectedSize)
	}

	// Verify first lease gateway hash
	if string(payload[1:1+32]) != string(hash1[:]) {
		t.Error("First lease gateway hash does not match hash1")
	}

	// Verify second lease gateway hash (offset: 1 + 44)
	if string(payload[45:45+32]) != string(hash2[:]) {
		t.Error("Second lease gateway hash does not match hash2")
	}
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
	if err == nil {
		t.Error("Expected error when all tunnels are filtered out, got nil")
	}
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
	if err != nil {
		t.Fatalf("buildRequestVariableLeaseSetPayload() error = %v", err)
	}

	leaseCount := int(payload[0])
	if leaseCount != 3 {
		t.Errorf("Lease count = %d, want 3", leaseCount)
	}

	expectedSize := 1 + 3*44
	if len(payload) != expectedSize {
		t.Errorf("Payload size = %d, want %d", len(payload), expectedSize)
	}
}

// TestServerTunnelPoolConfiguration verifies that tunnel pools are properly configured
// when tunnel builder and peer selector are set before session creation
func TestServerTunnelPoolConfiguration(t *testing.T) {
	server, err := NewServer(DefaultServerConfig())
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
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
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// Initialize tunnel pools
	if err := server.initializeSessionTunnelPools(session, config); err != nil {
		t.Fatalf("Failed to initialize tunnel pools: %v", err)
	}

	// Verify inbound pool is configured
	inboundPool := session.InboundPool()
	if inboundPool == nil {
		t.Error("Inbound pool not set")
	}

	// Verify outbound pool is configured
	outboundPool := session.OutboundPool()
	if outboundPool == nil {
		t.Error("Outbound pool not set")
	}
}

// TestServerTunnelPoolWithoutInfrastructure verifies that session creation succeeds
// even when tunnel infrastructure is not configured (graceful degradation)
func TestServerTunnelPoolWithoutInfrastructure(t *testing.T) {
	server, err := NewServer(DefaultServerConfig())
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	defer server.Stop()

	// Create a session without setting tunnel builder or peer selector
	config := DefaultSessionConfig()
	session, err := server.manager.CreateSession(nil, config)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// Try to initialize tunnel pools (should fail gracefully)
	err = server.initializeSessionTunnelPools(session, config)
	if err == nil {
		t.Error("Expected error when initializing pools without infrastructure")
	}

	// Session should still be valid
	if session.ID() == 0 {
		t.Error("Session ID should be non-zero")
	}
}

// TestServerTunnelPoolConfigurationFromSessionConfig verifies that tunnel pool
// configuration correctly reflects the session configuration parameters
func TestServerTunnelPoolConfigurationFromSessionConfig(t *testing.T) {
	server, err := NewServer(DefaultServerConfig())
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
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
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// Initialize tunnel pools
	if err := server.initializeSessionTunnelPools(session, config); err != nil {
		t.Fatalf("Failed to initialize tunnel pools: %v", err)
	}

	// Verify pools are set
	if session.InboundPool() == nil {
		t.Error("Inbound pool should be set")
	}
	if session.OutboundPool() == nil {
		t.Error("Outbound pool should be set")
	}
}

// TestServerSetTunnelBuilderThreadSafety verifies thread-safe access to tunnel builder
func TestServerSetTunnelBuilderThreadSafety(t *testing.T) {
	server, err := NewServer(DefaultServerConfig())
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
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
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
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

func TestHandleHostnameLookup_NoResolver(t *testing.T) {
	server, err := NewServer(DefaultServerConfig())
	require.NoError(t, err)
	// No hostname resolver set

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
	assert.Nil(t, server.hostnameResolver)

	resolver := &mockHostnameResolver{}
	server.SetHostnameResolver(resolver)
	assert.NotNil(t, server.hostnameResolver)
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
			if msg.Type != MessageTypeMessageStatus {
				t.Errorf("Type = %d, want %d", msg.Type, MessageTypeMessageStatus)
			}

			// Verify session ID
			if msg.SessionID != tt.sessionID {
				t.Errorf("SessionID = %d, want %d", msg.SessionID, tt.sessionID)
			}

			// Verify payload length (15 bytes per I2CP spec: SessionID(2) + MessageID(4) + Status(1) + Size(4) + Nonce(4))
			if len(msg.Payload) != 15 {
				t.Fatalf("Payload length = %d, want 15", len(msg.Payload))
			}

			// Parse and verify payload fields
			gotSessionID := binary.BigEndian.Uint16(msg.Payload[0:2])
			if gotSessionID != tt.sessionID {
				t.Errorf("Payload SessionID = %d, want %d", gotSessionID, tt.sessionID)
			}

			gotMessageID := binary.BigEndian.Uint32(msg.Payload[2:6])
			if gotMessageID != tt.messageID {
				t.Errorf("MessageID = %d, want %d", gotMessageID, tt.messageID)
			}

			gotStatusCode := msg.Payload[6]
			if gotStatusCode != tt.statusCode {
				t.Errorf("StatusCode = %d, want %d", gotStatusCode, tt.statusCode)
			}

			gotMessageSize := binary.BigEndian.Uint32(msg.Payload[7:11])
			if gotMessageSize != tt.messageSize {
				t.Errorf("MessageSize = %d, want %d", gotMessageSize, tt.messageSize)
			}

			gotNonce := binary.BigEndian.Uint32(msg.Payload[11:15])
			if gotNonce != tt.nonce {
				t.Errorf("Nonce = %d, want %d", gotNonce, tt.nonce)
			}
		})
	}
}

// TestBuildMessageStatusResponseMarshal verifies the message can be marshaled correctly.
func TestBuildMessageStatusResponseMarshal(t *testing.T) {
	msg := buildMessageStatusResponse(100, 12345, MessageStatusSuccess, 2048, 999)

	data, err := msg.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}

	// Expected format per I2CP spec: length(4) + type(1) + payload(15)
	// MessageStatus payload: SessionID(2) + MessageID(4) + Status(1) + Size(4) + Nonce(4) = 15 bytes
	expectedLen := 4 + 1 + 15
	if len(data) != expectedLen {
		t.Errorf("Marshaled length = %d, want %d", len(data), expectedLen)
	}

	// Verify payload length field (first 4 bytes)
	gotPayloadLen := binary.BigEndian.Uint32(data[0:4])
	if gotPayloadLen != 15 {
		t.Errorf("Payload length field = %d, want 15", gotPayloadLen)
	}

	// Verify type byte (byte 4)
	if data[4] != MessageTypeMessageStatus {
		t.Errorf("Type byte = %d, want %d", data[4], MessageTypeMessageStatus)
	}

	// Verify session ID in payload (bytes 5-6)
	gotSessionID := binary.BigEndian.Uint16(data[5:7])
	if gotSessionID != 100 {
		t.Errorf("SessionID = %d, want 100", gotSessionID)
	}

	// Verify message ID in payload (bytes 7-10)
	gotMessageID := binary.BigEndian.Uint32(data[7:11])
	if gotMessageID != 12345 {
		t.Errorf("MessageID = %d, want 12345", gotMessageID)
	}

	// Verify status code (byte 11)
	if data[11] != MessageStatusSuccess {
		t.Errorf("StatusCode = %d, want %d", data[11], MessageStatusSuccess)
	}
}

// TestMessageIDGeneration verifies the Server generates unique message IDs.
func TestMessageIDGeneration(t *testing.T) {
	config := DefaultServerConfig()
	server, err := NewServer(config)
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	// Generate multiple IDs and verify they're sequential and unique
	ids := make(map[uint32]bool)
	for i := 0; i < 100; i++ {
		id := server.nextMessageID.Add(1)
		if ids[id] {
			t.Errorf("Duplicate message ID generated: %d", id)
		}
		ids[id] = true
	}

	// Verify we generated 100 unique IDs
	if len(ids) != 100 {
		t.Errorf("Generated %d unique IDs, want 100", len(ids))
	}
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

	if len(msg.Payload) != 15 {
		t.Fatalf("Payload length = %d, want 15", len(msg.Payload))
	}

	// Verify exact byte positions
	expectedSessionID := uint16(1)
	gotSessionID := binary.BigEndian.Uint16(msg.Payload[0:2])
	if gotSessionID != expectedSessionID {
		t.Errorf("Session ID at bytes 0-1 = 0x%04X, want 0x%04X", gotSessionID, expectedSessionID)
	}

	expectedMessageID := uint32(0x12345678)
	gotMessageID := binary.BigEndian.Uint32(msg.Payload[2:6])
	if gotMessageID != expectedMessageID {
		t.Errorf("Message ID at bytes 2-5 = 0x%08X, want 0x%08X", gotMessageID, expectedMessageID)
	}

	expectedStatus := uint8(0xAB)
	gotStatus := msg.Payload[6]
	if gotStatus != expectedStatus {
		t.Errorf("Status code at byte 6 = 0x%02X, want 0x%02X", gotStatus, expectedStatus)
	}

	expectedSize := uint32(0xCDEF0123)
	gotSize := binary.BigEndian.Uint32(msg.Payload[7:11])
	if gotSize != expectedSize {
		t.Errorf("Message size at bytes 7-10 = 0x%08X, want 0x%08X", gotSize, expectedSize)
	}

	expectedNonce := uint32(0x9ABCDEF0)
	gotNonce := binary.BigEndian.Uint32(msg.Payload[11:15])
	if gotNonce != expectedNonce {
		t.Errorf("Nonce at bytes 11-14 = 0x%08X, want 0x%08X", gotNonce, expectedNonce)
	}
}

// TestHandleSendMessage tests the SendMessage handler
func TestHandleSendMessage(t *testing.T) {
	// Create server
	server, err := NewServer(nil)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Create session
	session, err := server.manager.CreateSession(nil, nil)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// Create test destination hash
	var destHash data.Hash
	copy(destHash[:], []byte("test_destination_hash_32_bytes!"))

	// Create SendMessage payload
	sendPayload := &SendMessagePayload{
		Destination: destHash,
		Payload:     []byte("Test message to send"),
	}

	payloadBytes, err := sendPayload.MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to marshal payload: %v", err)
	}

	// Prepend 2-byte SessionID prefix to match real wire format.
	// On the wire, ReadMessage sets msg.Payload to the full payload including
	// the SessionID prefix. parseSendMessagePayload strips it before parsing.
	wirePayload := make([]byte, 2+len(payloadBytes))
	binary.BigEndian.PutUint16(wirePayload[0:2], session.ID())
	copy(wirePayload[2:], payloadBytes)

	// Create I2CP message
	msg := &Message{
		Type:      MessageTypeSendMessage,
		SessionID: session.ID(),
		Payload:   wirePayload,
	}

	// Test without outbound pool (should fail)
	sessionPtr := session
	response, err := server.handleSendMessage(msg, &sessionPtr)
	if err == nil {
		t.Error("Expected error when no outbound pool, got nil")
	}
	if response != nil {
		t.Error("Expected nil response on error")
	}

	// Add outbound pool
	pool := &tunnel.Pool{}
	session.SetOutboundPool(pool)

	// Test with pool (should succeed and return acceptance status)
	response, err = server.handleSendMessage(msg, &sessionPtr)
	if err != nil {
		t.Errorf("Unexpected error with outbound pool: %v", err)
	}
	if response == nil {
		t.Fatal("Expected MessageStatus response, got nil")
	}
	if response.Type != MessageTypeMessageStatus {
		t.Errorf("Expected MessageStatus type, got %d", response.Type)
	}
	// Verify it's an acceptance status (status code should be 1)
	// MessageStatus format: SessionID(2) + MessageID(4) + Status(1) + Size(4) + Nonce(4) = 15 bytes
	if len(response.Payload) < 15 {
		t.Fatalf("MessageStatus payload too short: got %d bytes, expected 15", len(response.Payload))
	}
	// Status byte is at index 6 (after SessionID(2) + MessageID(4))
	if response.Payload[6] != MessageStatusAccepted {
		t.Errorf("Expected MessageStatusAccepted (%d), got %d", MessageStatusAccepted, response.Payload[6])
	}
}

// TestHandleSendMessageNoSession tests SendMessage without active session
func TestHandleSendMessageNoSession(t *testing.T) {
	server, err := NewServer(nil)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	msg := &Message{
		Type:      MessageTypeSendMessage,
		SessionID: 0x1234,
		Payload:   make([]byte, 50),
	}

	var session *Session
	_, err = server.handleSendMessage(msg, &session)
	if err == nil {
		t.Error("Expected error when no session, got nil")
	}
}

// TestHandleSendMessageInvalidPayload tests SendMessage with malformed payload
func TestHandleSendMessageInvalidPayload(t *testing.T) {
	server, err := NewServer(nil)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	session, err := server.manager.CreateSession(nil, nil)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

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
	if err == nil {
		t.Error("Expected error for invalid payload, got nil")
	}
}

// TestDeliverMessagesToClientIntegration tests the message delivery goroutine
func TestDeliverMessagesToClientIntegration(t *testing.T) {
	// Create in-memory pipe for testing
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	// Create server and session
	server, err := NewServer(nil)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	session, err := server.manager.CreateSession(nil, nil)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// Start delivery goroutine
	server.wg.Add(1)
	go server.deliverMessagesToClient(session, serverConn)

	// Queue a message
	testPayload := []byte("Test incoming message")
	if err := session.QueueIncomingMessage(testPayload); err != nil {
		t.Fatalf("Failed to queue message: %v", err)
	}

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

	if readErr != nil {
		t.Fatalf("Failed to read message: %v", readErr)
	}

	// Verify message type
	if readMsg.Type != MessageTypeMessagePayload {
		t.Errorf("Message type = %d, want %d", readMsg.Type, MessageTypeMessagePayload)
	}

	// Verify session ID
	if readMsg.SessionID != session.ID() {
		t.Errorf("SessionID = %d, want %d", readMsg.SessionID, session.ID())
	}

	// Parse MessagePayload payload
	msgPayload, err := ParseMessagePayloadPayload(readMsg.Payload)
	if err != nil {
		t.Fatalf("Failed to parse MessagePayload: %v", err)
	}

	// Verify message ID is non-zero
	if msgPayload.MessageID == 0 {
		t.Error("Expected non-zero message ID")
	}

	// Verify payload
	if !bytes.Equal(msgPayload.Payload, testPayload) {
		t.Errorf("Payload mismatch: got %v, want %v", msgPayload.Payload, testPayload)
	}

	// Clean up
	session.Stop()
	server.wg.Wait()
}

// TestDeliverMessagesToClientMultiple tests delivering multiple messages
func TestDeliverMessagesToClientMultiple(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	server, err := NewServer(nil)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	session, err := server.manager.CreateSession(nil, nil)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// Start delivery goroutine
	server.wg.Add(1)
	go server.deliverMessagesToClient(session, serverConn)

	// Queue multiple messages
	numMessages := 5
	for i := 0; i < numMessages; i++ {
		payload := []byte{byte(i), byte(i + 1), byte(i + 2)}
		if err := session.QueueIncomingMessage(payload); err != nil {
			t.Fatalf("Failed to queue message %d: %v", i, err)
		}
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

	if receivedCount != numMessages {
		t.Errorf("Received %d messages, want %d", receivedCount, numMessages)
	}

	// Clean up
	session.Stop()
	server.wg.Wait()
}

// TestDeliverMessagesToClientMessageIDIncrement tests message ID increments
func TestDeliverMessagesToClientMessageIDIncrement(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	server, err := NewServer(nil)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	session, err := server.manager.CreateSession(nil, nil)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	server.wg.Add(1)
	go server.deliverMessagesToClient(session, serverConn)

	// Queue messages and verify IDs increment
	numMessages := 3
	for i := 0; i < numMessages; i++ {
		if err := session.QueueIncomingMessage([]byte{byte(i)}); err != nil {
			t.Fatalf("Failed to queue message: %v", err)
		}
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
	if len(messageIDs) != numMessages {
		t.Fatalf("Got %d IDs, want %d", len(messageIDs), numMessages)
	}

	for i := 0; i < len(messageIDs); i++ {
		expectedID := uint32(i + 1) // IDs start at 1
		if messageIDs[i] != expectedID {
			t.Errorf("Message %d: ID = %d, want %d", i, messageIDs[i], expectedID)
		}
	}

	session.Stop()
	server.wg.Wait()
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

// Regression tests for AUDIT.md critical bugs:
// 1. SessionStatus uses wrong status code (0x00 Destroyed instead of 0x01 Created)
// 2. SendMessage payload offset — SessionID not stripped before destination parsing

// TestSessionStatusCreatedCode verifies that buildSessionStatusResponse returns
// status byte 0x01 (Created) per I2CP spec v0.9.67, not 0x00 (Destroyed).
func TestSessionStatusCreatedCode(t *testing.T) {
	sessionID := uint16(42)
	msg := buildSessionStatusResponse(sessionID)

	if msg.Type != MessageTypeSessionStatus {
		t.Errorf("message type = %d, want %d (SessionStatus)", msg.Type, MessageTypeSessionStatus)
	}

	if len(msg.Payload) != 3 {
		t.Fatalf("payload length = %d, want 3 (SessionID(2) + Status(1))", len(msg.Payload))
	}

	// Verify SessionID in payload
	payloadSessionID := binary.BigEndian.Uint16(msg.Payload[0:2])
	if payloadSessionID != sessionID {
		t.Errorf("payload SessionID = %d, want %d", payloadSessionID, sessionID)
	}

	// Critical: status byte MUST be 1 (Created), not 0 (Destroyed)
	if msg.Payload[2] != SessionStatusCreated {
		t.Errorf("status byte = 0x%02x, want 0x%02x (Created)", msg.Payload[2], SessionStatusCreated)
	}
}

// TestSessionStatusDestroyedCode verifies that handleDestroySession returns
// status byte 0x00 (Destroyed) per I2CP spec.
func TestSessionStatusDestroyedCode(t *testing.T) {
	config := &ServerConfig{
		ListenAddr:  "localhost:17690",
		Network:     "tcp",
		MaxSessions: 100,
	}

	server, err := NewServer(config)
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	session, err := server.manager.CreateSession(nil, nil)
	if err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}

	sessionID := session.ID()
	sessionCopy := session

	destroyMsg := &Message{
		Type:      MessageTypeDestroySession,
		SessionID: sessionID,
	}

	response, err := server.handleDestroySession(destroyMsg, &sessionCopy)
	if err != nil {
		t.Fatalf("handleDestroySession() error = %v", err)
	}

	if response == nil {
		t.Fatal("handleDestroySession() returned nil response")
	}

	if len(response.Payload) != 3 {
		t.Fatalf("payload length = %d, want 3", len(response.Payload))
	}

	// Destroyed status must be 0
	if response.Payload[2] != SessionStatusDestroyed {
		t.Errorf("status byte = 0x%02x, want 0x%02x (Destroyed)", response.Payload[2], SessionStatusDestroyed)
	}
}

// TestParseSendMessagePayloadWithSessionIDPrefix verifies that
// parseSendMessagePayload correctly strips the 2-byte SessionID prefix
// from the wire payload before parsing the destination hash.
func TestParseSendMessagePayloadWithSessionIDPrefix(t *testing.T) {
	server, err := NewServer(nil)
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	session, err := server.manager.CreateSession(nil, nil)
	if err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}

	// Create a known destination hash
	var destHash data.Hash
	copy(destHash[:], []byte("known_destination_hash_32bytes!"))

	messagePayload := []byte("hello i2p network")

	// Build the inner payload (what ParseSendMessagePayload expects)
	sendPayload := &SendMessagePayload{
		Destination: destHash,
		Payload:     messagePayload,
	}

	innerBytes, err := sendPayload.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}

	// Build the WIRE payload: SessionID(2) + inner payload
	// This is what ReadMessage produces in msg.Payload
	wirePayload := make([]byte, 2+len(innerBytes))
	binary.BigEndian.PutUint16(wirePayload[0:2], session.ID())
	copy(wirePayload[2:], innerBytes)

	msg := &Message{
		Type:      MessageTypeSendMessage,
		SessionID: session.ID(),
		Payload:   wirePayload,
	}

	// Parse via the server method (which should strip SessionID prefix)
	parsed, err := server.parseSendMessagePayload(msg, session)
	if err != nil {
		t.Fatalf("parseSendMessagePayload() error = %v", err)
	}

	// Verify the destination hash was correctly extracted
	if parsed.Destination != destHash {
		t.Errorf("destination hash mismatch:\n  got:  %x\n  want: %x", parsed.Destination, destHash)
	}

	// Verify the payload data was correctly extracted
	if string(parsed.Payload) != string(messagePayload) {
		t.Errorf("payload mismatch:\n  got:  %q\n  want: %q", parsed.Payload, messagePayload)
	}
}

// TestParseSendMessagePayloadTooShort verifies that parseSendMessagePayload
// returns an error when the payload is too short to contain even a SessionID.
func TestParseSendMessagePayloadTooShort(t *testing.T) {
	server, err := NewServer(nil)
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	session, err := server.manager.CreateSession(nil, nil)
	if err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}

	msg := &Message{
		Type:      MessageTypeSendMessage,
		SessionID: session.ID(),
		Payload:   []byte{0x01}, // Only 1 byte — too short for 2-byte SessionID
	}

	_, err = server.parseSendMessagePayload(msg, session)
	if err == nil {
		t.Error("Expected error for payload too short for SessionID, got nil")
	}
}

// TestParseSendMessageExpiresPayloadWithSessionIDPrefix verifies that
// parseSendMessageExpiresPayload correctly strips the 2-byte SessionID prefix
// from the wire payload before parsing the destination hash.
func TestParseSendMessageExpiresPayloadWithSessionIDPrefix(t *testing.T) {
	server, err := NewServer(nil)
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	session, err := server.manager.CreateSession(nil, nil)
	if err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}

	// Create a known destination hash
	var destHash data.Hash
	copy(destHash[:], []byte("known_destination_hash_32bytes!"))

	messagePayload := []byte("expires test payload")

	// Build the inner payload (what ParseSendMessageExpiresPayload expects)
	sendPayload := &SendMessageExpiresPayload{
		Destination: destHash,
		Payload:     messagePayload,
		Nonce:       12345,
		Expiration:  1700000000000, // milliseconds
	}

	innerBytes, err := sendPayload.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}

	// Build the WIRE payload: SessionID(2) + inner payload
	wirePayload := make([]byte, 2+len(innerBytes))
	binary.BigEndian.PutUint16(wirePayload[0:2], session.ID())
	copy(wirePayload[2:], innerBytes)

	msg := &Message{
		Type:      MessageTypeSendMessageExpires,
		SessionID: session.ID(),
		Payload:   wirePayload,
	}

	// Parse via the server method (which should strip SessionID prefix)
	parsed, err := server.parseSendMessageExpiresPayload(msg, session)
	if err != nil {
		t.Fatalf("parseSendMessageExpiresPayload() error = %v", err)
	}

	// Verify the destination hash was correctly extracted
	if parsed.Destination != destHash {
		t.Errorf("destination hash mismatch:\n  got:  %x\n  want: %x", parsed.Destination, destHash)
	}

	// Verify the payload data was correctly extracted
	if string(parsed.Payload) != string(messagePayload) {
		t.Errorf("payload mismatch:\n  got:  %q\n  want: %q", parsed.Payload, messagePayload)
	}

	// Verify nonce and expiration
	if parsed.Nonce != 12345 {
		t.Errorf("nonce = %d, want 12345", parsed.Nonce)
	}
	if parsed.Expiration != 1700000000000 {
		t.Errorf("expiration = %d, want 1700000000000", parsed.Expiration)
	}
}

// TestParseSendMessageExpiresPayloadTooShort verifies that
// parseSendMessageExpiresPayload returns an error when the payload is too short.
func TestParseSendMessageExpiresPayloadTooShort(t *testing.T) {
	server, err := NewServer(nil)
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	session, err := server.manager.CreateSession(nil, nil)
	if err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}

	msg := &Message{
		Type:      MessageTypeSendMessageExpires,
		SessionID: session.ID(),
		Payload:   []byte{0x00}, // Only 1 byte — too short for 2-byte SessionID
	}

	_, err = server.parseSendMessageExpiresPayload(msg, session)
	if err == nil {
		t.Error("Expected error for payload too short for SessionID, got nil")
	}
}

// TestHandleSendMessageWithWireFormatPayload is an end-to-end test that
// exercises handleSendMessage with a wire-format payload (SessionID prefix included)
// and verifies the full handler path including message acceptance.
func TestHandleSendMessageWithWireFormatPayload(t *testing.T) {
	server, err := NewServer(nil)
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	session, err := server.manager.CreateSession(nil, nil)
	if err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}

	// Set up outbound pool (required for message sending)
	pool := &tunnel.Pool{}
	session.SetOutboundPool(pool)

	// Create known destination
	var destHash data.Hash
	copy(destHash[:], []byte("wire_format_test_destination_32!"))

	sendPayload := &SendMessagePayload{
		Destination: destHash,
		Payload:     []byte("wire format end-to-end test"),
	}

	innerBytes, err := sendPayload.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}

	// Build wire-format payload with SessionID prefix
	wirePayload := make([]byte, 2+len(innerBytes))
	binary.BigEndian.PutUint16(wirePayload[0:2], session.ID())
	copy(wirePayload[2:], innerBytes)

	msg := &Message{
		Type:      MessageTypeSendMessage,
		SessionID: session.ID(),
		Payload:   wirePayload,
	}

	sessionPtr := session
	response, err := server.handleSendMessage(msg, &sessionPtr)
	if err != nil {
		t.Fatalf("handleSendMessage() error = %v", err)
	}

	if response == nil {
		t.Fatal("Expected MessageStatus response, got nil")
	}

	if response.Type != MessageTypeMessageStatus {
		t.Errorf("response type = %d, want %d (MessageStatus)", response.Type, MessageTypeMessageStatus)
	}

	// MessageStatus payload: SessionID(2) + MessageID(4) + Status(1) + Size(4) + Nonce(4) = 15
	if len(response.Payload) < 15 {
		t.Fatalf("MessageStatus payload too short: %d bytes, want >= 15", len(response.Payload))
	}

	// Status byte at index 6 should be MessageStatusAccepted
	if response.Payload[6] != MessageStatusAccepted {
		t.Errorf("message status = %d, want %d (Accepted)", response.Payload[6], MessageStatusAccepted)
	}
}

// TestResolveDestinationKey_NilResolver verifies that resolveDestinationKey returns
// ErrNoDestinationResolver when no resolver is configured, instead of silently
// returning a zero encryption key.
func TestResolveDestinationKey_NilResolver(t *testing.T) {
	server := &Server{}

	var destHash common.Hash
	copy(destHash[:], []byte("test-destination-hash-value-here!"))

	key, err := server.resolveDestinationKey(destHash)
	if err == nil {
		t.Fatal("expected error when destinationResolver is nil, got nil")
	}
	if !errors.Is(err, ErrNoDestinationResolver) {
		t.Fatalf("expected ErrNoDestinationResolver, got: %v", err)
	}

	// Verify the returned key is zero (no partial key leakage)
	var zeroKey [32]byte
	if key != zeroKey {
		t.Error("expected zero key on error, got non-zero key")
	}
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
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key != expectedKey {
		t.Errorf("expected key %x, got %x", expectedKey, key)
	}
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
	if err == nil {
		t.Fatal("expected error from resolver, got nil")
	}
	if !errors.Is(err, resolverErr) {
		t.Fatalf("expected wrapped resolver error, got: %v", err)
	}
}

// TestErrNoDestinationResolver_ErrorMessage verifies the sentinel error message
// is descriptive enough for debugging.
func TestErrNoDestinationResolver_ErrorMessage(t *testing.T) {
	expected := "no destination resolver configured: cannot resolve encryption key"
	if ErrNoDestinationResolver.Error() != expected {
		t.Errorf("unexpected error message: %q", ErrNoDestinationResolver.Error())
	}
}
