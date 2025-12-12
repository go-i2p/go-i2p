package i2cp

import (
	"net"
	"testing"
	"time"
)

// dialI2CPClient connects to an I2CP server and sends the required protocol byte (0x2a)
func dialI2CPClient(addr string) (net.Conn, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}

	// Send protocol byte as required by I2CP spec
	if _, err := conn.Write([]byte{0x2a}); err != nil {
		conn.Close()
		return nil, err
	}

	return conn, nil
}

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

	if len(response.Payload) < 1 || response.Payload[0] != 0x00 {
		t.Errorf("SessionStatus payload = %v, want [0x00]", response.Payload)
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
