package i2cp

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func decodeDisconnectFrame(t *testing.T, msg []byte) string {
	t.Helper()
	if len(msg) < 7 {
		t.Fatalf("disconnect frame too short: got %d bytes, need at least 7", len(msg))
	}

	payloadLen := int(binary.BigEndian.Uint32(msg[0:4]))
	if msg[4] != MessageTypeDisconnect {
		t.Fatalf("expected disconnect message type %d, got %d", MessageTypeDisconnect, msg[4])
	}
	if len(msg) != 5+payloadLen {
		t.Fatalf("disconnect frame length mismatch: declared payload %d, total %d", payloadLen, len(msg))
	}
	if payloadLen < 2 {
		t.Fatalf("disconnect payload too short: %d", payloadLen)
	}

	reasonLen := int(binary.BigEndian.Uint16(msg[5:7]))
	if payloadLen != 2+reasonLen {
		t.Fatalf("disconnect reason length mismatch: payload=%d reason=%d", payloadLen, reasonLen)
	}
	return string(msg[7 : 7+reasonLen])
}

// mockConn is a mock network connection for testing
type mockConn struct {
	writeBuffer bytes.Buffer
	readBuffer  bytes.Buffer
	closed      bool
	readErr     error
	writeErr    error
}

func (m *mockConn) Read(b []byte) (int, error) {
	if m.readErr != nil {
		return 0, m.readErr
	}
	return m.readBuffer.Read(b)
}

func (m *mockConn) Write(b []byte) (int, error) {
	if m.writeErr != nil {
		return 0, m.writeErr
	}
	n, err := m.writeBuffer.Write(b)
	return n, err
}

func (m *mockConn) Close() error {
	m.closed = true
	return nil
}

func (m *mockConn) LocalAddr() net.Addr {
	return &net.TCPAddr{}
}

func (m *mockConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{}
}

func (m *mockConn) SetDeadline(t time.Time) error {
	return nil
}

func (m *mockConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (m *mockConn) SetWriteDeadline(t time.Time) error {
	return nil
}

// TestM8_SendDisconnectMessage_SessionLimitReason verifies that when max-sessions
// is reached, a proper I2CP Disconnect message is sent before closing.
// M-8 FIX: Protocol compliance — send Disconnect("session_limit_reached") instead of silently closing.
func TestM8_SendDisconnectMessage_SessionLimitReason(t *testing.T) {
	server := &Server{
		config: &ServerConfig{
			MaxSessions:    100,
			SessionTimeout: 0,
		},
		manager: NewSessionManager(),
	}

	mockConn := &mockConn{}
	server.sendDisconnectMessage(mockConn, "session_limit_reached")

	// M-8 FIX: Verify framed I2CP Disconnect message was written
	msg := mockConn.writeBuffer.Bytes()
	if len(msg) == 0 {
		t.Fatalf("no message written to connection")
	}

	expectedReason := "session_limit_reached"
	reason := decodeDisconnectFrame(t, msg)
	if reason != expectedReason {
		t.Errorf("expected reason %q, got %q", expectedReason, reason)
	}
}

// TestM8_SendDisconnectMessage_ConnectionLimitReason verifies connection-limit
// rejection also sends a proper I2CP Disconnect message.
func TestM8_SendDisconnectMessage_ConnectionLimitReason(t *testing.T) {
	server := &Server{
		config: &ServerConfig{
			MaxSessions:    100,
			SessionTimeout: 0,
		},
		manager: NewSessionManager(),
	}

	mockConn := &mockConn{}
	server.sendDisconnectMessage(mockConn, "connection_limit_reached")

	// M-8 FIX: Verify Disconnect message was written
	msg := mockConn.writeBuffer.Bytes()
	if len(msg) == 0 {
		t.Fatalf("no message written to connection")
	}

	expectedReason := "connection_limit_reached"
	reason := decodeDisconnectFrame(t, msg)
	if reason != expectedReason {
		t.Errorf("expected reason %q, got %q", expectedReason, reason)
	}
}

// TestM8_ShouldRejectConnection_SendsDisconnectOnMaxSessions verifies that
// shouldRejectConnection sends a Disconnect message when max-sessions limit is hit.
// M-8 FIX: Integration test for protocol compliance in shouldRejectConnection.
func TestM8_ShouldRejectConnection_SendsDisconnectOnMaxSessions(t *testing.T) {
	server := &Server{
		config: &ServerConfig{
			MaxSessions:    2,
			SessionTimeout: 0,
		},
		manager: NewSessionManager(),
	}

	// M-8 FIX: Create a session to reach the limit
	s := &Session{
		id:           1,
		config:       &SessionConfig{},
		active:       true,
		lastActivity: time.Now(),
	}
	server.manager.sessions[1] = s

	// M-8 FIX: Create another session to reach the limit
	s2 := &Session{
		id:           2,
		config:       &SessionConfig{},
		active:       true,
		lastActivity: time.Now(),
	}
	server.manager.sessions[2] = s2

	mockConn := &mockConn{}

	// M-8 FIX: shouldRejectConnection should reject the 3rd connection
	if !server.shouldRejectConnection(mockConn) {
		t.Fatal("expected shouldRejectConnection to return true for max-sessions")
	}

	// M-8 FIX: Verify Disconnect message was sent
	msg := mockConn.writeBuffer.Bytes()
	if len(msg) == 0 {
		t.Fatalf("no Disconnect message sent before closing connection")
	}

	// M-8 FIX: Verify connection was closed
	if !mockConn.closed {
		t.Error("connection was not closed after rejection")
	}
}

// TestM8_ShouldRejectConnection_SendsDisconnectOnMaxConnections verifies
// that max-connection limit also sends a Disconnect message.
// M-8 FIX: Verify both rejection paths send protocol messages.
func TestM8_ShouldRejectConnection_SendsDisconnectOnMaxConnections(t *testing.T) {
	server := &Server{
		config: &ServerConfig{
			MaxSessions:    100,
			SessionTimeout: 0,
		},
		manager: NewSessionManager(),
	}

	// M-8 FIX: Simulate max connections (2x MaxSessions = 200)
	server.activeConnCount.Store(200)

	mockConn := &mockConn{}

	// M-8 FIX: shouldRejectConnection should reject when maxConns exceeded
	if !server.shouldRejectConnection(mockConn) {
		t.Fatal("expected shouldRejectConnection to return true for max-connections")
	}

	// M-8 FIX: Verify Disconnect message was sent
	msg := mockConn.writeBuffer.Bytes()
	if len(msg) == 0 {
		t.Fatalf("no Disconnect message sent before closing connection")
	}

	// M-8 FIX: Verify framed disconnect is valid and has expected reason
	reason := decodeDisconnectFrame(t, msg)
	if reason != "connection_limit_reached" {
		t.Errorf("expected reason %q, got %q", "connection_limit_reached", reason)
	}
}

// TestM8_DisconnectMessage_EmptyReason handles edge case of empty reason string
func TestM8_DisconnectMessage_EmptyReason(t *testing.T) {
	server := &Server{
		config: &ServerConfig{
			MaxSessions:    100,
			SessionTimeout: 0,
		},
		manager: NewSessionManager(),
	}

	mockConn := &mockConn{}
	server.sendDisconnectMessage(mockConn, "")

	// M-8 FIX: Verify framed message format even with empty reason
	msg := mockConn.writeBuffer.Bytes()
	reason := decodeDisconnectFrame(t, msg)
	if reason != "" {
		t.Errorf("expected empty reason, got %q", reason)
	}
}

// TestM8_DisconnectMessage_LongReason verifies handling of longer reason strings
func TestM8_DisconnectMessage_LongReason(t *testing.T) {
	server := &Server{
		config: &ServerConfig{
			MaxSessions:    100,
			SessionTimeout: 0,
		},
		manager: NewSessionManager(),
	}

	mockConn := &mockConn{}
	longReason := "session_limit_reached_due_to_resource_exhaustion_on_i2p_router_service"
	server.sendDisconnectMessage(mockConn, longReason)

	// M-8 FIX: Verify long reason is properly encoded
	msg := mockConn.writeBuffer.Bytes()
	reason := decodeDisconnectFrame(t, msg)
	if reason != longReason {
		t.Errorf("expected reason %q, got %q", longReason, reason)
	}
}
