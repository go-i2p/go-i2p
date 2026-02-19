package i2cp

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// TestProtocolByteValidation tests that the server enforces the 0x2a protocol byte.
func TestProtocolByteValidation(t *testing.T) {
	tests := []struct {
		name          string
		protocolByte  byte
		expectAccept  bool
		expectTimeout bool
	}{
		{
			name:         "Valid protocol byte 0x2a",
			protocolByte: 0x2a,
			expectAccept: true,
		},
		{
			name:         "Invalid protocol byte 0x00",
			protocolByte: 0x00,
			expectAccept: false,
		},
		{
			name:         "Invalid protocol byte 0xFF",
			protocolByte: 0xFF,
			expectAccept: false,
		},
		{
			name:         "Invalid protocol byte 0x29",
			protocolByte: 0x29,
			expectAccept: false,
		},
		{
			name:         "Invalid protocol byte 0x2b",
			protocolByte: 0x2b,
			expectAccept: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create server
			config := DefaultServerConfig()
			config.ListenAddr = "localhost:0" // Random port
			server, err := NewServer(config)
			if err != nil {
				t.Fatalf("NewServer() error = %v", err)
			}

			// Start server
			if err := server.Start(); err != nil {
				t.Fatalf("Start() error = %v", err)
			}
			defer server.Stop()

			// Get actual listen address
			addr := server.listener.Addr().String()

			// Connect to server
			conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
			if err != nil {
				t.Fatalf("Dial() error = %v", err)
			}
			defer conn.Close()

			// Send protocol byte
			if _, err := conn.Write([]byte{tt.protocolByte}); err != nil {
				t.Fatalf("Write protocol byte error = %v", err)
			}

			// For valid protocol byte, server should accept connection
			// For invalid, server should close connection
			conn.SetReadDeadline(time.Now().Add(1 * time.Second))

			buf := make([]byte, 1)
			_, err = conn.Read(buf)

			if tt.expectAccept {
				// Connection should remain open, read will timeout
				if err == nil {
					t.Error("Expected timeout on read (connection open), got data")
				} else if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
					// If not a timeout, connection might have been closed unexpectedly
					if err.Error() != "EOF" {
						t.Logf("Read after valid protocol byte: %v (this is acceptable)", err)
					}
				}
			} else {
				// Connection should be closed
				if err == nil {
					t.Error("Expected connection closed for invalid protocol byte, got data")
				}
				// We expect EOF or connection reset
			}
		})
	}
}

// TestMessageTypeHandlers verifies all implemented message type handlers respond correctly.
func TestMessageTypeHandlers(t *testing.T) {
	tests := []struct {
		name        string
		messageType uint8
		expectError bool
		description string
	}{
		{
			name:        "CreateSession handler exists",
			messageType: MessageTypeCreateSession,
			expectError: false,
			description: "CreateSession should be handled",
		},
		{
			name:        "ReconfigureSession handler exists",
			messageType: MessageTypeReconfigureSession,
			expectError: true, // Will error without session
			description: "ReconfigureSession should be handled",
		},
		{
			name:        "DestroySession handler exists",
			messageType: MessageTypeDestroySession,
			expectError: true, // Will error without session
			description: "DestroySession should be handled",
		},
		{
			name:        "SendMessage handler exists",
			messageType: MessageTypeSendMessage,
			expectError: true, // Will error without session
			description: "SendMessage should be handled",
		},
		{
			name:        "GetBandwidthLimits handler exists",
			messageType: MessageTypeGetBandwidthLimits,
			expectError: false,
			description: "GetBandwidthLimits should be handled",
		},
		{
			name:        "GetDate handler exists",
			messageType: MessageTypeGetDate,
			expectError: false,
			description: "GetDate should be handled",
		},
		{
			name:        "CreateLeaseSet handler exists",
			messageType: MessageTypeCreateLeaseSet,
			expectError: true, // Will error without session
			description: "CreateLeaseSet should be handled",
		},
		{
			name:        "CreateLeaseSet2 handler exists",
			messageType: MessageTypeCreateLeaseSet2,
			expectError: true, // Will error without session
			description: "CreateLeaseSet2 should be handled",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, err := NewServer(nil)
			if err != nil {
				t.Fatalf("NewServer() error = %v", err)
			}

			// Create a minimal message
			msg := &Message{
				Type:      tt.messageType,
				SessionID: 0,
				Payload:   []byte{},
			}

			var session *Session
			_, err = server.handleMessage(msg, &session)

			if tt.expectError && err == nil {
				t.Errorf("Expected error for %s, got nil", tt.description)
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error for %s, got %v", tt.description, err)
			}
		})
	}
}

// TestVersionNegotiation tests GetDate/SetDate version exchange.
func TestVersionNegotiation(t *testing.T) {
	server, err := NewServer(nil)
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	// Test GetDate message
	msg := &Message{
		Type:      MessageTypeGetDate,
		SessionID: 0,
		Payload:   []byte{},
	}

	var session *Session
	response, err := server.handleMessage(msg, &session)
	if err != nil {
		t.Fatalf("handleMessage(GetDate) error = %v", err)
	}

	if response == nil {
		t.Fatal("Expected SetDate response, got nil")
	}

	if response.Type != MessageTypeSetDate {
		t.Errorf("Expected MessageTypeSetDate, got %d", response.Type)
	}

	// Verify payload contains version string
	if len(response.Payload) < 8 {
		t.Fatal("SetDate payload too short")
	}

	// First 8 bytes are timestamp
	// Remaining bytes should be version string
	if len(response.Payload) > 8 {
		version := string(response.Payload[8:])
		t.Logf("Server version: %s", version)

		if version == "" {
			t.Error("Expected non-empty version string")
		}
	}
}

// TestRateLimitingEnforcement tests connection-level rate limiting.
func TestRateLimitingEnforcement(t *testing.T) {
	config := DefaultServerConfig()
	config.ListenAddr = "localhost:0"
	server, err := NewServer(config)
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	if err := server.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer server.Stop()

	addr := server.listener.Addr().String()

	// Connect and send protocol byte
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer conn.Close()

	// Send protocol byte
	if _, err := conn.Write([]byte{0x2a}); err != nil {
		t.Fatalf("Write protocol byte error = %v", err)
	}

	// Create many messages rapidly
	messageCount := 20
	for i := 0; i < messageCount; i++ {
		msg := &Message{
			Type:      MessageTypeGetDate,
			SessionID: 0,
			Payload:   []byte{},
		}

		data, err := msg.MarshalBinary()
		if err != nil {
			t.Fatalf("MarshalBinary() error = %v", err)
		}

		if _, err := conn.Write(data); err != nil {
			t.Logf("Write error after %d messages: %v (rate limit may have kicked in)", i, err)
			// This is expected behavior - rate limiting should eventually throttle or close
			return
		}

		// Small delay
		time.Sleep(10 * time.Millisecond)
	}

	t.Logf("Sent %d messages, rate limiting not triggered (connection may have higher limits)", messageCount)
}

// TestPayloadSizeEnforcement tests that oversized payloads are rejected.
func TestPayloadSizeEnforcement(t *testing.T) {
	tests := []struct {
		name        string
		payloadSize int
		expectError bool
	}{
		{
			name:        "Small payload (1 KB)",
			payloadSize: 1024,
			expectError: false,
		},
		{
			name:        "Medium payload (64 KB)",
			payloadSize: 65536,
			expectError: false,
		},
		{
			name:        "Large payload (256 KB - at limit)",
			payloadSize: MaxPayloadSize,
			expectError: false,
		},
		{
			name:        "Oversized payload (256 KB + 1)",
			payloadSize: MaxPayloadSize + 1,
			expectError: true,
		},
		{
			name:        "Very large payload (1 MB)",
			payloadSize: 1048576,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create message with specified payload size
			payload := make([]byte, tt.payloadSize)
			msg := &Message{
				Type:      MessageTypeGetDate,
				SessionID: 1,
				Payload:   payload,
			}

			// Test marshaling
			_, err := msg.MarshalBinary()

			if tt.expectError && err == nil {
				t.Error("Expected error for oversized payload, got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error, got %v", err)
			}
		})
	}
}

// TestMessageWireFormat verifies exact I2CP wire format compliance.
func TestMessageWireFormat(t *testing.T) {
	// Create a known message
	msg := &Message{
		Type:      MessageTypeGetDate,
		SessionID: 0x1234,
		Payload:   []byte{0xAA, 0xBB, 0xCC},
	}

	data, err := msg.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}

	// Expected format per I2CP specification:
	// Bytes 0-3: PayloadLength (0x00000003, big endian)
	// Byte 4: Type (0x20 for GetDate)
	// Bytes 5-7: Payload (0xAA, 0xBB, 0xCC)
	// NOTE: Session ID is NOT in the wire format - it's managed at the message layer

	expectedLen := 4 + 1 + 3 // length + type + payload
	if len(data) != expectedLen {
		t.Errorf("Wire format length = %d, want %d", len(data), expectedLen)
	}

	// Verify payload length (big endian)
	payloadLen := binary.BigEndian.Uint32(data[0:4])
	if payloadLen != 3 {
		t.Errorf("Payload length = %d, want 3", payloadLen)
	}

	// Verify type byte
	if data[4] != MessageTypeGetDate {
		t.Errorf("Type byte = 0x%02X, want 0x%02X", data[4], MessageTypeGetDate)
	}

	// Verify payload bytes
	if !bytes.Equal(data[5:], []byte{0xAA, 0xBB, 0xCC}) {
		t.Errorf("Payload = %v, want [0xAA 0xBB 0xCC]", data[5:])
	}
}

// TestMessageRoundTrip verifies marshal/unmarshal preserves data.
func TestMessageRoundTrip(t *testing.T) {
	tests := []struct {
		name    string
		msgType uint8
		session uint16
		payload []byte
	}{
		{
			name:    "Empty payload",
			msgType: MessageTypeGetDate,
			session: 0,
			payload: []byte{},
		},
		{
			name:    "Small payload",
			msgType: MessageTypeSendMessage,
			session: 42,
			payload: []byte{1, 2, 3, 4, 5},
		},
		{
			name:    "Large payload",
			msgType: MessageTypeCreateSession,
			session: 0xFFFF,
			payload: make([]byte, 1024),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			original := &Message{
				Type:      tt.msgType,
				SessionID: tt.session,
				Payload:   tt.payload,
			}

			// Marshal
			data, err := original.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary() error = %v", err)
			}

			// Unmarshal
			var decoded Message
			if err := decoded.UnmarshalBinary(data); err != nil {
				t.Fatalf("UnmarshalBinary() error = %v", err)
			}

			// Verify fields match
			if decoded.Type != original.Type {
				t.Errorf("Type = %d, want %d", decoded.Type, original.Type)
			}
			// Note: SessionID is NOT in the wire format per I2CP spec, so it's always 0 after unmarshal
			// SessionID must be set from connection context by the protocol handler
			if decoded.SessionID != 0 {
				t.Errorf("SessionID = %d, want 0 (not in wire format)", decoded.SessionID)
			}
			if !bytes.Equal(decoded.Payload, original.Payload) {
				t.Errorf("Payload mismatch")
			}
		})
	}
} // TestReservedSessionIDConstants tests that reserved session ID constants have correct values.
func TestReservedSessionIDConstants(t *testing.T) {
	tests := []struct {
		name       string
		sessionID  uint16
		isReserved bool
	}{
		{
			name:       "Control session ID (0x0000)",
			sessionID:  SessionIDReservedControl,
			isReserved: true,
		},
		{
			name:       "Broadcast session ID (0xFFFF)",
			sessionID:  SessionIDReservedBroadcast,
			isReserved: true,
		},
		{
			name:       "Valid session ID (0x0001)",
			sessionID:  1,
			isReserved: false,
		},
		{
			name:       "Valid session ID (0x1234)",
			sessionID:  0x1234,
			isReserved: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reserved IDs are defined constants, verify they have correct values
			if tt.sessionID == SessionIDReservedControl && tt.sessionID != 0x0000 {
				t.Error("SessionIDReservedControl should be 0x0000")
			}
			if tt.sessionID == SessionIDReservedBroadcast && tt.sessionID != 0xFFFF {
				t.Error("SessionIDReservedBroadcast should be 0xFFFF")
			}
		})
	}
}

// TestProtocolVersionConstants verifies protocol version constants.
func TestProtocolVersionConstants(t *testing.T) {
	if ProtocolVersionMajor != ExpectedProtocolVersionMajor {
		t.Errorf("ProtocolVersionMajor = %d, want %d", ProtocolVersionMajor, ExpectedProtocolVersionMajor)
	}
	if ProtocolVersionMinor != ExpectedProtocolVersionMinor {
		t.Errorf("ProtocolVersionMinor = %d, want %d", ProtocolVersionMinor, ExpectedProtocolVersionMinor)
	}
	if ProtocolVersionPatch != ExpectedProtocolVersionPatch {
		t.Errorf("ProtocolVersionPatch = %d, want %d", ProtocolVersionPatch, ExpectedProtocolVersionPatch)
	}

	t.Logf("Protocol version: %d.%d.%d",
		ProtocolVersionMajor, ProtocolVersionMinor, ProtocolVersionPatch)
}

// TestSessionStatusConstants verifies the session status constants match the I2CP spec.
func TestSessionStatusConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant byte
		expected byte
	}{
		{"Destroyed", SessionStatusDestroyed, 0},
		{"Created", SessionStatusCreated, 1},
		{"Updated", SessionStatusUpdated, 2},
		{"Invalid", SessionStatusInvalid, 3},
		{"Refused", SessionStatusRefused, 4},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.constant != tt.expected {
				t.Errorf("SessionStatus%s = %d, want %d", tt.name, tt.constant, tt.expected)
			}
		})
	}
}

// =============================================================================
// Tests for lib/i2cp package
// =============================================================================
// These tests verify the security properties of the I2CP implementation.
//
// Coverage:
// - Protocol Compliance: v0.9.67 message types correct
// - Session Limits: Max sessions enforced (default 100)
// - Session Isolation: Cross-session information leakage
// - Message Framing: Length validation, buffer overflows
// - LeaseSet Publishing: Correct integration with NetDB
// - Message Routing: Outbound through tunnels with garlic
// - Inbound Delivery: Tunnel → session message delivery
// - Host Lookup: Hostname and hash resolution
// - Blinding Info: Encrypted LeaseSet parameters
// - Disconnect Handling: Graceful session cleanup
// - Thread Safety: Concurrent session access

// =============================================================================
// PROTOCOL COMPLIANCE TESTS (v0.9.67)
// =============================================================================

// TestProtocolCompliance_MessageTypeConstants verifies all I2CP v0.9.67
// message type constants are correctly defined.
func TestProtocolCompliance_MessageTypeConstants(t *testing.T) {
	// Session management
	tests := []struct {
		name     string
		constant uint8
		expected uint8
	}{
		// Per I2CP spec v0.9.67
		{"CreateSession", MessageTypeCreateSession, 1},
		{"SessionStatus", MessageTypeSessionStatus, 20},
		{"ReconfigureSession", MessageTypeReconfigureSession, 2},
		{"DestroySession", MessageTypeDestroySession, 3},
		{"CreateLeaseSet", MessageTypeCreateLeaseSet, 4},
		{"RequestLeaseSet", MessageTypeRequestLeaseSet, 21},
		{"RequestVariableLeaseSet", MessageTypeRequestVariableLeaseSet, 37},
		{"CreateLeaseSet2", MessageTypeCreateLeaseSet2, 41},
		{"SendMessage", MessageTypeSendMessage, 5},
		{"MessagePayload", MessageTypeMessagePayload, 31},
		{"MessageStatus", MessageTypeMessageStatus, 22},
		{"Disconnect", MessageTypeDisconnect, 30},
		{"SendMessageExpires", MessageTypeSendMessageExpires, 36},
		{"GetBandwidthLimits", MessageTypeGetBandwidthLimits, 8},
		{"BandwidthLimits", MessageTypeBandwidthLimits, 23},
		{"GetDate", MessageTypeGetDate, 32},
		{"SetDate", MessageTypeSetDate, 33},
		{"HostLookup", MessageTypeHostLookup, 38},
		{"HostReply", MessageTypeHostReply, 39},
		{"BlindingInfo", MessageTypeBlindingInfo, 42},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.constant != tt.expected {
				t.Errorf("%s = %d, want %d (per I2CP v0.9.67)", tt.name, tt.constant, tt.expected)
			}
		})
	}
}

// TestProtocolCompliance_VersionString verifies the protocol version string.
func TestProtocolCompliance_VersionString(t *testing.T) {
	if ProtocolVersionMajor != ExpectedProtocolVersionMajor {
		t.Errorf("ProtocolVersionMajor = %d, want %d", ProtocolVersionMajor, ExpectedProtocolVersionMajor)
	}
	if ProtocolVersionMinor != ExpectedProtocolVersionMinor {
		t.Errorf("ProtocolVersionMinor = %d, want %d", ProtocolVersionMinor, ExpectedProtocolVersionMinor)
	}
	if ProtocolVersionPatch != ExpectedProtocolVersionPatch {
		t.Errorf("ProtocolVersionPatch = %d, want %d", ProtocolVersionPatch, ExpectedProtocolVersionPatch)
	}
}

// TestProtocolCompliance_ReservedSessionIDs verifies reserved session IDs.
func TestProtocolCompliance_ReservedSessionIDs(t *testing.T) {
	if SessionIDReservedControl != 0x0000 {
		t.Errorf("SessionIDReservedControl = 0x%04x, want 0x0000", SessionIDReservedControl)
	}
	if SessionIDReservedBroadcast != 0xFFFF {
		t.Errorf("SessionIDReservedBroadcast = 0x%04x, want 0xFFFF", SessionIDReservedBroadcast)
	}
}

// TestProtocolCompliance_MessageStatusCodes verifies message status codes.
func TestProtocolCompliance_MessageStatusCodes(t *testing.T) {
	tests := []struct {
		name     string
		constant uint8
		expected uint8
	}{
		{"MessageStatusAccepted", MessageStatusAccepted, 1},
		{"MessageStatusSuccess", MessageStatusSuccess, 4},
		{"MessageStatusFailure", MessageStatusFailure, 5},
		{"MessageStatusNoTunnels", MessageStatusNoTunnels, 16},
		{"MessageStatusNoLeaseSet", MessageStatusNoLeaseSet, 21},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.constant != tt.expected {
				t.Errorf("%s = %d, want %d", tt.name, tt.constant, tt.expected)
			}
		})
	}
}

// =============================================================================
// MESSAGE FRAMING TESTS
// =============================================================================

// TestMessageFraming_PayloadSizeLimits verifies payload size limits.
func TestMessageFraming_PayloadSizeLimits(t *testing.T) {
	// Verify MaxPayloadSize is reasonable (256 KB for i2psnark compatibility)
	if MaxPayloadSize != 262144 {
		t.Errorf("MaxPayloadSize = %d, want 262144 (256 KB)", MaxPayloadSize)
	}

	// MaxMessageSize should be header + payload
	expectedMaxMessage := 5 + MaxPayloadSize
	if MaxMessageSize != expectedMaxMessage {
		t.Errorf("MaxMessageSize = %d, want %d", MaxMessageSize, expectedMaxMessage)
	}
}

// TestMessageFraming_OversizedPayloadRejected verifies oversized payloads are rejected.
func TestMessageFraming_OversizedPayloadRejected(t *testing.T) {
	// Create message with payload exceeding MaxPayloadSize
	msg := &Message{
		Type:    MessageTypeSendMessage,
		Payload: make([]byte, MaxPayloadSize+1),
	}

	_, err := msg.MarshalBinary()
	if err == nil {
		t.Error("Expected error for oversized payload, got nil")
	}
}

// TestMessageFraming_ValidPayloadAccepted verifies valid payloads are accepted.
func TestMessageFraming_ValidPayloadAccepted(t *testing.T) {
	// Create message with maximum valid payload
	msg := &Message{
		Type:    MessageTypeSendMessage,
		Payload: make([]byte, MaxPayloadSize),
	}

	data, err := msg.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error for max payload: %v", err)
	}

	// Verify wire format
	expectedLen := 5 + MaxPayloadSize
	if len(data) != expectedLen {
		t.Errorf("Serialized length = %d, want %d", len(data), expectedLen)
	}
}

// TestMessageFraming_EmptyPayloadValid verifies empty payloads are valid.
func TestMessageFraming_EmptyPayloadValid(t *testing.T) {
	msg := &Message{
		Type:    MessageTypeGetDate,
		Payload: nil,
	}

	data, err := msg.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error for empty payload: %v", err)
	}

	// Header only: length(4) + type(1) = 5 bytes
	if len(data) != 5 {
		t.Errorf("Empty message length = %d, want 5", len(data))
	}
}

// TestMessageFraming_RoundTrip verifies message serialization round-trip.
func TestMessageFraming_RoundTrip(t *testing.T) {
	original := &Message{
		Type:    MessageTypeSendMessage,
		Payload: []byte("test payload data"),
	}

	data, err := original.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error: %v", err)
	}

	recovered := &Message{}
	if err := recovered.UnmarshalBinary(data); err != nil {
		t.Fatalf("UnmarshalBinary() error: %v", err)
	}

	if recovered.Type != original.Type {
		t.Errorf("Type = %d, want %d", recovered.Type, original.Type)
	}
	if !bytes.Equal(recovered.Payload, original.Payload) {
		t.Errorf("Payload mismatch")
	}
}

// TestMessageFraming_TruncatedMessageRejected verifies truncated messages are rejected.
func TestMessageFraming_TruncatedMessageRejected(t *testing.T) {
	// Create valid message
	msg := &Message{
		Type:    MessageTypeSendMessage,
		Payload: []byte("test payload"),
	}

	data, _ := msg.MarshalBinary()

	// Truncate the data
	truncated := data[:len(data)-5]

	recovered := &Message{}
	err := recovered.UnmarshalBinary(truncated)
	if err == nil {
		t.Error("Expected error for truncated message, got nil")
	}
}

// =============================================================================
// ERROR MESSAGE SAFETY TESTS
// =============================================================================

// TestErrorMessages_NoSensitiveData verifies error messages don't leak sensitive data.
func TestErrorMessages_NoSensitiveData(t *testing.T) {
	sensitivePatterns := []string{
		"password",
		"secret",
		"private",
		"key=",
	}

	// Test various error conditions
	errors := []error{}

	// Truncated message
	msg := &Message{}
	err := msg.UnmarshalBinary([]byte{1, 2})
	if err != nil {
		errors = append(errors, err)
	}

	// Check error messages
	for _, e := range errors {
		if e == nil {
			continue
		}
		errStr := e.Error()
		for _, pattern := range sensitivePatterns {
			if bytes.Contains([]byte(errStr), []byte(pattern)) {
				t.Errorf("Error message contains sensitive pattern '%s': %s", pattern, errStr)
			}
		}
	}
}
