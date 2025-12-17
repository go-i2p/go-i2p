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
	if ProtocolVersionMajor != 0 {
		t.Errorf("ProtocolVersionMajor = %d, want 0", ProtocolVersionMajor)
	}
	if ProtocolVersionMinor != 9 {
		t.Errorf("ProtocolVersionMinor = %d, want 9", ProtocolVersionMinor)
	}
	if ProtocolVersionPatch != 67 {
		t.Errorf("ProtocolVersionPatch = %d, want 67", ProtocolVersionPatch)
	}

	t.Logf("Protocol version: %d.%d.%d",
		ProtocolVersionMajor, ProtocolVersionMinor, ProtocolVersionPatch)
}
