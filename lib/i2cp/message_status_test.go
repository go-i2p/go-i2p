package i2cp

import (
	"encoding/binary"
	"testing"
)

// TestMessageStatusConstants verifies all message status codes are defined correctly.
func TestMessageStatusConstants(t *testing.T) {
	tests := []struct {
		name     string
		code     uint8
		expected uint8
	}{
		{"Accepted", MessageStatusAccepted, 1},
		{"Success", MessageStatusSuccess, 4},
		{"Failure", MessageStatusFailure, 5},
		{"NoTunnels", MessageStatusNoTunnels, 16},
		{"NoLeaseSet", MessageStatusNoLeaseSet, 21},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.code != tt.expected {
				t.Errorf("MessageStatus%s = %d, want %d", tt.name, tt.code, tt.expected)
			}
		})
	}
}

// TestMessageTypeMessageStatus verifies the MessageStatus type constant.
func TestMessageTypeMessageStatus(t *testing.T) {
	if MessageTypeMessageStatus != 22 {
		t.Errorf("MessageTypeMessageStatus = %d, want 22", MessageTypeMessageStatus)
	}

	// Verify MessageTypeName includes MessageStatus
	name := MessageTypeName(MessageTypeMessageStatus)
	if name != "MessageStatus" {
		t.Errorf("MessageTypeName(22) = %q, want \"MessageStatus\"", name)
	}
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

// TestMessageStatusUnmarshal verifies a MessageStatus message can be unmarshaled.
func TestMessageStatusUnmarshal(t *testing.T) {
	// Create a MessageStatus message
	originalMsg := buildMessageStatusResponse(50, 99999, MessageStatusFailure, 1024, 5555)

	// Marshal it
	data, err := originalMsg.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}

	// Unmarshal it
	var parsedMsg Message
	if err := parsedMsg.UnmarshalBinary(data); err != nil {
		t.Fatalf("UnmarshalBinary() error = %v", err)
	}

	// Verify message fields match
	if parsedMsg.Type != originalMsg.Type {
		t.Errorf("Type = %d, want %d", parsedMsg.Type, originalMsg.Type)
	}

	// Per I2CP spec: SessionID is NOT in common header, it's in the payload
	// UnmarshalBinary sets SessionID=0, we must extract it from payload
	if len(parsedMsg.Payload) >= 2 {
		payloadSessionID := binary.BigEndian.Uint16(parsedMsg.Payload[0:2])
		if payloadSessionID != originalMsg.SessionID {
			t.Errorf("Payload SessionID = %d, want %d", payloadSessionID, originalMsg.SessionID)
		}
	} else {
		t.Fatalf("Payload too short to contain SessionID")
	}

	if len(parsedMsg.Payload) != len(originalMsg.Payload) {
		t.Fatalf("Payload length = %d, want %d", len(parsedMsg.Payload), len(originalMsg.Payload))
	}

	// Verify payload bytes match
	for i := range parsedMsg.Payload {
		if parsedMsg.Payload[i] != originalMsg.Payload[i] {
			t.Errorf("Payload[%d] = %d, want %d", i, parsedMsg.Payload[i], originalMsg.Payload[i])
		}
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
	// According to I2CP spec v2.10.0, MessageStatus payload is:
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
