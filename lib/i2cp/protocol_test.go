package i2cp

import (
	"bytes"
	"testing"
)

func TestMessageMarshalUnmarshal(t *testing.T) {
	tests := []struct {
		name    string
		msg     *Message
		wantErr bool
	}{
		{
			name: "CreateSession message",
			msg: &Message{
				Type:      MessageTypeCreateSession,
				SessionID: 0x0000,
				Payload:   []byte{0x01, 0x02, 0x03},
			},
			wantErr: false,
		},
		{
			name: "SessionStatus with session ID",
			msg: &Message{
				Type:      MessageTypeSessionStatus,
				SessionID: 0x1234,
				Payload:   []byte{0x00}, // Success status
			},
			wantErr: false,
		},
		{
			name: "Empty payload",
			msg: &Message{
				Type:      MessageTypeDestroySession,
				SessionID: 0x5678,
				Payload:   []byte{},
			},
			wantErr: false,
		},
		{
			name: "Large payload",
			msg: &Message{
				Type:      MessageTypeSendMessage,
				SessionID: 0xABCD,
				Payload:   make([]byte, 1024),
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Marshal
			data, err := tt.msg.MarshalBinary()
			if (err != nil) != tt.wantErr {
				t.Errorf("MarshalBinary() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}

			// Validate structure: header should be 5 bytes (length + type) per I2CP spec
			if len(data) < 5 {
				t.Errorf("Marshaled data too short: %d bytes", len(data))
				return
			}

			// Unmarshal
			got := &Message{}
			if err := got.UnmarshalBinary(data); err != nil {
				t.Errorf("UnmarshalBinary() error = %v", err)
				return
			}

			// Compare: Type and Payload should match
			// SessionID is NOT in wire format, so it won't be preserved
			if got.Type != tt.msg.Type {
				t.Errorf("Type mismatch: got %d, want %d", got.Type, tt.msg.Type)
			}
			if got.SessionID != 0 {
				t.Errorf("SessionID should be 0 after unmarshal (not in wire format), got 0x%04X", got.SessionID)
			}
			if !bytes.Equal(got.Payload, tt.msg.Payload) {
				t.Errorf("Payload mismatch: got %v, want %v", got.Payload, tt.msg.Payload)
			}
		})
	}
}

func TestMessageUnmarshalErrors(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr string
	}{
		{
			name:    "Too short - empty",
			data:    []byte{},
			wantErr: "too short",
		},
		{
			name:    "Too short - only type",
			data:    []byte{0x01},
			wantErr: "too short",
		},
		{
			name:    "Too short - missing payload length",
			data:    []byte{0x01, 0x00, 0x01},
			wantErr: "too short",
		},
		{
			name:    "Truncated payload",
			data:    []byte{0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x10}, // Claims 16 bytes payload but none provided
			wantErr: "truncated",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := &Message{}
			err := msg.UnmarshalBinary(tt.data)
			if err == nil {
				t.Errorf("Expected error containing %q, got nil", tt.wantErr)
				return
			}
			if tt.wantErr != "" && !bytes.Contains([]byte(err.Error()), []byte(tt.wantErr)) {
				t.Errorf("Error %q does not contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestReadWriteMessage(t *testing.T) {
	original := &Message{
		Type:      MessageTypeCreateSession,
		SessionID: 0x4242,
		Payload:   []byte("test payload"),
	}

	// Write to buffer
	buf := &bytes.Buffer{}
	if err := WriteMessage(buf, original); err != nil {
		t.Fatalf("WriteMessage() error = %v", err)
	}

	// Read from buffer
	got, err := ReadMessage(buf)
	if err != nil {
		t.Fatalf("ReadMessage() error = %v", err)
	}

	// Compare: Type and Payload should match
	// SessionID is NOT in wire format per I2CP spec, so it won't be preserved
	if got.Type != original.Type {
		t.Errorf("Type mismatch: got %d, want %d", got.Type, original.Type)
	}
	if got.SessionID != 0 {
		t.Errorf("SessionID should be 0 after read (not in wire format), got 0x%04X", got.SessionID)
	}
	if !bytes.Equal(got.Payload, original.Payload) {
		t.Errorf("Payload mismatch: got %v, want %v", got.Payload, original.Payload)
	}
}

func TestMessageTypeName(t *testing.T) {
	tests := []struct {
		msgType uint8
		want    string
	}{
		{MessageTypeCreateSession, "CreateSession"},
		{MessageTypeSessionStatus, "SessionStatus"},
		{MessageTypeSendMessage, "SendMessage"},
		{MessageTypeMessagePayload, "MessagePayload"},
		{MessageTypeDestroySession, "DestroySession"},
		{255, "Unknown(255)"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := MessageTypeName(tt.msgType)
			if got != tt.want {
				t.Errorf("MessageTypeName(%d) = %q, want %q", tt.msgType, got, tt.want)
			}
		})
	}
}

func TestReservedSessionIDs(t *testing.T) {
	// Verify reserved session IDs are as expected
	if SessionIDReservedControl != 0x0000 {
		t.Errorf("SessionIDReservedControl = 0x%04X, want 0x0000", SessionIDReservedControl)
	}
	if SessionIDReservedBroadcast != 0xFFFF {
		t.Errorf("SessionIDReservedBroadcast = 0x%04X, want 0xFFFF", SessionIDReservedBroadcast)
	}
}

func BenchmarkMessageMarshal(b *testing.B) {
	msg := &Message{
		Type:      MessageTypeSendMessage,
		SessionID: 0x1234,
		Payload:   make([]byte, 512),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = msg.MarshalBinary()
	}
}

func BenchmarkMessageUnmarshal(b *testing.B) {
	msg := &Message{
		Type:      MessageTypeSendMessage,
		SessionID: 0x1234,
		Payload:   make([]byte, 512),
	}
	data, _ := msg.MarshalBinary()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m := &Message{}
		_ = m.UnmarshalBinary(data)
	}
}

// TestMessagePayloadSizeLimit verifies that I2CP enforces the payload size limit.
// Limit increased to 256 KB for i2psnark compatibility (from original 64 KB assumption).
func TestMessagePayloadSizeLimit(t *testing.T) {
	tests := []struct {
		name        string
		payloadSize int
		wantErr     bool
		errContains string
	}{
		{
			name:        "Maximum allowed size (256 KB for i2psnark compatibility)",
			payloadSize: MaxPayloadSize,
			wantErr:     false,
		},
		{
			name:        "Just under maximum",
			payloadSize: MaxPayloadSize - 1000,
			wantErr:     false,
		},
		{
			name:        "Exceeds maximum by 1 byte",
			payloadSize: MaxPayloadSize + 1,
			wantErr:     true,
			errContains: "too large",
		},
		{
			name:        "Significantly exceeds maximum",
			payloadSize: MaxPayloadSize * 2,
			wantErr:     true,
			errContains: "too large",
		},
		{
			name:        "Empty payload",
			payloadSize: 0,
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := &Message{
				Type:      MessageTypeSendMessage,
				SessionID: 0x1234,
				Payload:   make([]byte, tt.payloadSize),
			}

			_, err := msg.MarshalBinary()

			if tt.wantErr {
				if err == nil {
					t.Errorf("Expected error for payload size %d, got nil", tt.payloadSize)
					return
				}
				if tt.errContains != "" && !bytes.Contains([]byte(err.Error()), []byte(tt.errContains)) {
					t.Errorf("Error %q does not contain %q", err.Error(), tt.errContains)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for payload size %d: %v", tt.payloadSize, err)
				}
			}
		})
	}
}

// TestReadMessagePayloadSizeLimit verifies that reading messages enforces the size limit
func TestReadMessagePayloadSizeLimit(t *testing.T) {
	// Create a message header claiming an oversized payload
	// Per I2CP spec: header is length(4) + type(1)
	oversizedLength := uint32(MaxPayloadSize + 1000)

	header := make([]byte, 5)
	// Length (4 bytes, big endian)
	header[0] = byte(oversizedLength >> 24)
	header[1] = byte(oversizedLength >> 16)
	header[2] = byte(oversizedLength >> 8)
	header[3] = byte(oversizedLength)
	// Type (1 byte)
	header[4] = MessageTypeSendMessage

	buf := bytes.NewBuffer(header)

	_, err := ReadMessage(buf)
	if err == nil {
		t.Error("Expected error when reading oversized message, got nil")
		return
	}

	if !bytes.Contains([]byte(err.Error()), []byte("too large")) {
		t.Errorf("Error %q does not contain 'too large'", err.Error())
	}
}

// TestProtocolConstants verifies I2CP protocol constants
func TestProtocolConstants(t *testing.T) {
	// Test protocol version
	if ProtocolVersionMajor != 9 {
		t.Errorf("ProtocolVersionMajor = %d, want 0", ProtocolVersionMajor)
	}
	if ProtocolVersionMinor != 67 {
		t.Errorf("ProtocolVersionMinor = %d, want 9", ProtocolVersionMinor)
	}
	if ProtocolVersionPatch != 0 {
		t.Errorf("ProtocolVersionPatch = %d, want 67", ProtocolVersionPatch)
	}

	// Test reserved session IDs
	if SessionIDReservedControl != 0x0000 {
		t.Errorf("SessionIDReservedControl = 0x%04X, want 0x0000", SessionIDReservedControl)
	}
	if SessionIDReservedBroadcast != 0xFFFF {
		t.Errorf("SessionIDReservedBroadcast = 0x%04X, want 0xFFFF", SessionIDReservedBroadcast)
	}

	// Test critical message type constants
	if MessageTypeCreateSession != 1 {
		t.Errorf("MessageTypeCreateSession = %d, want 1", MessageTypeCreateSession)
	}
	if MessageTypeRequestVariableLeaseSet != 37 {
		t.Errorf("MessageTypeRequestVariableLeaseSet = %d, want 37", MessageTypeRequestVariableLeaseSet)
	}
	if MessageTypeCreateLeaseSet2 != 41 {
		t.Errorf("MessageTypeCreateLeaseSet2 = %d, want 41", MessageTypeCreateLeaseSet2)
	}
}

// TestMessageTypeNames verifies message type name lookups
func TestMessageTypeNames(t *testing.T) {
	tests := []struct {
		msgType uint8
		want    string
	}{
		{MessageTypeCreateSession, "CreateSession"},
		{MessageTypeSessionStatus, "SessionStatus"},
		{MessageTypeRequestVariableLeaseSet, "RequestVariableLeaseSet"},
		{MessageTypeCreateLeaseSet2, "CreateLeaseSet2"},
		{255, "Unknown(255)"}, // Unknown type
	}

	for _, tt := range tests {
		got := MessageTypeName(tt.msgType)
		if got != tt.want {
			t.Errorf("MessageTypeName(%d) = %q, want %q", tt.msgType, got, tt.want)
		}
	}
}
