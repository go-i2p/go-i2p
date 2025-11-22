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

			// Validate structure
			if len(data) < 7 {
				t.Errorf("Marshaled data too short: %d bytes", len(data))
				return
			}

			// Unmarshal
			got := &Message{}
			if err := got.UnmarshalBinary(data); err != nil {
				t.Errorf("UnmarshalBinary() error = %v", err)
				return
			}

			// Compare
			if got.Type != tt.msg.Type {
				t.Errorf("Type mismatch: got %d, want %d", got.Type, tt.msg.Type)
			}
			if got.SessionID != tt.msg.SessionID {
				t.Errorf("SessionID mismatch: got 0x%04X, want 0x%04X", got.SessionID, tt.msg.SessionID)
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

	// Compare
	if got.Type != original.Type {
		t.Errorf("Type mismatch: got %d, want %d", got.Type, original.Type)
	}
	if got.SessionID != original.SessionID {
		t.Errorf("SessionID mismatch: got 0x%04X, want 0x%04X", got.SessionID, original.SessionID)
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
