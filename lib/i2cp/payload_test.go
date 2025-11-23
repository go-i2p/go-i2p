package i2cp

import (
	"bytes"
	"testing"

	"github.com/go-i2p/common/data"
)

// TestParseSendMessagePayload tests parsing of SendMessage payloads
func TestParseSendMessagePayload(t *testing.T) {
	tests := []struct {
		name          string
		input         []byte
		wantErr       bool
		expectedDest  data.Hash
		expectedSize  int
		errorContains string
	}{
		{
			name: "Valid payload with data",
			input: func() []byte {
				// Create 32-byte destination + message payload
				dest := make([]byte, 32)
				for i := 0; i < 32; i++ {
					dest[i] = byte(i)
				}
				payload := []byte("Hello, I2P!")
				return append(dest, payload...)
			}(),
			wantErr: false,
			expectedDest: func() data.Hash {
				var h data.Hash
				for i := 0; i < 32; i++ {
					h[i] = byte(i)
				}
				return h
			}(),
			expectedSize: len("Hello, I2P!"),
		},
		{
			name: "Valid payload with empty message",
			input: func() []byte {
				dest := make([]byte, 32)
				for i := 0; i < 32; i++ {
					dest[i] = byte(255 - i)
				}
				return dest
			}(),
			wantErr: false,
			expectedDest: func() data.Hash {
				var h data.Hash
				for i := 0; i < 32; i++ {
					h[i] = byte(255 - i)
				}
				return h
			}(),
			expectedSize: 0,
		},
		{
			name:          "Too short - empty",
			input:         []byte{},
			wantErr:       true,
			errorContains: "too short",
		},
		{
			name:          "Too short - only 16 bytes",
			input:         make([]byte, 16),
			wantErr:       true,
			errorContains: "too short",
		},
		{
			name:          "Too short - 31 bytes",
			input:         make([]byte, 31),
			wantErr:       true,
			errorContains: "too short",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseSendMessagePayload(tt.input)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseSendMessagePayload() expected error, got nil")
				} else if tt.errorContains != "" && !bytes.Contains([]byte(err.Error()), []byte(tt.errorContains)) {
					t.Errorf("ParseSendMessagePayload() error = %v, should contain %q", err, tt.errorContains)
				}
				return
			}

			if err != nil {
				t.Errorf("ParseSendMessagePayload() unexpected error = %v", err)
				return
			}

			if result == nil {
				t.Fatalf("ParseSendMessagePayload() returned nil result")
			}

			// Verify destination hash
			if result.Destination != tt.expectedDest {
				t.Errorf("Destination mismatch: got %x, want %x", result.Destination, tt.expectedDest)
			}

			// Verify payload size
			if len(result.Payload) != tt.expectedSize {
				t.Errorf("Payload size mismatch: got %d, want %d", len(result.Payload), tt.expectedSize)
			}
		})
	}
}

// TestSendMessagePayloadMarshalBinary tests marshaling of SendMessagePayload
func TestSendMessagePayloadMarshalBinary(t *testing.T) {
	// Create test destination hash
	var destHash data.Hash
	for i := 0; i < 32; i++ {
		destHash[i] = byte(i * 2)
	}

	payload := []byte("Test message payload")

	smp := &SendMessagePayload{
		Destination: destHash,
		Payload:     payload,
	}

	// Marshal
	data, err := smp.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}

	// Verify total size
	expectedSize := 32 + len(payload)
	if len(data) != expectedSize {
		t.Errorf("Marshaled size = %d, want %d", len(data), expectedSize)
	}

	// Verify destination hash
	for i := 0; i < 32; i++ {
		if data[i] != byte(i*2) {
			t.Errorf("Destination byte %d = %d, want %d", i, data[i], i*2)
		}
	}

	// Verify payload
	if !bytes.Equal(data[32:], payload) {
		t.Errorf("Payload mismatch: got %v, want %v", data[32:], payload)
	}
}

// TestSendMessagePayloadRoundTrip tests marshal/unmarshal round trip
func TestSendMessagePayloadRoundTrip(t *testing.T) {
	var destHash data.Hash
	copy(destHash[:], []byte("this_is_a_32_byte_destination!!"))

	original := &SendMessagePayload{
		Destination: destHash,
		Payload:     []byte("Round trip test payload"),
	}

	// Marshal
	data, err := original.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}

	// Unmarshal
	result, err := ParseSendMessagePayload(data)
	if err != nil {
		t.Fatalf("ParseSendMessagePayload() error = %v", err)
	}

	// Compare
	if result.Destination != original.Destination {
		t.Errorf("Destination mismatch after round trip")
	}

	if !bytes.Equal(result.Payload, original.Payload) {
		t.Errorf("Payload mismatch after round trip")
	}
}

// TestParseMessagePayloadPayload tests parsing of MessagePayload payloads
func TestParseMessagePayloadPayload(t *testing.T) {
	tests := []struct {
		name          string
		input         []byte
		wantErr       bool
		expectedMsgID uint32
		expectedSize  int
		errorContains string
	}{
		{
			name: "Valid payload with data",
			input: func() []byte {
				// MessageID (4 bytes) + payload
				data := make([]byte, 4)
				data[0] = 0x00
				data[1] = 0x00
				data[2] = 0x12
				data[3] = 0x34 // MessageID = 0x1234 = 4660
				return append(data, []byte("Received message")...)
			}(),
			wantErr:       false,
			expectedMsgID: 0x1234,
			expectedSize:  len("Received message"),
		},
		{
			name: "Valid payload with empty message",
			input: func() []byte {
				data := make([]byte, 4)
				data[0] = 0xFF
				data[1] = 0xFF
				data[2] = 0xFF
				data[3] = 0xFF // MessageID = 0xFFFFFFFF
				return data
			}(),
			wantErr:       false,
			expectedMsgID: 0xFFFFFFFF,
			expectedSize:  0,
		},
		{
			name:          "Too short - empty",
			input:         []byte{},
			wantErr:       true,
			errorContains: "too short",
		},
		{
			name:          "Too short - only 2 bytes",
			input:         make([]byte, 2),
			wantErr:       true,
			errorContains: "too short",
		},
		{
			name:          "Too short - 3 bytes",
			input:         make([]byte, 3),
			wantErr:       true,
			errorContains: "too short",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseMessagePayloadPayload(tt.input)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseMessagePayloadPayload() expected error, got nil")
				} else if tt.errorContains != "" && !bytes.Contains([]byte(err.Error()), []byte(tt.errorContains)) {
					t.Errorf("ParseMessagePayloadPayload() error = %v, should contain %q", err, tt.errorContains)
				}
				return
			}

			if err != nil {
				t.Errorf("ParseMessagePayloadPayload() unexpected error = %v", err)
				return
			}

			if result == nil {
				t.Fatalf("ParseMessagePayloadPayload() returned nil result")
			}

			// Verify message ID
			if result.MessageID != tt.expectedMsgID {
				t.Errorf("MessageID mismatch: got %d, want %d", result.MessageID, tt.expectedMsgID)
			}

			// Verify payload size
			if len(result.Payload) != tt.expectedSize {
				t.Errorf("Payload size mismatch: got %d, want %d", len(result.Payload), tt.expectedSize)
			}
		})
	}
}

// TestMessagePayloadPayloadMarshalBinary tests marshaling of MessagePayloadPayload
func TestMessagePayloadPayloadMarshalBinary(t *testing.T) {
	payload := []byte("Inbound message data")

	mpp := &MessagePayloadPayload{
		MessageID: 0x00ABCDEF,
		Payload:   payload,
	}

	// Marshal
	data, err := mpp.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}

	// Verify total size
	expectedSize := 4 + len(payload)
	if len(data) != expectedSize {
		t.Errorf("Marshaled size = %d, want %d", len(data), expectedSize)
	}

	// Verify message ID (big endian)
	if data[0] != 0x00 || data[1] != 0xAB || data[2] != 0xCD || data[3] != 0xEF {
		t.Errorf("MessageID bytes incorrect: got [%02x %02x %02x %02x]", data[0], data[1], data[2], data[3])
	}

	// Verify payload
	if !bytes.Equal(data[4:], payload) {
		t.Errorf("Payload mismatch: got %v, want %v", data[4:], payload)
	}
}

// TestMessagePayloadPayloadRoundTrip tests marshal/unmarshal round trip
func TestMessagePayloadPayloadRoundTrip(t *testing.T) {
	original := &MessagePayloadPayload{
		MessageID: 12345,
		Payload:   []byte("Round trip message payload test"),
	}

	// Marshal
	data, err := original.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}

	// Unmarshal
	result, err := ParseMessagePayloadPayload(data)
	if err != nil {
		t.Fatalf("ParseMessagePayloadPayload() error = %v", err)
	}

	// Compare
	if result.MessageID != original.MessageID {
		t.Errorf("MessageID mismatch after round trip: got %d, want %d", result.MessageID, original.MessageID)
	}

	if !bytes.Equal(result.Payload, original.Payload) {
		t.Errorf("Payload mismatch after round trip")
	}
}

// TestSendMessagePayloadEmptyPayload tests handling of empty payload
func TestSendMessagePayloadEmptyPayload(t *testing.T) {
	var destHash data.Hash
	copy(destHash[:], make([]byte, 32)) // All zeros

	smp := &SendMessagePayload{
		Destination: destHash,
		Payload:     []byte{}, // Empty payload
	}

	// Marshal
	data, err := smp.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}

	// Should be exactly 32 bytes (just the destination)
	if len(data) != 32 {
		t.Errorf("Marshaled size = %d, want 32", len(data))
	}

	// Unmarshal
	result, err := ParseSendMessagePayload(data)
	if err != nil {
		t.Fatalf("ParseSendMessagePayload() error = %v", err)
	}

	if len(result.Payload) != 0 {
		t.Errorf("Expected empty payload, got %d bytes", len(result.Payload))
	}
}

// TestMessagePayloadPayloadZeroID tests handling of message ID = 0
func TestMessagePayloadPayloadZeroID(t *testing.T) {
	mpp := &MessagePayloadPayload{
		MessageID: 0,
		Payload:   []byte("Message with ID 0"),
	}

	// Marshal
	data, err := mpp.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}

	// Unmarshal
	result, err := ParseMessagePayloadPayload(data)
	if err != nil {
		t.Fatalf("ParseMessagePayloadPayload() error = %v", err)
	}

	if result.MessageID != 0 {
		t.Errorf("MessageID should be 0, got %d", result.MessageID)
	}
}

// BenchmarkParseSendMessagePayload benchmarks SendMessage parsing
func BenchmarkParseSendMessagePayload(b *testing.B) {
	// Create test data
	data := make([]byte, 32+512) // 32-byte dest + 512-byte payload
	for i := 0; i < len(data); i++ {
		data[i] = byte(i)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParseSendMessagePayload(data)
	}
}

// BenchmarkParseMessagePayloadPayload benchmarks MessagePayload parsing
func BenchmarkParseMessagePayloadPayload(b *testing.B) {
	// Create test data
	data := make([]byte, 4+512) // 4-byte ID + 512-byte payload
	for i := 0; i < len(data); i++ {
		data[i] = byte(i)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParseMessagePayloadPayload(data)
	}
}
