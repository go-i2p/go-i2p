package i2cp

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

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
				// SessionID (2 bytes) + MessageID (4 bytes) + payload
				data := make([]byte, 6)
				data[0] = 0x00
				data[1] = 0x01 // SessionID = 0x0001
				data[2] = 0x00
				data[3] = 0x00
				data[4] = 0x12
				data[5] = 0x34 // MessageID = 0x00001234 = 4660
				return append(data, []byte("Received message")...)
			}(),
			wantErr:       false,
			expectedMsgID: 0x1234,
			expectedSize:  len("Received message"),
		},
		{
			name: "Valid payload with empty message",
			input: func() []byte {
				// SessionID (2 bytes) + MessageID (4 bytes), no payload
				data := make([]byte, 6)
				data[0] = 0x00
				data[1] = 0x02 // SessionID = 0x0002
				data[2] = 0xFF
				data[3] = 0xFF
				data[4] = 0xFF
				data[5] = 0xFF // MessageID = 0xFFFFFFFF
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
		SessionID: 0x1234,
		MessageID: 0x00ABCDEF,
		Payload:   payload,
	}

	// Marshal
	data, err := mpp.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}

	// Verify total size: SessionID(2) + MessageID(4) + payload
	expectedSize := 6 + len(payload)
	if len(data) != expectedSize {
		t.Errorf("Marshaled size = %d, want %d", len(data), expectedSize)
	}

	// Verify session ID (big endian)
	if data[0] != 0x12 || data[1] != 0x34 {
		t.Errorf("SessionID bytes incorrect: got [%02x %02x]", data[0], data[1])
	}

	// Verify message ID (big endian)
	if data[2] != 0x00 || data[3] != 0xAB || data[4] != 0xCD || data[5] != 0xEF {
		t.Errorf("MessageID bytes incorrect: got [%02x %02x %02x %02x]", data[2], data[3], data[4], data[5])
	}

	// Verify payload
	if !bytes.Equal(data[6:], payload) {
		t.Errorf("Payload mismatch: got %v, want %v", data[6:], payload)
	}
}

// TestMessagePayloadPayloadRoundTrip tests marshal/unmarshal round trip
func TestMessagePayloadPayloadRoundTrip(t *testing.T) {
	original := &MessagePayloadPayload{
		SessionID: 0x5678,
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
		SessionID: 0x9ABC,
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

func TestBlindingInfoPayloadParse(t *testing.T) {
	tests := []struct {
		name        string
		data        []byte
		wantEnabled bool
		wantSecret  []byte
		shouldError bool
	}{
		{
			name:        "disabled",
			data:        []byte{0x00},
			wantEnabled: false,
			wantSecret:  nil,
			shouldError: false,
		},
		{
			name:        "enabled_no_secret",
			data:        []byte{0x01},
			wantEnabled: true,
			wantSecret:  nil,
			shouldError: false,
		},
		{
			name: "enabled_with_secret",
			data: func() []byte {
				result := []byte{0x01}
				secret := make([]byte, 32)
				for i := range secret {
					secret[i] = byte(i)
				}
				result = append(result, secret...)
				return result
			}(),
			wantEnabled: true,
			wantSecret: func() []byte {
				secret := make([]byte, 32)
				for i := range secret {
					secret[i] = byte(i)
				}
				return secret
			}(),
			shouldError: false,
		},
		{
			name:        "empty",
			data:        []byte{},
			shouldError: true,
		},
		{
			name:        "invalid_secret_length_short",
			data:        []byte{0x01, 0x11, 0x22, 0x33}, // Only 3 bytes of secret
			shouldError: true,
		},
		{
			name: "invalid_secret_length_long",
			data: func() []byte {
				result := []byte{0x01}
				result = append(result, make([]byte, 33)...) // 33 bytes of secret
				return result
			}(),
			shouldError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload, err := ParseBlindingInfoPayload(tt.data)

			if tt.shouldError {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if payload.Enabled != tt.wantEnabled {
				t.Errorf("Enabled = %v, want %v", payload.Enabled, tt.wantEnabled)
			}

			if !bytes.Equal(payload.Secret, tt.wantSecret) {
				t.Errorf("Secret = %v, want %v", payload.Secret, tt.wantSecret)
			}
		})
	}
}

func TestBlindingInfoPayloadMarshal(t *testing.T) {
	tests := []struct {
		name        string
		payload     *BlindingInfoPayload
		wantSize    int
		shouldError bool
	}{
		{
			name: "disabled",
			payload: &BlindingInfoPayload{
				Enabled: false,
				Secret:  nil,
			},
			wantSize:    1,
			shouldError: false,
		},
		{
			name: "enabled_no_secret",
			payload: &BlindingInfoPayload{
				Enabled: true,
				Secret:  nil,
			},
			wantSize:    1,
			shouldError: false,
		},
		{
			name: "enabled_with_secret",
			payload: &BlindingInfoPayload{
				Enabled: true,
				Secret:  make([]byte, 32),
			},
			wantSize:    33,
			shouldError: false,
		},
		{
			name: "invalid_secret_length",
			payload: &BlindingInfoPayload{
				Enabled: true,
				Secret:  make([]byte, 16), // Wrong length
			},
			shouldError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.payload.MarshalBinary()

			if tt.shouldError {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("MarshalBinary() error: %v", err)
			}

			if len(data) != tt.wantSize {
				t.Errorf("data length = %d, want %d", len(data), tt.wantSize)
			}

			// Verify enabled flag
			if tt.payload.Enabled && data[0] != 0x01 {
				t.Errorf("enabled flag = 0x%02x, want 0x01", data[0])
			} else if !tt.payload.Enabled && data[0] != 0x00 {
				t.Errorf("enabled flag = 0x%02x, want 0x00", data[0])
			}

			// Verify secret if present
			if tt.payload.Enabled && len(tt.payload.Secret) == 32 {
				if !bytes.Equal(data[1:33], tt.payload.Secret) {
					t.Error("marshaled secret does not match input")
				}
			}
		})
	}
}

func TestBlindingInfoRoundTrip(t *testing.T) {
	tests := []struct {
		name    string
		payload *BlindingInfoPayload
	}{
		{
			name: "disabled",
			payload: &BlindingInfoPayload{
				Enabled: false,
				Secret:  nil,
			},
		},
		{
			name: "enabled_no_secret",
			payload: &BlindingInfoPayload{
				Enabled: true,
				Secret:  nil,
			},
		},
		{
			name: "enabled_with_secret",
			payload: &BlindingInfoPayload{
				Enabled: true,
				Secret: func() []byte {
					secret := make([]byte, 32)
					for i := range secret {
						secret[i] = byte(i * 7 % 256)
					}
					return secret
				}(),
			},
		},
		{
			name: "enabled_with_zero_secret",
			payload: &BlindingInfoPayload{
				Enabled: true,
				Secret:  make([]byte, 32),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.payload.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary() error: %v", err)
			}

			parsed, err := ParseBlindingInfoPayload(data)
			if err != nil {
				t.Fatalf("ParseBlindingInfoPayload() error: %v", err)
			}

			if parsed.Enabled != tt.payload.Enabled {
				t.Errorf("Enabled = %v, want %v", parsed.Enabled, tt.payload.Enabled)
			}

			if !bytes.Equal(parsed.Secret, tt.payload.Secret) {
				t.Errorf("Secret mismatch after round trip")
			}
		})
	}
}

func TestBlindingInfoConstants(t *testing.T) {
	if MessageTypeBlindingInfo != 42 {
		t.Errorf("MessageTypeBlindingInfo = %d, want 42", MessageTypeBlindingInfo)
	}

	if name := MessageTypeName(MessageTypeBlindingInfo); name != "BlindingInfo" {
		t.Errorf("MessageTypeName(BlindingInfo) = %q, want %q", name, "BlindingInfo")
	}
}

func TestBlindingInfoEnableDisable(t *testing.T) {
	// Test enabling blinding
	enablePayload := &BlindingInfoPayload{
		Enabled: true,
		Secret:  nil, // Random secret will be generated
	}
	enableData, err := enablePayload.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error: %v", err)
	}
	if len(enableData) != 1 {
		t.Errorf("enable payload length = %d, want 1", len(enableData))
	}
	if enableData[0] != 0x01 {
		t.Errorf("enable flag = 0x%02x, want 0x01", enableData[0])
	}

	// Test disabling blinding
	disablePayload := &BlindingInfoPayload{
		Enabled: false,
		Secret:  nil,
	}
	disableData, err := disablePayload.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error: %v", err)
	}
	if len(disableData) != 1 {
		t.Errorf("disable payload length = %d, want 1", len(disableData))
	}
	if disableData[0] != 0x00 {
		t.Errorf("disable flag = 0x%02x, want 0x00", disableData[0])
	}
}

func TestBlindingInfoSecretFormats(t *testing.T) {
	tests := []struct {
		name   string
		secret []byte
		valid  bool
	}{
		{
			name:   "nil_secret",
			secret: nil,
			valid:  true,
		},
		{
			name:   "valid_32_byte_secret",
			secret: make([]byte, 32),
			valid:  true,
		},
		{
			name:   "all_ones_secret",
			secret: bytes.Repeat([]byte{0xFF}, 32),
			valid:  true,
		},
		{
			name:   "all_zeros_secret",
			secret: bytes.Repeat([]byte{0x00}, 32),
			valid:  true,
		},
		{
			name:   "invalid_16_bytes",
			secret: make([]byte, 16),
			valid:  false,
		},
		{
			name:   "invalid_64_bytes",
			secret: make([]byte, 64),
			valid:  false,
		},
		{
			name:   "invalid_1_byte",
			secret: []byte{0x42},
			valid:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := &BlindingInfoPayload{
				Enabled: true,
				Secret:  tt.secret,
			}

			data, err := payload.MarshalBinary()

			if tt.valid {
				if err != nil {
					t.Errorf("unexpected error for valid secret: %v", err)
				}
				if tt.secret != nil && len(data) != 33 {
					t.Errorf("data length = %d, want 33", len(data))
				}
				if tt.secret == nil && len(data) != 1 {
					t.Errorf("data length = %d, want 1", len(data))
				}
			} else {
				if err == nil {
					t.Error("expected error for invalid secret length but got none")
				}
			}
		})
	}
}

// TestDisconnectPayloadParse tests parsing of Disconnect payload
func TestDisconnectPayloadParse(t *testing.T) {
	tests := []struct {
		name         string
		payload      []byte
		expectError  bool
		expectReason string
	}{
		{
			name: "empty_reason",
			payload: func() []byte {
				buf := make([]byte, 2)
				binary.BigEndian.PutUint16(buf[0:2], 0) // length = 0
				return buf
			}(),
			expectError:  false,
			expectReason: "",
		},
		{
			name: "short_reason",
			payload: func() []byte {
				reason := "timeout"
				buf := make([]byte, 2+len(reason))
				binary.BigEndian.PutUint16(buf[0:2], uint16(len(reason)))
				copy(buf[2:], reason)
				return buf
			}(),
			expectError:  false,
			expectReason: "timeout",
		},
		{
			name: "normal_reason",
			payload: func() []byte {
				reason := "client shutdown"
				buf := make([]byte, 2+len(reason))
				binary.BigEndian.PutUint16(buf[0:2], uint16(len(reason)))
				copy(buf[2:], reason)
				return buf
			}(),
			expectError:  false,
			expectReason: "client shutdown",
		},
		{
			name: "long_reason",
			payload: func() []byte {
				reason := "Connection terminated due to protocol version mismatch: expected 0.9.67, got 2.9.0"
				buf := make([]byte, 2+len(reason))
				binary.BigEndian.PutUint16(buf[0:2], uint16(len(reason)))
				copy(buf[2:], reason)
				return buf
			}(),
			expectError:  false,
			expectReason: "Connection terminated due to protocol version mismatch: expected 0.9.67, got 2.9.0",
		},
		{
			name: "utf8_reason",
			payload: func() []byte {
				reason := "クライアント終了" // "Client termination" in Japanese
				buf := make([]byte, 2+len(reason))
				binary.BigEndian.PutUint16(buf[0:2], uint16(len(reason)))
				copy(buf[2:], reason)
				return buf
			}(),
			expectError:  false,
			expectReason: "クライアント終了",
		},
		{
			name:        "too_short_no_length",
			payload:     make([]byte, 1), // Need at least 2 bytes
			expectError: true,
		},
		{
			name:        "empty_payload",
			payload:     []byte{},
			expectError: true,
		},
		{
			name: "incomplete_reason",
			payload: func() []byte {
				buf := make([]byte, 2+5) // Says 10 bytes but only has 5
				binary.BigEndian.PutUint16(buf[0:2], 10)
				copy(buf[2:], "short")
				return buf
			}(),
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := ParseDisconnectPayload(tt.payload)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if parsed.Reason != tt.expectReason {
				t.Errorf("Reason mismatch: got %q, want %q", parsed.Reason, tt.expectReason)
			}
		})
	}
}

// TestDisconnectPayloadMarshal tests marshaling of Disconnect payload
func TestDisconnectPayloadMarshal(t *testing.T) {
	tests := []struct {
		name   string
		reason string
	}{
		{"empty", ""},
		{"short", "bye"},
		{"normal", "client shutdown"},
		{"long", "Connection closed due to inactivity timeout after 300 seconds"},
		{"utf8", "再見"}, // "Goodbye" in Chinese
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dp := &DisconnectPayload{Reason: tt.reason}

			marshaled, err := dp.MarshalBinary()
			if err != nil {
				t.Fatalf("Marshal error: %v", err)
			}

			expectedSize := 2 + len(tt.reason)
			if len(marshaled) != expectedSize {
				t.Errorf("Marshaled size mismatch: got %d, want %d", len(marshaled), expectedSize)
			}

			// Verify length field
			reasonLen := binary.BigEndian.Uint16(marshaled[0:2])
			if reasonLen != uint16(len(tt.reason)) {
				t.Errorf("Length field mismatch: got %d, want %d", reasonLen, len(tt.reason))
			}

			// Verify reason string
			if len(tt.reason) > 0 {
				actualReason := string(marshaled[2:])
				if actualReason != tt.reason {
					t.Errorf("Reason mismatch: got %q, want %q", actualReason, tt.reason)
				}
			}
		})
	}
}

// TestDisconnectRoundTrip tests marshal/unmarshal integrity
func TestDisconnectRoundTrip(t *testing.T) {
	reasons := []string{
		"",
		"timeout",
		"client shutdown",
		"protocol error",
		"version mismatch",
		"Connection terminated by user request with a very long explanation that includes many details about why",
		"エラー発生", // "Error occurred" in Japanese
	}

	for _, reason := range reasons {
		t.Run("reason_"+reason, func(t *testing.T) {
			original := &DisconnectPayload{Reason: reason}

			// Marshal
			marshaled, err := original.MarshalBinary()
			if err != nil {
				t.Fatalf("Marshal error: %v", err)
			}

			// Unmarshal
			parsed, err := ParseDisconnectPayload(marshaled)
			if err != nil {
				t.Fatalf("Parse error: %v", err)
			}

			// Compare
			if parsed.Reason != original.Reason {
				t.Errorf("Reason mismatch after round trip: got %q, want %q", parsed.Reason, original.Reason)
			}
		})
	}
}

// TestDisconnectCommonReasons tests parsing common disconnect reasons
func TestDisconnectCommonReasons(t *testing.T) {
	commonReasons := []string{
		"client shutdown",
		"timeout",
		"protocol error",
		"version mismatch",
		"authentication failed",
		"resource exhausted",
		"connection reset",
		"server shutdown",
	}

	for _, reason := range commonReasons {
		t.Run(reason, func(t *testing.T) {
			// Create payload
			dp := &DisconnectPayload{Reason: reason}
			data, err := dp.MarshalBinary()
			if err != nil {
				t.Fatalf("Marshal failed: %v", err)
			}

			// Parse it back
			parsed, err := ParseDisconnectPayload(data)
			if err != nil {
				t.Fatalf("Parse failed: %v", err)
			}

			if parsed.Reason != reason {
				t.Errorf("Reason mismatch: got %q, want %q", parsed.Reason, reason)
			}
		})
	}
}

// TestDisconnectMaxLength tests handling of maximum length reasons
func TestDisconnectMaxLength(t *testing.T) {
	// Maximum uint16 is 65535, but that's impractical
	// Test a reasonable maximum (e.g., 1024 bytes)
	longReason := string(bytes.Repeat([]byte("X"), 1024))

	dp := &DisconnectPayload{Reason: longReason}
	data, err := dp.MarshalBinary()
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	parsed, err := ParseDisconnectPayload(data)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if parsed.Reason != longReason {
		t.Errorf("Long reason not preserved: got %d bytes, want %d bytes", len(parsed.Reason), len(longReason))
	}
}

// TestSendMessageExpiresPayloadParse tests parsing of SendMessageExpires payload
func TestSendMessageExpiresPayloadParse(t *testing.T) {
	tests := []struct {
		name         string
		payload      []byte
		expectError  bool
		checkDest    bool
		checkNonce   uint32
		checkFlags   uint16
		checkExpMs   uint64
		checkPayload []byte
	}{
		{
			name: "valid_empty_payload",
			payload: func() []byte {
				buf := make([]byte, 44) // 32 + 0 + 4 + 2 + 6
				// Destination (32 bytes)
				copy(buf[0:32], bytes.Repeat([]byte{0x01}, 32))
				// Empty message payload (0 bytes)
				// Nonce (4 bytes) at offset 32
				binary.BigEndian.PutUint32(buf[32:36], 0x12345678)
				// Flags (2 bytes) at offset 36
				binary.BigEndian.PutUint16(buf[36:38], 0x0000)
				// Expiration (6 bytes) at offset 38
				expMs := uint64(time.Now().Add(5 * time.Minute).UnixMilli())
				buf[38] = byte(expMs >> 40)
				buf[39] = byte(expMs >> 32)
				buf[40] = byte(expMs >> 24)
				buf[41] = byte(expMs >> 16)
				buf[42] = byte(expMs >> 8)
				buf[43] = byte(expMs)
				return buf
			}(),
			expectError:  false,
			checkNonce:   0x12345678,
			checkFlags:   0x0000,
			checkPayload: []byte{},
		},
		{
			name: "valid_with_payload",
			payload: func() []byte {
				msgPayload := []byte("test message")
				totalSize := 32 + len(msgPayload) + 12 // dest + payload + fixed
				buf := make([]byte, totalSize)
				// Destination
				copy(buf[0:32], bytes.Repeat([]byte{0x02}, 32))
				// Message payload
				copy(buf[32:32+len(msgPayload)], msgPayload)
				offset := 32 + len(msgPayload)
				// Nonce
				binary.BigEndian.PutUint32(buf[offset:offset+4], 0xABCDEF01)
				// Flags
				binary.BigEndian.PutUint16(buf[offset+4:offset+6], 0x0001)
				// Expiration
				expMs := uint64(time.Now().Add(10 * time.Minute).UnixMilli())
				buf[offset+6] = byte(expMs >> 40)
				buf[offset+7] = byte(expMs >> 32)
				buf[offset+8] = byte(expMs >> 24)
				buf[offset+9] = byte(expMs >> 16)
				buf[offset+10] = byte(expMs >> 8)
				buf[offset+11] = byte(expMs)
				return buf
			}(),
			expectError:  false,
			checkNonce:   0xABCDEF01,
			checkFlags:   0x0001,
			checkPayload: []byte("test message"),
		},
		{
			name:        "too_short_missing_all",
			payload:     make([]byte, 31), // Need at least 44
			expectError: true,
		},
		{
			name:        "too_short_missing_fixed_fields",
			payload:     make([]byte, 40), // 32 dest + 8, but need 12 fixed
			expectError: true,
		},
		{
			name: "large_payload",
			payload: func() []byte {
				msgPayload := bytes.Repeat([]byte("X"), 1024)
				totalSize := 32 + len(msgPayload) + 12
				buf := make([]byte, totalSize)
				copy(buf[0:32], bytes.Repeat([]byte{0x03}, 32))
				copy(buf[32:32+len(msgPayload)], msgPayload)
				offset := 32 + len(msgPayload)
				binary.BigEndian.PutUint32(buf[offset:offset+4], 0x99999999)
				binary.BigEndian.PutUint16(buf[offset+4:offset+6], 0xFFFF)
				expMs := uint64(time.Now().Add(1 * time.Hour).UnixMilli())
				buf[offset+6] = byte(expMs >> 40)
				buf[offset+7] = byte(expMs >> 32)
				buf[offset+8] = byte(expMs >> 24)
				buf[offset+9] = byte(expMs >> 16)
				buf[offset+10] = byte(expMs >> 8)
				buf[offset+11] = byte(expMs)
				return buf
			}(),
			expectError:  false,
			checkNonce:   0x99999999,
			checkFlags:   0xFFFF,
			checkPayload: bytes.Repeat([]byte("X"), 1024),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := ParseSendMessageExpiresPayload(tt.payload)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if parsed.Nonce != tt.checkNonce {
				t.Errorf("Nonce mismatch: got 0x%X, want 0x%X", parsed.Nonce, tt.checkNonce)
			}

			if parsed.Flags != tt.checkFlags {
				t.Errorf("Flags mismatch: got 0x%X, want 0x%X", parsed.Flags, tt.checkFlags)
			}

			if !bytes.Equal(parsed.Payload, tt.checkPayload) {
				t.Errorf("Payload mismatch: got %d bytes, want %d bytes", len(parsed.Payload), len(tt.checkPayload))
			}

			if parsed.Expiration == 0 {
				t.Error("Expiration should not be zero")
			}
		})
	}
}

// TestSendMessageExpiresPayloadMarshal tests marshaling of SendMessageExpires payload
func TestSendMessageExpiresPayloadMarshal(t *testing.T) {
	dest := data.Hash{}
	copy(dest[:], bytes.Repeat([]byte{0xAA}, 32))

	expMs := uint64(time.Now().Add(15 * time.Minute).UnixMilli())

	smp := &SendMessageExpiresPayload{
		Destination: dest,
		Payload:     []byte("hello world"),
		Nonce:       0x11223344,
		Flags:       0x0002,
		Expiration:  expMs,
	}

	marshaled, err := smp.MarshalBinary()
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	expectedSize := 32 + len(smp.Payload) + 12 // dest + payload + fixed
	if len(marshaled) != expectedSize {
		t.Errorf("Marshaled size mismatch: got %d, want %d", len(marshaled), expectedSize)
	}

	// Verify destination
	if !bytes.Equal(marshaled[0:32], dest[:]) {
		t.Error("Destination mismatch in marshaled data")
	}

	// Verify payload
	if !bytes.Equal(marshaled[32:32+len(smp.Payload)], smp.Payload) {
		t.Error("Payload mismatch in marshaled data")
	}

	// Verify fixed fields
	offset := 32 + len(smp.Payload)
	nonce := binary.BigEndian.Uint32(marshaled[offset : offset+4])
	if nonce != 0x11223344 {
		t.Errorf("Nonce mismatch: got 0x%X, want 0x11223344", nonce)
	}

	flags := binary.BigEndian.Uint16(marshaled[offset+4 : offset+6])
	if flags != 0x0002 {
		t.Errorf("Flags mismatch: got 0x%X, want 0x0002", flags)
	}

	// Verify expiration (48-bit)
	expBytes := marshaled[offset+6 : offset+12]
	exp := uint64(expBytes[0])<<40 |
		uint64(expBytes[1])<<32 |
		uint64(expBytes[2])<<24 |
		uint64(expBytes[3])<<16 |
		uint64(expBytes[4])<<8 |
		uint64(expBytes[5])
	if exp != expMs {
		t.Errorf("Expiration mismatch: got %d, want %d", exp, expMs)
	}
}

// TestSendMessageExpiresRoundTrip tests marshal/unmarshal integrity
func TestSendMessageExpiresRoundTrip(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
	}{
		{"empty", []byte{}},
		{"small", []byte("test")},
		{"medium", bytes.Repeat([]byte("AB"), 512)},
		{"large", bytes.Repeat([]byte("XYZ"), 8192)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dest := data.Hash{}
			copy(dest[:], bytes.Repeat([]byte{0xBB}, 32))

			original := &SendMessageExpiresPayload{
				Destination: dest,
				Payload:     tt.payload,
				Nonce:       0xDEADBEEF,
				Flags:       0x1234,
				Expiration:  uint64(time.Now().Add(30 * time.Minute).UnixMilli()),
			}

			// Marshal
			marshaled, err := original.MarshalBinary()
			if err != nil {
				t.Fatalf("Marshal error: %v", err)
			}

			// Unmarshal
			parsed, err := ParseSendMessageExpiresPayload(marshaled)
			if err != nil {
				t.Fatalf("Parse error: %v", err)
			}

			// Compare
			if parsed.Destination != original.Destination {
				t.Error("Destination mismatch after round trip")
			}

			if !bytes.Equal(parsed.Payload, original.Payload) {
				t.Errorf("Payload mismatch: got %d bytes, want %d bytes", len(parsed.Payload), len(original.Payload))
			}

			if parsed.Nonce != original.Nonce {
				t.Errorf("Nonce mismatch: got 0x%X, want 0x%X", parsed.Nonce, original.Nonce)
			}

			if parsed.Flags != original.Flags {
				t.Errorf("Flags mismatch: got 0x%X, want 0x%X", parsed.Flags, original.Flags)
			}

			if parsed.Expiration != original.Expiration {
				t.Errorf("Expiration mismatch: got %d, want %d", parsed.Expiration, original.Expiration)
			}
		})
	}
}

// TestMessageTypeConstants verifies SendMessageExpires constant
func TestMessageTypeSendMessageExpires(t *testing.T) {
	if MessageTypeSendMessageExpires != 36 {
		t.Errorf("MessageTypeSendMessageExpires = %d, want 36", MessageTypeSendMessageExpires)
	}

	name := MessageTypeName(MessageTypeSendMessageExpires)
	if name != "SendMessageExpires" {
		t.Errorf("MessageTypeName(36) = %q, want %q", name, "SendMessageExpires")
	}
}

// TestMessageTypeDisconnect verifies Disconnect constant
func TestMessageTypeDisconnect(t *testing.T) {
	if MessageTypeDisconnect != 30 {
		t.Errorf("MessageTypeDisconnect = %d, want 30", MessageTypeDisconnect)
	}

	name := MessageTypeName(MessageTypeDisconnect)
	if name != "Disconnect" {
		t.Errorf("MessageTypeName(30) = %q, want %q", name, "Disconnect")
	}
}

// TestExpirationTime tests expiration time calculations
func TestExpirationTime(t *testing.T) {
	// Test past expiration
	pastMs := uint64(time.Now().Add(-5 * time.Minute).UnixMilli())
	currentMs := uint64(time.Now().UnixMilli())
	if currentMs < pastMs {
		t.Error("Past time should be less than current time")
	}

	// Test future expiration
	futureMs := uint64(time.Now().Add(10 * time.Minute).UnixMilli())
	if futureMs <= currentMs {
		t.Error("Future time should be greater than current time")
	}

	// Test 48-bit range (max value that fits in 6 bytes)
	maxExpiration := uint64(1<<48 - 1) // 2814740.9.67655 ms = ~8925 years from epoch
	if maxExpiration < futureMs {
		t.Error("48-bit expiration should support far future dates")
	}
}

func TestHostLookupPayloadParse(t *testing.T) {
	tests := []struct {
		name        string
		data        []byte
		wantID      uint32
		wantType    uint16
		wantQuery   string
		shouldError bool
	}{
		{
			name: "hash_lookup",
			data: func() []byte {
				buf := new(bytes.Buffer)
				binary.Write(buf, binary.BigEndian, uint32(12345))                      // RequestID
				binary.Write(buf, binary.BigEndian, uint16(HostLookupTypeHash))         // Type
				binary.Write(buf, binary.BigEndian, uint16(52))                         // Query length (base64 hash)
				buf.WriteString("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA") // 52 char hash
				return buf.Bytes()
			}(),
			wantID:      12345,
			wantType:    HostLookupTypeHash,
			wantQuery:   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			shouldError: false,
		},
		{
			name: "hostname_lookup",
			data: func() []byte {
				buf := new(bytes.Buffer)
				binary.Write(buf, binary.BigEndian, uint32(67890))
				binary.Write(buf, binary.BigEndian, uint16(HostLookupTypeHostname))
				hostname := "example.i2p"
				binary.Write(buf, binary.BigEndian, uint16(len(hostname)))
				buf.WriteString(hostname)
				return buf.Bytes()
			}(),
			wantID:      67890,
			wantType:    HostLookupTypeHostname,
			wantQuery:   "example.i2p",
			shouldError: false,
		},
		{
			name: "empty_query",
			data: func() []byte {
				buf := new(bytes.Buffer)
				binary.Write(buf, binary.BigEndian, uint32(99999))
				binary.Write(buf, binary.BigEndian, uint16(HostLookupTypeHostname))
				binary.Write(buf, binary.BigEndian, uint16(0)) // Empty query
				return buf.Bytes()
			}(),
			wantID:      99999,
			wantType:    HostLookupTypeHostname,
			wantQuery:   "",
			shouldError: false,
		},
		{
			name:        "too_short",
			data:        []byte{0x00, 0x01, 0x02}, // Only 3 bytes
			shouldError: true,
		},
		{
			name: "truncated_query",
			data: func() []byte {
				buf := new(bytes.Buffer)
				binary.Write(buf, binary.BigEndian, uint32(11111))
				binary.Write(buf, binary.BigEndian, uint16(HostLookupTypeHostname))
				binary.Write(buf, binary.BigEndian, uint16(100)) // Claims 100 bytes
				buf.WriteString("short")                         // Only 5 bytes
				return buf.Bytes()
			}(),
			shouldError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload, err := ParseHostLookupPayload(tt.data)

			if tt.shouldError {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if payload.RequestID != tt.wantID {
				t.Errorf("RequestID = %d, want %d", payload.RequestID, tt.wantID)
			}

			if payload.LookupType != tt.wantType {
				t.Errorf("LookupType = %d, want %d", payload.LookupType, tt.wantType)
			}

			if payload.Query != tt.wantQuery {
				t.Errorf("Query = %q, want %q", payload.Query, tt.wantQuery)
			}
		})
	}
}

func TestHostLookupPayloadMarshal(t *testing.T) {
	tests := []struct {
		name    string
		payload *HostLookupPayload
		check   func([]byte) error
	}{
		{
			name: "hash_lookup",
			payload: &HostLookupPayload{
				RequestID:  54321,
				LookupType: HostLookupTypeHash,
				Query:      "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
			},
			check: func(data []byte) error {
				if len(data) != 8+52 {
					t.Errorf("data length = %d, want %d", len(data), 8+52)
				}
				reqID := binary.BigEndian.Uint32(data[0:4])
				if reqID != 54321 {
					t.Errorf("RequestID = %d, want 54321", reqID)
				}
				lookupType := binary.BigEndian.Uint16(data[4:6])
				if lookupType != HostLookupTypeHash {
					t.Errorf("LookupType = %d, want %d", lookupType, HostLookupTypeHash)
				}
				queryLen := binary.BigEndian.Uint16(data[6:8])
				if queryLen != 52 {
					t.Errorf("QueryLength = %d, want 52", queryLen)
				}
				return nil
			},
		},
		{
			name: "hostname_lookup",
			payload: &HostLookupPayload{
				RequestID:  11111,
				LookupType: HostLookupTypeHostname,
				Query:      "test.i2p",
			},
			check: func(data []byte) error {
				if len(data) != 8+8 {
					t.Errorf("data length = %d, want 16", len(data))
				}
				lookupType := binary.BigEndian.Uint16(data[4:6])
				if lookupType != HostLookupTypeHostname {
					t.Errorf("LookupType = %d, want %d", lookupType, HostLookupTypeHostname)
				}
				query := string(data[8:])
				if query != "test.i2p" {
					t.Errorf("Query = %q, want %q", query, "test.i2p")
				}
				return nil
			},
		},
		{
			name: "empty_query",
			payload: &HostLookupPayload{
				RequestID:  0,
				LookupType: HostLookupTypeHostname,
				Query:      "",
			},
			check: func(data []byte) error {
				if len(data) != 8 {
					t.Errorf("data length = %d, want 8", len(data))
				}
				queryLen := binary.BigEndian.Uint16(data[6:8])
				if queryLen != 0 {
					t.Errorf("QueryLength = %d, want 0", queryLen)
				}
				return nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.payload.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary() error: %v", err)
			}

			if err := tt.check(data); err != nil {
				t.Error(err)
			}
		})
	}
}

func TestHostLookupRoundTrip(t *testing.T) {
	tests := []struct {
		name    string
		payload *HostLookupPayload
	}{
		{
			name: "hash_lookup",
			payload: &HostLookupPayload{
				RequestID:  12345,
				LookupType: HostLookupTypeHash,
				Query:      "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
			},
		},
		{
			name: "hostname_lookup",
			payload: &HostLookupPayload{
				RequestID:  67890,
				LookupType: HostLookupTypeHostname,
				Query:      "example.i2p",
			},
		},
		{
			name: "long_hostname",
			payload: &HostLookupPayload{
				RequestID:  99999,
				LookupType: HostLookupTypeHostname,
				Query:      "very-long-hostname-that-tests-longer-queries.i2p",
			},
		},
		{
			name: "empty_query",
			payload: &HostLookupPayload{
				RequestID:  0,
				LookupType: HostLookupTypeHash,
				Query:      "",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.payload.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary() error: %v", err)
			}

			parsed, err := ParseHostLookupPayload(data)
			if err != nil {
				t.Fatalf("ParseHostLookupPayload() error: %v", err)
			}

			if parsed.RequestID != tt.payload.RequestID {
				t.Errorf("RequestID = %d, want %d", parsed.RequestID, tt.payload.RequestID)
			}

			if parsed.LookupType != tt.payload.LookupType {
				t.Errorf("LookupType = %d, want %d", parsed.LookupType, tt.payload.LookupType)
			}

			if parsed.Query != tt.payload.Query {
				t.Errorf("Query = %q, want %q", parsed.Query, tt.payload.Query)
			}
		})
	}
}

func TestHostReplyPayloadParse(t *testing.T) {
	tests := []struct {
		name        string
		data        []byte
		wantID      uint32
		wantCode    uint8
		wantDestLen int
		shouldError bool
	}{
		{
			name: "success_with_destination",
			data: func() []byte {
				buf := new(bytes.Buffer)
				binary.Write(buf, binary.BigEndian, uint32(12345))
				buf.WriteByte(HostReplySuccess)
				buf.Write(make([]byte, 387)) // Standard destination size
				return buf.Bytes()
			}(),
			wantID:      12345,
			wantCode:    HostReplySuccess,
			wantDestLen: 387,
			shouldError: false,
		},
		{
			name: "not_found",
			data: func() []byte {
				buf := new(bytes.Buffer)
				binary.Write(buf, binary.BigEndian, uint32(67890))
				buf.WriteByte(HostReplyNotFound)
				return buf.Bytes()
			}(),
			wantID:      67890,
			wantCode:    HostReplyNotFound,
			wantDestLen: 0,
			shouldError: false,
		},
		{
			name: "timeout",
			data: func() []byte {
				buf := new(bytes.Buffer)
				binary.Write(buf, binary.BigEndian, uint32(11111))
				buf.WriteByte(HostReplyTimeout)
				return buf.Bytes()
			}(),
			wantID:      11111,
			wantCode:    HostReplyTimeout,
			wantDestLen: 0,
			shouldError: false,
		},
		{
			name: "error",
			data: func() []byte {
				buf := new(bytes.Buffer)
				binary.Write(buf, binary.BigEndian, uint32(99999))
				buf.WriteByte(HostReplyError)
				return buf.Bytes()
			}(),
			wantID:      99999,
			wantCode:    HostReplyError,
			wantDestLen: 0,
			shouldError: false,
		},
		{
			name:        "too_short",
			data:        []byte{0x00, 0x01, 0x02}, // Only 3 bytes
			shouldError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload, err := ParseHostReplyPayload(tt.data)

			if tt.shouldError {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if payload.RequestID != tt.wantID {
				t.Errorf("RequestID = %d, want %d", payload.RequestID, tt.wantID)
			}

			if payload.ResultCode != tt.wantCode {
				t.Errorf("ResultCode = %d, want %d", payload.ResultCode, tt.wantCode)
			}

			if len(payload.Destination) != tt.wantDestLen {
				t.Errorf("Destination length = %d, want %d", len(payload.Destination), tt.wantDestLen)
			}
		})
	}
}

func TestHostReplyPayloadMarshal(t *testing.T) {
	tests := []struct {
		name    string
		payload *HostReplyPayload
		check   func([]byte) error
	}{
		{
			name: "success_with_destination",
			payload: &HostReplyPayload{
				RequestID:   54321,
				ResultCode:  HostReplySuccess,
				Destination: make([]byte, 387),
			},
			check: func(data []byte) error {
				if len(data) != 5+387 {
					t.Errorf("data length = %d, want %d", len(data), 5+387)
				}
				reqID := binary.BigEndian.Uint32(data[0:4])
				if reqID != 54321 {
					t.Errorf("RequestID = %d, want 54321", reqID)
				}
				resultCode := data[4]
				if resultCode != HostReplySuccess {
					t.Errorf("ResultCode = %d, want %d", resultCode, HostReplySuccess)
				}
				return nil
			},
		},
		{
			name: "not_found",
			payload: &HostReplyPayload{
				RequestID:   11111,
				ResultCode:  HostReplyNotFound,
				Destination: nil,
			},
			check: func(data []byte) error {
				if len(data) != 5 {
					t.Errorf("data length = %d, want 5", len(data))
				}
				resultCode := data[4]
				if resultCode != HostReplyNotFound {
					t.Errorf("ResultCode = %d, want %d", resultCode, HostReplyNotFound)
				}
				return nil
			},
		},
		{
			name: "timeout",
			payload: &HostReplyPayload{
				RequestID:   22222,
				ResultCode:  HostReplyTimeout,
				Destination: []byte{}, // Empty slice
			},
			check: func(data []byte) error {
				if len(data) != 5 {
					t.Errorf("data length = %d, want 5", len(data))
				}
				resultCode := data[4]
				if resultCode != HostReplyTimeout {
					t.Errorf("ResultCode = %d, want %d", resultCode, HostReplyTimeout)
				}
				return nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.payload.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary() error: %v", err)
			}

			if err := tt.check(data); err != nil {
				t.Error(err)
			}
		})
	}
}

func TestHostReplyRoundTrip(t *testing.T) {
	tests := []struct {
		name    string
		payload *HostReplyPayload
	}{
		{
			name: "success_with_destination",
			payload: &HostReplyPayload{
				RequestID:   12345,
				ResultCode:  HostReplySuccess,
				Destination: make([]byte, 387),
			},
		},
		{
			name: "not_found",
			payload: &HostReplyPayload{
				RequestID:   67890,
				ResultCode:  HostReplyNotFound,
				Destination: nil,
			},
		},
		{
			name: "timeout",
			payload: &HostReplyPayload{
				RequestID:   11111,
				ResultCode:  HostReplyTimeout,
				Destination: []byte{},
			},
		},
		{
			name: "error",
			payload: &HostReplyPayload{
				RequestID:   99999,
				ResultCode:  HostReplyError,
				Destination: nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.payload.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary() error: %v", err)
			}

			parsed, err := ParseHostReplyPayload(data)
			if err != nil {
				t.Fatalf("ParseHostReplyPayload() error: %v", err)
			}

			if parsed.RequestID != tt.payload.RequestID {
				t.Errorf("RequestID = %d, want %d", parsed.RequestID, tt.payload.RequestID)
			}

			if parsed.ResultCode != tt.payload.ResultCode {
				t.Errorf("ResultCode = %d, want %d", parsed.ResultCode, tt.payload.ResultCode)
			}

			if len(parsed.Destination) != len(tt.payload.Destination) {
				t.Errorf("Destination length = %d, want %d",
					len(parsed.Destination), len(tt.payload.Destination))
			}
		})
	}
}

func TestHostLookupConstants(t *testing.T) {
	// Verify lookup type constants
	if HostLookupTypeHash != 0 {
		t.Errorf("HostLookupTypeHash = %d, want 0", HostLookupTypeHash)
	}
	if HostLookupTypeHostname != 1 {
		t.Errorf("HostLookupTypeHostname = %d, want 1", HostLookupTypeHostname)
	}

	// Verify result code constants
	if HostReplySuccess != 0 {
		t.Errorf("HostReplySuccess = %d, want 0", HostReplySuccess)
	}
	if HostReplyNotFound != 1 {
		t.Errorf("HostReplyNotFound = %d, want 1", HostReplyNotFound)
	}
	if HostReplyTimeout != 2 {
		t.Errorf("HostReplyTimeout = %d, want 2", HostReplyTimeout)
	}
	if HostReplyError != 3 {
		t.Errorf("HostReplyError = %d, want 3", HostReplyError)
	}
}

func TestHostLookupTypeNames(t *testing.T) {
	// Verify message type constants
	if MessageTypeHostLookup != 38 {
		t.Errorf("MessageTypeHostLookup = %d, want 38", MessageTypeHostLookup)
	}
	if MessageTypeHostReply != 39 {
		t.Errorf("MessageTypeHostReply = %d, want 39", MessageTypeHostReply)
	}

	// Verify message type names
	if name := MessageTypeName(MessageTypeHostLookup); name != "HostLookup" {
		t.Errorf("MessageTypeName(HostLookup) = %q, want %q", name, "HostLookup")
	}
	if name := MessageTypeName(MessageTypeHostReply); name != "HostReply" {
		t.Errorf("MessageTypeName(HostReply) = %q, want %q", name, "HostReply")
	}

	// Verify deprecated types are distinct
	if MessageTypeDestLookup != 34 {
		t.Errorf("MessageTypeDestLookup = %d, want 34", MessageTypeDestLookup)
	}
	if MessageTypeDestReply != 35 {
		t.Errorf("MessageTypeDestReply = %d, want 35", MessageTypeDestReply)
	}
}

// =============================================================================
// HOST LOOKUP TESTS
// =============================================================================

// TestHostLookup_PayloadParsing verifies HostLookup payload parsing.
func TestHostLookup_PayloadParsing(t *testing.T) {
	// Valid hash lookup - correct wire format:
	// bytes 0-3:   RequestID (uint32, big endian)
	// bytes 4-5:   LookupType (uint16, big endian)
	// bytes 6-7:   Query length (uint16, big endian)
	// bytes 8+:    Query string
	t.Run("valid_hash_lookup", func(t *testing.T) {
		// Create a hash lookup with a 32-byte hash query
		hashQuery := string(make([]byte, 32))
		payload := make([]byte, 8+len(hashQuery)) // 4+2+2 header + query
		binary.BigEndian.PutUint32(payload[0:4], 12345)
		binary.BigEndian.PutUint16(payload[4:6], HostLookupTypeHash)
		binary.BigEndian.PutUint16(payload[6:8], uint16(len(hashQuery)))
		copy(payload[8:], hashQuery)

		lookup, err := ParseHostLookupPayload(payload)
		if err != nil {
			t.Fatalf("ParseHostLookupPayload() error: %v", err)
		}

		if lookup.RequestID != 12345 {
			t.Errorf("RequestID = %d, want 12345", lookup.RequestID)
		}
		if lookup.LookupType != HostLookupTypeHash {
			t.Errorf("LookupType = %d, want %d", lookup.LookupType, HostLookupTypeHash)
		}
	})

	// Truncated payload
	t.Run("truncated_payload", func(t *testing.T) {
		payload := []byte{1, 2} // Too short

		_, err := ParseHostLookupPayload(payload)
		if err == nil {
			t.Error("Expected error for truncated payload")
		}
	})
}

// TestHostLookup_ReplyPayloadMarshaling verifies HostReply marshaling.
func TestHostLookup_ReplyPayloadMarshaling(t *testing.T) {
	reply := &HostReplyPayload{
		RequestID:   12345,
		ResultCode:  HostReplySuccess,
		Destination: make([]byte, 387), // Minimal destination
	}

	data, err := reply.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error: %v", err)
	}

	// Verify header
	if binary.BigEndian.Uint32(data[0:4]) != 12345 {
		t.Error("RequestID not serialized correctly")
	}
	if data[4] != HostReplySuccess {
		t.Error("ResultCode not serialized correctly")
	}
}

// =============================================================================
// BLINDING INFO TESTS
// =============================================================================

// TestBlindingInfo_PayloadParsing verifies BlindingInfo payload parsing.
func TestBlindingInfo_PayloadParsing(t *testing.T) {
	// Valid blinding info - correct wire format:
	// byte 0: enabled flag (0x00 = disabled, 0x01 = enabled)
	// bytes 1-32: secret (only if enabled, exactly 32 bytes)
	t.Run("valid_blinding_info", func(t *testing.T) {
		payload := make([]byte, 33)         // 1 (enabled flag) + 32 (secret)
		payload[0] = 0x01                   // enabled
		copy(payload[1:], make([]byte, 32)) // 32-byte secret

		info, err := ParseBlindingInfoPayload(payload)
		if err != nil {
			t.Fatalf("ParseBlindingInfoPayload() error: %v", err)
		}

		if !info.Enabled {
			t.Error("Enabled should be true")
		}
		if len(info.Secret) != 32 {
			t.Errorf("Secret length = %d, want 32", len(info.Secret))
		}
	})

	// Disabled blinding
	t.Run("disabled_blinding", func(t *testing.T) {
		payload := []byte{0x00} // disabled

		info, err := ParseBlindingInfoPayload(payload)
		if err != nil {
			t.Fatalf("ParseBlindingInfoPayload() error: %v", err)
		}

		if info.Enabled {
			t.Error("Enabled should be false")
		}
	})
}
