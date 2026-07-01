package i2cp

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParseSendMessagePayload tests parsing of SendMessage payloads
func TestParseSendMessagePayload(t *testing.T) {
	tests := []struct {
		name          string
		input         []byte
		wantErr       bool
		expectedSize  int
		expectedNonce uint32
		errorContains string
	}{
		{
			name: "Valid payload with data",
			input: func() []byte {
				dest, err := createTestDestination()
				if err != nil {
					panic(err)
				}
				destBytes, err := dest.Bytes()
				if err != nil {
					panic(err)
				}
				payload := []byte("Hello, I2P!")
				buf := make([]byte, 0, len(destBytes)+4+len(payload)+4)
				buf = append(buf, destBytes...)
				lenBytes := make([]byte, 4)
				binary.BigEndian.PutUint32(lenBytes, uint32(len(payload)))
				buf = append(buf, lenBytes...)
				buf = append(buf, payload...)
				nonceBytes := make([]byte, 4)
				binary.BigEndian.PutUint32(nonceBytes, 0x11223344)
				buf = append(buf, nonceBytes...)
				return buf
			}(),
			wantErr:       false,
			expectedSize:  len("Hello, I2P!"),
			expectedNonce: 0x11223344,
		},
		{
			name: "Valid payload with empty message",
			input: func() []byte {
				dest, err := createTestDestination()
				if err != nil {
					panic(err)
				}
				destBytes, err := dest.Bytes()
				if err != nil {
					panic(err)
				}
				buf := make([]byte, 0, len(destBytes)+8)
				buf = append(buf, destBytes...)
				lenBytes := make([]byte, 4)
				binary.BigEndian.PutUint32(lenBytes, 0)
				buf = append(buf, lenBytes...)
				nonceBytes := make([]byte, 4)
				binary.BigEndian.PutUint32(nonceBytes, 0xAABBCCDD)
				buf = append(buf, nonceBytes...)
				return buf
			}(),
			wantErr:       false,
			expectedSize:  0,
			expectedNonce: 0xAABBCCDD,
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
			errorContains: "failed to parse destination",
		},
		{
			name:          "Too short - 31 bytes",
			input:         make([]byte, 31),
			wantErr:       true,
			errorContains: "failed to parse destination",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseSendMessagePayload(tt.input)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
				return
			}

			require.NoError(t, err)
			require.NotNil(t, result)

			assert.Equal(t, tt.expectedSize, len(result.Payload), "payload size")
			assert.Equal(t, tt.expectedNonce, result.Nonce, "nonce")
		})
	}
}

// TestSendMessagePayloadMarshalBinary tests marshaling of SendMessagePayload
func TestSendMessagePayloadMarshalBinary(t *testing.T) {
	dest, err := createTestDestination()
	require.NoError(t, err)
	destBytes, err := dest.Bytes()
	require.NoError(t, err)

	payload := []byte("Test message payload")

	smp := &SendMessagePayload{
		Destination: *dest,
		Payload:     payload,
	}

	// Marshal
	data, err := smp.MarshalBinary()
	require.NoError(t, err)

	expectedSize := len(destBytes) + 4 + len(payload) + 4
	assert.Equal(t, expectedSize, len(data), "marshaled size")

	assert.True(t, bytes.Equal(destBytes, data[:len(destBytes)]), "destination bytes mismatch")
	payloadLen := binary.BigEndian.Uint32(data[len(destBytes) : len(destBytes)+4])
	assert.Equal(t, uint32(len(payload)), payloadLen, "payload length field")

	payloadStart := len(destBytes) + 4
	payloadEnd := payloadStart + len(payload)
	assert.True(t, bytes.Equal(data[payloadStart:payloadEnd], payload), "payload mismatch")
}

// TestSendMessagePayloadRoundTrip tests marshal/unmarshal round trip
func TestSendMessagePayloadRoundTrip(t *testing.T) {
	dest, err := createTestDestination()
	require.NoError(t, err)

	original := &SendMessagePayload{
		Destination: *dest,
		Payload:     []byte("Round trip test payload"),
	}

	// Marshal
	data, err := original.MarshalBinary()
	require.NoError(t, err)

	// Unmarshal
	result, err := ParseSendMessagePayload(data)
	require.NoError(t, err)

	assert.True(t, original.Destination.Equals(&result.Destination), "destination")
	assert.True(t, bytes.Equal(original.Payload, result.Payload), "payload")
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
				payload := []byte("Received message")
				data := make([]byte, 10+len(payload))
				data[0] = 0x00
				data[1] = 0x01 // SessionID = 0x0001
				data[2] = 0x00
				data[3] = 0x00
				data[4] = 0x12
				data[5] = 0x34 // MessageID = 0x00001234 = 4660
				binary.BigEndian.PutUint32(data[6:10], uint32(len(payload)))
				copy(data[10:], payload)
				return data
			}(),
			wantErr:       false,
			expectedMsgID: 0x1234,
			expectedSize:  len("Received message"),
		},
		{
			name: "Valid payload with empty message",
			input: func() []byte {
				// SessionID (2 bytes) + MessageID (4 bytes) + payloadLen(4), no payload
				data := make([]byte, 10)
				data[0] = 0x00
				data[1] = 0x02 // SessionID = 0x0002
				data[2] = 0xFF
				data[3] = 0xFF
				data[4] = 0xFF
				data[5] = 0xFF // MessageID = 0xFFFFFFFF
				binary.BigEndian.PutUint32(data[6:10], 0)
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
			name:          "Too short - 9 bytes",
			input:         make([]byte, 9),
			wantErr:       true,
			errorContains: "too short",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseMessagePayloadPayload(tt.input)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
				return
			}

			require.NoError(t, err)
			require.NotNil(t, result)

			assert.Equal(t, tt.expectedMsgID, result.MessageID, "message ID")
			assert.Equal(t, tt.expectedSize, len(result.Payload), "payload size")
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
	require.NoError(t, err)

	expectedSize := 10 + len(payload)
	assert.Equal(t, expectedSize, len(data), "marshaled size")

	assert.Equal(t, byte(0x12), data[0], "sessionID high byte")
	assert.Equal(t, byte(0x34), data[1], "sessionID low byte")

	assert.Equal(t, byte(0x00), data[2], "messageID byte 0")
	assert.Equal(t, byte(0xAB), data[3], "messageID byte 1")
	assert.Equal(t, byte(0xCD), data[4], "messageID byte 2")
	assert.Equal(t, byte(0xEF), data[5], "messageID byte 3")

	payloadLen := binary.BigEndian.Uint32(data[6:10])
	assert.Equal(t, uint32(len(payload)), payloadLen, "payload length")
	assert.True(t, bytes.Equal(data[10:], payload), "payload mismatch")
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
	require.NoError(t, err)

	// Unmarshal
	result, err := ParseMessagePayloadPayload(data)
	require.NoError(t, err)

	assert.Equal(t, original.MessageID, result.MessageID, "message ID")
	assert.True(t, bytes.Equal(original.Payload, result.Payload), "payload")
}

// TestSendMessagePayloadEmptyPayload tests handling of empty payload
func TestSendMessagePayloadEmptyPayload(t *testing.T) {
	dest, err := createTestDestination()
	require.NoError(t, err)
	destBytes, err := dest.Bytes()
	require.NoError(t, err)

	smp := &SendMessagePayload{
		Destination: *dest,
		Payload:     []byte{},
	}

	data, err := smp.MarshalBinary()
	require.NoError(t, err)
	assert.Equal(t, len(destBytes)+8, len(data), "marshaled size")

	result, err := ParseSendMessagePayload(data)
	require.NoError(t, err)
	assert.Empty(t, result.Payload)
}

// TestMessagePayloadPayloadZeroID tests handling of message ID = 0
func TestMessagePayloadPayloadZeroID(t *testing.T) {
	mpp := &MessagePayloadPayload{
		SessionID: 0x9ABC,
		MessageID: 0,
		Payload:   []byte("Message with ID 0"),
	}

	data, err := mpp.MarshalBinary()
	require.NoError(t, err)

	result, err := ParseMessagePayloadPayload(data)
	require.NoError(t, err)
	assert.Equal(t, uint32(0), result.MessageID)
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
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantEnabled, payload.Enabled)
			assert.True(t, bytes.Equal(tt.wantSecret, payload.Secret), "secret mismatch")
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
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantSize, len(data), "data length")

			if tt.payload.Enabled {
				assert.Equal(t, byte(0x01), data[0], "enabled flag")
			} else {
				assert.Equal(t, byte(0x00), data[0], "enabled flag")
			}

			if tt.payload.Enabled && len(tt.payload.Secret) == 32 {
				assert.True(t, bytes.Equal(data[1:33], tt.payload.Secret), "marshaled secret mismatch")
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
			require.NoError(t, err)

			parsed, err := ParseBlindingInfoPayload(data)
			require.NoError(t, err)

			assert.Equal(t, tt.payload.Enabled, parsed.Enabled)
			assert.True(t, bytes.Equal(tt.payload.Secret, parsed.Secret), "secret mismatch")
		})
	}
}

func TestBlindingInfoConstants(t *testing.T) {
	assert.Equal(t, uint8(42), MessageTypeBlindingInfo)
	assert.Equal(t, "BlindingInfo", MessageTypeName(MessageTypeBlindingInfo))
}

func TestBlindingInfoEnableDisable(t *testing.T) {
	enablePayload := &BlindingInfoPayload{
		Enabled: true,
		Secret:  nil,
	}
	enableData, err := enablePayload.MarshalBinary()
	require.NoError(t, err)
	assert.Equal(t, 1, len(enableData), "enable payload length")
	assert.Equal(t, byte(0x01), enableData[0], "enable flag")

	disablePayload := &BlindingInfoPayload{
		Enabled: false,
		Secret:  nil,
	}
	disableData, err := disablePayload.MarshalBinary()
	require.NoError(t, err)
	assert.Equal(t, 1, len(disableData), "disable payload length")
	assert.Equal(t, byte(0x00), disableData[0], "disable flag")
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
				require.NoError(t, err, "unexpected error for valid secret")
				if tt.secret != nil {
					assert.Equal(t, 33, len(data), "data length")
				} else {
					assert.Equal(t, 1, len(data), "data length")
				}
			} else {
				assert.Error(t, err, "expected error for invalid secret length")
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
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expectReason, parsed.Reason)
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
			require.NoError(t, err)

			expectedSize := 2 + len(tt.reason)
			assert.Equal(t, expectedSize, len(marshaled), "marshaled size")

			reasonLen := binary.BigEndian.Uint16(marshaled[0:2])
			assert.Equal(t, uint16(len(tt.reason)), reasonLen, "length field")

			if len(tt.reason) > 0 {
				assert.Equal(t, tt.reason, string(marshaled[2:]), "reason")
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

			marshaled, err := original.MarshalBinary()
			require.NoError(t, err)

			parsed, err := ParseDisconnectPayload(marshaled)
			require.NoError(t, err)

			assert.Equal(t, original.Reason, parsed.Reason)
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
			dp := &DisconnectPayload{Reason: reason}
			data, err := dp.MarshalBinary()
			require.NoError(t, err)

			parsed, err := ParseDisconnectPayload(data)
			require.NoError(t, err)

			assert.Equal(t, reason, parsed.Reason)
		})
	}
}

// TestDisconnectMaxLength tests handling of maximum length reasons
func TestDisconnectMaxLength(t *testing.T) {
	longReason := string(bytes.Repeat([]byte("X"), 1024))

	dp := &DisconnectPayload{Reason: longReason}
	data, err := dp.MarshalBinary()
	require.NoError(t, err)

	parsed, err := ParseDisconnectPayload(data)
	require.NoError(t, err)

	assert.Equal(t, longReason, parsed.Reason)
}

// TestSendMessageExpiresPayloadParse tests parsing of SendMessageExpires payload
func TestSendMessageExpiresPayloadParse(t *testing.T) {
	testDest, err := createTestDestination()
	require.NoError(t, err)
	testDestBytes, err := testDest.Bytes()
	require.NoError(t, err)

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
				buf := make([]byte, 0, len(testDestBytes)+16)
				buf = append(buf, testDestBytes...)
				lenBytes := make([]byte, 4)
				binary.BigEndian.PutUint32(lenBytes, 0)
				buf = append(buf, lenBytes...)
				nonceBytes := make([]byte, 4)
				binary.BigEndian.PutUint32(nonceBytes, 0x12345678)
				buf = append(buf, nonceBytes...)
				flagsBytes := make([]byte, 2)
				binary.BigEndian.PutUint16(flagsBytes, 0x0000)
				buf = append(buf, flagsBytes...)
				expMs := uint64(time.Now().Add(5 * time.Minute).UnixMilli())
				buf = append(
					buf,
					byte(expMs>>40),
					byte(expMs>>32),
					byte(expMs>>24),
					byte(expMs>>16),
					byte(expMs>>8),
					byte(expMs),
				)
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
				buf := make([]byte, 0, len(testDestBytes)+4+len(msgPayload)+12)
				buf = append(buf, testDestBytes...)
				lenBytes := make([]byte, 4)
				binary.BigEndian.PutUint32(lenBytes, uint32(len(msgPayload)))
				buf = append(buf, lenBytes...)
				buf = append(buf, msgPayload...)
				nonceBytes := make([]byte, 4)
				binary.BigEndian.PutUint32(nonceBytes, 0xABCDEF01)
				buf = append(buf, nonceBytes...)
				flagsBytes := make([]byte, 2)
				binary.BigEndian.PutUint16(flagsBytes, 0x0001)
				buf = append(buf, flagsBytes...)
				expMs := uint64(time.Now().Add(10 * time.Minute).UnixMilli())
				buf = append(
					buf,
					byte(expMs>>40),
					byte(expMs>>32),
					byte(expMs>>24),
					byte(expMs>>16),
					byte(expMs>>8),
					byte(expMs),
				)
				return buf
			}(),
			expectError:  false,
			checkNonce:   0xABCDEF01,
			checkFlags:   0x0001,
			checkPayload: []byte("test message"),
		},
		{
			name:        "too_short_missing_all",
			payload:     make([]byte, 3), // Need at least destination + length
			expectError: true,
		},
		{
			name:        "too_short_missing_fixed_fields",
			payload:     append(append([]byte{}, testDestBytes...), make([]byte, 8)...),
			expectError: true,
		},
		{
			name: "large_payload",
			payload: func() []byte {
				msgPayload := bytes.Repeat([]byte("X"), 1024)
				buf := make([]byte, 0, len(testDestBytes)+4+len(msgPayload)+12)
				buf = append(buf, testDestBytes...)
				lenBytes := make([]byte, 4)
				binary.BigEndian.PutUint32(lenBytes, uint32(len(msgPayload)))
				buf = append(buf, lenBytes...)
				buf = append(buf, msgPayload...)
				nonceBytes := make([]byte, 4)
				binary.BigEndian.PutUint32(nonceBytes, 0x99999999)
				buf = append(buf, nonceBytes...)
				flagsBytes := make([]byte, 2)
				binary.BigEndian.PutUint16(flagsBytes, 0xFFFF)
				buf = append(buf, flagsBytes...)
				expMs := uint64(time.Now().Add(1 * time.Hour).UnixMilli())
				buf = append(
					buf,
					byte(expMs>>40),
					byte(expMs>>32),
					byte(expMs>>24),
					byte(expMs>>16),
					byte(expMs>>8),
					byte(expMs),
				)
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
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.checkNonce, parsed.Nonce, "nonce")
			assert.Equal(t, tt.checkFlags, parsed.Flags, "flags")
			assert.True(t, bytes.Equal(tt.checkPayload, parsed.Payload), "payload")
			assert.NotZero(t, parsed.Expiration, "expiration")
		})
	}
}

// TestSendMessageExpiresPayloadMarshal tests marshaling of SendMessageExpires payload
func TestSendMessageExpiresPayloadMarshal(t *testing.T) {
	dest, err := createTestDestination()
	require.NoError(t, err)
	destBytes, err := dest.Bytes()
	require.NoError(t, err)

	expMs := uint64(time.Now().Add(15 * time.Minute).UnixMilli())

	smp := &SendMessageExpiresPayload{
		Destination: *dest,
		Payload:     []byte("hello world"),
		Nonce:       0x11223344,
		Flags:       0x0002,
		Expiration:  expMs,
	}

	marshaled, err := smp.MarshalBinary()
	require.NoError(t, err)

	expectedSize := len(destBytes) + 4 + len(smp.Payload) + 12
	assert.Equal(t, expectedSize, len(marshaled), "marshaled size")

	assert.True(t, bytes.Equal(marshaled[0:len(destBytes)], destBytes), "destination mismatch")
	payloadLen := binary.BigEndian.Uint32(marshaled[len(destBytes) : len(destBytes)+4])
	assert.Equal(t, uint32(len(smp.Payload)), payloadLen, "payload length")
	payloadStart := len(destBytes) + 4
	payloadEnd := payloadStart + len(smp.Payload)
	assert.True(t, bytes.Equal(marshaled[payloadStart:payloadEnd], smp.Payload), "payload mismatch")

	offset := payloadEnd
	nonce := binary.BigEndian.Uint32(marshaled[offset : offset+4])
	assert.Equal(t, uint32(0x11223344), nonce, "nonce")

	flags := binary.BigEndian.Uint16(marshaled[offset+4 : offset+6])
	assert.Equal(t, uint16(0x0002), flags, "flags")

	expBytes := marshaled[offset+6 : offset+12]
	exp := uint64(expBytes[0])<<40 |
		uint64(expBytes[1])<<32 |
		uint64(expBytes[2])<<24 |
		uint64(expBytes[3])<<16 |
		uint64(expBytes[4])<<8 |
		uint64(expBytes[5])
	assert.Equal(t, expMs, exp, "expiration")
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
			dest, err := createTestDestination()
			require.NoError(t, err)

			original := &SendMessageExpiresPayload{
				Destination: *dest,
				Payload:     tt.payload,
				Nonce:       0xDEADBEEF,
				Flags:       0x1234,
				Expiration:  uint64(time.Now().Add(30 * time.Minute).UnixMilli()),
			}

			// Marshal
			marshaled, err := original.MarshalBinary()
			require.NoError(t, err)

			// Unmarshal
			parsed, err := ParseSendMessageExpiresPayload(marshaled)
			require.NoError(t, err)

			assert.True(t, original.Destination.Equals(&parsed.Destination), "destination")
			assert.True(t, bytes.Equal(original.Payload, parsed.Payload), "payload")
			assert.Equal(t, original.Nonce, parsed.Nonce, "nonce")
			assert.Equal(t, original.Flags, parsed.Flags, "flags")
			assert.Equal(t, original.Expiration, parsed.Expiration, "expiration")
		})
	}
}

// TestMessageTypeConstants verifies SendMessageExpires constant
func TestMessageTypeSendMessageExpires(t *testing.T) {
	assert.Equal(t, uint8(36), MessageTypeSendMessageExpires)
	assert.Equal(t, "SendMessageExpires", MessageTypeName(MessageTypeSendMessageExpires))
}

// TestMessageTypeDisconnect verifies Disconnect constant
func TestMessageTypeDisconnect(t *testing.T) {
	assert.Equal(t, uint8(30), MessageTypeDisconnect)
	assert.Equal(t, "Disconnect", MessageTypeName(MessageTypeDisconnect))
}

// TestExpirationTime tests expiration time calculations
func TestExpirationTime(t *testing.T) {
	pastMs := uint64(time.Now().Add(-5 * time.Minute).UnixMilli())
	currentMs := uint64(time.Now().UnixMilli())
	assert.Greater(t, currentMs, pastMs, "past time should be less than current")

	futureMs := uint64(time.Now().Add(10 * time.Minute).UnixMilli())
	assert.Greater(t, futureMs, currentMs, "future time should be greater than current")

	maxExpiration := uint64(1<<48 - 1)
	assert.GreaterOrEqual(t, maxExpiration, futureMs, "48-bit expiration should support far future")
}

func TestHostLookupPayloadParse(t *testing.T) {
	tests := []struct {
		name          string
		data          []byte
		wantSessionID uint16
		wantID        uint32
		wantTimeoutMs uint32
		wantType      uint16
		wantQuery     string
		shouldError   bool
	}{
		{
			name: "hash_lookup",
			data: func() []byte {
				buf := make([]byte, 11+32)
				binary.BigEndian.PutUint16(buf[0:2], 0x1234)
				binary.BigEndian.PutUint32(buf[2:6], 12345)
				binary.BigEndian.PutUint32(buf[6:10], 6000)
				buf[10] = byte(HostLookupTypeHash)
				copy(buf[11:], bytes.Repeat([]byte{0xaa}, 32))
				return buf
			}(),
			wantSessionID: 0x1234,
			wantID:        12345,
			wantTimeoutMs: 6000,
			wantType:      HostLookupTypeHash,
			wantQuery:     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			shouldError:   false,
		},
		{
			name: "hostname_lookup",
			data: func() []byte {
				buf := make([]byte, 11+12)
				binary.BigEndian.PutUint16(buf[0:2], 0x4321)
				binary.BigEndian.PutUint32(buf[2:6], 67890)
				binary.BigEndian.PutUint32(buf[6:10], 7000)
				buf[10] = byte(HostLookupTypeHostname)
				copy(buf[11:], []byte{0x0b, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'i', '2', 'p'})
				return buf
			}(),
			wantSessionID: 0x4321,
			wantID:        67890,
			wantTimeoutMs: 7000,
			wantType:      HostLookupTypeHostname,
			wantQuery:     "example.i2p",
			shouldError:   false,
		},
		{
			name: "empty_query",
			data: func() []byte {
				buf := make([]byte, 11)
				binary.BigEndian.PutUint16(buf[0:2], 0)
				binary.BigEndian.PutUint32(buf[2:6], 99999)
				binary.BigEndian.PutUint32(buf[6:10], 0)
				buf[10] = byte(HostLookupTypeHostname)
				return buf
			}(),
			wantSessionID: 0,
			wantID:        99999,
			wantTimeoutMs: 0,
			wantType:      HostLookupTypeHostname,
			wantQuery:     "",
			shouldError:   true,
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
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantSessionID, payload.SessionID)
			assert.Equal(t, tt.wantID, payload.RequestID)
			assert.Equal(t, tt.wantTimeoutMs, payload.TimeoutMs)
			assert.Equal(t, tt.wantType, payload.LookupType)
			assert.Equal(t, tt.wantQuery, payload.Query)
		})
	}
}

func TestHostLookupPayloadMarshal(t *testing.T) {
	tests := []struct {
		name    string
		payload *HostLookupPayload
	}{
		{
			name: "hash_lookup",
			payload: &HostLookupPayload{
				SessionID:  0x1234,
				RequestID:  54321,
				TimeoutMs:  1000,
				LookupType: HostLookupTypeHash,
				Query:      "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			},
		},
		{
			name: "hostname_lookup",
			payload: &HostLookupPayload{
				SessionID:  0x4321,
				RequestID:  11111,
				TimeoutMs:  2000,
				LookupType: HostLookupTypeHostname,
				Query:      "test.i2p",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.payload.MarshalBinary()
			require.NoError(t, err)

			parsed, err := ParseHostLookupPayload(data)
			require.NoError(t, err)

			assert.Equal(t, tt.payload.SessionID, parsed.SessionID)
			assert.Equal(t, tt.payload.RequestID, parsed.RequestID)
			assert.Equal(t, tt.payload.TimeoutMs, parsed.TimeoutMs)
			assert.Equal(t, tt.payload.LookupType, parsed.LookupType)
			assert.Equal(t, tt.payload.Query, parsed.Query)
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
				SessionID:  0x1234,
				RequestID:  12345,
				TimeoutMs:  3000,
				LookupType: HostLookupTypeHash,
				Query:      "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
			},
		},
		{
			name: "hostname_lookup",
			payload: &HostLookupPayload{
				SessionID:  0x5678,
				RequestID:  67890,
				TimeoutMs:  4000,
				LookupType: HostLookupTypeHostname,
				Query:      "example.i2p",
			},
		},
		{
			name: "long_hostname",
			payload: &HostLookupPayload{
				SessionID:  0x9abc,
				RequestID:  99999,
				TimeoutMs:  5000,
				LookupType: HostLookupTypeHostname,
				Query:      "very-long-hostname-that-tests-longer-queries.i2p",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.payload.MarshalBinary()
			require.NoError(t, err)

			parsed, err := ParseHostLookupPayload(data)
			require.NoError(t, err)

			assert.Equal(t, tt.payload.SessionID, parsed.SessionID)
			assert.Equal(t, tt.payload.RequestID, parsed.RequestID)
			assert.Equal(t, tt.payload.TimeoutMs, parsed.TimeoutMs)
			assert.Equal(t, tt.payload.LookupType, parsed.LookupType)
			assert.Equal(t, tt.payload.Query, parsed.Query)
		})
	}
}

func TestHostReplyPayloadParse(t *testing.T) {
	tests := []struct {
		name          string
		data          []byte
		wantSessionID uint16
		wantID        uint32
		wantCode      uint8
		wantDestLen   int
		shouldError   bool
	}{
		{
			name: "success_with_destination",
			data: func() []byte {
				buf := new(bytes.Buffer)
				binary.Write(buf, binary.BigEndian, uint16(0x1234))
				binary.Write(buf, binary.BigEndian, uint32(12345))
				buf.WriteByte(HostReplySuccess)
				buf.Write(make([]byte, 387)) // Standard destination size
				return buf.Bytes()
			}(),
			wantSessionID: 0x1234,
			wantID:        12345,
			wantCode:      HostReplySuccess,
			wantDestLen:   387,
			shouldError:   false,
		},
		{
			name: "not_found",
			data: func() []byte {
				buf := new(bytes.Buffer)
				binary.Write(buf, binary.BigEndian, uint16(0x1234))
				binary.Write(buf, binary.BigEndian, uint32(67890))
				buf.WriteByte(HostReplyNotFound)
				return buf.Bytes()
			}(),
			wantSessionID: 0x1234,
			wantID:        67890,
			wantCode:      HostReplyNotFound,
			wantDestLen:   0,
			shouldError:   false,
		},
		{
			name: "timeout",
			data: func() []byte {
				buf := new(bytes.Buffer)
				binary.Write(buf, binary.BigEndian, uint16(0x1234))
				binary.Write(buf, binary.BigEndian, uint32(11111))
				buf.WriteByte(HostReplyTimeout)
				return buf.Bytes()
			}(),
			wantSessionID: 0x1234,
			wantID:        11111,
			wantCode:      HostReplyTimeout,
			wantDestLen:   0,
			shouldError:   false,
		},
		{
			name: "error",
			data: func() []byte {
				buf := new(bytes.Buffer)
				binary.Write(buf, binary.BigEndian, uint16(0x1234))
				binary.Write(buf, binary.BigEndian, uint32(99999))
				buf.WriteByte(HostReplyError)
				return buf.Bytes()
			}(),
			wantSessionID: 0x1234,
			wantID:        99999,
			wantCode:      HostReplyError,
			wantDestLen:   0,
			shouldError:   false,
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
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantSessionID, payload.SessionID)
			assert.Equal(t, tt.wantID, payload.RequestID)
			assert.Equal(t, tt.wantCode, payload.ResultCode)
			assert.Equal(t, tt.wantDestLen, len(payload.Destination))
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
				SessionID:   0x1234,
				RequestID:   54321,
				ResultCode:  HostReplySuccess,
				Destination: make([]byte, 387),
			},
			check: func(data []byte) error {
				assert.Equal(t, 7+387, len(data), "data length")
				assert.Equal(t, uint16(0x1234), binary.BigEndian.Uint16(data[0:2]), "SessionID")
				reqID := binary.BigEndian.Uint32(data[2:6])
				assert.Equal(t, uint32(54321), reqID, "RequestID")
				assert.Equal(t, HostReplySuccess, data[6], "ResultCode")
				return nil
			},
		},
		{
			name: "not_found",
			payload: &HostReplyPayload{
				SessionID:   0x1234,
				RequestID:   11111,
				ResultCode:  HostReplyNotFound,
				Destination: nil,
			},
			check: func(data []byte) error {
				assert.Equal(t, 7, len(data), "data length")
				assert.Equal(t, HostReplyNotFound, data[6], "ResultCode")
				return nil
			},
		},
		{
			name: "timeout",
			payload: &HostReplyPayload{
				SessionID:   0x1234,
				RequestID:   22222,
				ResultCode:  HostReplyTimeout,
				Destination: []byte{}, // Empty slice
			},
			check: func(data []byte) error {
				assert.Equal(t, 7, len(data), "data length")
				assert.Equal(t, HostReplyTimeout, data[6], "ResultCode")
				return nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.payload.MarshalBinary()
			require.NoError(t, err)

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
				SessionID:   0x1234,
				RequestID:   12345,
				ResultCode:  HostReplySuccess,
				Destination: make([]byte, 387),
			},
		},
		{
			name: "not_found",
			payload: &HostReplyPayload{
				SessionID:   0x1234,
				RequestID:   67890,
				ResultCode:  HostReplyNotFound,
				Destination: nil,
			},
		},
		{
			name: "timeout",
			payload: &HostReplyPayload{
				SessionID:   0x1234,
				RequestID:   11111,
				ResultCode:  HostReplyTimeout,
				Destination: []byte{},
			},
		},
		{
			name: "error",
			payload: &HostReplyPayload{
				SessionID:   0x1234,
				RequestID:   99999,
				ResultCode:  HostReplyError,
				Destination: nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.payload.MarshalBinary()
			require.NoError(t, err)

			parsed, err := ParseHostReplyPayload(data)
			require.NoError(t, err)

			assert.Equal(t, tt.payload.SessionID, parsed.SessionID)
			assert.Equal(t, tt.payload.RequestID, parsed.RequestID)
			assert.Equal(t, tt.payload.ResultCode, parsed.ResultCode)
			assert.Equal(t, len(tt.payload.Destination), len(parsed.Destination))
		})
	}
}

func TestHostLookupConstants(t *testing.T) {
	assert.Equal(t, uint16(0), HostLookupTypeHash)
	assert.Equal(t, uint16(1), HostLookupTypeHostname)

	assert.Equal(t, uint8(0), HostReplySuccess)
	assert.Equal(t, uint8(1), HostReplyNotFound)
	assert.Equal(t, uint8(2), HostReplyTimeout)
	assert.Equal(t, uint8(3), HostReplyError)
}

func TestHostLookupTypeNames(t *testing.T) {
	assert.Equal(t, uint8(38), MessageTypeHostLookup)
	assert.Equal(t, uint8(39), MessageTypeHostReply)
	assert.Equal(t, "HostLookup", MessageTypeName(MessageTypeHostLookup))
	assert.Equal(t, "HostReply", MessageTypeName(MessageTypeHostReply))
	assert.Equal(t, uint8(34), MessageTypeDestLookup)
	assert.Equal(t, uint8(35), MessageTypeDestReply)
}

// =============================================================================
// HOST LOOKUP TESTS
// =============================================================================

// TestHostLookup_PayloadParsing verifies HostLookup payload parsing.
func TestHostLookup_PayloadParsing(t *testing.T) {
	t.Run("valid_hash_lookup", func(t *testing.T) {
		payload := make([]byte, 11+32)
		binary.BigEndian.PutUint16(payload[0:2], 0x1234)
		binary.BigEndian.PutUint32(payload[2:6], 12345)
		binary.BigEndian.PutUint32(payload[6:10], 6000)
		payload[10] = byte(HostLookupTypeHash)
		copy(payload[11:], bytes.Repeat([]byte{0xab}, 32))

		lookup, err := ParseHostLookupPayload(payload)
		require.NoError(t, err)

		assert.Equal(t, uint16(0x1234), lookup.SessionID)
		assert.Equal(t, uint32(12345), lookup.RequestID)
		assert.Equal(t, uint32(6000), lookup.TimeoutMs)
		assert.Equal(t, HostLookupTypeHash, lookup.LookupType)
		assert.Equal(t, "abababababababababababababababababababababababababababababababab", lookup.Query)
	})

	// Truncated payload
	t.Run("truncated_payload", func(t *testing.T) {
		payload := []byte{1, 2} // Too short

		_, err := ParseHostLookupPayload(payload)
		assert.Error(t, err)
	})
}

// TestHostLookup_ReplyPayloadMarshaling verifies HostReply marshaling.
func TestHostLookup_ReplyPayloadMarshaling(t *testing.T) {
	reply := &HostReplyPayload{
		SessionID:   0x1234,
		RequestID:   12345,
		ResultCode:  HostReplySuccess,
		Destination: make([]byte, 387), // Minimal destination
	}

	data, err := reply.MarshalBinary()
	require.NoError(t, err)

	// Verify header
	assert.Equal(t, uint16(0x1234), binary.BigEndian.Uint16(data[0:2]), "SessionID not serialized correctly")
	assert.Equal(t, uint32(12345), binary.BigEndian.Uint32(data[2:6]), "RequestID not serialized correctly")
	assert.Equal(t, HostReplySuccess, data[6], "ResultCode not serialized correctly")
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
		require.NoError(t, err)

		assert.True(t, info.Enabled)
		assert.Equal(t, 32, len(info.Secret))
	})

	// Disabled blinding
	t.Run("disabled_blinding", func(t *testing.T) {
		payload := []byte{0x00} // disabled

		info, err := ParseBlindingInfoPayload(payload)
		require.NoError(t, err)

		assert.False(t, info.Enabled)
	})
}
