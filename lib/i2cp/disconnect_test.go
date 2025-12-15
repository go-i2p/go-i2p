package i2cp

import (
	"bytes"
	"encoding/binary"
	"testing"
)

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
				reason := "Connection terminated due to protocol version mismatch: expected 9.67.0, got 2.9.0"
				buf := make([]byte, 2+len(reason))
				binary.BigEndian.PutUint16(buf[0:2], uint16(len(reason)))
				copy(buf[2:], reason)
				return buf
			}(),
			expectError:  false,
			expectReason: "Connection terminated due to protocol version mismatch: expected 9.67.0, got 2.9.0",
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
