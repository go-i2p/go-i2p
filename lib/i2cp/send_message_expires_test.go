package i2cp

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"github.com/go-i2p/common/data"
)

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
