package tunnel

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	"github.com/go-i2p/crypto/rand"
	"github.com/go-i2p/crypto/tunnel"
)

// Helper function to generate a random 32-byte key
func generateRandomKey() tunnel.TunnelKey {
	var key tunnel.TunnelKey
	if _, err := rand.Read(key[:]); err != nil {
		panic(fmt.Sprintf("Failed to generate random key: %v", err))
	}
	return key
}

// TestNewParticipant tests the creation of a new participant
func TestNewParticipant(t *testing.T) {
	// Create real AES encryptor for testing
	layerKey := generateRandomKey()
	ivKey := generateRandomKey()
	validEncryptor, err := tunnel.NewAESEncryptor(layerKey, ivKey)
	if err != nil {
		t.Fatalf("failed to create AES encryptor: %v", err)
	}

	tests := []struct {
		name        string
		tunnelID    TunnelID
		decryption  tunnel.TunnelEncryptor
		expectError bool
		errorType   error
	}{
		{
			name:        "valid participant creation with AES",
			tunnelID:    12345,
			decryption:  validEncryptor,
			expectError: false,
		},
		{
			name:        "nil decryption should fail",
			tunnelID:    12345,
			decryption:  nil,
			expectError: true,
			errorType:   ErrNilParticipantDecryption,
		},
		{
			name:        "zero tunnel ID is valid",
			tunnelID:    0,
			decryption:  validEncryptor,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := NewParticipant(tt.tunnelID, tt.decryption)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got nil")
				}
				if tt.errorType != nil && err != tt.errorType {
					t.Errorf("expected error %v, got %v", tt.errorType, err)
				}
				if p != nil {
					t.Errorf("expected nil participant on error, got %v", p)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if p == nil {
					t.Errorf("expected participant, got nil")
				}
				if p != nil && p.TunnelID() != tt.tunnelID {
					t.Errorf("expected tunnel ID %d, got %d", tt.tunnelID, p.TunnelID())
				}
			}
		})
	}
}

// TestParticipantProcess tests the message processing functionality
func TestParticipantProcess(t *testing.T) {
	// Create AES encryptor for valid tests
	layerKey := generateRandomKey()
	ivKey := generateRandomKey()
	aesEncryptor, err := tunnel.NewAESEncryptor(layerKey, ivKey)
	if err != nil {
		t.Fatalf("failed to create AES encryptor: %v", err)
	}

	tests := []struct {
		name        string
		dataSize    int
		tunnelID    TunnelID
		nextHopID   TunnelID
		expectError bool
		errorType   error
	}{
		{
			name:        "valid 1028 byte message",
			dataSize:    1028,
			tunnelID:    100,
			nextHopID:   200,
			expectError: false,
		},
		{
			name:        "invalid message size - too small",
			dataSize:    512,
			tunnelID:    100,
			expectError: true,
			errorType:   ErrInvalidParticipantData,
		},
		{
			name:        "invalid message size - too large",
			dataSize:    2048,
			tunnelID:    100,
			expectError: true,
			errorType:   ErrInvalidParticipantData,
		},
		{
			name:        "invalid message size - zero",
			dataSize:    0,
			tunnelID:    100,
			expectError: true,
			errorType:   ErrInvalidParticipantData,
		},
		{
			name:        "maximum tunnel ID",
			dataSize:    1028,
			tunnelID:    0xFFFFFFFF,
			nextHopID:   0xFFFFFFFE,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create participant with AES encryption
			p, err := NewParticipant(tt.tunnelID, aesEncryptor)
			if err != nil {
				t.Fatalf("failed to create participant: %v", err)
			}

			var encryptedData []byte
			if tt.dataSize == 1028 {
				// For valid tunnel messages, create proper 1008-byte payload
				// The payload contains: [Tunnel ID (4)] [IV placeholder (16)] [Checksum (4)] [Padding + Data (984)]
				payload := make([]byte, 1008)

				// Set tunnel ID at start of payload
				binary.BigEndian.PutUint32(payload[:4], uint32(tt.nextHopID))

				// Fill rest with test pattern
				for i := 4; i < len(payload); i++ {
					payload[i] = byte(i % 256)
				}

				// Encrypt to get full 1028-byte tunnel message
				encryptedData, err = aesEncryptor.Encrypt(payload)
				if err != nil {
					t.Fatalf("failed to encrypt: %v", err)
				}
			} else {
				// For invalid sizes, create test data directly
				encryptedData = make([]byte, tt.dataSize)
			}

			// Process the message
			nextHop, decrypted, err := p.Process(encryptedData)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got nil")
				}
				if tt.errorType != nil && err != tt.errorType {
					t.Errorf("expected error %v, got %v", tt.errorType, err)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if nextHop != tt.nextHopID {
					t.Errorf("expected next hop ID %d, got %d", tt.nextHopID, nextHop)
				}
				// After decryption, we get the 1008-byte payload back
				if len(decrypted) != 1008 {
					t.Errorf("expected decrypted data length 1008, got %d", len(decrypted))
				}

				// Verify the tunnel ID at the start of the decrypted payload
				if len(decrypted) >= 4 {
					decryptedTunnelID := binary.BigEndian.Uint32(decrypted[:4])
					if decryptedTunnelID != uint32(tt.nextHopID) {
						t.Errorf("expected decrypted tunnel ID %d, got %d", tt.nextHopID, decryptedTunnelID)
					}
				}
			}
		})
	}
}

// TestParticipantProcessMultiLayer tests that participants can process messages sequentially
// This test uses real AES encryption to verify the participant processing pipeline.
func TestParticipantProcessMultiLayer(t *testing.T) {
	// Create AES encryptor
	layerKey := generateRandomKey()
	ivKey := generateRandomKey()
	aesEncryptor, err := tunnel.NewAESEncryptor(layerKey, ivKey)
	if err != nil {
		t.Fatalf("failed to create AES encryptor: %v", err)
	}

	// Create a participant
	p, err := NewParticipant(1000, aesEncryptor)
	if err != nil {
		t.Fatalf("failed to create participant: %v", err)
	}

	// Create a 1008-byte payload (what goes into AES encryption)
	payload := make([]byte, 1008)
	nextHopID := TunnelID(2000)
	binary.BigEndian.PutUint32(payload[:4], uint32(nextHopID))
	for i := 4; i < len(payload); i++ {
		payload[i] = byte(i % 256)
	}

	// Encrypt it (produces 1028-byte tunnel message)
	encryptedMsg, err := aesEncryptor.Encrypt(payload)
	if err != nil {
		t.Fatalf("failed to encrypt: %v", err)
	}

	// Verify we got a full tunnel message
	if len(encryptedMsg) != 1028 {
		t.Fatalf("expected encrypted message length 1028, got %d", len(encryptedMsg))
	}

	// Process through participant (decrypts back to 1008-byte payload)
	extractedNextHop, decryptedMsg, err := p.Process(encryptedMsg)
	if err != nil {
		t.Fatalf("participant process failed: %v", err)
	}

	// Verify next hop ID was extracted correctly
	if extractedNextHop != nextHopID {
		t.Errorf("expected next hop %d, got %d", nextHopID, extractedNextHop)
	}

	// Verify decryption worked (should return 1008-byte payload)
	if len(decryptedMsg) != 1008 {
		t.Errorf("expected 1008 bytes, got %d", len(decryptedMsg))
	}

	// The decrypted tunnel ID should match what we put in the payload
	decryptedTunnelID := binary.BigEndian.Uint32(decryptedMsg[:4])
	if decryptedTunnelID != uint32(nextHopID) {
		t.Errorf("expected tunnel ID %d, got %d", nextHopID, decryptedTunnelID)
	}

	// Verify payload matches original
	if !bytes.Equal(decryptedMsg, payload) {
		t.Errorf("decrypted payload doesn't match original")
		t.Logf("Expected first 20 bytes: %x", payload[:20])
		t.Logf("Got first 20 bytes: %x", decryptedMsg[:20])
	}
}

// TestParticipantTunnelID tests the TunnelID getter
func TestParticipantTunnelID(t *testing.T) {
	layerKey := generateRandomKey()
	ivKey := generateRandomKey()
	aesEncryptor, err := tunnel.NewAESEncryptor(layerKey, ivKey)
	if err != nil {
		t.Fatalf("failed to create AES encryptor: %v", err)
	}

	testID := TunnelID(42)
	p, err := NewParticipant(testID, aesEncryptor)
	if err != nil {
		t.Fatalf("failed to create participant: %v", err)
	}

	if p.TunnelID() != testID {
		t.Errorf("expected tunnel ID %d, got %d", testID, p.TunnelID())
	}
}

// BenchmarkParticipantProcess benchmarks the message processing
func BenchmarkParticipantProcess(b *testing.B) {
	layerKey := generateRandomKey()
	ivKey := generateRandomKey()
	aesEncryptor, err := tunnel.NewAESEncryptor(layerKey, ivKey)
	if err != nil {
		b.Fatalf("failed to create AES encryptor: %v", err)
	}

	p, err := NewParticipant(1000, aesEncryptor)
	if err != nil {
		b.Fatalf("failed to create participant: %v", err)
	}

	// Create test message (1008-byte payload)
	payload := make([]byte, 1008)
	binary.BigEndian.PutUint32(payload[:4], 2000)
	for i := 4; i < len(payload); i++ {
		payload[i] = byte(i % 256)
	}

	// Encrypt it (produces 1028-byte tunnel message)
	encryptedData, err := aesEncryptor.Encrypt(payload)
	if err != nil {
		b.Fatalf("failed to encrypt: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Make a copy for each iteration
		data := make([]byte, len(encryptedData))
		copy(data, encryptedData)
		_, _, err := p.Process(data)
		if err != nil {
			b.Fatalf("process failed: %v", err)
		}
	}
}

// TestParticipantErrorConditions tests various error scenarios
func TestParticipantErrorConditions(t *testing.T) {
	layerKey := generateRandomKey()
	ivKey := generateRandomKey()
	aesEncryptor, err := tunnel.NewAESEncryptor(layerKey, ivKey)
	if err != nil {
		t.Fatalf("failed to create AES encryptor: %v", err)
	}

	p, err := NewParticipant(1000, aesEncryptor)
	if err != nil {
		t.Fatalf("failed to create participant: %v", err)
	}

	tests := []struct {
		name      string
		input     []byte
		wantError error
	}{
		{
			name:      "nil input",
			input:     nil,
			wantError: ErrInvalidParticipantData,
		},
		{
			name:      "empty input",
			input:     []byte{},
			wantError: ErrInvalidParticipantData,
		},
		{
			name:      "too small",
			input:     make([]byte, 1027),
			wantError: ErrInvalidParticipantData,
		},
		{
			name:      "too large",
			input:     make([]byte, 1029),
			wantError: ErrInvalidParticipantData,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := p.Process(tt.input)
			if err == nil {
				t.Errorf("expected error but got nil")
			}
			if err != tt.wantError {
				t.Errorf("expected error %v, got %v", tt.wantError, err)
			}
		})
	}
}

// TestParticipantIdleDetection tests the idle tunnel detection functionality
func TestParticipantIdleDetection(t *testing.T) {
	// Create a valid participant
	layerKey := generateRandomKey()
	ivKey := generateRandomKey()
	encryptor, err := tunnel.NewAESEncryptor(layerKey, ivKey)
	if err != nil {
		t.Fatalf("failed to create AES encryptor: %v", err)
	}

	p, err := NewParticipant(12345, encryptor)
	if err != nil {
		t.Fatalf("failed to create participant: %v", err)
	}

	// Test that new participant is not idle
	now := time.Now()
	if p.IsIdle(now) {
		t.Error("new participant should not be idle immediately")
	}

	// Test that participant becomes idle after timeout
	futureTime := now.Add(DefaultIdleTimeout + time.Second)
	if !p.IsIdle(futureTime) {
		t.Error("participant should be idle after timeout period")
	}

	// Test LastActivity returns the creation time initially
	if p.LastActivity().IsZero() {
		t.Error("last activity should not be zero")
	}

	// Test SetIdleTimeout
	p.SetIdleTimeout(5 * time.Minute)
	// With longer timeout, should no longer be idle at futureTime
	if p.IsIdle(futureTime) {
		t.Error("participant should not be idle with longer timeout")
	}
}

// TestParticipantProcessUpdatesActivity tests that Process updates last activity
func TestParticipantProcessUpdatesActivity(t *testing.T) {
	// Create a valid participant
	layerKey := generateRandomKey()
	ivKey := generateRandomKey()
	encryptor, err := tunnel.NewAESEncryptor(layerKey, ivKey)
	if err != nil {
		t.Fatalf("failed to create AES encryptor: %v", err)
	}

	p, err := NewParticipant(12345, encryptor)
	if err != nil {
		t.Fatalf("failed to create participant: %v", err)
	}

	initialActivity := p.LastActivity()

	// Wait a tiny bit and process a message (even if it fails, activity should update)
	time.Sleep(1 * time.Millisecond)

	// Create a valid 1028-byte message
	encryptedData := make([]byte, 1028)
	binary.BigEndian.PutUint32(encryptedData[:4], 99999)

	// Process will update lastActivity even before validation
	p.Process(encryptedData)

	newActivity := p.LastActivity()
	if !newActivity.After(initialActivity) {
		t.Error("Process should update last activity timestamp")
	}
}
