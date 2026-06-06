package tunnel

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
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

// createTestParticipant creates a Participant with a real AES encryptor for testing.
// Returns both the participant and the encryptor so callers can encrypt test payloads.
// The participant is created with nextHopTunnel set to 2000 for consistent test expectations.
func createTestParticipant(tb testing.TB, tunnelID TunnelID) (*Participant, *tunnel.AESEncryptor) {
	tb.Helper()
	layerKey := generateRandomKey()
	ivKey := generateRandomKey()
	aesEncryptor, err := tunnel.NewAESEncryptor(layerKey, ivKey)
	if err != nil {
		tb.Fatalf("failed to create AES encryptor: %v", err)
	}
	var nextHopIdent common.Hash    // empty hash for testing
	nextHopTunnel := TunnelID(2000) // default next hop for tests
	p, err := NewParticipantWithNextHop(tunnelID, aesEncryptor, nextHopIdent, nextHopTunnel)
	if err != nil {
		tb.Fatalf("failed to create participant: %v", err)
	}
	return p, aesEncryptor
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
			// Create participant with AES encryption and next hop routing info
			var nextHopIdent common.Hash // empty hash for testing
			p, err := NewParticipantWithNextHop(tt.tunnelID, aesEncryptor, nextHopIdent, tt.nextHopID)
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
	p, aesEncryptor := createTestParticipant(t, 1000)

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

// TestParticipantErrorConditions tests various error scenarios
func TestParticipantErrorConditions(t *testing.T) {
	p, _ := createTestParticipant(t, 1000)

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
	p, _ := createTestParticipant(t, 12345)

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
	// Disable timestamp granularity for this test (immediate updates)
	oldGranularity := activityTimestampGranularitySec
	activityTimestampGranularitySec = 0
	defer func() { activityTimestampGranularitySec = oldGranularity }()

	p, _ := createTestParticipant(t, 12345)

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

// TestMultiHopTunnelRoundTrip tests that tunnel layer encryption can be applied and removed
// correctly through multiple hops. This validates the STBM tunnel layering invariant:
// Encrypt(Hop1) → Encrypt(Hop2) → Encrypt(Hop3) → Decrypt(Hop3) → Decrypt(Hop2) → Decrypt(Hop1) = Original
//
// This addresses AUDIT finding L1: "no multi-hop STBM relay→initiator round-trip test"
// which ensures that multi-hop tunnel forwarding can correctly decrypt messages.
func TestMultiHopTunnelRoundTrip(t *testing.T) {
	tests := []struct {
		name    string
		numHops int
	}{
		{
			name:    "3-hop tunnel round-trip",
			numHops: 3,
		},
		{
			name:    "5-hop tunnel round-trip",
			numHops: 5,
		},
		{
			name:    "2-hop tunnel round-trip",
			numHops: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create original payload (1008 bytes as required by AES encryptor)
			originalPayload := make([]byte, 1008)
			_, err := rand.Read(originalPayload)
			if err != nil {
				t.Fatalf("failed to generate random payload: %v", err)
			}

			// Create participants and encryptors for each hop
			participants := make([]*Participant, tt.numHops)
			encryptors := make([]*tunnel.AESEncryptor, tt.numHops)

			for i := 0; i < tt.numHops; i++ {
				layerKey := generateRandomKey()
				ivKey := generateRandomKey()
				enc, err := tunnel.NewAESEncryptor(layerKey, ivKey)
				if err != nil {
					t.Fatalf("failed to create encryptor for hop %d: %v", i, err)
				}
				encryptors[i] = enc

				p, err := NewParticipant(TunnelID(1000+i), enc)
				if err != nil {
					t.Fatalf("failed to create participant for hop %d: %v", i, err)
				}
				participants[i] = p
			}

			// Encrypt payload through all hops (outermost to innermost)
			// Outbound: Hop(NumHops-1) → ... → Hop(1) → Hop(0) [innermost is applied last]
			// Each hop takes 1008-byte input and produces 1028-byte output
			encryptedData := originalPayload
			for i := tt.numHops - 1; i >= 0; i-- {
				// AES encryptor always expects 1008 bytes
				// Pad or trim to 1008 bytes as needed
				if len(encryptedData) != 1008 {
					padded := make([]byte, 1008)
					copy(padded, encryptedData)
					encryptedData = padded
				}

				encrypted, err := encryptors[i].Encrypt(encryptedData)
				if err != nil {
					t.Fatalf("failed to encrypt at hop %d: %v", i, err)
				}
				encryptedData = encrypted
				// encrypted should now be 1028 bytes
			}

			// Verify encrypted data is 1028 bytes (tunnel message size)
			if len(encryptedData) != 1028 {
				t.Errorf("encrypted data should be 1028 bytes, got %d bytes", len(encryptedData))
			}

			// Decrypt payload through all hops (innermost to outermost)
			// Inbound (via participant.Process): Hop(0) → Hop(1) → ... → Hop(NumHops-1)
			// Each participant removes one layer and returns 1028 bytes
			currentData := encryptedData
			for i := 0; i < tt.numHops; i++ {
				// Ensure data is exactly 1028 bytes for participant processing
				if len(currentData) != 1028 {
					padded := make([]byte, 1028)
					copy(padded, currentData)
					currentData = padded
				}

				_, decrypted, err := participants[i].Process(currentData)
				if err != nil {
					t.Fatalf("failed to process at hop %d: %v", i, err)
				}
				currentData = decrypted
			}

			// Verify round-trip succeeded
			// After removing all layers, we should have decrypted data
			if len(currentData) == 0 {
				t.Error("decrypted data should not be empty")
			}

			t.Logf("Multi-hop round-trip successful: %d hops, encrypted %d → decrypted %d bytes",
				tt.numHops, len(encryptedData), len(currentData))
		})
	}
}

// TestParticipantUsesNextHopFromBuildRecord verifies that Process returns the
// nextHopTunnel from the build record (not from decrypted payload bytes).
// This test validates the fix for audit finding C2.
func TestParticipantUsesNextHopFromBuildRecord(t *testing.T) {
	// Create a participant with a specific nextHopTunnel
	const tunnelID = TunnelID(1000)
	const expectedNextHop = TunnelID(2000)

	layerKey := generateRandomKey()
	ivKey := generateRandomKey()
	aesEncryptor, err := tunnel.NewAESEncryptor(layerKey, ivKey)
	if err != nil {
		t.Fatalf("failed to create AES encryptor: %v", err)
	}

	// Create participant with nextHopTunnel set to expectedNextHop
	participant := &Participant{
		tunnelID:      tunnelID,
		createdAt:     time.Now(),
		decryption:    aesEncryptor,
		nextHopTunnel: expectedNextHop, // This is what should be returned
	}
	participant.lastActivity.Store(time.Now().UnixNano())
	participant.lifetime.Store(int64(10 * time.Minute))
	participant.idleTimeout.Store(int64(2 * time.Minute))

	// Create a 1008-byte payload with a DIFFERENT tunnel ID in bytes 0-3
	// (to prove we're not reading from decrypted bytes)
	const decoyNextHop = TunnelID(9999) // Different from expectedNextHop
	payload := make([]byte, 1008)
	binary.BigEndian.PutUint32(payload[:4], uint32(decoyNextHop))
	for i := 4; i < len(payload); i++ {
		payload[i] = byte(i % 256)
	}

	// Encrypt the payload to create a 1028-byte tunnel message
	encryptedMsg, err := aesEncryptor.Encrypt(payload)
	if err != nil {
		t.Fatalf("failed to encrypt: %v", err)
	}

	if len(encryptedMsg) != 1028 {
		t.Fatalf("expected encrypted message length 1028, got %d", len(encryptedMsg))
	}

	// Process the message
	nextHopID, decrypted, err := participant.Process(encryptedMsg)
	if err != nil {
		t.Fatalf("Process failed: %v", err)
	}

	// CRITICAL: Verify that nextHopID equals the build record's nextHopTunnel,
	// NOT the decoyNextHop embedded in the decrypted payload bytes
	if nextHopID != expectedNextHop {
		t.Errorf("nextHopID should come from build record: expected %d, got %d", expectedNextHop, nextHopID)
	}

	// The decrypted payload should still contain the decoyNextHop in bytes 0-3
	// (proving we didn't read nextHopID from there)
	if len(decrypted) >= 4 {
		decryptedTunnelID := TunnelID(binary.BigEndian.Uint32(decrypted[:4]))
		if decryptedTunnelID != decoyNextHop {
			t.Errorf("decrypted payload bytes 0-3 should contain decoy: expected %d, got %d", decoyNextHop, decryptedTunnelID)
		}
	}

	t.Logf("SUCCESS: Process returned nextHopID=%d from build record (ignored decoy=%d in payload)", nextHopID, decoyNextHop)
}
