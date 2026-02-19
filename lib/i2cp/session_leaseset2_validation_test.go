package i2cp

import (
	"testing"
	"time"

	"github.com/go-i2p/common/lease_set2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestValidateLeaseSet2Data_ValidLeaseSet verifies that a properly constructed
// LeaseSet2 from the session passes validation.
func TestValidateLeaseSet2Data_ValidLeaseSet(t *testing.T) {
	session, leaseSetBytes := createTestSessionWithLeaseSet(t)
	defer session.Stop()

	err := session.ValidateLeaseSet2Data(leaseSetBytes)
	assert.NoError(t, err, "Valid LeaseSet2 should pass validation")
}

// TestValidateLeaseSet2Data_InvalidStructure verifies that garbage data
// is rejected during structural parsing.
func TestValidateLeaseSet2Data_InvalidStructure(t *testing.T) {
	session, _ := createTestSessionWithLeaseSet(t)
	defer session.Stop()

	// Send garbage bytes
	invalidData := []byte("this is not a valid LeaseSet2 at all")
	err := session.ValidateLeaseSet2Data(invalidData)
	assert.Error(t, err, "Garbage data should fail validation")
	assert.Contains(t, err.Error(), "invalid LeaseSet2 structure")
}

// TestValidateLeaseSet2Data_DestinationMismatch verifies that a LeaseSet2
// with a different destination than the session is rejected.
func TestValidateLeaseSet2Data_DestinationMismatch(t *testing.T) {
	// Create two separate sessions with different destinations
	session1, _ := createTestSessionWithLeaseSet(t)
	defer session1.Stop()

	session2, leaseSet2Bytes := createTestSessionWithLeaseSet(t)
	defer session2.Stop()

	// Try to validate session2's LeaseSet against session1
	err := session1.ValidateLeaseSet2Data(leaseSet2Bytes)
	assert.Error(t, err, "LeaseSet2 from different session should fail destination matching")
	assert.Contains(t, err.Error(), "destination mismatch")
}

// TestValidateLeaseSet2Data_CorruptedSigningKey verifies that corrupting the
// signing public key in a LeaseSet2 causes validation to fail (destination mismatch).
func TestValidateLeaseSet2Data_CorruptedSigningKey(t *testing.T) {
	session, leaseSetBytes := createTestSessionWithLeaseSet(t)
	defer session.Stop()

	// The signing public key sits near the end of the destination's KeysAndCert
	// (at byte offset ~356 for Ed25519/X25519). Corrupt a few bytes there to
	// break the destination identity match.
	corrupted := make([]byte, len(leaseSetBytes))
	copy(corrupted, leaseSetBytes)

	// Corruption targets: bytes 360-363 are in the signing public key region
	// for an Ed25519/X25519 destination (total KeysAndCert = 391 bytes;
	// signing key at offset 384-415 in the raw data, but with padding it's ~356-387)
	corruptOffset := 360
	if corruptOffset < len(corrupted) {
		corrupted[corruptOffset] ^= 0xFF
		corrupted[corruptOffset+1] ^= 0xFF
		corrupted[corruptOffset+2] ^= 0xFF
	}

	err := session.ValidateLeaseSet2Data(corrupted)
	assert.Error(t, err, "Corrupted signing key should cause validation failure")
}

// TestValidateLeaseSet2Data_TooShortPayload verifies that too-short data
// is rejected during parsing.
func TestValidateLeaseSet2Data_TooShortPayload(t *testing.T) {
	session, _ := createTestSessionWithLeaseSet(t)
	defer session.Stop()

	// Send just a few bytes
	shortData := make([]byte, 50)
	err := session.ValidateLeaseSet2Data(shortData)
	assert.Error(t, err, "Too-short data should fail validation")
}

// TestValidateLeaseSet2Data_ExpiredLeaseSet verifies that an already-expired
// LeaseSet2 is rejected. We create a valid LeaseSet2 and then tamper with the
// published timestamp and expires offset to make it expired.
func TestValidateLeaseSet2Data_ExpiredLeaseSet(t *testing.T) {
	session, leaseSetBytes := createTestSessionWithLeaseSet(t)
	defer session.Stop()

	// The LeaseSet2 format has a 4-byte published timestamp (seconds since epoch)
	// right after the destination, and a 2-byte expires offset after that.
	// We'll tamper with the published timestamp to make it very old, so that
	// published + expiresOffset is in the past.
	//
	// Find the published field: it's at a fixed offset after the destination.
	// Destination is 391 bytes (Ed25519/X25519 with KeyCert), then:
	// published (4 bytes) + expires (2 bytes) + flags (2 bytes)
	//
	// Rather than hard-coding the offset, we'll use ReadLeaseSet2 to confirm
	// the format is valid, then set published to 0 (Jan 1 1970) with a tiny
	// expires offset to guarantee expiration.
	if len(leaseSetBytes) < 400 {
		t.Skip("LeaseSet2 bytes too short to manipulate")
	}

	// Parse to find the destination size by reading the keycert
	parsed, _, err := lease_set2.ReadLeaseSet2(leaseSetBytes)
	require.NoError(t, err)
	assert.False(t, parsed.IsExpired(), "Fresh LeaseSet2 should not be expired")

	// Tamper: set published timestamp to 0 (epoch) — this makes the LeaseSet2
	// expire at epoch + expiresOffset (seconds), which is long past.
	// The published field is a 4-byte big-endian uint32 right after the destination.
	// Destination size for Ed25519/X25519 is 391 bytes.
	destBytes, err := session.Destination().Bytes()
	require.NoError(t, err)
	destSize := len(destBytes)

	tampered := make([]byte, len(leaseSetBytes))
	copy(tampered, leaseSetBytes)

	// Zero out the published timestamp (4 bytes at destSize offset)
	tampered[destSize] = 0
	tampered[destSize+1] = 0
	tampered[destSize+2] = 0
	tampered[destSize+3] = 0
	// Set expires offset to 1 second
	tampered[destSize+4] = 0
	tampered[destSize+5] = 1

	// This tampered LeaseSet2 should fail validation (either expired or signature invalid)
	err = session.ValidateLeaseSet2Data(tampered)
	assert.Error(t, err, "Tampered/expired LeaseSet2 should fail validation")
}

// TestHandleCreateLeaseSet2_WithValidation verifies that handleCreateLeaseSet2
// now validates the LeaseSet2 before publishing.
func TestHandleCreateLeaseSet2_WithValidation(t *testing.T) {
	publisher := newMockLeaseSetPublisher()

	session, leaseSetBytes := createTestSessionWithLeaseSet(t)
	defer session.Stop()
	session.SetLeaseSetPublisher(publisher)

	config := DefaultServerConfig()
	config.LeaseSetPublisher = publisher
	server, err := NewServer(config)
	require.NoError(t, err)

	// Build wire-format payload: SessionID(2 bytes) + LeaseSet2 data
	wirePayload := prependSessionID(session.ID(), leaseSetBytes)

	msg := &Message{
		Type:      MessageTypeCreateLeaseSet2,
		SessionID: session.ID(),
		Payload:   wirePayload,
	}

	sessionPtr := session
	response, err := server.handleCreateLeaseSet2(msg, &sessionPtr)

	assert.NoError(t, err, "handleCreateLeaseSet2 should succeed with valid data")
	assert.Nil(t, response, "CreateLeaseSet2 should not return a response")

	// Verify session cached the LeaseSet (should be the stripped payload, not wire format)
	cached := session.CurrentLeaseSet()
	assert.Equal(t, leaseSetBytes, cached, "Session should cache the validated LeaseSet2")
}

// TestHandleCreateLeaseSet2_RejectsGarbage verifies that handleCreateLeaseSet2
// rejects arbitrary payload bytes.
func TestHandleCreateLeaseSet2_RejectsGarbage(t *testing.T) {
	publisher := newMockLeaseSetPublisher()

	session, _ := createTestSessionWithLeaseSet(t)
	defer session.Stop()
	session.SetLeaseSetPublisher(publisher)

	config := DefaultServerConfig()
	server, err := NewServer(config)
	require.NoError(t, err)

	// Send garbage bytes as payload (>400 bytes after session ID to pass the length check)
	garbage := make([]byte, 500)
	for i := range garbage {
		garbage[i] = byte(i % 256)
	}

	// Build wire-format payload: SessionID(2 bytes) + garbage data
	wirePayload := prependSessionID(session.ID(), garbage)

	msg := &Message{
		Type:      MessageTypeCreateLeaseSet2,
		SessionID: session.ID(),
		Payload:   wirePayload,
	}

	sessionPtr := session
	_, err = server.handleCreateLeaseSet2(msg, &sessionPtr)
	assert.Error(t, err, "handleCreateLeaseSet2 should reject garbage data")
	assert.Contains(t, err.Error(), "validation failed")

	// Verify publisher was NOT called
	assert.Equal(t, 0, publisher.publishCalled, "Publisher should not be called for invalid data")
}

// TestHandleCreateLeaseSet2_RejectsWrongDestination verifies that handleCreateLeaseSet2
// rejects a LeaseSet2 with a destination that doesn't match the session.
func TestHandleCreateLeaseSet2_RejectsWrongDestination(t *testing.T) {
	publisher := newMockLeaseSetPublisher()

	// Create two sessions
	session1, _ := createTestSessionWithLeaseSet(t)
	defer session1.Stop()

	_, leaseSet2Bytes := createTestSessionWithLeaseSet(t)

	session1.SetLeaseSetPublisher(publisher)

	config := DefaultServerConfig()
	server, err := NewServer(config)
	require.NoError(t, err)

	// Try to publish session2's LeaseSet through session1
	// Build wire-format payload: SessionID(2 bytes) + LeaseSet2 data
	wirePayload := prependSessionID(session1.ID(), leaseSet2Bytes)

	msg := &Message{
		Type:      MessageTypeCreateLeaseSet2,
		SessionID: session1.ID(),
		Payload:   wirePayload,
	}

	sessionPtr := session1
	_, err = server.handleCreateLeaseSet2(msg, &sessionPtr)
	assert.Error(t, err, "handleCreateLeaseSet2 should reject LeaseSet2 with wrong destination")
	assert.Contains(t, err.Error(), "validation failed")

	// Verify publisher was NOT called
	assert.Equal(t, 0, publisher.publishCalled, "Publisher should not be called for mismatched destination")
}

// TestHandleCreateLeaseSet2_RejectsTooShort verifies that handleCreateLeaseSet2
// rejects payloads that are too short.
func TestHandleCreateLeaseSet2_RejectsTooShort(t *testing.T) {
	session, _ := createTestSessionWithLeaseSet(t)
	defer session.Stop()

	config := DefaultServerConfig()
	server, err := NewServer(config)
	require.NoError(t, err)

	// Build wire-format payload: SessionID(2 bytes) + very short LeaseSet2 data
	// The handler will strip the 2-byte session ID, leaving only 1 byte,
	// which is too short for a valid LeaseSet2.
	msg := &Message{
		Type:      MessageTypeCreateLeaseSet2,
		SessionID: session.ID(),
		Payload:   []byte{0x00, 0x01, 0x03},
	}

	sessionPtr := session
	_, err = server.handleCreateLeaseSet2(msg, &sessionPtr)
	assert.Error(t, err, "handleCreateLeaseSet2 should reject too-short payload")
	assert.Contains(t, err.Error(), "too short")
}

// TestSetCurrentLeaseSet verifies that SetCurrentLeaseSet properly caches data.
func TestSetCurrentLeaseSet(t *testing.T) {
	session, err := NewSession(1, nil, nil)
	require.NoError(t, err)
	defer session.Stop()

	// Initially nil
	assert.Nil(t, session.CurrentLeaseSet())

	// Set and verify
	testData := []byte("test-leaseset-data")
	session.SetCurrentLeaseSet(testData)
	assert.Equal(t, testData, session.CurrentLeaseSet())

	// Age should be very recent
	assert.Less(t, session.LeaseSetAge(), 5*time.Second)
}
