package i2cp

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
