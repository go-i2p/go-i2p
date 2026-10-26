package i2cp

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHandleCreateLeaseSet2_WithValidation verifies that handleCreateLeaseSet2
// validates the declared lease set before publishing, and caches exactly the
// framed structure.
func TestHandleCreateLeaseSet2_WithValidation(t *testing.T) {
	publisher := newMockLeaseSetPublisher()

	session, leaseSetBytes := createTestSessionWithLeaseSet(t)
	defer session.Stop()
	session.SetLeaseSetPublisher(publisher)

	config := DefaultServerConfig()
	config.LeaseSetPublisher = publisher
	server, err := NewServer(config)
	require.NoError(t, err)

	// Build wire-format payload: SessionID(2) + StoreType(1) + LeaseSet2
	msg := buildCreateLeaseSet2Message(t, session.ID(), LeaseSetStoreTypeLeaseSet2, leaseSetBytes, nil)

	sessionPtr := session
	response, err := server.handleCreateLeaseSet2(msg, &sessionPtr)
	require.NoError(t, err, "a valid LeaseSet2 declared with store type 3 must be accepted")
	assert.Nil(t, response, "CreateLeaseSet2 does not return a response message")

	// Verify session cached the LeaseSet (the framed structure, not the wire payload)
	cached := session.CurrentLeaseSet()
	assert.Equal(t, leaseSetBytes, cached, "Session should cache the validated LeaseSet2")
	assert.Equal(t, 1, publisher.publishCalled, "the validated LeaseSet2 must be published")
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

	// Send garbage bytes as payload (large enough to clear the upstream minimum
	// LeaseSet2 size, so the structural parse is what must reject it)
	garbage := make([]byte, 1200)
	for i := range garbage {
		garbage[i] = byte(i % 256)
	}

	// Build wire-format payload: SessionID(2) + StoreType(1) + garbage data
	msg := buildCreateLeaseSet2Message(t, session.ID(), LeaseSetStoreTypeLeaseSet2, garbage, nil)

	sessionPtr := session
	_, err = server.handleCreateLeaseSet2(msg, &sessionPtr)
	assert.Error(t, err, "handleCreateLeaseSet2 should reject garbage data")
	assert.Contains(t, err.Error(), "invalid LeaseSet2")

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
	msg := buildCreateLeaseSet2Message(t, session1.ID(), LeaseSetStoreTypeLeaseSet2, leaseSet2Bytes, nil)

	sessionPtr := session1
	_, err = server.handleCreateLeaseSet2(msg, &sessionPtr)
	assert.Error(t, err, "handleCreateLeaseSet2 should reject LeaseSet2 with wrong destination")
	assert.Contains(t, err.Error(), "does not match")

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

	// SessionID(2) + store type 3 + a 1-byte body, far below the upstream
	// minimum LeaseSet2 size.
	msg := &Message{
		Type:      MessageTypeCreateLeaseSet2,
		SessionID: session.ID(),
		Payload:   []byte{0x00, 0x01, 0x03, 0x00},
	}

	sessionPtr := session
	_, err = server.handleCreateLeaseSet2(msg, &sessionPtr)
	assert.Error(t, err, "handleCreateLeaseSet2 should reject too-short payload")
	assert.Contains(t, err.Error(), "too short")
}
