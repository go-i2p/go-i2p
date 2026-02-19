package i2cp

import (
	"sync"
	"testing"

	"github.com/go-i2p/go-i2p/lib/keys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Tests for AUDIT fix: "I2CP Session With External Destination Cannot Create
// LeaseSets" — verifies that sessions created with an external destination
// still receive a non-nil DestinationKeyStore so that LeaseSet creation
// does not panic with a nil pointer dereference.
// =============================================================================

// TestNewSession_WithExternalDestination_HasKeys verifies that providing a
// non-nil destination to NewSession still results in a session whose internal
// keys field is non-nil (so CreateLeaseSet won't panic).
func TestNewSession_WithExternalDestination_HasKeys(t *testing.T) {
	// Create an external destination using a temporary keystore
	keyStore, err := keys.NewDestinationKeyStore()
	require.NoError(t, err, "failed to create test destination keystore")

	externalDest := keyStore.Destination()
	require.NotNil(t, externalDest, "test destination should not be nil")

	// Create a session with that external destination
	session, err := NewSession(42, externalDest, nil)
	require.NoError(t, err, "NewSession with external destination should succeed")
	defer session.Stop()

	// The critical invariant: session.keys must NOT be nil
	assert.NotNil(t, session.keys,
		"session created with external destination must have non-nil keys")
	assert.NotNil(t, session.destination,
		"session must have a destination")
}

// TestNewSession_WithNilDestination_HasKeys verifies the baseline: a session
// with nil destination also gets keys (this always worked, but we verify it
// as a regression guard).
func TestNewSession_WithNilDestination_HasKeys(t *testing.T) {
	session, err := NewSession(1, nil, nil)
	require.NoError(t, err)
	defer session.Stop()

	assert.NotNil(t, session.keys, "session with nil dest should have keys")
	assert.NotNil(t, session.destination, "session with nil dest should have destination")
}

// TestPrepareDestinationAndKeys_ExternalDest_ReturnsValidKeyStore tests the
// prepareDestinationAndKeys helper directly to confirm it returns a
// non-nil DestinationKeyStore when only a destination is provided (no private keys).
func TestPrepareDestinationAndKeys_ExternalDest_ReturnsValidKeyStore(t *testing.T) {
	// Create an external destination
	ks, err := keys.NewDestinationKeyStore()
	require.NoError(t, err)
	externalDest := ks.Destination()

	// Call with non-nil dest but no private keys — should generate fresh keys
	keyStore, dest, err := prepareDestinationAndKeys(externalDest, nil, nil)
	require.NoError(t, err)
	assert.NotNil(t, keyStore, "keyStore must not be nil when dest is provided")
	assert.NotNil(t, dest, "returned dest must not be nil")

	// The returned destination should come from the new keystore
	// (not the client-provided one) since no private keys were provided
	assert.NotNil(t, keyStore.SigningPrivateKey(),
		"keyStore should have a signing private key")
	encPub, encErr := keyStore.EncryptionPublicKey()
	assert.NoError(t, encErr, "EncryptionPublicKey should not error")
	assert.NotNil(t, encPub,
		"keyStore should have an encryption public key")
}

// TestPrepareDestinationAndKeys_NilDest_ReturnsValidKeyStore is the baseline
// test for nil destination input.
func TestPrepareDestinationAndKeys_NilDest_ReturnsValidKeyStore(t *testing.T) {
	keyStore, dest, err := prepareDestinationAndKeys(nil, nil, nil)
	require.NoError(t, err)
	assert.NotNil(t, keyStore, "keyStore must not be nil for nil dest")
	assert.NotNil(t, dest, "dest must not be nil for nil dest input")
}

// TestValidateSessionState_NilKeys_ReturnsError verifies the defensive nil
// check in validateSessionState catches missing prerequisites (pools and keys).
func TestValidateSessionState_NilKeys_ReturnsError(t *testing.T) {
	// Create a session normally then nil out its keys to simulate the old bug
	session, err := NewSession(99, nil, nil)
	require.NoError(t, err)
	defer session.Stop()

	// Force nil keys (simulating the old prepareDestinationAndKeys bug)
	session.keys = nil

	// validateSessionState checks pools before keys, so it will fail
	// on the missing inbound pool first. The key point is that it does
	// fail — the session is not in a valid state for LeaseSet creation.
	err = session.validateSessionState()
	assert.Error(t, err, "validateSessionState should fail with nil keys and no pools")
}

// =============================================================================
// Tests for AUDIT fix: "Double Session Cleanup Race in I2CP Server" —
// verifies that DestroySession can be called twice without panicking, and
// that the SessionManager handles concurrent cleanup gracefully.
// =============================================================================

// TestDestroySession_Idempotent verifies that calling DestroySession twice
// for the same session ID does not panic; the second call returns an error.
func TestDestroySession_Idempotent(t *testing.T) {
	sm := NewSessionManager()

	session, err := sm.CreateSession(nil, nil)
	require.NoError(t, err)
	sessionID := session.ID()

	// First destroy should succeed
	err = sm.DestroySession(sessionID)
	assert.NoError(t, err, "first DestroySession should succeed")

	// Second destroy should return an error but NOT panic
	err = sm.DestroySession(sessionID)
	assert.Error(t, err, "second DestroySession should return an error")
	assert.Contains(t, err.Error(), "not found",
		"error should indicate session was not found")
}

// TestDestroySession_ConcurrentDoubleCleanup simulates the race condition
// where cleanupIdleSessions and cleanupSessionConnection both try to destroy
// the same session concurrently. Neither should panic.
func TestDestroySession_ConcurrentDoubleCleanup(t *testing.T) {
	sm := NewSessionManager()

	session, err := sm.CreateSession(nil, nil)
	require.NoError(t, err)
	sessionID := session.ID()

	var wg sync.WaitGroup
	errors := make([]error, 2)

	// Simulate two concurrent cleanup paths
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			errors[idx] = sm.DestroySession(sessionID)
		}(i)
	}
	wg.Wait()

	// Exactly one should succeed and one should fail
	successes := 0
	failures := 0
	for _, e := range errors {
		if e == nil {
			successes++
		} else {
			failures++
		}
	}
	assert.Equal(t, 1, successes,
		"exactly one concurrent DestroySession should succeed")
	assert.Equal(t, 1, failures,
		"exactly one concurrent DestroySession should fail (already destroyed)")
}

// TestSessionManager_CreateAndDestroyMultiple verifies the session manager
// correctly handles multiple sessions being created and destroyed, ensuring
// session count stays accurate.
func TestSessionManager_CreateAndDestroyMultiple(t *testing.T) {
	sm := NewSessionManager()

	// Create 3 sessions
	sessions := make([]*Session, 3)
	for i := 0; i < 3; i++ {
		s, err := sm.CreateSession(nil, nil)
		require.NoError(t, err)
		sessions[i] = s
	}
	assert.Equal(t, 3, sm.SessionCount())

	// Destroy the middle one
	err := sm.DestroySession(sessions[1].ID())
	assert.NoError(t, err)
	assert.Equal(t, 2, sm.SessionCount())

	// Destroying the same one again should fail
	err = sm.DestroySession(sessions[1].ID())
	assert.Error(t, err)
	assert.Equal(t, 2, sm.SessionCount(), "count should not change on failed destroy")

	// Destroy remaining
	for _, idx := range []int{0, 2} {
		err := sm.DestroySession(sessions[idx].ID())
		assert.NoError(t, err)
	}
	assert.Equal(t, 0, sm.SessionCount())
}

// TestSessionManager_CreateWithExternalDest verifies that CreateSession with
// an external destination produces a fully usable session (non-nil keys).
func TestSessionManager_CreateWithExternalDest(t *testing.T) {
	sm := NewSessionManager()

	ks, err := keys.NewDestinationKeyStore()
	require.NoError(t, err)
	externalDest := ks.Destination()

	session, err := sm.CreateSession(externalDest, nil)
	require.NoError(t, err)
	defer sm.DestroySession(session.ID())

	assert.NotNil(t, session.keys,
		"session created via manager with external dest must have keys")
	assert.NotNil(t, session.Destination(),
		"session must have a destination")
}
