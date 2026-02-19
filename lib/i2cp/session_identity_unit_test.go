package i2cp

import (
	"bytes"
	"testing"

	"github.com/go-i2p/go-i2p/lib/keys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Tests for AUDIT fix: "I2CP Server Always Replaces Client-Provided Destination"
// (FUNCTIONAL MISMATCH / I2CP-03)
//
// These tests verify that clients can maintain persistent I2P identities
// by providing their own private keys when creating sessions.
// =============================================================================

// TestPrepareDestinationAndKeys_WithPrivateKeys_PreservesIdentity verifies that
// providing both signing and encryption private keys produces a DestinationKeyStore
// whose destination matches the original identity (same .b32.i2p address).
func TestPrepareDestinationAndKeys_WithPrivateKeys_PreservesIdentity(t *testing.T) {
	// Generate an original identity
	originalKS, err := keys.NewDestinationKeyStore()
	require.NoError(t, err)

	originalDest := originalKS.Destination()
	originalDestBytes, err := originalDest.Bytes()
	require.NoError(t, err)

	// Extract the private keys
	sigPriv := originalKS.SigningPrivateKey()
	encPriv := originalKS.EncryptionPrivateKey()

	// Reconstruct via prepareDestinationAndKeys with the same private keys
	resultKS, resultDest, err := prepareDestinationAndKeys(originalDest, sigPriv, encPriv)
	require.NoError(t, err)
	require.NotNil(t, resultKS)
	require.NotNil(t, resultDest)

	// The destination should be identical (same .b32.i2p address)
	resultDestBytes, err := resultDest.Bytes()
	require.NoError(t, err)
	assert.True(t, bytes.Equal(originalDestBytes, resultDestBytes),
		"destination should be preserved when private keys are provided")
}

// TestNewSession_WithPrivateKeys_PreservesIdentity verifies that a session
// created with client-provided private keys has the same destination identity
// as the original keystore.
func TestNewSession_WithPrivateKeys_PreservesIdentity(t *testing.T) {
	// Generate an original identity
	originalKS, err := keys.NewDestinationKeyStore()
	require.NoError(t, err)

	originalDest := originalKS.Destination()
	originalDestBytes, err := originalDest.Bytes()
	require.NoError(t, err)
	sigPriv := originalKS.SigningPrivateKey()
	encPriv := originalKS.EncryptionPrivateKey()

	// Create session with the original private keys
	session, err := NewSession(1, originalDest, nil, sigPriv, encPriv)
	require.NoError(t, err)
	defer session.Stop()

	// Session destination should match the original
	sessionDestBytes, err := session.Destination().Bytes()
	require.NoError(t, err)
	assert.True(t, bytes.Equal(originalDestBytes, sessionDestBytes),
		"session destination should match original when private keys are provided")

	// Session keys should produce the same signing and encryption behavior
	assert.NotNil(t, session.keys, "session keys must not be nil")
	assert.NotNil(t, session.keys.SigningPrivateKey(), "signing private key must be present")
	assert.NotNil(t, session.keys.EncryptionPrivateKey(), "encryption private key must be present")
}

// TestCreateSession_WithPrivateKeys_PreservesIdentity verifies that the
// SessionManager.CreateSession method correctly passes through private keys.
func TestCreateSession_WithPrivateKeys_PreservesIdentity(t *testing.T) {
	sm := NewSessionManager()

	// Generate an original identity
	originalKS, err := keys.NewDestinationKeyStore()
	require.NoError(t, err)

	originalDest := originalKS.Destination()
	originalDestBytes, err := originalDest.Bytes()
	require.NoError(t, err)
	sigPriv := originalKS.SigningPrivateKey()
	encPriv := originalKS.EncryptionPrivateKey()

	// Create session via manager with private keys
	session, err := sm.CreateSession(originalDest, nil, sigPriv, encPriv)
	require.NoError(t, err)
	defer sm.DestroySession(session.ID())

	// Session destination should match the original
	sessionDestBytes, err := session.Destination().Bytes()
	require.NoError(t, err)
	assert.True(t, bytes.Equal(originalDestBytes, sessionDestBytes),
		"session destination should match original when private keys are provided via SessionManager")
}

// TestNewSession_WithoutPrivateKeys_GeneratesFreshIdentity verifies that
// when no private keys are provided, a fresh identity is always generated
// (backward compatibility with the previous behavior).
func TestNewSession_WithoutPrivateKeys_GeneratesFreshIdentity(t *testing.T) {
	// Generate a destination but DON'T provide its private keys
	originalKS, err := keys.NewDestinationKeyStore()
	require.NoError(t, err)

	originalDest := originalKS.Destination()
	originalDestBytes, err := originalDest.Bytes()
	require.NoError(t, err)

	// Create session without private keys
	session, err := NewSession(1, originalDest, nil)
	require.NoError(t, err)
	defer session.Stop()

	// Session destination should be DIFFERENT from the original
	// (fresh keys generated, different identity)
	sessionDestBytes, err := session.Destination().Bytes()
	require.NoError(t, err)
	assert.False(t, bytes.Equal(originalDestBytes, sessionDestBytes),
		"session destination should differ when no private keys are provided")

	// But session should still have valid keys
	assert.NotNil(t, session.keys, "session keys must not be nil")
	assert.NotNil(t, session.keys.SigningPrivateKey(), "signing private key must be present")
}

// TestNewSession_WithNilDestAndNilKeys_GeneratesFreshIdentity verifies the
// base case where both destination and keys are nil (completely fresh session).
func TestNewSession_WithNilDestAndNilKeys_GeneratesFreshIdentity(t *testing.T) {
	session, err := NewSession(1, nil, nil)
	require.NoError(t, err)
	defer session.Stop()

	assert.NotNil(t, session.destination, "destination must not be nil")
	assert.NotNil(t, session.keys, "keys must not be nil")
	assert.NotNil(t, session.keys.SigningPrivateKey(), "signing private key must be present")
	assert.NotNil(t, session.keys.EncryptionPrivateKey(), "encryption private key must be present")
}

// TestPrepareDestinationAndKeys_WithPartialKeys_GeneratesFresh verifies that
// providing only one private key (partial) falls back to generating fresh keys.
func TestPrepareDestinationAndKeys_WithPartialKeys_GeneratesFresh(t *testing.T) {
	originalKS, err := keys.NewDestinationKeyStore()
	require.NoError(t, err)

	sigPriv := originalKS.SigningPrivateKey()

	// Provide only signing key, no encryption key — should generate fresh
	keyStore, dest, err := prepareDestinationAndKeys(nil, sigPriv, nil)
	require.NoError(t, err)
	assert.NotNil(t, keyStore)
	assert.NotNil(t, dest)

	// Should have generated fresh keys (different from original)
	originalDestBytes, err := originalKS.Destination().Bytes()
	require.NoError(t, err)
	resultDestBytes, err := dest.Bytes()
	require.NoError(t, err)
	assert.False(t, bytes.Equal(originalDestBytes, resultDestBytes),
		"with partial keys, should generate fresh identity")
}

// TestPrepareDestinationAndKeys_IdentityStableAcrossReconstructions verifies
// that the same private keys always produce the same destination identity.
func TestPrepareDestinationAndKeys_IdentityStableAcrossReconstructions(t *testing.T) {
	// Generate an original identity
	originalKS, err := keys.NewDestinationKeyStore()
	require.NoError(t, err)

	sigPriv := originalKS.SigningPrivateKey()
	encPriv := originalKS.EncryptionPrivateKey()

	// Reconstruct multiple times
	var destinations [][]byte
	for i := 0; i < 3; i++ {
		ks, dest, err := prepareDestinationAndKeys(nil, sigPriv, encPriv)
		require.NoError(t, err)
		require.NotNil(t, ks)
		db, err := dest.Bytes()
		require.NoError(t, err)
		destinations = append(destinations, db)
	}

	// All should produce identical destinations
	for i := 1; i < len(destinations); i++ {
		assert.True(t, bytes.Equal(destinations[0], destinations[i]),
			"reconstruction %d should produce identical destination", i)
	}
}

// TestNewSession_VariadicPrivKeysBackwardCompat verifies that the variadic
// privKeys parameter maintains backward compatibility — existing callers
// that don't provide private keys continue to work.
func TestNewSession_VariadicPrivKeysBackwardCompat(t *testing.T) {
	// No extra args (most existing callers)
	session1, err := NewSession(1, nil, nil)
	require.NoError(t, err)
	defer session1.Stop()
	assert.NotNil(t, session1.keys)

	// Empty variadic (should not panic)
	session2, err := NewSession(2, nil, nil)
	require.NoError(t, err)
	defer session2.Stop()
	assert.NotNil(t, session2.keys)

	// Wrong types in variadic (should be ignored, generate fresh)
	session3, err := NewSession(3, nil, nil, "not-a-key", 42)
	require.NoError(t, err)
	defer session3.Stop()
	assert.NotNil(t, session3.keys)
}
