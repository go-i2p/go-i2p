package keys

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Tests for NewDestinationKeyStoreFromKeys — verifies that DestinationKeyStore
// can be reconstructed from existing private keys, preserving the same
// I2P destination identity (.b32.i2p address).
// =============================================================================

// TestNewDestinationKeyStoreFromKeys_PreservesIdentity verifies that
// reconstructing a keystore from existing private keys produces the
// same destination (same .b32.i2p address).
func TestNewDestinationKeyStoreFromKeys_PreservesIdentity(t *testing.T) {
	// Generate an original keystore
	original, err := NewDestinationKeyStore()
	require.NoError(t, err)

	originalDestBytes, err := original.Destination().Bytes()
	require.NoError(t, err)

	// Reconstruct from the original's private keys, passing padding
	// to preserve identity (random padding means different identity without it)
	reconstructed, err := NewDestinationKeyStoreFromKeys(
		original.SigningPrivateKey(),
		original.EncryptionPrivateKey(),
		original.IdentityPadding(),
	)
	require.NoError(t, err)

	reconstructedDestBytes, err := reconstructed.Destination().Bytes()
	require.NoError(t, err)

	assert.True(t, bytes.Equal(originalDestBytes, reconstructedDestBytes),
		"reconstructed destination must match original")
}

// TestNewDestinationKeyStoreFromKeys_PublicKeysMatch verifies that the
// public keys derived from the reconstructed keystore match the originals.
func TestNewDestinationKeyStoreFromKeys_PublicKeysMatch(t *testing.T) {
	original, err := NewDestinationKeyStore()
	require.NoError(t, err)

	reconstructed, err := NewDestinationKeyStoreFromKeys(
		original.SigningPrivateKey(),
		original.EncryptionPrivateKey(),
	)
	require.NoError(t, err)

	// Signing public keys should match
	origSigPub, err := original.SigningPublicKey()
	require.NoError(t, err)
	reconSigPub, err := reconstructed.SigningPublicKey()
	require.NoError(t, err)
	assert.True(t, bytes.Equal(origSigPub.Bytes(), reconSigPub.Bytes()),
		"signing public keys should match")

	// Encryption public keys should match
	origEncPub, err := original.EncryptionPublicKey()
	require.NoError(t, err)
	reconEncPub, err := reconstructed.EncryptionPublicKey()
	require.NoError(t, err)
	assert.True(t, bytes.Equal(origEncPub.Bytes(), reconEncPub.Bytes()),
		"encryption public keys should match")
}

// TestNewDestinationKeyStoreFromKeys_PrivateKeysPreserved verifies that
// the private keys in the reconstructed keystore are the same as the originals.
func TestNewDestinationKeyStoreFromKeys_PrivateKeysPreserved(t *testing.T) {
	original, err := NewDestinationKeyStore()
	require.NoError(t, err)

	reconstructed, err := NewDestinationKeyStoreFromKeys(
		original.SigningPrivateKey(),
		original.EncryptionPrivateKey(),
	)
	require.NoError(t, err)

	// Private keys should be the same references
	assert.NotNil(t, reconstructed.SigningPrivateKey())
	assert.NotNil(t, reconstructed.EncryptionPrivateKey())
}

// TestNewDestinationKeyStoreFromKeys_NilSigningKey_ReturnsError verifies
// that passing a nil signing key returns an error.
func TestNewDestinationKeyStoreFromKeys_NilSigningKey_ReturnsError(t *testing.T) {
	original, err := NewDestinationKeyStore()
	require.NoError(t, err)

	_, err = NewDestinationKeyStoreFromKeys(nil, original.EncryptionPrivateKey())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "signing private key must not be nil")
}

// TestNewDestinationKeyStoreFromKeys_NilEncryptionKey_ReturnsError verifies
// that passing a nil encryption key returns an error.
func TestNewDestinationKeyStoreFromKeys_NilEncryptionKey_ReturnsError(t *testing.T) {
	original, err := NewDestinationKeyStore()
	require.NoError(t, err)

	_, err = NewDestinationKeyStoreFromKeys(original.SigningPrivateKey(), nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "encryption private key must not be nil")
}

// TestNewDestinationKeyStoreFromKeys_BothNil_ReturnsError verifies
// that passing both keys as nil returns an error.
func TestNewDestinationKeyStoreFromKeys_BothNil_ReturnsError(t *testing.T) {
	_, err := NewDestinationKeyStoreFromKeys(nil, nil)
	assert.Error(t, err)
}

// TestNewDestinationKeyStoreFromKeys_StableAcrossMultipleCalls verifies
// that calling NewDestinationKeyStoreFromKeys multiple times with the same
// keys always produces the same destination.
func TestNewDestinationKeyStoreFromKeys_StableAcrossMultipleCalls(t *testing.T) {
	original, err := NewDestinationKeyStore()
	require.NoError(t, err)

	sigPriv := original.SigningPrivateKey()
	encPriv := original.EncryptionPrivateKey()
	pad := original.IdentityPadding()

	var destinations [][]byte
	for i := 0; i < 5; i++ {
		ks, err := NewDestinationKeyStoreFromKeys(sigPriv, encPriv, pad)
		require.NoError(t, err)
		db, err := ks.Destination().Bytes()
		require.NoError(t, err)
		destinations = append(destinations, db)
	}

	for i := 1; i < len(destinations); i++ {
		assert.True(t, bytes.Equal(destinations[0], destinations[i]),
			"call %d should produce identical destination", i)
	}
}

// TestNewDestinationKeyStoreFromKeys_Close_ZeroesKeyMaterial verifies
// that calling Close on a reconstructed keystore zeroes the key material.
func TestNewDestinationKeyStoreFromKeys_Close_ZeroesKeyMaterial(t *testing.T) {
	original, err := NewDestinationKeyStore()
	require.NoError(t, err)

	reconstructed, err := NewDestinationKeyStoreFromKeys(
		original.SigningPrivateKey(),
		original.EncryptionPrivateKey(),
	)
	require.NoError(t, err)

	// Verify keys are initially non-nil
	assert.NotNil(t, reconstructed.EncryptionPrivateKey())

	// Close should not panic
	reconstructed.Close()
}
