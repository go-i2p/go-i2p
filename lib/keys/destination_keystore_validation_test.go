package keys

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
