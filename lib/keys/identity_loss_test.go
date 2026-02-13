package keys

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLoadOrCreateDestinationKeyStore_CorruptFileReturnsError verifies that
// a corrupt key file causes an error instead of silently generating a new identity.
func TestLoadOrCreateDestinationKeyStore_CorruptFileReturnsError(t *testing.T) {
	dir := t.TempDir()
	name := "test"
	filename := filepath.Join(dir, name+".dest.key")

	// Write corrupt data to the key file
	err := os.WriteFile(filename, []byte("this is corrupt data"), 0644)
	require.NoError(t, err)

	// LoadOrCreateDestinationKeyStore should fail rather than silently replace
	_, err = LoadOrCreateDestinationKeyStore(dir, name)
	assert.Error(t, err, "should return error for corrupt key file, not silently generate new keys")
	assert.Contains(t, err.Error(), "identity loss")
}

// TestLoadOrCreateDestinationKeyStore_UnreadableFileReturnsError verifies that
// a key file with wrong permissions causes an error rather than regeneration.
func TestLoadOrCreateDestinationKeyStore_UnreadableFileReturnsError(t *testing.T) {
	// Skip on systems where we can't set permissions (e.g. running as root)
	if os.Getuid() == 0 {
		t.Skip("Cannot test permission denied as root")
	}

	dir := t.TempDir()
	name := "test"
	filename := filepath.Join(dir, name+".dest.key")

	// Create a valid-looking file first
	dks, err := NewDestinationKeyStore()
	require.NoError(t, err)
	require.NoError(t, dks.StoreKeys(dir, name))

	// Make it unreadable
	require.NoError(t, os.Chmod(filename, 0000))
	defer os.Chmod(filename, 0644) // cleanup

	// Should error rather than silently generate new identity
	_, err = LoadOrCreateDestinationKeyStore(dir, name)
	assert.Error(t, err, "should return error for unreadable key file")
}

// TestLoadOrCreateDestinationKeyStore_MissingFileCreatesNew verifies that
// when no file exists, a new key store is properly created and persisted.
func TestLoadOrCreateDestinationKeyStore_MissingFileCreatesNew(t *testing.T) {
	dir := t.TempDir()
	name := "newkeys"
	filename := filepath.Join(dir, name+".dest.key")

	// File should not exist yet
	_, err := os.Stat(filename)
	require.True(t, os.IsNotExist(err))

	// Should create new keys successfully
	dks, err := LoadOrCreateDestinationKeyStore(dir, name)
	require.NoError(t, err)
	require.NotNil(t, dks)

	// File should now exist
	_, err = os.Stat(filename)
	assert.NoError(t, err, "key file should have been created")
}
