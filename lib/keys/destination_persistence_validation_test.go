package keys

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDestinationKeyStore_StoreKeys_FilePermissions(t *testing.T) {
	dir := t.TempDir()
	name := "test-perm"

	dks, err := NewDestinationKeyStore()
	require.NoError(t, err)

	err = dks.StoreKeys(dir, name)
	require.NoError(t, err)

	filename := filepath.Join(dir, name+".dest.key")
	info, err := os.Stat(filename)
	require.NoError(t, err)

	// File should be owner-only readable/writable (0600)
	perm := info.Mode().Perm()
	assert.Equal(t, testKeyFilePerms, perm,
		"key file should have 0600 permissions")
}

func TestLoadDestinationKeyStore_FileNotFound(t *testing.T) {
	dir := t.TempDir()

	_, err := LoadDestinationKeyStore(dir, "nonexistent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestLoadDestinationKeyStore_CorruptedFile(t *testing.T) {
	dir := t.TempDir()
	name := "corrupt"

	// Write garbage data
	filename := filepath.Join(dir, name+".dest.key")
	err := os.WriteFile(filename, []byte("not a valid key file"), testKeyFilePerms)
	require.NoError(t, err)

	_, err = LoadDestinationKeyStore(dir, name)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid magic header")
}

func TestLoadDestinationKeyStore_TruncatedFile(t *testing.T) {
	dir := t.TempDir()
	name := "truncated"

	// Write just the magic header
	filename := filepath.Join(dir, name+".dest.key")
	err := os.WriteFile(filename, destinationKeyStoreMagicV2, testKeyFilePerms)
	require.NoError(t, err)

	_, err = LoadDestinationKeyStore(dir, name)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too short")
}

func TestUnmarshal_EmptyData(t *testing.T) {
	_, err := unmarshalDestinationKeyStore([]byte{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too short")
}

func TestUnmarshal_WrongMagic(t *testing.T) {
	_, err := unmarshalDestinationKeyStore([]byte("XXXX"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid magic")
}

// TestLoadOrCreateDestinationKeyStore_CorruptFileReturnsError verifies that
// a corrupt key file causes an error instead of silently generating a new identity.
func TestLoadOrCreateDestinationKeyStore_CorruptFileReturnsError(t *testing.T) {
	dir := t.TempDir()
	name := "test"
	filename := filepath.Join(dir, name+".dest.key")

	// Write corrupt data to the key file
	err := os.WriteFile(filename, []byte("this is corrupt data"), 0o644)
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
	require.NoError(t, os.Chmod(filename, 0o000))
	defer os.Chmod(filename, 0o644) // cleanup

	// Should error rather than silently generate new identity
	_, err = LoadOrCreateDestinationKeyStore(dir, name)
	assert.Error(t, err, "should return error for unreadable key file")
}
