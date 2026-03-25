package keys

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMarshalUnmarshal_MagicHeader verifies the v2 magic header in marshaled data.
func TestMarshalUnmarshal_MagicHeader(t *testing.T) {
	dks, err := NewDestinationKeyStore()
	require.NoError(t, err)

	data, err := dks.marshal()
	require.NoError(t, err)

	// Check magic header
	assert.Equal(t, destinationKeyStoreMagicV2, data[:4],
		"marshaled data should start with v2 magic header")
}

// TestDestinationKeyPersistenceFormat_DKSMagic verifies the destination key
// persistence uses the DKS\x02 magic header format (v2 includes padding).
func TestDestinationKeyPersistenceFormat_DKSMagic(t *testing.T) {
	tmpDir := t.TempDir()

	dks, err := NewDestinationKeyStore()
	if err != nil {
		t.Fatalf("NewDestinationKeyStore() failed: %v", err)
	}

	err = dks.StoreKeys(tmpDir, "dest")
	if err != nil {
		t.Fatalf("StoreKeys() failed: %v", err)
	}

	dksPath := filepath.Join(tmpDir, "dest.dest.key")
	data, err := os.ReadFile(dksPath)
	if err != nil {
		t.Fatalf("ReadFile() failed: %v", err)
	}

	// Verify DKS v2 magic header (v2 includes padding for identity stability)
	magic := "DKS\x02"
	if len(data) < 4 || string(data[:4]) != magic {
		t.Errorf("destination key file does not start with DKS\\x02 magic; got %q", data[:min(4, len(data))])
	}
}

// TestRotateDestinationKeys_ArchivesOldKeys verifies that key rotation:
// 1. Archives the old keys to a timestamped file
// 2. Creates new keys with a different destination hash
// 3. Persists the new keys
func TestRotateDestinationKeys_ArchivesOldKeys(t *testing.T) {
	tmpDir := t.TempDir()
	name := "test-dest"

	// Create and store initial keys
	dks, err := NewDestinationKeyStore()
	require.NoError(t, err)

	err = dks.StoreKeys(tmpDir, name)
	require.NoError(t, err)

	oldDest := dks.Destination()
	oldHash, err := oldDest.Hash()
	require.NoError(t, err)

	// Rotate keys
	newDKS, err := dks.RotateDestinationKeys(tmpDir, name)
	require.NoError(t, err)
	require.NotNil(t, newDKS)

	// Verify new destination has different hash
	newDest := newDKS.Destination()
	newHash, err := newDest.Hash()
	require.NoError(t, err)
	assert.NotEqual(t, oldHash, newHash, "rotated keys should produce different destination hash")

	// Verify archive file was created
	entries, err := os.ReadDir(tmpDir)
	require.NoError(t, err)

	archiveFound := false
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".archive" {
			archiveFound = true
			break
		}
	}
	assert.True(t, archiveFound, "archive file should exist after rotation")

	// Verify the main key file was updated (contains the new keys)
	loadedDKS, err := LoadDestinationKeyStore(tmpDir, name)
	require.NoError(t, err)

	loadedHash, err := loadedDKS.Destination().Hash()
	require.NoError(t, err)
	assert.Equal(t, newHash, loadedHash, "loaded keys should match rotated keys")
}
