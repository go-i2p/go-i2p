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
