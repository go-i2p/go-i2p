package keys

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/go-i2p/crypto/ed25519"
)

func TestStoreKeys_SecurePermissions(t *testing.T) {
	// Skip this test on Windows as file permissions work differently
	if runtime.GOOS == "windows" {
		t.Skip("Skipping file permission test on Windows")
	}

	// Create a temporary directory
	tmpDir, err := os.MkdirTemp("", "keys_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a test key store
	_, privateKey, err := ed25519.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to create private key: %v", err)
	}

	ks := &KeyStoreImpl{
		dir:        tmpDir,
		privateKey: privateKey,
		name:       "test",
	}

	// Store the keys
	err = ks.StoreKeys()
	if err != nil {
		t.Fatalf("StoreKeys failed: %v", err)
	}

	expectedPath := filepath.Join(tmpDir, "private-test.key")
	assertKeyFilePermissions(t, expectedPath, testKeyFilePerms)
}
