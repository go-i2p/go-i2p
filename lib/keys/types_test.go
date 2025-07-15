package keys

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/go-i2p/crypto/ed25519"
	"github.com/go-i2p/crypto/types"
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
	privateKey, err := ed25519.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("Failed to create private key: %v", err)
	}

	ks := &KeyStoreImpl{
		dir:        tmpDir,
		privateKey: privateKey.(types.PrivateKey),
		name:       "test",
	}

	// Store the keys
	err = ks.StoreKeys()
	if err != nil {
		t.Fatalf("StoreKeys failed: %v", err)
	}

	// Check that the file was created in the correct directory
	expectedPath := filepath.Join(tmpDir, "private-test.key")
	if _, err := os.Stat(expectedPath); os.IsNotExist(err) {
		t.Errorf("Key file was not created at expected path: %s", expectedPath)
	}

	// Check file permissions
	fileInfo, err := os.Stat(expectedPath)
	if err != nil {
		t.Fatalf("Failed to stat key file: %v", err)
	}

	// Check that permissions are 0o600 (owner read/write only)
	perm := fileInfo.Mode().Perm()
	if perm != 0o600 {
		t.Errorf("Expected file permissions 0o600, got %o", perm)
	}
}
