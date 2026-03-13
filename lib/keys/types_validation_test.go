package keys

import (
	"path/filepath"
	"testing"
)

func TestStoreKeys_SecurePermissions(t *testing.T) {
	tmpDir, privateKey := setupPermissionTest(t, "keys_test")

	ks := &KeyStoreImpl{
		dir:        tmpDir,
		privateKey: privateKey,
		name:       "test",
	}

	err := ks.StoreKeys()
	if err != nil {
		t.Fatalf("StoreKeys failed: %v", err)
	}

	expectedPath := filepath.Join(tmpDir, "private-test.key")
	assertKeyFilePermissions(t, expectedPath, testKeyFilePerms)
}
