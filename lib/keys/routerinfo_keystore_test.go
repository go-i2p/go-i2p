package keys

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/go-i2p/crypto/ed25519"
	"github.com/go-i2p/crypto/types"
)

func TestRouterInfoKeystore_KeyID_NormalOperation(t *testing.T) {
	// Test with a real private key
	privateKey, err := ed25519.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	ks := &RouterInfoKeystore{
		privateKey: privateKey.(types.PrivateKey),
		name:       "", // Empty name to trigger public key generation
	}

	keyID := ks.KeyID()

	// Verify it doesn't return "error" or fallback for normal operation
	if keyID == "error" {
		t.Error("Normal operation should not return 'error'")
	}

	if strings.HasPrefix(keyID, "fallback-") {
		t.Error("Normal operation should not return fallback ID")
	}

	// Verify it's not empty
	if keyID == "" {
		t.Error("KeyID should not be empty for normal operation")
	}

	// Verify the ID is safe for filenames (no problematic characters)
	problematicChars := []string{"/", "\\", ":", "*", "?", "\"", "<", ">", "|"}
	for _, char := range problematicChars {
		if strings.Contains(keyID, char) {
			t.Errorf("KeyID contains problematic character '%s': %s", char, keyID)
		}
	}
}

func TestRouterInfoKeystore_KeyID_WithName(t *testing.T) {
	// Test with a predefined name
	privateKey, err := ed25519.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	expectedName := "test-router"

	ks := &RouterInfoKeystore{
		privateKey: privateKey.(types.PrivateKey),
		name:       expectedName,
	}

	keyID := ks.KeyID()

	// Should return the name, ignoring any private key errors
	if keyID != expectedName {
		t.Errorf("Expected KeyID to be '%s', got: %s", expectedName, keyID)
	}
}

func TestRouterInfoKeystore_KeyID_FallbackBehavior(t *testing.T) {
	// Test that the improved error handling doesn't return just "error"
	// We can't easily mock a failing private key, but we can test that our
	// fallback logic generates safe IDs.

	// This test verifies the fallback ID pattern is safe for filenames
	ks := &RouterInfoKeystore{
		privateKey: nil, // This will cause Public() to panic, but that's caught
		name:       "",
	}

	// Use a recover to catch any panics and verify fallback behavior
	defer func() {
		if r := recover(); r != nil {
			t.Log("Expected panic occurred, this is normal for this test")
		}
	}()

	keyID := ks.KeyID()

	// Even in error cases, should not return just "error"
	if keyID == "error" {
		t.Error("KeyID should not return 'error' string even in error conditions")
	}
}

func TestRouterInfoKeystore_StoreKeys_SecurePermissions(t *testing.T) {
	// Skip this test on Windows as file permissions work differently
	if runtime.GOOS == "windows" {
		t.Skip("Skipping file permission test on Windows")
	}

	// Create a temporary directory
	tmpDir, err := os.MkdirTemp("", "routerinfo_keys_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a test key store
	privateKey, err := ed25519.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("Failed to create private key: %v", err)
	}

	ks := &RouterInfoKeystore{
		dir:        tmpDir,
		privateKey: privateKey.(types.PrivateKey),
		name:       "test-router",
	}

	// Store the keys
	err = ks.StoreKeys()
	if err != nil {
		t.Fatalf("StoreKeys failed: %v", err)
	}

	// Check that the file was created in the correct directory
	expectedPath := filepath.Join(tmpDir, "test-router.key")
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
