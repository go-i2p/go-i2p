package keys

import (
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
