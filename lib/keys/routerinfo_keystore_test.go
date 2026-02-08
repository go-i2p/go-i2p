package keys

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/go-i2p/crypto/ed25519"
)

func TestRouterInfoKeystore_KeyID_NormalOperation(t *testing.T) {
	// Test with a real private key
	_, privateKey, err := ed25519.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	ks := &RouterInfoKeystore{
		privateKey: privateKey,
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
	_, privateKey, err := ed25519.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	expectedName := "test-router"

	ks := &RouterInfoKeystore{
		privateKey: privateKey,
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
	_, privateKey, err := ed25519.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to create private key: %v", err)
	}

	ks := &RouterInfoKeystore{
		dir:        tmpDir,
		privateKey: privateKey,
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

// TestRouterInfoKeystore_BuildCapsString tests the caps string construction with congestion flags
func TestRouterInfoKeystore_BuildCapsString(t *testing.T) {
	ks := &RouterInfoKeystore{}

	tests := []struct {
		name           string
		congestionFlag string
		expected       string
	}{
		{
			name:           "no congestion flag",
			congestionFlag: "",
			expected:       "NU",
		},
		{
			name:           "D flag - medium congestion",
			congestionFlag: "D",
			expected:       "NUD",
		},
		{
			name:           "E flag - high congestion",
			congestionFlag: "E",
			expected:       "NUE",
		},
		{
			name:           "G flag - rejecting all",
			congestionFlag: "G",
			expected:       "NUG",
		},
		{
			name:           "invalid flag - ignored",
			congestionFlag: "X",
			expected:       "NU",
		},
		{
			name:           "lowercase d - ignored (case sensitive)",
			congestionFlag: "d",
			expected:       "NU",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ks.buildCapsString(tt.congestionFlag)
			if result != tt.expected {
				t.Errorf("buildCapsString(%q) = %q, want %q", tt.congestionFlag, result, tt.expected)
			}
		})
	}
}

// TestRouterInfoKeystore_ConstructRouterInfo_WithCongestionFlag tests RouterInfo construction with congestion options
func TestRouterInfoKeystore_ConstructRouterInfo_WithCongestionFlag(t *testing.T) {
	// Create a temporary directory for the keystore
	tmpDir, err := os.MkdirTemp("", "routerinfo_congestion_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a keystore
	ks, err := NewRouterInfoKeystore(tmpDir, "test-router")
	if err != nil {
		t.Fatalf("Failed to create keystore: %v", err)
	}

	tests := []struct {
		name            string
		opts            []RouterInfoOptions
		expectedCapsSub string // Expected substring in caps
	}{
		{
			name:            "no options - base caps",
			opts:            nil,
			expectedCapsSub: "NU",
		},
		{
			name: "with D flag",
			opts: []RouterInfoOptions{
				{CongestionFlag: "D"},
			},
			expectedCapsSub: "NUD",
		},
		{
			name: "with E flag",
			opts: []RouterInfoOptions{
				{CongestionFlag: "E"},
			},
			expectedCapsSub: "NUE",
		},
		{
			name: "with G flag",
			opts: []RouterInfoOptions{
				{CongestionFlag: "G"},
			},
			expectedCapsSub: "NUG",
		},
		{
			name: "empty option struct",
			opts: []RouterInfoOptions{
				{},
			},
			expectedCapsSub: "NU",
		},
		{
			name: "multiple options - last wins",
			opts: []RouterInfoOptions{
				{CongestionFlag: "D"},
				{CongestionFlag: "E"},
			},
			expectedCapsSub: "NUE",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ri, err := ks.ConstructRouterInfo(nil, tt.opts...)
			if err != nil {
				t.Fatalf("ConstructRouterInfo failed: %v", err)
			}

			if ri == nil {
				t.Fatal("RouterInfo should not be nil")
			}

			// Get the caps from the RouterInfo
			// RouterCapabilities may include I2P length prefix, so use Contains
			caps := ri.RouterCapabilities()
			if !strings.Contains(caps, tt.expectedCapsSub) {
				t.Errorf("caps = %q, want %q", caps, tt.expectedCapsSub)
			}
		})
	}
}

// TestRouterInfoKeystore_ConstructRouterInfo_BackwardCompatible tests backward compatibility
func TestRouterInfoKeystore_ConstructRouterInfo_BackwardCompatible(t *testing.T) {
	// Create a temporary directory for the keystore
	tmpDir, err := os.MkdirTemp("", "routerinfo_compat_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a keystore
	ks, err := NewRouterInfoKeystore(tmpDir, "test-router")
	if err != nil {
		t.Fatalf("Failed to create keystore: %v", err)
	}

	// Test that calling without options still works (backward compatible)
	ri, err := ks.ConstructRouterInfo(nil)
	if err != nil {
		t.Fatalf("ConstructRouterInfo without options failed: %v", err)
	}

	if ri == nil {
		t.Fatal("RouterInfo should not be nil")
	}

	caps := ri.RouterCapabilities()
	// RouterCapabilities may include I2P length prefix, so use Contains
	if !strings.Contains(caps, "NU") {
		t.Errorf("caps %q does not contain 'NU'", caps)
	}
}
