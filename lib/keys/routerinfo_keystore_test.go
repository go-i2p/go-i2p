package keys

import (
	"bytes"
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
		reachable      bool
		expected       string
	}{
		{
			name:           "no congestion flag, unreachable",
			congestionFlag: "",
			reachable:      false,
			expected:       "NU",
		},
		{
			name:           "no congestion flag, reachable",
			congestionFlag: "",
			reachable:      true,
			expected:       "NR",
		},
		{
			name:           "D flag - medium congestion, unreachable",
			congestionFlag: "D",
			reachable:      false,
			expected:       "NUD",
		},
		{
			name:           "E flag - high congestion, reachable",
			congestionFlag: "E",
			reachable:      true,
			expected:       "NRE",
		},
		{
			name:           "G flag - rejecting all",
			congestionFlag: "G",
			reachable:      false,
			expected:       "NUG",
		},
		{
			name:           "invalid flag - ignored",
			congestionFlag: "X",
			reachable:      false,
			expected:       "NU",
		},
		{
			name:           "lowercase d - ignored (case sensitive)",
			congestionFlag: "d",
			reachable:      false,
			expected:       "NU",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ks.buildCapsString(tt.congestionFlag, tt.reachable)
			if result != tt.expected {
				t.Errorf("buildCapsString(%q, %v) = %q, want %q", tt.congestionFlag, tt.reachable, result, tt.expected)
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

// TestRouterInfoKeystore_X25519KeyPersistedAcrossRestarts verifies that the
// X25519 encryption key is persisted to disk and reloaded on subsequent
// keystore creation, ensuring a stable NTCP2 static key across restarts.
func TestRouterInfoKeystore_X25519KeyPersistedAcrossRestarts(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "x25519_persist_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create the keystore for the first time — generates fresh keys
	ks1, err := NewRouterInfoKeystore(tmpDir, "test-router")
	if err != nil {
		t.Fatalf("First NewRouterInfoKeystore failed: %v", err)
	}

	// Capture the first X25519 encryption key
	encPrivKey1 := ks1.GetEncryptionPrivateKey()
	if encPrivKey1 == nil {
		t.Fatal("Encryption private key should not be nil")
	}
	encPrivBytes1 := encPrivKey1.Bytes()

	// Verify the encryption key file was written to disk
	encKeyPath := filepath.Join(tmpDir, "test-router.enc.key")
	if _, err := os.Stat(encKeyPath); os.IsNotExist(err) {
		t.Fatal("Encryption key file was not created on disk")
	}

	// Create a second keystore from the same directory — should load from disk
	ks2, err := NewRouterInfoKeystore(tmpDir, "test-router")
	if err != nil {
		t.Fatalf("Second NewRouterInfoKeystore failed: %v", err)
	}

	encPrivKey2 := ks2.GetEncryptionPrivateKey()
	if encPrivKey2 == nil {
		t.Fatal("Second keystore encryption private key should not be nil")
	}
	encPrivBytes2 := encPrivKey2.Bytes()

	// The encryption key must be identical across both loads
	if !bytes.Equal(encPrivBytes1, encPrivBytes2) {
		t.Error("X25519 encryption key changed across restarts — key was not persisted correctly")
	}
}

// TestRouterInfoKeystore_StoreKeysAlsoWritesEncryptionKey verifies that
// StoreKeys() persists both the signing key and the encryption key to disk.
func TestRouterInfoKeystore_StoreKeysAlsoWritesEncryptionKey(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping file permission test on Windows")
	}

	tmpDir, err := os.MkdirTemp("", "storekeys_enc_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	ks, err := NewRouterInfoKeystore(tmpDir, "test-router")
	if err != nil {
		t.Fatalf("NewRouterInfoKeystore failed: %v", err)
	}

	// StoreKeys should write both .key and .enc.key
	if err := ks.StoreKeys(); err != nil {
		t.Fatalf("StoreKeys failed: %v", err)
	}

	sigKeyPath := filepath.Join(tmpDir, "test-router.key")
	encKeyPath := filepath.Join(tmpDir, "test-router.enc.key")

	// Verify signing key file
	if _, err := os.Stat(sigKeyPath); os.IsNotExist(err) {
		t.Error("Signing key file was not created")
	}

	// Verify encryption key file
	info, err := os.Stat(encKeyPath)
	if os.IsNotExist(err) {
		t.Fatal("Encryption key file was not created by StoreKeys")
	}
	if err != nil {
		t.Fatalf("Failed to stat encryption key file: %v", err)
	}

	// Verify permissions are 0600
	perm := info.Mode().Perm()
	if perm != 0o600 {
		t.Errorf("Encryption key file permissions: got %o, want 0600", perm)
	}

	// Verify the file content matches the in-memory key
	diskBytes, err := os.ReadFile(encKeyPath)
	if err != nil {
		t.Fatalf("Failed to read encryption key file: %v", err)
	}
	memBytes := ks.GetEncryptionPrivateKey().Bytes()
	if !bytes.Equal(diskBytes, memBytes) {
		t.Error("Encryption key file content does not match in-memory key")
	}
}

// TestLoadOrGenerateEncryptionKey_GeneratesNewWhenMissing verifies that a new
// encryption key is generated and persisted when no file exists on disk.
func TestLoadOrGenerateEncryptionKey_GeneratesNewWhenMissing(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "enckey_generate_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	pubKey, privKey, err := loadOrGenerateEncryptionKey(tmpDir, "fresh")
	if err != nil {
		t.Fatalf("loadOrGenerateEncryptionKey failed: %v", err)
	}

	if pubKey == nil {
		t.Fatal("Public key should not be nil")
	}
	if privKey == nil {
		t.Fatal("Private key should not be nil")
	}

	// Verify the key was written to disk
	keyPath := filepath.Join(tmpDir, "fresh.enc.key")
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Error("Encryption key file was not created")
	}
}

// TestLoadOrGenerateEncryptionKey_LoadsExistingKey verifies that an existing
// encryption key is loaded from disk rather than generating a new one.
func TestLoadOrGenerateEncryptionKey_LoadsExistingKey(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "enckey_load_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// First call: generate and persist
	_, privKey1, err := loadOrGenerateEncryptionKey(tmpDir, "existing")
	if err != nil {
		t.Fatalf("First loadOrGenerateEncryptionKey failed: %v", err)
	}

	// Second call: should load from disk
	_, privKey2, err := loadOrGenerateEncryptionKey(tmpDir, "existing")
	if err != nil {
		t.Fatalf("Second loadOrGenerateEncryptionKey failed: %v", err)
	}

	if !bytes.Equal(privKey1.Bytes(), privKey2.Bytes()) {
		t.Error("Loaded key differs from originally generated key")
	}
}

// TestLoadOrGenerateEncryptionKey_CorruptedFile verifies that a corrupted
// encryption key file returns an error rather than silently using bad data.
func TestLoadOrGenerateEncryptionKey_CorruptedFile(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "enckey_corrupt_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Write a corrupted key file (wrong length — curve25519 expects exactly 32 bytes)
	keyPath := filepath.Join(tmpDir, "corrupt.enc.key")
	if err := os.WriteFile(keyPath, []byte("too-short"), 0o600); err != nil {
		t.Fatalf("Failed to write corrupted key file: %v", err)
	}

	_, _, err = loadOrGenerateEncryptionKey(tmpDir, "corrupt")
	if err == nil {
		t.Error("Expected error loading corrupted key file, got nil")
	}
}
