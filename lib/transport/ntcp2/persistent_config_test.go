package ntcp2

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/go-i2p/crypto/curve25519"
)

// TestLoadOrGenerateObfuscationIV_NewFile tests IV generation when file doesn't exist
func TestLoadOrGenerateObfuscationIV_NewFile(t *testing.T) {
	// Create temporary directory for test
	tempDir := t.TempDir()

	pc := NewPersistentConfig(tempDir)
	iv, err := pc.LoadOrGenerateObfuscationIV()

	if err != nil {
		t.Fatalf("Failed to generate obfuscation IV: %v", err)
	}

	if len(iv) != obfuscationIVSize {
		t.Errorf("Expected IV size %d, got %d", obfuscationIVSize, len(iv))
	}

	// Verify file was created
	ivPath := filepath.Join(tempDir, obfuscationIVFilename)
	if _, err := os.Stat(ivPath); os.IsNotExist(err) {
		t.Error("Obfuscation IV file was not created")
	}
}

// TestLoadOrGenerateObfuscationIV_ExistingFile tests loading from existing file
func TestLoadOrGenerateObfuscationIV_ExistingFile(t *testing.T) {
	tempDir := t.TempDir()

	// First call creates the file
	pc := NewPersistentConfig(tempDir)
	iv1, err := pc.LoadOrGenerateObfuscationIV()
	if err != nil {
		t.Fatalf("Failed to generate obfuscation IV: %v", err)
	}

	// Second call should load the same IV
	iv2, err := pc.LoadOrGenerateObfuscationIV()
	if err != nil {
		t.Fatalf("Failed to load obfuscation IV: %v", err)
	}

	// IVs should be identical
	if string(iv1) != string(iv2) {
		t.Error("Loaded IV doesn't match originally generated IV")
	}
}

// TestLoadOrGenerateObfuscationIV_Persistence tests IV persists across instances
func TestLoadOrGenerateObfuscationIV_Persistence(t *testing.T) {
	tempDir := t.TempDir()

	// Generate IV with first instance
	pc1 := NewPersistentConfig(tempDir)
	iv1, err := pc1.LoadOrGenerateObfuscationIV()
	if err != nil {
		t.Fatalf("Failed to generate obfuscation IV: %v", err)
	}

	// Load IV with second instance (simulates router restart)
	pc2 := NewPersistentConfig(tempDir)
	iv2, err := pc2.LoadOrGenerateObfuscationIV()
	if err != nil {
		t.Fatalf("Failed to load obfuscation IV: %v", err)
	}

	if string(iv1) != string(iv2) {
		t.Error("IV not persistent across PersistentConfig instances")
	}
}

// TestLoadOrGenerateObfuscationIV_InvalidSize tests handling of corrupted IV file
func TestLoadOrGenerateObfuscationIV_InvalidSize(t *testing.T) {
	tempDir := t.TempDir()

	// Create invalid IV file (wrong size)
	ivPath := filepath.Join(tempDir, obfuscationIVFilename)
	invalidIV := []byte{0x01, 0x02, 0x03} // Only 3 bytes instead of 16
	if err := os.WriteFile(ivPath, invalidIV, 0o600); err != nil {
		t.Fatalf("Failed to create invalid IV file: %v", err)
	}

	pc := NewPersistentConfig(tempDir)
	_, err := pc.LoadOrGenerateObfuscationIV()

	if err == nil {
		t.Error("Expected error when loading invalid IV file, got nil")
	}
}

// TestLoadOrGenerateObfuscationIV_FilePermissions tests file is created with secure permissions
func TestLoadOrGenerateObfuscationIV_FilePermissions(t *testing.T) {
	tempDir := t.TempDir()

	pc := NewPersistentConfig(tempDir)
	_, err := pc.LoadOrGenerateObfuscationIV()
	if err != nil {
		t.Fatalf("Failed to generate obfuscation IV: %v", err)
	}

	// Check file permissions
	ivPath := filepath.Join(tempDir, obfuscationIVFilename)
	info, err := os.Stat(ivPath)
	if err != nil {
		t.Fatalf("Failed to stat IV file: %v", err)
	}

	// File should be readable/writable by owner only (0600)
	expectedPerms := os.FileMode(0o600)
	if info.Mode().Perm() != expectedPerms {
		t.Errorf("Expected file permissions %o, got %o", expectedPerms, info.Mode().Perm())
	}
}

// TestLoadOrGenerateObfuscationIV_DirectoryCreation tests directory is created if missing
func TestLoadOrGenerateObfuscationIV_DirectoryCreation(t *testing.T) {
	tempDir := t.TempDir()
	nestedDir := filepath.Join(tempDir, "config", "ntcp2")

	pc := NewPersistentConfig(nestedDir)
	_, err := pc.LoadOrGenerateObfuscationIV()

	if err != nil {
		t.Fatalf("Failed to generate IV with nested directory: %v", err)
	}

	// Verify directory was created
	if _, err := os.Stat(nestedDir); os.IsNotExist(err) {
		t.Error("Nested directory was not created")
	}
}

// TestLoadOrGenerateObfuscationIV_Randomness tests generated IVs are unique
func TestLoadOrGenerateObfuscationIV_Randomness(t *testing.T) {
	tempDir1 := t.TempDir()
	tempDir2 := t.TempDir()

	pc1 := NewPersistentConfig(tempDir1)
	iv1, err := pc1.LoadOrGenerateObfuscationIV()
	if err != nil {
		t.Fatalf("Failed to generate first IV: %v", err)
	}

	pc2 := NewPersistentConfig(tempDir2)
	iv2, err := pc2.LoadOrGenerateObfuscationIV()
	if err != nil {
		t.Fatalf("Failed to generate second IV: %v", err)
	}

	// Different instances should generate different IVs
	if string(iv1) == string(iv2) {
		t.Error("Two independently generated IVs are identical (extremely unlikely)")
	}
}

// TestGetStaticKeyFromRouter tests extraction of static key from router keystore
func TestGetStaticKeyFromRouter(t *testing.T) {
	// Generate X25519 key pair (same as RouterInfoKeystore does)
	_, privKey, err := curve25519.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	staticKey := GetStaticKeyFromRouter(privKey)

	// Verify key is 32 bytes
	if len(staticKey) != 32 {
		t.Errorf("Expected static key size 32, got %d", len(staticKey))
	}

	// Verify key matches original private key bytes
	if string(staticKey) != string(privKey.Bytes()) {
		t.Error("Static key doesn't match encryption private key")
	}
}

// TestGetStaticKeyFromRouter_Consistency tests static key remains consistent
func TestGetStaticKeyFromRouter_Consistency(t *testing.T) {
	_, privKey, err := curve25519.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Extract static key multiple times
	staticKey1 := GetStaticKeyFromRouter(privKey)
	staticKey2 := GetStaticKeyFromRouter(privKey)

	if string(staticKey1) != string(staticKey2) {
		t.Error("Static key extraction is not consistent")
	}
}

// BenchmarkLoadOrGenerateObfuscationIV_NewFile benchmarks IV generation
func BenchmarkLoadOrGenerateObfuscationIV_NewFile(b *testing.B) {
	for i := 0; i < b.N; i++ {
		tempDir := b.TempDir()
		pc := NewPersistentConfig(tempDir)
		_, _ = pc.LoadOrGenerateObfuscationIV()
	}
}

// BenchmarkLoadOrGenerateObfuscationIV_ExistingFile benchmarks IV loading
func BenchmarkLoadOrGenerateObfuscationIV_ExistingFile(b *testing.B) {
	tempDir := b.TempDir()
	pc := NewPersistentConfig(tempDir)

	// Create IV file once
	_, err := pc.LoadOrGenerateObfuscationIV()
	if err != nil {
		b.Fatalf("Failed to generate IV: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = pc.LoadOrGenerateObfuscationIV()
	}
}
