package keys

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/crypto/ed25519"
)

// =============================================================================
// Key Persistence Across Restarts
// =============================================================================

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
	if perm != testKeyFilePerms {
		t.Errorf("Encryption key file permissions: got %o, want %o", perm, testKeyFilePerms)
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

// TestKeyStoreFullRoundTrip verifies complete key storage and retrieval.
func TestKeyStoreFullRoundTrip(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "keys_roundtrip_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	keyName := "roundtrip-test"

	// Create and store a new keystore
	ks1, err := NewRouterInfoKeystore(tmpDir, keyName)
	if err != nil {
		t.Fatalf("Failed to create keystore: %v", err)
	}

	pubKey1, _, err := ks1.GetKeys()
	if err != nil {
		t.Fatalf("Failed to get keys from original keystore: %v", err)
	}

	err = ks1.StoreKeys()
	if err != nil {
		t.Fatalf("Failed to store keys: %v", err)
	}

	// Load the key from disk - filename format is KeyID().key
	keyPath := filepath.Join(tmpDir, ks1.KeyID()+".key")
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("Failed to read key file: %v", err)
	}

	loadedKey, err := loadExistingKey(keyData)
	if err != nil {
		t.Fatalf("Failed to load key: %v", err)
	}

	pubKey2, err := loadedKey.Public()
	if err != nil {
		t.Fatalf("Failed to get public key from loaded key: %v", err)
	}

	// Compare public keys
	if !bytes.Equal(pubKey1.Bytes(), pubKey2.Bytes()) {
		t.Error("Public key mismatch after full storage round-trip")
	}
}

// TestConcurrentKeyGeneration verifies that key generation is safe for
// concurrent use.
func TestConcurrentKeyGeneration(t *testing.T) {
	const goroutines = 10
	const keysPerGoroutine = 5

	var wg sync.WaitGroup
	errChan := make(chan error, goroutines*keysPerGoroutine)
	keyChan := make(chan []byte, goroutines*keysPerGoroutine)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < keysPerGoroutine; j++ {
				_, privKey, err := ed25519.GenerateEd25519KeyPair()
				if err != nil {
					errChan <- err
					return
				}
				keyChan <- privKey.Bytes()
			}
		}()
	}

	wg.Wait()
	close(errChan)
	close(keyChan)

	for err := range errChan {
		t.Errorf("Concurrent key generation error: %v", err)
	}

	keys := make([][]byte, 0, goroutines*keysPerGoroutine)
	for key := range keyChan {
		keys = append(keys, key)
	}

	if len(keys) != goroutines*keysPerGoroutine {
		t.Errorf("Expected %d keys, got %d", goroutines*keysPerGoroutine, len(keys))
	}

	seen := make(map[string]bool)
	for _, key := range keys {
		keyStr := string(key)
		if seen[keyStr] {
			t.Error("Duplicate key generated during concurrent access")
		}
		seen[keyStr] = true
	}
}

// TestKeyID_ConcurrentAccess verifies that KeyID is safe to call from multiple
// goroutines simultaneously and returns consistent values.
func TestKeyID_ConcurrentAccess(t *testing.T) {
	ks := &RouterInfoKeystore{
		privateKey: nil,
		name:       "",
	}

	const goroutines = 50
	const callsPerGoroutine = 20
	var wg sync.WaitGroup

	results := make(chan string, goroutines*callsPerGoroutine)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < callsPerGoroutine; j++ {
				results <- ks.KeyID()
			}
		}()
	}

	wg.Wait()
	close(results)

	keyIDMap := make(map[string]int)
	for keyID := range results {
		keyIDMap[keyID]++
	}

	if len(keyIDMap) != 1 {
		t.Errorf("KeyID returned %d different values under concurrent access, expected 1", len(keyIDMap))
		for keyID, count := range keyIDMap {
			t.Logf("  KeyID: %s (count: %d)", keyID, count)
		}
	}

	var singleKeyID string
	for keyID := range keyIDMap {
		singleKeyID = keyID
		break
	}

	if !strings.HasPrefix(singleKeyID, "fallback-") {
		t.Errorf("Expected fallback ID to start with 'fallback-', got: %s", singleKeyID)
	}

	t.Logf("All %d calls returned consistent KeyID: %s",
		goroutines*callsPerGoroutine, singleKeyID)
}

// =============================================================================
// Key Persistence Format
// =============================================================================

// TestKeyPersistenceFormat_NotJavaCompatible documents that go-i2p uses its own
// key persistence format rather than the Java I2P router.keys.dat format.
func TestKeyPersistenceFormat_NotJavaCompatible(t *testing.T) {
	tmpDir := t.TempDir()
	ks, err := NewRouterInfoKeystore(tmpDir, "persistence-test")
	if err != nil {
		t.Fatalf("NewRouterInfoKeystore() failed: %v", err)
	}

	err = ks.StoreKeys()
	if err != nil {
		t.Fatalf("StoreKeys() failed: %v", err)
	}

	// Verify go-i2p format files exist
	sigKeyPath := filepath.Join(tmpDir, "persistence-test.key")
	encKeyPath := filepath.Join(tmpDir, "persistence-test.enc.key")

	if _, err := os.Stat(sigKeyPath); os.IsNotExist(err) {
		t.Errorf("signing key file not found at %s", sigKeyPath)
	}
	if _, err := os.Stat(encKeyPath); os.IsNotExist(err) {
		t.Errorf("encryption key file not found at %s", encKeyPath)
	}

	// Verify Java-format file does NOT exist (documenting known divergence)
	javaPath := filepath.Join(tmpDir, "router.keys.dat")
	if _, err := os.Stat(javaPath); !os.IsNotExist(err) {
		t.Logf("NOTE: router.keys.dat exists — this would indicate Java-compatible format")
	}

	t.Logf("AUDIT NOTE: go-i2p uses .key/.enc.key format, NOT Java router.keys.dat. " +
		"This is a known divergence from net.i2p.router.KeyManager.")
}

// TestX25519InRouterInfoKeystore verifies that NewRouterInfoKeystore generates
// and stores X25519 encryption keys alongside Ed25519 signing keys.
func TestX25519InRouterInfoKeystore(t *testing.T) {
	tmpDir := t.TempDir()
	ks, err := NewRouterInfoKeystore(tmpDir, "x25519-test")
	if err != nil {
		t.Fatalf("NewRouterInfoKeystore() failed: %v", err)
	}

	encPrivKey := ks.GetEncryptionPrivateKey()
	if encPrivKey == nil {
		t.Fatal("GetEncryptionPrivateKey() returned nil — X25519 key not generated")
	}

	if len(encPrivKey.Bytes()) != testX25519KeySize {
		t.Errorf("encryption private key = %d bytes, want %d", len(encPrivKey.Bytes()), testX25519KeySize)
	}

	// Verify encryption key file exists
	encKeyPath := filepath.Join(tmpDir, "x25519-test.enc.key")
	if _, err := os.Stat(encKeyPath); os.IsNotExist(err) {
		t.Errorf("X25519 encryption key not persisted at %s", encKeyPath)
	}
}

// =============================================================================
// ConstructRouterInfo Integration
// =============================================================================

// TestRouterInfoKeystore_ConstructRouterInfo_WithCongestionFlag tests RouterInfo construction with congestion options
func TestRouterInfoKeystore_ConstructRouterInfo_WithCongestionFlag(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "routerinfo_congestion_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	ks, err := NewRouterInfoKeystore(tmpDir, "test-router")
	if err != nil {
		t.Fatalf("Failed to create keystore: %v", err)
	}

	tests := []struct {
		name            string
		opts            []RouterInfoOptions
		expectedCapsSub string
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

			caps := ri.RouterCapabilities()
			if !strings.Contains(caps, tt.expectedCapsSub) {
				t.Errorf("caps = %q, want %q", caps, tt.expectedCapsSub)
			}
		})
	}
}

// TestRouterInfoKeystore_ConstructRouterInfo_BackwardCompatible tests backward compatibility
func TestRouterInfoKeystore_ConstructRouterInfo_BackwardCompatible(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "routerinfo_compat_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	ks, err := NewRouterInfoKeystore(tmpDir, "test-router")
	if err != nil {
		t.Fatalf("Failed to create keystore: %v", err)
	}

	ri, err := ks.ConstructRouterInfo(nil)
	if err != nil {
		t.Fatalf("ConstructRouterInfo without options failed: %v", err)
	}

	if ri == nil {
		t.Fatal("RouterInfo should not be nil")
	}

	caps := ri.RouterCapabilities()
	if !strings.Contains(caps, "NU") {
		t.Errorf("caps %q does not contain 'NU'", caps)
	}
}

// TestRouterInfoKeystore_Close_ZeroesKeyMaterial verifies that Close() zeroes
// private key bytes from memory.
func TestRouterInfoKeystore_Close_ZeroesKeyMaterial(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "keys_close_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	ks, err := NewRouterInfoKeystore(tmpDir, "close-test")
	if err != nil {
		t.Fatalf("Failed to create keystore: %v", err)
	}

	// Capture key bytes before Close
	assertNotAllZeros(t, ks.privateKey.Bytes(), "Signing key should not be all zeros before Close")
	assertNotAllZeros(t, ks.encryptionPrivKey.Bytes(), "Encryption key should not be all zeros before Close")

	ks.Close()

	assertAllZeros(t, ks.privateKey.Bytes(), "Signing key should be all zeros after Close()")
	assertAllZeros(t, ks.encryptionPrivKey.Bytes(), "Encryption key should be all zeros after Close()")
}

// TestRouterInfoKeystorePaddingGeneration verifies that generateIdentityPaddingFromSizes
// produces padding of the correct size and caches it for identity stability.
func TestRouterInfoKeystorePaddingGeneration(t *testing.T) {
	tmpDir := t.TempDir()
	ks := &RouterInfoKeystore{dir: tmpDir, name: "test"}

	sizes, err := key_certificate.GetKeySizes(
		key_certificate.KEYCERT_SIGN_ED25519,
		key_certificate.KEYCERT_CRYPTO_X25519,
	)
	if err != nil {
		t.Fatalf("GetKeySizes() failed: %v", err)
	}

	padding1, err := ks.generateIdentityPaddingFromSizes(sizes.CryptoPublicKeySize, sizes.SigningPublicKeySize)
	if err != nil {
		t.Fatalf("generateIdentityPaddingFromSizes() failed: %v", err)
	}

	if len(padding1) != testExpectedPaddingSize {
		t.Errorf("padding size = %d, want %d", len(padding1), testExpectedPaddingSize)
	}

	// Second call should return cached padding (identity stability)
	padding2, err := ks.generateIdentityPaddingFromSizes(sizes.CryptoPublicKeySize, sizes.SigningPublicKeySize)
	if err != nil {
		t.Fatalf("second generateIdentityPaddingFromSizes() failed: %v", err)
	}

	if len(padding1) != len(padding2) {
		t.Fatalf("padding lengths differ: %d vs %d", len(padding1), len(padding2))
	}
	for i := range padding1 {
		if padding1[i] != padding2[i] {
			t.Errorf("padding byte[%d] differs between calls: cached padding not reused", i)
			break
		}
	}

	// Verify padding is persisted to disk
	paddingPath := filepath.Join(tmpDir, "test.padding")
	_, err = os.Stat(paddingPath)
	if err != nil {
		t.Errorf("padding file not persisted at %s: %v", paddingPath, err)
	}
}
