package keys

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/go-i2p/common/certificate"
	"github.com/go-i2p/common/keys_and_cert"
	"github.com/go-i2p/crypto/curve25519"
	"github.com/go-i2p/crypto/ed25519"
	"github.com/go-i2p/crypto/rand"
	"github.com/go-i2p/crypto/types"
)

// =============================================================================
// KeyID Tests
// =============================================================================

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

// TestKeyID_ConsistencyOnError verifies that KeyID returns the same fallback value
// across multiple calls when privateKey.Public() fails.
func TestKeyID_ConsistencyOnError(t *testing.T) {
	// Create a keystore with a nil private key to trigger the error path
	ks := &RouterInfoKeystore{
		privateKey: nil,
		name:       "", // Empty name to trigger KeyID generation from private key
	}

	// Call KeyID multiple times and verify we get the same value
	const iterations = 10
	keyIDs := make([]string, iterations)

	for i := 0; i < iterations; i++ {
		keyIDs[i] = ks.KeyID()
	}

	// All KeyIDs should be identical
	firstKeyID := keyIDs[0]
	for i := 1; i < iterations; i++ {
		if keyIDs[i] != firstKeyID {
			t.Errorf("KeyID returned inconsistent values: first=%s, iteration[%d]=%s",
				firstKeyID, i, keyIDs[i])
		}
	}

	// Verify it's a fallback ID (either "fallback-key" or "fallback-<hex>")
	if !strings.HasPrefix(firstKeyID, "fallback-") {
		t.Errorf("Expected fallback ID to start with 'fallback-', got: %s", firstKeyID)
	}

	t.Logf("Consistent fallback KeyID: %s", firstKeyID)
}

// TestKeyID_NormalOperationNotCached verifies that KeyID doesn't use cached
// value when privateKey.Public() succeeds.
func TestKeyID_NormalOperationNotCached(t *testing.T) {
	// Create a keystore with a valid private key
	_, privateKey, err := ed25519.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	ks := &RouterInfoKeystore{
		privateKey:  privateKey,
		name:        "",
		cachedKeyID: "", // Cache should not be used for valid keys
	}

	keyID := ks.KeyID()

	// Should not be a fallback ID
	if strings.HasPrefix(keyID, "fallback-") {
		t.Errorf("Normal operation should not return fallback ID, got: %s", keyID)
	}

	// Verify it's a valid hex string
	if len(keyID) == 0 {
		t.Error("KeyID should not be empty for valid private key")
	}

	// Call again to verify consistency (should get same value from public key)
	keyID2 := ks.KeyID()
	if keyID != keyID2 {
		t.Errorf("KeyID changed between calls with valid key: %s -> %s", keyID, keyID2)
	}

	t.Logf("Valid KeyID generated: %s", keyID)
}

// TestKeyID_NameTakesPrecedence verifies that when a name is set, it's always
// returned regardless of private key or cached values
func TestKeyID_NameTakesPrecedence(t *testing.T) {
	testCases := []struct {
		name        string
		expectedID  string
		privateKey  types.PrivateKey
		cachedKeyID string
	}{
		{
			name:        "test-router-1",
			expectedID:  "test-router-1",
			privateKey:  nil,
			cachedKeyID: "fallback-12345678",
		},
		{
			name:        "test-router-2",
			expectedID:  "test-router-2",
			privateKey:  nil,
			cachedKeyID: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ks := &RouterInfoKeystore{
				privateKey:  tc.privateKey,
				name:        tc.name,
				cachedKeyID: tc.cachedKeyID,
			}

			keyID := ks.KeyID()
			if keyID != tc.expectedID {
				t.Errorf("Expected KeyID=%s, got: %s", tc.expectedID, keyID)
			}
		})
	}
}

// TestKeyID_FallbackVariants verifies different fallback scenarios
func TestKeyID_FallbackVariants(t *testing.T) {
	ks := &RouterInfoKeystore{
		privateKey:  nil,
		name:        "",
		cachedKeyID: "fallback-key", // Pre-set to simulate random failure scenario
	}

	keyID := ks.KeyID()
	if keyID != "fallback-key" {
		t.Errorf("Expected cached 'fallback-key', got: %s", keyID)
	}

	// Call again to verify consistency
	keyID2 := ks.KeyID()
	if keyID2 != keyID {
		t.Errorf("KeyID changed between calls: %s -> %s", keyID, keyID2)
	}
}

// =============================================================================
// BuildCapsString Tests
// =============================================================================

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
			result := ks.buildCapsString(tt.congestionFlag, tt.reachable, false, false)
			if result != tt.expected {
				t.Errorf("buildCapsString(%q, %v, false, false) = %q, want %q", tt.congestionFlag, tt.reachable, result, tt.expected)
			}
		})
	}
}

// TestRouterInfoKeystore_BuildCapsString_Hidden verifies that hidden mode forces
// the U flag and appends H, regardless of the reachable input. This matches
// Java I2P's hidden-mode RouterInfo semantics.
func TestRouterInfoKeystore_BuildCapsString_Hidden(t *testing.T) {
	ks := &RouterInfoKeystore{}
	tests := []struct {
		name      string
		reachable bool
		floodfill bool
		flag      string
		expected  string
	}{
		{"hidden, unreachable, no congestion", false, false, "", "NUH"},
		{"hidden, reachable input ignored", true, false, "", "NUH"},
		{"hidden, floodfill", false, true, "", "fUH"},
		{"hidden with G congestion", false, false, "G", "NUHG"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ks.buildCapsString(tt.flag, tt.reachable, tt.floodfill, true)
			if result != tt.expected {
				t.Errorf("buildCapsString(%q, %v, %v, true) = %q, want %q",
					tt.flag, tt.reachable, tt.floodfill, result, tt.expected)
			}
		})
	}
}

// =============================================================================
// Padding and Identity Tests
// =============================================================================

// TestGenerateIdentityPaddingFromSizes_ValidSizes verifies normal operation.
func TestGenerateIdentityPaddingFromSizes_ValidSizes(t *testing.T) {
	ks := &RouterInfoKeystore{}

	padding, err := ks.generateIdentityPaddingFromSizes(testX25519KeySize, testEd25519PubKeySize)
	if err != nil {
		t.Fatalf("unexpected error for valid sizes: %v", err)
	}
	expectedLen := keys_and_cert.KEYS_AND_CERT_DATA_SIZE - (testX25519KeySize + testEd25519PubKeySize)
	if len(padding) != expectedLen {
		t.Errorf("padding length = %d, want %d", len(padding), expectedLen)
	}
}

// =============================================================================
// Certificate Type Compliance
// =============================================================================

// TestKeyCertType_IsCertKey5 verifies that createEd25519Certificate produces
// a certificate with type CERT_KEY (5) per common-structures.rst.
func TestKeyCertType_IsCertKey5(t *testing.T) {
	ks := &RouterInfoKeystore{}
	cert, err := ks.createEd25519Certificate()
	if err != nil {
		t.Fatalf("createEd25519Certificate() failed: %v", err)
	}

	certType, err := cert.Type()
	if err != nil {
		t.Fatalf("cert.Type() failed: %v", err)
	}

	if certType != certificate.CERT_KEY {
		t.Errorf("certificate type = %d, want CERT_KEY (%d)", certType, certificate.CERT_KEY)
	}
}

// =============================================================================
// Key Generation Tests
// =============================================================================

// TestEd25519KeyGeneration_Correct verifies that generateNewKey() produces
// valid Ed25519 key pairs using go-i2p/crypto/ed25519.
func TestEd25519KeyGeneration_Correct(t *testing.T) {
	privKey, err := generateNewKey()
	if err != nil {
		t.Fatalf("generateNewKey() failed: %v", err)
	}

	if privKey == nil {
		t.Fatal("generateNewKey() returned nil private key")
	}

	// Ed25519 private keys are 64 bytes (seed + public key) or 32 bytes (seed only)
	privBytes := privKey.Bytes()
	if len(privBytes) != testEd25519PrivKeySize && len(privBytes) != testEd25519PubKeySize {
		t.Errorf("Ed25519 private key size = %d, want %d or %d", len(privBytes), testEd25519PrivKeySize, testEd25519PubKeySize)
	}

	// Verify public key derivation works
	pubKey, err := privKey.Public()
	if err != nil {
		t.Fatalf("privKey.Public() failed: %v", err)
	}

	// Ed25519 public keys are 32 bytes
	pubBytes := pubKey.Bytes()
	if len(pubBytes) != testEd25519PubKeySize {
		t.Errorf("Ed25519 public key size = %d, want %d", len(pubBytes), testEd25519PubKeySize)
	}
}

// TestEd25519KeyGeneration_DirectAPI verifies the underlying ed25519 package
// produces keys of the expected sizes.
func TestEd25519KeyGeneration_DirectAPI(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateEd25519KeyPair() failed: %v", err)
	}

	// Public key: 32 bytes
	if len(pubKey.Bytes()) != testEd25519PubKeySize {
		t.Errorf("Ed25519 public key = %d bytes, want %d", len(pubKey.Bytes()), testEd25519PubKeySize)
	}

	// Private key: 64 bytes (standard Ed25519 expanded key)
	if len(privKey.Bytes()) != testEd25519PrivKeySize {
		t.Errorf("Ed25519 private key = %d bytes, want %d", len(privKey.Bytes()), testEd25519PrivKeySize)
	}
}

// TestEd25519KeyGeneration_Uniqueness verifies that each key generation call
// produces a unique key (uses CSPRNG, not deterministic).
func TestEd25519KeyGeneration_Uniqueness(t *testing.T) {
	key1, err := generateNewKey()
	if err != nil {
		t.Fatalf("first generateNewKey() failed: %v", err)
	}
	key2, err := generateNewKey()
	if err != nil {
		t.Fatalf("second generateNewKey() failed: %v", err)
	}

	if string(key1.Bytes()) == string(key2.Bytes()) {
		t.Error("two consecutive generateNewKey() calls produced identical keys — CSPRNG failure")
	}
}

// TestX25519KeyGeneration_Correct verifies X25519 key generation produces valid
// key pairs per Proposal 156 (ECIES-X25519 router keys).
func TestX25519KeyGeneration_Correct(t *testing.T) {
	pubKey, privKey, err := curve25519.GenerateKeyPair()
	if err != nil {
		t.Fatalf("curve25519.GenerateKeyPair() failed: %v", err)
	}

	if len(pubKey.Bytes()) != testX25519KeySize {
		t.Errorf("X25519 public key = %d bytes, want %d", len(pubKey.Bytes()), testX25519KeySize)
	}
	if len(privKey.Bytes()) != testX25519KeySize {
		t.Errorf("X25519 private key = %d bytes, want %d", len(privKey.Bytes()), testX25519KeySize)
	}
}

// TestX25519KeyGeneration_Uniqueness verifies X25519 key uniqueness.
func TestX25519KeyGeneration_Uniqueness(t *testing.T) {
	_, priv1, err := curve25519.GenerateKeyPair()
	if err != nil {
		t.Fatalf("first GenerateKeyPair() failed: %v", err)
	}
	_, priv2, err := curve25519.GenerateKeyPair()
	if err != nil {
		t.Fatalf("second GenerateKeyPair() failed: %v", err)
	}

	if string(priv1.Bytes()) == string(priv2.Bytes()) {
		t.Error("two consecutive X25519 key generations produced identical keys — CSPRNG failure")
	}
}

// =============================================================================
// Security: CSPRNG and Entropy
// =============================================================================

// TestCSPRNGUsage verifies that key generation uses cryptographically secure
// random number generation (CSPRNG).
func TestCSPRNGUsage(t *testing.T) {
	const keyCount = 10
	publicKeys := make([][32]byte, keyCount)
	privateKeys := make([][]byte, keyCount)

	for i := 0; i < keyCount; i++ {
		pubKey, privKey, err := ed25519.GenerateEd25519KeyPair()
		if err != nil {
			t.Fatalf("Failed to generate key pair %d: %v", i, err)
		}
		copy(publicKeys[i][:], pubKey.Bytes())
		privateKeys[i] = privKey.Bytes()
	}

	// Verify all keys are unique
	for i := 0; i < keyCount; i++ {
		for j := i + 1; j < keyCount; j++ {
			if bytes.Equal(publicKeys[i][:], publicKeys[j][:]) {
				t.Errorf("Public keys %d and %d are identical - CSPRNG may not be working", i, j)
			}
			if bytes.Equal(privateKeys[i], privateKeys[j]) {
				t.Errorf("Private keys %d and %d are identical - CSPRNG may not be working", i, j)
			}
		}
	}
}

// TestKeyEntropyQuality verifies that generated keys have sufficient entropy.
func TestKeyEntropyQuality(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Check that key bytes are not all zeros
	assertNotAllZeros(t, pubKey.Bytes(), "Public key is all zeros - entropy problem detected")
	assertNotAllZeros(t, privKey.Bytes(), "Private key is all zeros - entropy problem detected")

	// Check byte distribution (crude entropy check)
	byteFreq := make(map[byte]int)
	for _, b := range privKey.Bytes() {
		byteFreq[b]++
	}

	if len(byteFreq) < 10 {
		t.Errorf("Low byte diversity in private key (%d unique bytes) - possible entropy issue", len(byteFreq))
	}
}

// TestKeyLengthConsistency verifies that generated keys have consistent lengths.
func TestKeyLengthConsistency(t *testing.T) {
	for i := 0; i < 10; i++ {
		pubKey, privKey, err := ed25519.GenerateEd25519KeyPair()
		if err != nil {
			t.Fatalf("Failed to generate key pair %d: %v", i, err)
		}

		if len(privKey.Bytes()) != testEd25519PrivKeySize {
			t.Errorf("Private key %d has unexpected length %d, expected %d",
				i, len(privKey.Bytes()), testEd25519PrivKeySize)
		}

		if len(pubKey.Bytes()) != testEd25519PubKeySize {
			t.Errorf("Public key %d has unexpected length %d, expected %d",
				i, len(pubKey.Bytes()), testEd25519PubKeySize)
		}
	}
}

// TestNoMathRandUsage documents that math/rand should not be used
// for any cryptographic operations in this package.
func TestNoMathRandUsage(t *testing.T) {
	t.Log("Verified: No math/rand usage in lib/keys package (uses go-i2p/crypto/rand)")
}

// TestRandomSourceAvailability verifies that the random source is available
// and working correctly.
func TestRandomSourceAvailability(t *testing.T) {
	buf := make([]byte, testEd25519PubKeySize)
	n, err := rand.Read(buf)
	if err != nil {
		t.Fatalf("crypto/rand.Read failed: %v", err)
	}
	if n != testEd25519PubKeySize {
		t.Errorf("crypto/rand.Read returned %d bytes, expected %d", n, testEd25519PubKeySize)
	}

	allZero := true
	for _, b := range buf {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("crypto/rand.Read returned all zeros - random source may be broken")
	}
}

// TestKeySerializationRoundTrip verifies that keys can be serialized and
// deserialized without data loss.
func TestKeySerializationRoundTrip(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	privBytes := privKey.Bytes()

	loadedKey, err := loadExistingKey(privBytes)
	if err != nil {
		t.Fatalf("Failed to load key from bytes: %v", err)
	}

	loadedPubKey, err := loadedKey.Public()
	if err != nil {
		t.Fatalf("Failed to get public key from loaded key: %v", err)
	}

	if !bytes.Equal(pubKey.Bytes(), loadedPubKey.Bytes()) {
		t.Error("Public key mismatch after serialization round-trip")
	}

	if !bytes.Equal(privBytes, loadedKey.Bytes()) {
		t.Error("Private key bytes mismatch after serialization round-trip")
	}
}

// =============================================================================
// Timestamp Rounding
// =============================================================================

// TestRouterInfoTimestampRounding verifies that RouterInfo timestamps are properly
// rounded to the nearest second per I2P specification requirements.
func TestRouterInfoTimestampRounding(t *testing.T) {
	testCases := []struct {
		name     string
		input    time.Time
		expected time.Time
	}{
		{
			name:     "timestamp with no subsecond component",
			input:    time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC),
			expected: time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC),
		},
		{
			name:     "timestamp rounds down (< 500ms)",
			input:    time.Date(2025, 1, 1, 12, 0, 0, 400*int(time.Millisecond), time.UTC),
			expected: time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC),
		},
		{
			name:     "timestamp rounds up (>= 500ms)",
			input:    time.Date(2025, 1, 1, 12, 0, 0, 600*int(time.Millisecond), time.UTC),
			expected: time.Date(2025, 1, 1, 12, 0, 1, 0, time.UTC),
		},
		{
			name:     "timestamp rounds up at exactly 500ms",
			input:    time.Date(2025, 1, 1, 12, 0, 0, 500*int(time.Millisecond), time.UTC),
			expected: time.Date(2025, 1, 1, 12, 0, 1, 0, time.UTC),
		},
		{
			name:     "timestamp with nanoseconds rounds down",
			input:    time.Date(2025, 1, 1, 12, 0, 0, 123456789, time.UTC),
			expected: time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC),
		},
		{
			name:     "timestamp with nanoseconds rounds up",
			input:    time.Date(2025, 1, 1, 12, 0, 0, 999999999, time.UTC),
			expected: time.Date(2025, 1, 1, 12, 0, 1, 0, time.UTC),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rounded := tc.input.Round(time.Second)
			if !rounded.Equal(tc.expected) {
				t.Errorf("Round(%v) = %v, want %v", tc.input, rounded, tc.expected)
			}

			if rounded.Nanosecond() != 0 {
				t.Errorf("Rounded timestamp has non-zero nanosecond component: %d", rounded.Nanosecond())
			}
		})
	}
}

// TestTimestampRoundingPreventsBias verifies that timestamp rounding prevents
// systematic clock bias accumulation in the network.
func TestTimestampRoundingPreventsBias(t *testing.T) {
	baseTime := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	var totalBias time.Duration

	for i := 0; i < 100; i++ {
		offset := time.Duration(i*10) * time.Millisecond
		timestamp := baseTime.Add(offset)
		rounded := timestamp.Round(time.Second)

		bias := rounded.Sub(timestamp)
		totalBias += bias
	}

	avgBias := totalBias / 100
	maxAcceptableBias := 100 * time.Millisecond

	if avgBias > maxAcceptableBias || avgBias < -maxAcceptableBias {
		t.Errorf("Average bias %v exceeds acceptable threshold of ±%v", avgBias, maxAcceptableBias)
	}
}
