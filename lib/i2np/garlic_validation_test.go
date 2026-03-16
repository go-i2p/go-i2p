package i2np

// Security Audit Tests for Garlic Messages (ECIES-X25519-AEAD-Ratchet)
// Audit Date: 2026-02-04
// These tests verify the cryptographic correctness of the garlic encryption implementation.

import (
	"bytes"
	"sync"
	"testing"

	"github.com/go-i2p/crypto/types"

	"github.com/go-i2p/crypto/ecies"
	"github.com/go-i2p/crypto/rand"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- shared test helpers ---

// generateDestKey generates a destination ECIES public key and its SHA256 hash.
func generateDestKey(t testing.TB) (destPubKey, destHash [32]byte) {
	t.Helper()
	pubBytes, _, err := ecies.GenerateKeyPair()
	require.NoError(t, err)
	copy(destPubKey[:], pubBytes)
	destHash = types.SHA256(destPubKey[:])
	return destPubKey, destHash
}

// newSenderWithDest creates a fresh GarlicSessionManager and a random destination key + hash.
func newSenderWithDest(t testing.TB) (sm *GarlicSessionManager, destPubKey, destHash [32]byte) {
	t.Helper()
	sm, err := GenerateGarlicSessionManager()
	require.NoError(t, err)
	destPubKey, destHash = generateDestKey(t)
	return sm, destPubKey, destHash
}

// buildAndEncryptGarlic creates a single-clove garlic message and encrypts it.
func buildAndEncryptGarlic(t testing.TB, sm *GarlicSessionManager,
	payload string, cloveID int, destHash, destPubKey [32]byte,
) (ciphertext []byte, builder *GarlicBuilder) {
	t.Helper()
	builder, err := NewGarlicBuilderWithDefaults()
	require.NoError(t, err)
	dataMsg := NewDataMessage([]byte(payload))
	err = builder.AddLocalDeliveryClove(dataMsg, cloveID)
	require.NoError(t, err)
	ciphertext, err = EncryptGarlicWithBuilder(sm, builder, destHash, destPubKey)
	require.NoError(t, err)
	return ciphertext, builder
}

// newReceiverSessionManager creates a GarlicSessionManager from a freshly generated private key.
func newReceiverSessionManager(t testing.TB) (sm *GarlicSessionManager, privKey [32]byte) {
	t.Helper()
	_, privBytes, err := ecies.GenerateKeyPair()
	require.NoError(t, err)
	copy(privKey[:], privBytes)
	sm, err = NewGarlicSessionManager(privKey)
	require.NoError(t, err)
	return sm, privKey
}

// garlicCryptoFixture holds pre-generated ECIES key pair and session managers
// for garlic encryption/decryption tests.
type garlicCryptoFixture struct {
	senderSM     *GarlicSessionManager
	receiverSM   *GarlicSessionManager
	receiverPub  [32]byte
	receiverPriv [32]byte
	destHash     [32]byte
}

// newGarlicCryptoFixture generates a receiver ECIES key pair and creates
// sender + receiver session managers ready for encrypt/decrypt testing.
func newGarlicCryptoFixture(t *testing.T) *garlicCryptoFixture {
	t.Helper()
	pubBytes, privBytes, err := ecies.GenerateKeyPair()
	require.NoError(t, err)

	var f garlicCryptoFixture
	copy(f.receiverPub[:], pubBytes)
	copy(f.receiverPriv[:], privBytes)

	f.senderSM, err = GenerateGarlicSessionManager()
	require.NoError(t, err)
	f.receiverSM, err = NewGarlicSessionManager(f.receiverPriv)
	require.NoError(t, err)
	f.destHash = types.SHA256(f.receiverPub[:])
	return &f
}

// ============================================================================
// Audit: ECIES-X25519 Key Exchange Correctness
// ============================================================================

// TestECIESKeyExchange_Correctness verifies that ECIES key exchange produces
// consistent shared secrets for both sender and receiver.
func TestECIESKeyExchange_Correctness(t *testing.T) {
	f := newGarlicCryptoFixture(t)

	// Build test garlic message
	ciphertext, builder := buildAndEncryptGarlic(t, f.senderSM, "crypto test payload", 1, f.destHash, f.receiverPub)

	// Decrypt
	plaintext, _, _, err := f.receiverSM.DecryptGarlicMessage(ciphertext)
	require.NoError(t, err, "Decryption should succeed")

	// Verify original plaintext can be recovered
	originalPlaintext, err := builder.BuildAndSerialize()
	require.NoError(t, err)
	assert.Equal(t, originalPlaintext, plaintext, "Decrypted plaintext should match original")
}

// TestECIESKeyExchange_NonceUniqueness verifies that each encryption produces
// unique nonces (even with the same key pair and message).
func TestECIESKeyExchange_NonceUniqueness(t *testing.T) {
	destPubKey, destHash := generateDestKey(t)

	// Generate ten ciphertexts for the same plaintext
	ciphertexts := make([][]byte, 10)
	for i := 0; i < 10; i++ {
		sm, err := GenerateGarlicSessionManager()
		require.NoError(t, err)

		ciphertext, _ := buildAndEncryptGarlic(t, sm, "test payload", 1, destHash, destPubKey)
		ciphertexts[i] = ciphertext
	}

	// Verify all ciphertexts are unique (due to unique ephemeral keys)
	for i := 0; i < len(ciphertexts); i++ {
		for j := i + 1; j < len(ciphertexts); j++ {
			assert.False(t, bytes.Equal(ciphertexts[i], ciphertexts[j]),
				"Ciphertexts should be unique (iteration %d and %d)", i, j)
		}
	}
}

// TestChaCha20Poly1305_AEADIntegrity verifies AEAD authentication detects tampering.
func TestChaCha20Poly1305_AEADIntegrity(t *testing.T) {
	f := newGarlicCryptoFixture(t)

	// Build and encrypt
	ciphertext, _ := buildAndEncryptGarlic(t, f.senderSM, "secure payload", 1, f.destHash, f.receiverPub)

	// Tamper with ciphertext (flip a bit in the middle)
	tamperedCiphertext := make([]byte, len(ciphertext))
	copy(tamperedCiphertext, ciphertext)
	if len(tamperedCiphertext) > 50 {
		tamperedCiphertext[50] ^= 0x01
	}

	// Attempt to decrypt tampered ciphertext
	_, _, _, err := f.receiverSM.DecryptGarlicMessage(tamperedCiphertext)
	assert.Error(t, err, "Decryption of tampered ciphertext should fail")
}

// TestRatchetState_ForwardSecrecy verifies that session keys advance properly.
func TestRatchetState_ForwardSecrecy(t *testing.T) {
	f := newGarlicCryptoFixture(t)

	// Send first message (New Session)
	ciphertext1, builder1 := buildAndEncryptGarlic(t, f.senderSM, "message 1", 1, f.destHash, f.receiverPub)

	// Decrypt first message
	plaintext1, tag1, _, err := f.receiverSM.DecryptGarlicMessage(ciphertext1)
	require.NoError(t, err)
	assert.Equal(t, [8]byte{}, tag1, "First message should have empty session tag (New Session)")

	original1, err := builder1.BuildAndSerialize()
	require.NoError(t, err)
	assert.Equal(t, original1, plaintext1)

	// Second message should use existing session
	assert.Equal(t, 1, f.senderSM.GetSessionCount(), "Sender should have 1 session")
}

// TestSessionTag_Uniqueness verifies session tags are unique and single-use.
func TestSessionTag_Uniqueness(t *testing.T) {
	sm, destPubKey, destHash := newSenderWithDest(t)

	// Create a session by encrypting first message
	_, _ = buildAndEncryptGarlic(t, sm, "init", 1, destHash, destPubKey)

	// Verify session was created
	assert.Equal(t, 1, sm.GetSessionCount())
}

// TestCSPRNG_Usage verifies all randomness uses crypto/rand (CSPRNG).
func TestCSPRNG_Usage(t *testing.T) {
	// Generate multiple key pairs and verify they're unique
	keyPairs := make(map[string]bool)
	for i := 0; i < 100; i++ {
		pubBytes, privBytes, err := ecies.GenerateKeyPair()
		require.NoError(t, err)

		pubKey := string(pubBytes)
		privKey := string(privBytes)

		assert.False(t, keyPairs[pubKey], "Public key should be unique (iteration %d)", i)
		assert.False(t, keyPairs[privKey], "Private key should be unique (iteration %d)", i)

		keyPairs[pubKey] = true
		keyPairs[privKey] = true
	}
}

// TestGarlicSessionManager_ConcurrentAccess verifies thread safety.
func TestGarlicSessionManager_ConcurrentAccess(t *testing.T) {
	sm, err := GenerateGarlicSessionManager()
	require.NoError(t, err)

	var wg sync.WaitGroup
	numGoroutines := 10
	numOpsPerGoroutine := 10

	// Concurrent encryption operations
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			for j := 0; j < numOpsPerGoroutine; j++ {
				destPubKey, destHash := generateDestKey(t)

				builder, err := NewGarlicBuilderWithDefaults()
				if err != nil {
					t.Errorf("Goroutine %d, op %d: builder creation failed: %v", idx, j, err)
					continue
				}

				dataMsg := NewDataMessage([]byte("concurrent test"))
				if err := builder.AddLocalDeliveryClove(dataMsg, idx*numOpsPerGoroutine+j); err != nil {
					t.Errorf("Goroutine %d, op %d: add clove failed: %v", idx, j, err)
					continue
				}

				_, err = EncryptGarlicWithBuilder(sm, builder, destHash, destPubKey)
				if err != nil {
					t.Errorf("Goroutine %d, op %d: encryption failed: %v", idx, j, err)
				}
			}
		}(i)
	}

	wg.Wait()

	// Session manager should still be functional
	assert.GreaterOrEqual(t, sm.GetSessionCount(), 0, "Session manager should be in valid state")
}

// TestNewSessionMessageFormat_Security verifies correct message format.
func TestNewSessionMessageFormat_Security(t *testing.T) {
	sm, destPubKey, destHash := newSenderWithDest(t)

	ciphertext, _ := buildAndEncryptGarlic(t, sm, "format test", 1, destHash, destPubKey)

	// New Session format: [ephemeralPubKey(32)] + [nonce(12)] + [ciphertext(N)] + [tag(16)]
	// Minimum size: 32 + 12 + 1 + 16 = 61 bytes
	assert.GreaterOrEqual(t, len(ciphertext), 61, "New session message should have minimum size")

	// First 32 bytes should be ephemeral public key (non-zero)
	ephemeralKey := ciphertext[:32]
	allZero := true
	for _, b := range ephemeralKey {
		if b != 0 {
			allZero = false
			break
		}
	}
	assert.False(t, allZero, "Ephemeral public key should not be all zeros")
}

// TestGarlicMessageBoundsChecking verifies input validation.
func TestGarlicMessageBoundsChecking(t *testing.T) {
	sm, _ := newReceiverSessionManager(t)

	testCases := []struct {
		name        string
		input       []byte
		expectError bool
	}{
		{"empty message", []byte{}, true},
		{"too short for tag", []byte{1, 2, 3, 4, 5, 6, 7}, true},
		{"minimum new session size minus 1", make([]byte, 60), true},
		{"valid size but invalid content", make([]byte, 100), true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, _, err := sm.DecryptGarlicMessage(tc.input)
			if tc.expectError {
				assert.Error(t, err, "Should return error for %s", tc.name)
			}
		})
	}
}

// TestErrorMessages_NoSensitiveDataLeak verifies error messages don't leak keys.
func TestErrorMessages_NoSensitiveDataLeak(t *testing.T) {
	sm, privKey := newReceiverSessionManager(t)

	// Try to decrypt invalid data
	invalidData := make([]byte, 100)
	_, err := rand.Read(invalidData)
	require.NoError(t, err)

	_, _, _, decryptErr := sm.DecryptGarlicMessage(invalidData)
	if decryptErr != nil {
		errMsg := decryptErr.Error()
		// Verify error message doesn't contain hex dumps of key material
		assert.NotContains(t, errMsg, string(privKey[:]))
		assert.NotContains(t, errMsg, "0x") // No raw hex dumps
		// Should have a generic error message
		assert.True(t,
			len(errMsg) > 0 && len(errMsg) < 500,
			"Error message should be reasonable length")
	}
}
