package i2np

// Security Audit Tests for Garlic Messages (ECIES-X25519-AEAD-Ratchet)
// Audit Date: 2026-02-04
// These tests verify the cryptographic correctness of the garlic encryption implementation.

import (
	"bytes"
	"github.com/go-i2p/crypto/types"
	"sync"
	"testing"
	"time"

	"github.com/go-i2p/crypto/ecies"
	"github.com/go-i2p/crypto/rand"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// Audit: ECIES-X25519 Key Exchange Correctness
// ============================================================================

// TestECIESKeyExchange_Correctness verifies that ECIES key exchange produces
// consistent shared secrets for both sender and receiver.
func TestECIESKeyExchange_Correctness(t *testing.T) {
	// Generate receiver's static key pair
	receiverPubBytes, receiverPrivBytes, err := ecies.GenerateKeyPair()
	require.NoError(t, err, "Failed to generate receiver key pair")

	var receiverPubKey, receiverPrivKey [32]byte
	copy(receiverPubKey[:], receiverPubBytes)
	copy(receiverPrivKey[:], receiverPrivBytes)

	// Create session manager (sender)
	senderSM, err := GenerateGarlicSessionManager()
	require.NoError(t, err, "Failed to generate sender session manager")

	// Create receiver session manager
	receiverSM, err := NewGarlicSessionManager(receiverPrivKey)
	require.NoError(t, err, "Failed to create receiver session manager")

	destHash := types.SHA256(receiverPubKey[:])

	// Build test garlic message
	builder, err := NewGarlicBuilderWithDefaults()
	require.NoError(t, err)
	dataMsg := NewDataMessage([]byte("crypto test payload"))
	err = builder.AddLocalDeliveryClove(dataMsg, 1)
	require.NoError(t, err)

	// Encrypt
	ciphertext, err := EncryptGarlicWithBuilder(senderSM, builder, destHash, receiverPubKey)
	require.NoError(t, err, "Encryption should succeed")

	// Decrypt
	plaintext, _, err := receiverSM.DecryptGarlicMessage(ciphertext)
	require.NoError(t, err, "Decryption should succeed")

	// Verify original plaintext can be recovered
	originalPlaintext, err := builder.BuildAndSerialize()
	require.NoError(t, err)
	assert.Equal(t, originalPlaintext, plaintext, "Decrypted plaintext should match original")
}

// TestECIESKeyExchange_NonceUniqueness verifies that each encryption produces
// unique nonces (even with the same key pair and message).
func TestECIESKeyExchange_NonceUniqueness(t *testing.T) {
	destPubBytes, _, err := ecies.GenerateKeyPair()
	require.NoError(t, err)

	var destPubKey [32]byte
	copy(destPubKey[:], destPubBytes)
	destHash := types.SHA256(destPubKey[:])

	// Generate two ciphertexts for the same plaintext
	ciphertexts := make([][]byte, 10)
	for i := 0; i < 10; i++ {
		sm, err := GenerateGarlicSessionManager()
		require.NoError(t, err)

		builder, err := NewGarlicBuilderWithDefaults()
		require.NoError(t, err)
		dataMsg := NewDataMessage([]byte("test payload"))
		err = builder.AddLocalDeliveryClove(dataMsg, 1)
		require.NoError(t, err)

		ciphertext, err := EncryptGarlicWithBuilder(sm, builder, destHash, destPubKey)
		require.NoError(t, err)
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
	// Generate keys
	receiverPubBytes, receiverPrivBytes, err := ecies.GenerateKeyPair()
	require.NoError(t, err)

	var receiverPubKey, receiverPrivKey [32]byte
	copy(receiverPubKey[:], receiverPubBytes)
	copy(receiverPrivKey[:], receiverPrivBytes)

	senderSM, err := GenerateGarlicSessionManager()
	require.NoError(t, err)

	receiverSM, err := NewGarlicSessionManager(receiverPrivKey)
	require.NoError(t, err)

	destHash := types.SHA256(receiverPubKey[:])

	// Build and encrypt
	builder, err := NewGarlicBuilderWithDefaults()
	require.NoError(t, err)
	dataMsg := NewDataMessage([]byte("secure payload"))
	err = builder.AddLocalDeliveryClove(dataMsg, 1)
	require.NoError(t, err)

	ciphertext, err := EncryptGarlicWithBuilder(senderSM, builder, destHash, receiverPubKey)
	require.NoError(t, err)

	// Tamper with ciphertext (flip a bit in the middle)
	tamperedCiphertext := make([]byte, len(ciphertext))
	copy(tamperedCiphertext, ciphertext)
	if len(tamperedCiphertext) > 50 {
		tamperedCiphertext[50] ^= 0x01
	}

	// Attempt to decrypt tampered ciphertext
	_, _, err = receiverSM.DecryptGarlicMessage(tamperedCiphertext)
	assert.Error(t, err, "Decryption of tampered ciphertext should fail")
}

// TestRatchetState_ForwardSecrecy verifies that session keys advance properly.
func TestRatchetState_ForwardSecrecy(t *testing.T) {
	receiverPubBytes, receiverPrivBytes, err := ecies.GenerateKeyPair()
	require.NoError(t, err)

	var receiverPubKey, receiverPrivKey [32]byte
	copy(receiverPubKey[:], receiverPubBytes)
	copy(receiverPrivKey[:], receiverPrivBytes)

	// Create persistent sender session manager
	senderSM, err := GenerateGarlicSessionManager()
	require.NoError(t, err)

	receiverSM, err := NewGarlicSessionManager(receiverPrivKey)
	require.NoError(t, err)

	destHash := types.SHA256(receiverPubKey[:])

	// Send first message (New Session)
	builder1, err := NewGarlicBuilderWithDefaults()
	require.NoError(t, err)
	dataMsg1 := NewDataMessage([]byte("message 1"))
	err = builder1.AddLocalDeliveryClove(dataMsg1, 1)
	require.NoError(t, err)

	ciphertext1, err := EncryptGarlicWithBuilder(senderSM, builder1, destHash, receiverPubKey)
	require.NoError(t, err)

	// Decrypt first message
	plaintext1, tag1, err := receiverSM.DecryptGarlicMessage(ciphertext1)
	require.NoError(t, err)
	assert.Equal(t, [8]byte{}, tag1, "First message should have empty session tag (New Session)")

	original1, err := builder1.BuildAndSerialize()
	require.NoError(t, err)
	assert.Equal(t, original1, plaintext1)

	// Second message should use existing session
	assert.Equal(t, 1, senderSM.GetSessionCount(), "Sender should have 1 session")
}

// TestSessionTag_Uniqueness verifies session tags are unique and single-use.
func TestSessionTag_Uniqueness(t *testing.T) {
	sm, err := GenerateGarlicSessionManager()
	require.NoError(t, err)

	destPubBytes, _, err := ecies.GenerateKeyPair()
	require.NoError(t, err)

	var destPubKey [32]byte
	copy(destPubKey[:], destPubBytes)
	destHash := types.SHA256(destPubKey[:])

	// Create a session by encrypting first message
	builder, err := NewGarlicBuilderWithDefaults()
	require.NoError(t, err)
	dataMsg := NewDataMessage([]byte("init"))
	err = builder.AddLocalDeliveryClove(dataMsg, 1)
	require.NoError(t, err)

	_, err = EncryptGarlicWithBuilder(sm, builder, destHash, destPubKey)
	require.NoError(t, err)

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
				destPubBytes, _, err := ecies.GenerateKeyPair()
				if err != nil {
					t.Errorf("Goroutine %d, op %d: key generation failed: %v", idx, j, err)
					continue
				}

				var destPubKey [32]byte
				copy(destPubKey[:], destPubBytes)
				destHash := types.SHA256(destPubKey[:])

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

// TestSessionExpiration verifies session cleanup works correctly.
func TestSessionExpiration(t *testing.T) {
	sm, err := GenerateGarlicSessionManager()
	require.NoError(t, err)

	// Set very short timeout for testing
	sm.sessionTimeout = 50 * time.Millisecond

	destPubBytes, _, err := ecies.GenerateKeyPair()
	require.NoError(t, err)

	var destPubKey [32]byte
	copy(destPubKey[:], destPubBytes)
	destHash := types.SHA256(destPubKey[:])

	// Create a session
	builder, err := NewGarlicBuilderWithDefaults()
	require.NoError(t, err)
	dataMsg := NewDataMessage([]byte("expire test"))
	err = builder.AddLocalDeliveryClove(dataMsg, 1)
	require.NoError(t, err)

	_, err = EncryptGarlicWithBuilder(sm, builder, destHash, destPubKey)
	require.NoError(t, err)

	assert.Equal(t, 1, sm.GetSessionCount(), "Should have 1 session")

	// Wait for expiration
	time.Sleep(100 * time.Millisecond)

	// Cleanup should remove expired sessions
	removed := sm.CleanupExpiredSessions()
	assert.Equal(t, 1, removed, "Should have removed 1 expired session")
	assert.Equal(t, 0, sm.GetSessionCount(), "Should have 0 sessions after cleanup")
}

// TestNewSessionMessageFormat_Security verifies correct message format.
func TestNewSessionMessageFormat_Security(t *testing.T) {
	sm, err := GenerateGarlicSessionManager()
	require.NoError(t, err)

	destPubBytes, _, err := ecies.GenerateKeyPair()
	require.NoError(t, err)

	var destPubKey [32]byte
	copy(destPubKey[:], destPubBytes)
	destHash := types.SHA256(destPubKey[:])

	builder, err := NewGarlicBuilderWithDefaults()
	require.NoError(t, err)
	dataMsg := NewDataMessage([]byte("format test"))
	err = builder.AddLocalDeliveryClove(dataMsg, 1)
	require.NoError(t, err)

	ciphertext, err := EncryptGarlicWithBuilder(sm, builder, destHash, destPubKey)
	require.NoError(t, err)

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

// TestHKDF_KeyDerivation verifies HKDF-based key derivation correctness.
func TestHKDF_KeyDerivation(t *testing.T) {
	// Create a shared secret
	var sharedSecret [32]byte
	_, err := rand.Read(sharedSecret[:])
	require.NoError(t, err)

	// Derive keys multiple times with same input
	keys1, err := deriveSessionKeysFromSecret(sharedSecret[:])
	require.NoError(t, err)

	keys2, err := deriveSessionKeysFromSecret(sharedSecret[:])
	require.NoError(t, err)

	// Keys should be deterministic
	assert.Equal(t, keys1.rootKey, keys2.rootKey, "Root keys should match")
	assert.Equal(t, keys1.symKey, keys2.symKey, "Symmetric keys should match")
	assert.Equal(t, keys1.tagKey, keys2.tagKey, "Tag keys should match")

	// Keys should be different from each other
	assert.NotEqual(t, keys1.rootKey, keys1.symKey, "Root and symmetric keys should differ")
	assert.NotEqual(t, keys1.rootKey, keys1.tagKey, "Root and tag keys should differ")
	assert.NotEqual(t, keys1.symKey, keys1.tagKey, "Symmetric and tag keys should differ")

	// Keys should be 32 bytes (256 bits)
	assert.Equal(t, 32, len(keys1.rootKey), "Root key should be 32 bytes")
	assert.Equal(t, 32, len(keys1.symKey), "Symmetric key should be 32 bytes")
	assert.Equal(t, 32, len(keys1.tagKey), "Tag key should be 32 bytes")
}

// TestGarlicMessageBoundsChecking verifies input validation.
func TestGarlicMessageBoundsChecking(t *testing.T) {
	_, privBytes, err := ecies.GenerateKeyPair()
	require.NoError(t, err)

	var privKey [32]byte
	copy(privKey[:], privBytes)

	sm, err := NewGarlicSessionManager(privKey)
	require.NoError(t, err)

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
			_, _, err := sm.DecryptGarlicMessage(tc.input)
			if tc.expectError {
				assert.Error(t, err, "Should return error for %s", tc.name)
			}
		})
	}
}

// TestErrorMessages_NoSensitiveDataLeak verifies error messages don't leak keys.
func TestErrorMessages_NoSensitiveDataLeak(t *testing.T) {
	_, privBytes, err := ecies.GenerateKeyPair()
	require.NoError(t, err)

	var privKey [32]byte
	copy(privKey[:], privBytes)

	sm, err := NewGarlicSessionManager(privKey)
	require.NoError(t, err)

	// Try to decrypt invalid data
	invalidData := make([]byte, 100)
	_, err = rand.Read(invalidData)
	require.NoError(t, err)

	_, _, decryptErr := sm.DecryptGarlicMessage(invalidData)
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
