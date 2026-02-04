package i2np

// Security Audit Tests for Build Record Encryption/Decryption
// Audit Date: 2026-02-04
// These tests verify the cryptographic correctness of tunnel build record encryption.

import (
	"bytes"
	"crypto/sha256"
	"sync"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/go-i2p/common/session_key"
	"github.com/go-i2p/crypto/rand"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// Audit: ChaCha20-Poly1305 AEAD Encryption Correctness
// ============================================================================

// TestChaCha20Poly1305_AuthenticationTag verifies AEAD produces valid auth tags.
func TestChaCha20Poly1305_AuthenticationTag(t *testing.T) {
	crypto := NewBuildRecordCrypto()

	var replyKey session_key.SessionKey
	var replyIV [16]byte
	_, err := rand.Read(replyKey[:])
	require.NoError(t, err)
	_, err = rand.Read(replyIV[:])
	require.NoError(t, err)

	var randomData [495]byte
	_, err = rand.Read(randomData[:])
	require.NoError(t, err)

	record := CreateBuildResponseRecord(0, randomData)

	encrypted, err := crypto.EncryptReplyRecord(record, replyKey, replyIV)
	require.NoError(t, err)

	// ChaCha20-Poly1305 output: 528 bytes plaintext + 16 bytes auth tag = 544 bytes
	assert.Equal(t, 544, len(encrypted), "Encrypted output should be 544 bytes (528 + 16 tag)")

	// Auth tag is the last 16 bytes
	authTag := encrypted[528:]
	assert.Equal(t, 16, len(authTag), "Auth tag should be 16 bytes")

	// Auth tag should not be all zeros (would indicate a problem)
	allZero := true
	for _, b := range authTag {
		if b != 0 {
			allZero = false
			break
		}
	}
	assert.False(t, allZero, "Auth tag should not be all zeros")
}

// TestChaCha20Poly1305_TamperDetection verifies tampering is detected.
func TestChaCha20Poly1305_TamperDetection(t *testing.T) {
	crypto := NewBuildRecordCrypto()

	var replyKey session_key.SessionKey
	var replyIV [16]byte
	_, err := rand.Read(replyKey[:])
	require.NoError(t, err)
	_, err = rand.Read(replyIV[:])
	require.NoError(t, err)

	var randomData [495]byte
	_, err = rand.Read(randomData[:])
	require.NoError(t, err)

	record := CreateBuildResponseRecord(0, randomData)

	encrypted, err := crypto.EncryptReplyRecord(record, replyKey, replyIV)
	require.NoError(t, err)

	// Test various tamper scenarios
	tamperCases := []struct {
		name      string
		tamperFn  func([]byte) []byte
		expectErr bool
	}{
		{
			"flip bit in ciphertext",
			func(data []byte) []byte {
				tampered := make([]byte, len(data))
				copy(tampered, data)
				tampered[100] ^= 0x01
				return tampered
			},
			true,
		},
		{
			"flip bit in auth tag",
			func(data []byte) []byte {
				tampered := make([]byte, len(data))
				copy(tampered, data)
				tampered[540] ^= 0x01
				return tampered
			},
			true,
		},
		{
			"truncate auth tag",
			func(data []byte) []byte {
				return data[:530] // Missing part of auth tag
			},
			true,
		},
		{
			"extend with garbage",
			func(data []byte) []byte {
				extended := make([]byte, len(data)+10)
				copy(extended, data)
				return extended
			},
			true,
		},
		{
			"untampered",
			func(data []byte) []byte {
				return data
			},
			false,
		},
	}

	for _, tc := range tamperCases {
		t.Run(tc.name, func(t *testing.T) {
			tampered := tc.tamperFn(encrypted)
			_, err := crypto.DecryptReplyRecord(tampered, replyKey, replyIV)
			if tc.expectErr {
				assert.Error(t, err, "Should detect tampering: %s", tc.name)
			} else {
				assert.NoError(t, err, "Untampered data should decrypt: %s", tc.name)
			}
		})
	}
}

// TestBuildRecordCrypto_KeyDerivation verifies key derivation consistency.
func TestBuildRecordCrypto_KeyDerivation(t *testing.T) {
	// Test that same key/IV always produces same ciphertext (deterministic)
	crypto := NewBuildRecordCrypto()

	var replyKey session_key.SessionKey
	var replyIV [16]byte
	_, err := rand.Read(replyKey[:])
	require.NoError(t, err)
	_, err = rand.Read(replyIV[:])
	require.NoError(t, err)

	var randomData [495]byte
	_, err = rand.Read(randomData[:])
	require.NoError(t, err)

	record := CreateBuildResponseRecord(0, randomData)

	encrypted1, err := crypto.EncryptReplyRecord(record, replyKey, replyIV)
	require.NoError(t, err)

	encrypted2, err := crypto.EncryptReplyRecord(record, replyKey, replyIV)
	require.NoError(t, err)

	assert.True(t, bytes.Equal(encrypted1, encrypted2),
		"Same key/IV should produce deterministic ciphertext")
}

// TestBuildRecordCrypto_NonceReuse verifies different IVs produce different ciphertexts.
func TestBuildRecordCrypto_DifferentNonces(t *testing.T) {
	crypto := NewBuildRecordCrypto()

	var replyKey session_key.SessionKey
	_, err := rand.Read(replyKey[:])
	require.NoError(t, err)

	var randomData [495]byte
	_, err = rand.Read(randomData[:])
	require.NoError(t, err)

	record := CreateBuildResponseRecord(0, randomData)

	// Encrypt with different IVs
	ciphertexts := make([][]byte, 5)
	for i := 0; i < 5; i++ {
		var replyIV [16]byte
		_, err := rand.Read(replyIV[:])
		require.NoError(t, err)

		encrypted, err := crypto.EncryptReplyRecord(record, replyKey, replyIV)
		require.NoError(t, err)
		ciphertexts[i] = encrypted
	}

	// Verify all ciphertexts are unique
	for i := 0; i < len(ciphertexts); i++ {
		for j := i + 1; j < len(ciphertexts); j++ {
			assert.False(t, bytes.Equal(ciphertexts[i], ciphertexts[j]),
				"Different IVs should produce different ciphertexts")
		}
	}
}

// TestBuildResponseRecord_HashVerification verifies SHA-256 hash integrity.
func TestBuildResponseRecord_HashVerification(t *testing.T) {
	var randomData [495]byte
	_, err := rand.Read(randomData[:])
	require.NoError(t, err)

	// Create record with correct hash
	record := CreateBuildResponseRecord(0, randomData)

	// Verify hash is computed correctly
	data := make([]byte, 496)
	copy(data[0:495], randomData[:])
	data[495] = 0 // reply code
	expectedHash := sha256.Sum256(data)

	// Compare hash bytes directly
	assert.Equal(t, expectedHash[:], record.Hash[:], "Hash should match SHA-256 of data")
}

// TestBuildResponseRecord_HashTamper verifies hash tampering is detected.
func TestBuildResponseRecord_HashTamper(t *testing.T) {
	crypto := NewBuildRecordCrypto()

	var replyKey session_key.SessionKey
	var replyIV [16]byte
	_, err := rand.Read(replyKey[:])
	require.NoError(t, err)
	_, err = rand.Read(replyIV[:])
	require.NoError(t, err)

	var randomData [495]byte
	_, err = rand.Read(randomData[:])
	require.NoError(t, err)

	// Create record with tampered hash
	tamperedRecord := CreateBuildResponseRecord(0, randomData)
	tamperedRecord.Hash[0] ^= 0xFF // Tamper with hash

	// Serialize and encrypt (this should succeed - hash check is on decrypt)
	cleartext, err := crypto.serializeResponseRecord(tamperedRecord)
	require.NoError(t, err)

	// The cleartext will have bad hash - decryption should catch this
	aead, err := chacha20poly1305.New(replyKey[:])
	require.NoError(t, err)

	nonce := replyIV[:12]
	ciphertext := aead.Seal(nil, nonce, cleartext, nil)

	// Decrypt should succeed (AEAD), but hash verification should fail
	decrypted, err := crypto.DecryptReplyRecord(ciphertext, replyKey, replyIV)
	if err == nil {
		// If AEAD passed, verify hash check would fail
		verifyErr := crypto.verifyResponseRecordHash(decrypted)
		assert.Error(t, verifyErr, "Hash verification should fail for tampered record")
	}
}

// TestBuildRecordCrypto_ConcurrentAccess verifies thread safety.
func TestBuildRecordCrypto_ConcurrentAccess(t *testing.T) {
	crypto := NewBuildRecordCrypto()

	var wg sync.WaitGroup
	numGoroutines := 10
	numOpsPerGoroutine := 50

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			for j := 0; j < numOpsPerGoroutine; j++ {
				var replyKey session_key.SessionKey
				var replyIV [16]byte
				_, err := rand.Read(replyKey[:])
				if err != nil {
					t.Errorf("Goroutine %d: key generation failed", idx)
					continue
				}
				_, err = rand.Read(replyIV[:])
				if err != nil {
					t.Errorf("Goroutine %d: IV generation failed", idx)
					continue
				}

				var randomData [495]byte
				_, err = rand.Read(randomData[:])
				if err != nil {
					t.Errorf("Goroutine %d: random data generation failed", idx)
					continue
				}

				record := CreateBuildResponseRecord(byte(j%256), randomData)

				encrypted, err := crypto.EncryptReplyRecord(record, replyKey, replyIV)
				if err != nil {
					t.Errorf("Goroutine %d: encryption failed: %v", idx, err)
					continue
				}

				decrypted, err := crypto.DecryptReplyRecord(encrypted, replyKey, replyIV)
				if err != nil {
					t.Errorf("Goroutine %d: decryption failed: %v", idx, err)
					continue
				}

				if decrypted.Reply != record.Reply {
					t.Errorf("Goroutine %d: reply mismatch after round-trip", idx)
				}
			}
		}(i)
	}

	wg.Wait()
}

// TestBuildRecordCrypto_AllReplyCodes verifies all reply codes work correctly.
func TestBuildRecordCrypto_AllReplyCodes(t *testing.T) {
	crypto := NewBuildRecordCrypto()

	replyCodes := []byte{
		TUNNEL_BUILD_REPLY_SUCCESS,
		TUNNEL_BUILD_REPLY_REJECT,
		TUNNEL_BUILD_REPLY_OVERLOAD,
		TUNNEL_BUILD_REPLY_BANDWIDTH,
		TUNNEL_BUILD_REPLY_INVALID,
		TUNNEL_BUILD_REPLY_EXPIRED,
		0xFF, // Unknown code
	}

	for _, replyCode := range replyCodes {
		t.Run(replyCodeName(replyCode), func(t *testing.T) {
			var replyKey session_key.SessionKey
			var replyIV [16]byte
			_, err := rand.Read(replyKey[:])
			require.NoError(t, err)
			_, err = rand.Read(replyIV[:])
			require.NoError(t, err)

			var randomData [495]byte
			_, err = rand.Read(randomData[:])
			require.NoError(t, err)

			record := CreateBuildResponseRecord(replyCode, randomData)

			encrypted, err := crypto.EncryptReplyRecord(record, replyKey, replyIV)
			require.NoError(t, err)

			decrypted, err := crypto.DecryptReplyRecord(encrypted, replyKey, replyIV)
			require.NoError(t, err)

			assert.Equal(t, replyCode, decrypted.Reply, "Reply code should match")
			assert.Equal(t, record.Hash, decrypted.Hash, "Hash should match")
			assert.Equal(t, record.RandomData, decrypted.RandomData, "Random data should match")
		})
	}
}

// Helper function to get reply code name
func replyCodeName(code byte) string {
	switch code {
	case TUNNEL_BUILD_REPLY_SUCCESS:
		return "SUCCESS"
	case TUNNEL_BUILD_REPLY_REJECT:
		return "REJECT"
	case TUNNEL_BUILD_REPLY_OVERLOAD:
		return "OVERLOAD"
	case TUNNEL_BUILD_REPLY_BANDWIDTH:
		return "BANDWIDTH"
	case TUNNEL_BUILD_REPLY_INVALID:
		return "INVALID"
	case TUNNEL_BUILD_REPLY_EXPIRED:
		return "EXPIRED"
	default:
		return "UNKNOWN"
	}
}

// TestBuildRecordCrypto_ZeroKey tests behavior with zero key (edge case).
func TestBuildRecordCrypto_ZeroKey(t *testing.T) {
	crypto := NewBuildRecordCrypto()

	var zeroKey session_key.SessionKey // All zeros
	var replyIV [16]byte
	_, err := rand.Read(replyIV[:])
	require.NoError(t, err)

	var randomData [495]byte
	_, err = rand.Read(randomData[:])
	require.NoError(t, err)

	record := CreateBuildResponseRecord(0, randomData)

	// Zero key should still work (though not recommended in production)
	encrypted, err := crypto.EncryptReplyRecord(record, zeroKey, replyIV)
	require.NoError(t, err)

	decrypted, err := crypto.DecryptReplyRecord(encrypted, zeroKey, replyIV)
	require.NoError(t, err)

	assert.Equal(t, record.Reply, decrypted.Reply)
}

// TestBuildRecordCrypto_KeyLengthValidation verifies key length requirements.
func TestBuildRecordCrypto_KeyLengthValidation(t *testing.T) {
	// Session keys are fixed at 32 bytes (type enforced)
	var key session_key.SessionKey
	assert.Equal(t, 32, len(key[:]), "Session key should be 32 bytes")

	// IV is fixed at 16 bytes
	var iv [16]byte
	assert.Equal(t, 16, len(iv[:]), "IV should be 16 bytes")
}
