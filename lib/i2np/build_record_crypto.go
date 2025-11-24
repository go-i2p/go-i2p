package i2np

import (
	"crypto/sha256"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/go-i2p/common/session_key"
	"github.com/go-i2p/logger"
)

// BuildRecordCrypto provides encryption/decryption for tunnel build records.
// Uses modern ChaCha20-Poly1305 AEAD encryption (I2P 0.9.44+).
type BuildRecordCrypto struct {
	// No configuration needed - always uses ChaCha20-Poly1305
}

// NewBuildRecordCrypto creates a new build record crypto handler.
// Uses modern ChaCha20-Poly1305 AEAD encryption (I2P 0.9.44+).
func NewBuildRecordCrypto() *BuildRecordCrypto {
	return &BuildRecordCrypto{}
}

// EncryptReplyRecord encrypts a BuildResponseRecord using the reply key and IV.
// This encrypts the 528-byte response record that participants send back to the
// tunnel creator during tunnel build.
//
// Uses ChaCha20-Poly1305 AEAD encryption (I2P 0.9.44+):
//
//	Output: 528 bytes encrypted data + 16 bytes authentication tag = 544 bytes
//
// Format (cleartext before encryption):
//
//	bytes 0-31:   SHA-256 hash of bytes 32-527
//	bytes 32-526: Random data
//	byte 527:     Reply status code
//
// The reply key and IV are provided in the BuildRequestRecord.
func (c *BuildRecordCrypto) EncryptReplyRecord(
	record BuildResponseRecord,
	replyKey session_key.SessionKey,
	replyIV [16]byte,
) ([]byte, error) {
	// Serialize the cleartext record
	cleartext, err := c.serializeResponseRecord(record)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize response record: %w", err)
	}

	if len(cleartext) != 528 {
		return nil, fmt.Errorf("invalid cleartext size: expected 528 bytes, got %d", len(cleartext))
	}

	// ChaCha20-Poly1305 AEAD encryption
	encrypted, err := c.encryptChaCha20Poly1305(cleartext, replyKey, replyIV)
	if err != nil {
		return nil, fmt.Errorf("ChaCha20-Poly1305 encryption failed: %w", err)
	}

	logger.WithFields(logger.Fields{
		"encryption": "ChaCha20-Poly1305",
		"size":       len(encrypted),
	}).Debug("Encrypted build response record")

	return encrypted, nil
}

// DecryptReplyRecord decrypts an encrypted BuildResponseRecord.
// This is the counterpart to EncryptReplyRecord, used by the tunnel creator
// to decrypt replies from participants.
//
// Uses ChaCha20-Poly1305 AEAD decryption (I2P 0.9.44+).
// Expects 544 bytes input (528 ciphertext + 16 auth tag).
func (c *BuildRecordCrypto) DecryptReplyRecord(
	encryptedData []byte,
	replyKey session_key.SessionKey,
	replyIV [16]byte,
) (BuildResponseRecord, error) {
	// ChaCha20-Poly1305 AEAD decryption
	// Expected size: 528 bytes plaintext + 16 bytes auth tag = 544 bytes
	if len(encryptedData) != 544 {
		return BuildResponseRecord{}, fmt.Errorf("invalid encrypted data size: expected 544 bytes, got %d", len(encryptedData))
	}

	cleartext, err := c.decryptChaCha20Poly1305(encryptedData, replyKey, replyIV)
	if err != nil {
		return BuildResponseRecord{}, fmt.Errorf("ChaCha20-Poly1305 decryption failed: %w", err)
	}

	if len(cleartext) != 528 {
		return BuildResponseRecord{}, fmt.Errorf("invalid decrypted data size: expected 528 bytes, got %d", len(cleartext))
	}

	// Parse the decrypted record
	record, err := ReadBuildResponseRecord(cleartext)
	if err != nil {
		return BuildResponseRecord{}, fmt.Errorf("failed to parse decrypted record: %w", err)
	}

	// Verify the hash
	if err := c.verifyResponseRecordHash(record); err != nil {
		return BuildResponseRecord{}, fmt.Errorf("hash verification failed: %w", err)
	}

	log.Debug("Decrypted and verified build response record")

	return record, nil
}

// serializeResponseRecord converts a BuildResponseRecord to its wire format (528 bytes).
func (c *BuildRecordCrypto) serializeResponseRecord(record BuildResponseRecord) ([]byte, error) {
	buf := make([]byte, 528)

	// bytes 0-31: SHA-256 hash
	copy(buf[0:32], record.Hash[:])

	// bytes 32-526: random data
	copy(buf[32:527], record.RandomData[:])

	// byte 527: reply status
	buf[527] = record.Reply

	return buf, nil
}

// verifyResponseRecordHash verifies the SHA-256 hash in the response record.
// The hash should cover bytes 32-527 of the serialized record.
func (c *BuildRecordCrypto) verifyResponseRecordHash(record BuildResponseRecord) error {
	// Compute expected hash of random data + reply byte
	data := make([]byte, 495+1)
	copy(data[0:495], record.RandomData[:])
	data[495] = record.Reply

	expectedHash := sha256.Sum256(data)

	// Compare with the hash in the record
	if record.Hash != expectedHash {
		log.WithFields(logger.Fields{
			"expected": fmt.Sprintf("%x", expectedHash[:8]),
			"actual":   fmt.Sprintf("%x", record.Hash[:8]),
		}).Warn("Build response record hash mismatch")
		return fmt.Errorf("hash verification failed")
	}

	return nil
}

// encryptChaCha20Poly1305 encrypts data using ChaCha20-Poly1305 AEAD.
// This is the modern encryption mode for tunnel build records (I2P 0.9.44+).
//
// Parameters:
//   - plaintext: 528 bytes of plaintext to encrypt
//   - key: 32-byte session key
//   - iv: 16-byte initialization vector (first 12 bytes used as nonce)
//
// Returns:
//   - 544 bytes: 528 bytes ciphertext + 16 bytes authentication tag
func (c *BuildRecordCrypto) encryptChaCha20Poly1305(
	plaintext []byte,
	key session_key.SessionKey,
	iv [16]byte,
) ([]byte, error) {
	if len(plaintext) != 528 {
		return nil, fmt.Errorf("plaintext must be 528 bytes, got %d", len(plaintext))
	}

	// Create ChaCha20-Poly1305 AEAD cipher
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, fmt.Errorf("failed to create ChaCha20-Poly1305 cipher: %w", err)
	}

	// Use first 12 bytes of IV as nonce (ChaCha20-Poly1305 requires 12-byte nonce)
	nonce := iv[:12]

	// Encrypt and authenticate
	// Seal appends the ciphertext and auth tag to dst (nil means allocate new slice)
	ciphertext := aead.Seal(nil, nonce, plaintext, nil)

	// Result should be 528 bytes ciphertext + 16 bytes tag = 544 bytes
	if len(ciphertext) != 544 {
		return nil, fmt.Errorf("unexpected ciphertext length: %d", len(ciphertext))
	}

	return ciphertext, nil
}

// decryptChaCha20Poly1305 decrypts data using ChaCha20-Poly1305 AEAD.
// This is the modern decryption mode for tunnel build records (I2P 0.9.44+).
//
// Parameters:
//   - ciphertext: 544 bytes (528 bytes encrypted + 16 bytes auth tag)
//   - key: 32-byte session key
//   - iv: 16-byte initialization vector (first 12 bytes used as nonce)
//
// Returns:
//   - 528 bytes of decrypted plaintext
//   - Error if authentication fails or decryption fails
func (c *BuildRecordCrypto) decryptChaCha20Poly1305(
	ciphertext []byte,
	key session_key.SessionKey,
	iv [16]byte,
) ([]byte, error) {
	if len(ciphertext) != 544 {
		return nil, fmt.Errorf("ciphertext must be 544 bytes (528 + 16 tag), got %d", len(ciphertext))
	}

	// Create ChaCha20-Poly1305 AEAD cipher
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, fmt.Errorf("failed to create ChaCha20-Poly1305 cipher: %w", err)
	}

	// Use first 12 bytes of IV as nonce
	nonce := iv[:12]

	// Decrypt and verify authentication tag
	// Open verifies the tag and decrypts the message
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed (authentication error): %w", err)
	}

	// Result should be exactly 528 bytes
	if len(plaintext) != 528 {
		return nil, fmt.Errorf("unexpected plaintext length: %d", len(plaintext))
	}

	return plaintext, nil
}

// CreateBuildResponseRecord creates a new BuildResponseRecord with proper hash.
// This is a helper function for participants to create valid response records.
//
// Parameters:
//   - reply: Status code (0=accept, non-zero=reject reason)
//   - randomData: 495 bytes of random data (should be cryptographically random)
//
// Returns a BuildResponseRecord with the SHA-256 hash properly computed.
func CreateBuildResponseRecord(reply byte, randomData [495]byte) BuildResponseRecord {
	// Compute SHA-256 hash of random data + reply byte
	data := make([]byte, 496)
	copy(data[0:495], randomData[:])
	data[495] = reply

	hash := sha256.Sum256(data)

	return BuildResponseRecord{
		Hash:       hash,
		RandomData: randomData,
		Reply:      reply,
	}
}
