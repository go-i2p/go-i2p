package i2np

import (
	"crypto/sha256"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/common/session_key"
	"github.com/go-i2p/crypto/ecies"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
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

// EncryptBuildRequestRecord encrypts a BuildRequestRecord using ECIES-X25519-AEAD encryption.
//
// This implements the I2P specification for encrypted tunnel build records.
// The 222-byte cleartext record is encrypted using the recipient router's X25519 public key,
// then padded to the standard 528-byte format.
//
// Format:
//   - Bytes 0-15: First 16 bytes of SHA-256 hash of recipient's RouterIdentity
//   - Bytes 16-527: ECIES-X25519 encrypted data
//
// The ECIES encryption produces: [ephemeral_pubkey(32)][nonce(12)][aead_ciphertext(222+16_tag=238)]
// Total ECIES output: 32 + 12 + 238 = 282 bytes
// Remaining padding: 512 - 282 = 230 bytes of zeros
//
// Parameters:
//   - record: The cleartext BuildRequestRecord (serializes to 222 bytes)
//   - recipientRouterInfo: The RouterInfo of the hop that will decrypt this record
//
// Returns:
//   - [528]byte: Encrypted build request record ready for network transmission
//   - error: Any encryption error encountered
func EncryptBuildRequestRecord(record BuildRequestRecord, recipientRouterInfo router_info.RouterInfo) ([528]byte, error) {
	var encrypted [528]byte

	// Step 1: Serialize the cleartext record (222 bytes)
	cleartext := record.Bytes()
	if len(cleartext) != 222 {
		return encrypted, oops.Errorf("invalid cleartext size: expected 222 bytes, got %d", len(cleartext))
	}

	// Step 2: Get recipient's X25519 public encryption key from RouterInfo
	recipientPubKey, err := extractEncryptionPublicKey(recipientRouterInfo)
	if err != nil {
		return encrypted, oops.Wrapf(err, "failed to extract encryption public key")
	}

	// Step 3: Calculate first 16 bytes of SHA-256 hash of RouterIdentity (toPeer field)
	identityHash := calculateIdentityHash(recipientRouterInfo)
	copy(encrypted[0:16], identityHash[:16])

	// Step 4: Encrypt the 222-byte cleartext using ECIES-X25519
	// This produces: ephemeral_pubkey(32) + nonce(12) + aead_ciphertext(222+16=238) = 282 bytes
	ciphertext, err := ecies.EncryptECIESX25519(recipientPubKey, cleartext)
	if err != nil {
		return encrypted, oops.Wrapf(err, "ECIES encryption failed")
	}

	// Step 5: Verify ciphertext size
	if len(ciphertext) > 512 {
		return encrypted, oops.Errorf("ciphertext too large: %d bytes (max 512)", len(ciphertext))
	}

	// Step 6: Copy ciphertext to bytes 16-527 (remaining bytes are zero-padded)
	copy(encrypted[16:], ciphertext)

	log.WithField("record_size", 528).
		WithField("cleartext_size", 222).
		WithField("ciphertext_size", len(ciphertext)).
		Debug("BuildRequestRecord encrypted successfully")

	return encrypted, nil
}

// DecryptBuildRequestRecord decrypts an encrypted BuildRequestRecord using ECIES-X25519-AEAD.
//
// This implements the I2P specification for decrypting tunnel build records.
// The recipient router uses its X25519 private key to decrypt the 512-byte ciphertext portion,
// extracting the 222-byte cleartext BuildRequestRecord.
//
// Format:
//   - Bytes 0-15: First 16 bytes of SHA-256 hash of our RouterIdentity (ignored during decryption)
//   - Bytes 16-527: ECIES-X25519 encrypted data (ephemeral_pubkey + nonce + aead_ciphertext)
//
// Parameters:
//   - encrypted: The 528-byte encrypted build request record
//   - privateKey: Our router's X25519 private encryption key (32 bytes)
//
// Returns:
//   - BuildRequestRecord: Decrypted and parsed build request record
//   - error: Any decryption or parsing error encountered
func DecryptBuildRequestRecord(encrypted [528]byte, privateKey []byte) (BuildRequestRecord, error) {
	// Step 1: Validate private key size
	if len(privateKey) != 32 {
		return BuildRequestRecord{}, oops.Errorf("invalid private key size: expected 32 bytes, got %d", len(privateKey))
	}

	// Step 2: Extract ciphertext portion (bytes 16-527)
	// Bytes 0-15 contain the identity hash prefix (not needed for decryption)
	ciphertext := encrypted[16:]

	// Step 3: Decrypt using ECIES-X25519
	// This should produce the original 222-byte cleartext
	cleartext, err := ecies.DecryptECIESX25519(privateKey, ciphertext)
	if err != nil {
		return BuildRequestRecord{}, oops.Wrapf(err, "ECIES decryption failed")
	}

	// Step 4: Verify cleartext size
	if len(cleartext) != 222 {
		return BuildRequestRecord{}, oops.Errorf("invalid decrypted size: expected 222 bytes, got %d", len(cleartext))
	}

	// Step 5: Parse the cleartext into BuildRequestRecord structure
	record, err := ReadBuildRequestRecord(cleartext)
	if err != nil {
		return BuildRequestRecord{}, oops.Wrapf(err, "failed to parse decrypted record")
	}

	log.WithField("record_size", 528).
		WithField("cleartext_size", len(cleartext)).
		Debug("BuildRequestRecord decrypted successfully")

	return record, nil
}

// extractEncryptionPublicKey retrieves the X25519 public encryption key from a RouterInfo.
//
// This extracts the 32-byte X25519 public key used for ECIES encryption from the
// RouterInfo's RouterIdentity KeysAndCert structure.
//
// Parameters:
//   - routerInfo: The RouterInfo containing the encryption public key
//
// Returns:
//   - []byte: 32-byte X25519 public encryption key
//   - error: If the RouterInfo is invalid or key extraction fails
func extractEncryptionPublicKey(routerInfo router_info.RouterInfo) ([]byte, error) {
	// Get the RouterIdentity from RouterInfo
	identity := routerInfo.RouterIdentity()
	if identity == nil {
		return nil, oops.Errorf("RouterInfo has nil RouterIdentity")
	}

	// Get the KeysAndCert which contains the encryption public key
	keysAndCert := identity.KeysAndCert
	if keysAndCert == nil {
		return nil, oops.Errorf("RouterIdentity has nil KeysAndCert")
	}

	// Extract the public encryption key (X25519, 32 bytes for modern I2P routers)
	pubKey, err := keysAndCert.PublicKey()
	if err != nil {
		return nil, oops.Wrapf(err, "failed to get PublicKey from KeysAndCert")
	}
	if pubKey == nil {
		return nil, oops.Errorf("KeysAndCert has nil PublicKey")
	}

	pubKeyBytes := pubKey.Bytes()
	if len(pubKeyBytes) != 32 {
		return nil, oops.Errorf("invalid public key size: expected 32 bytes (X25519), got %d", len(pubKeyBytes))
	}

	return pubKeyBytes, nil
}

// calculateIdentityHash computes the SHA-256 hash of a RouterIdentity.
//
// This is used to create the "toPeer" field in encrypted BuildRequestRecords,
// which helps routers quickly identify if a record is intended for them without
// attempting full decryption.
//
// Parameters:
//   - routerInfo: The RouterInfo whose identity should be hashed
//
// Returns:
//   - [32]byte: SHA-256 hash of the RouterIdentity bytes
func calculateIdentityHash(routerInfo router_info.RouterInfo) [32]byte {
	identity := routerInfo.RouterIdentity()
	// Get bytes from KeysAndCert (which is what RouterIdentity wraps)
	identityBytes, _ := identity.KeysAndCert.Bytes()
	return sha256.Sum256(identityBytes)
}

// VerifyIdentityHash checks if an encrypted BuildRequestRecord is intended for us.
//
// This provides a fast pre-check before attempting decryption by comparing the
// first 16 bytes of the record (identity hash prefix) with our own identity hash.
//
// Parameters:
//   - encrypted: The 528-byte encrypted build request record
//   - ourRouterInfo: Our router's RouterInfo
//
// Returns:
//   - bool: true if the record is likely intended for us, false otherwise
func VerifyIdentityHash(encrypted [528]byte, ourRouterInfo router_info.RouterInfo) bool {
	// Calculate our identity hash
	ourHash := calculateIdentityHash(ourRouterInfo)

	// Compare first 16 bytes
	for i := 0; i < 16; i++ {
		if encrypted[i] != ourHash[i] {
			return false
		}
	}

	return true
}

// ExtractIdentityHashPrefix returns the first 16 bytes of an encrypted record.
//
// This is useful for debugging and logging to identify which router a record
// is intended for without performing full decryption.
//
// Parameters:
//   - encrypted: The 528-byte encrypted build request record
//
// Returns:
//   - common.Hash: The identity hash prefix (first 16 bytes copied to Hash type)
func ExtractIdentityHashPrefix(encrypted [528]byte) common.Hash {
	var hash common.Hash
	copy(hash[:16], encrypted[0:16])
	return hash
}
