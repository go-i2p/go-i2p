package curve25519

import (
	"crypto/sha256"

	"github.com/samber/oops"
	"go.step.sm/crypto/x25519"
	"golang.org/x/crypto/chacha20poly1305"
)

// Curve25519Decrypter handles Curve25519-based decryption
type Curve25519Decrypter struct {
	privateKey x25519.PrivateKey
}

// Decrypt decrypts data encrypted with Curve25519 and ChaCha20-Poly1305
func (c *Curve25519Decrypter) Decrypt(data []byte) ([]byte, error) {
	log.WithField("data_length", len(data)).Debug("Decrypting data with Curve25519")

	// Validate data length - must be at least public key + minimum nonce + tag size
	minSize := x25519.PublicKeySize + 12 + 16 // 12 is ChaCha20-Poly1305 nonce size, 16 is tag size
	if len(data) < minSize {
		return nil, oops.Errorf("data too short for Curve25519 decryption: %d bytes", len(data))
	}

	// Extract the ephemeral public key
	ephemeralPub := data[:x25519.PublicKeySize]

	// Create a proper public key
	var pubKey x25519.PublicKey
	copy(pubKey[:], ephemeralPub)

	// Derive shared secret using X25519 key exchange
	sharedSecret, err := c.privateKey.SharedKey(pubKey[:])
	if err != nil {
		return nil, oops.Errorf("Curve25519 key exchange failed: %w", err)
	}

	// Derive decryption key using SHA-256
	key := sha256.Sum256(sharedSecret)

	// Create ChaCha20-Poly1305 cipher
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, oops.Errorf("failed to create ChaCha20-Poly1305 cipher: %w", err)
	}

	nonceSize := aead.NonceSize()
	if len(data) < x25519.PublicKeySize+nonceSize {
		return nil, oops.Errorf("data too short to extract nonce")
	}

	// Extract nonce and ciphertext
	nonce := data[x25519.PublicKeySize : x25519.PublicKeySize+nonceSize]
	ciphertext := data[x25519.PublicKeySize+nonceSize:]

	// Decrypt the data
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, oops.Errorf("failed to decrypt data: %w", err)
	}

	log.Debug("Data decrypted successfully")
	return plaintext, nil
}
