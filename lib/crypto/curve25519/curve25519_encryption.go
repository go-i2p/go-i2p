package curve25519

import (
	"crypto/rand"
	"crypto/sha256"
	"io"

	"github.com/samber/oops"
	curve25519 "go.step.sm/crypto/x25519"
	"golang.org/x/crypto/chacha20poly1305"
)

type Curve25519Encryption struct {
	publicKey curve25519.PublicKey
	ephemeral curve25519.PrivateKey
}

// Encrypt encrypts data with zero padding
// uses ChaCha20-Poly1305 AEAD cipher
func (c *Curve25519Encryption) Encrypt(data []byte) ([]byte, error) {
	return c.EncryptPadding(data, true)
}

// EncryptPadding encrypts data with optional zero padding and returns the encrypted data
// uses ChaCha20-Poly1305 AEAD cipher
func (c *Curve25519Encryption) EncryptPadding(data []byte, zeroPadding bool) ([]byte, error) {
	// Maximum data size is 222 bytes for Curve25519 encryption
	if len(data) > 222 {
		return nil, ErrDataTooBig
	}

	// Derive shared secret using X25519 key exchange
	sharedSecret, err := c.ephemeral.SharedKey(c.publicKey)
	if err != nil {
		return nil, oops.Errorf("failed to derive shared secret: %w", err)
	}

	// Derive encryption key using SHA-256
	key := sha256.Sum256(sharedSecret)

	// Create ChaCha20-Poly1305 cipher
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, oops.Errorf("failed to create ChaCha20-Poly1305 cipher: %w", err)
	}

	// Create nonce
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, oops.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt data
	ciphertext := aead.Seal(nil, nonce, data, nil)

	// Calculate final size and prepare buffer
	ephemeralPub := c.ephemeral.Public().(curve25519.PublicKey)
	totalSize := curve25519.PublicKeySize + len(nonce) + len(ciphertext)
	if zeroPadding {
		totalSize++ // Add 1 byte for zero padding
	}

	// Build result directly with correct size
	result := make([]byte, totalSize)
	offset := 0

	if zeroPadding {
		// Add a zero byte prefix if requested
		result[0] = 0x00
		offset = 1
	}

	// Format output as: [ephemeral public key][nonce][ciphertext]
	copy(result[offset:], ephemeralPub)
	offset += curve25519.PublicKeySize
	copy(result[offset:], nonce)
	offset += len(nonce)
	copy(result[offset:], ciphertext)

	return result, nil
}

// NewCurve25519Encryption creates a new Curve25519 encryption instance
func NewCurve25519Encryption(pub *curve25519.PublicKey, rand io.Reader) (*Curve25519Encryption, error) {
	if pub == nil || len(*pub) != curve25519.PublicKeySize {
		return nil, ErrInvalidPublicKey
	}

	// Generate ephemeral key pair
	_, ephemeralPriv, err := curve25519.GenerateKey(rand)
	if err != nil {
		return nil, oops.Errorf("failed to generate ephemeral key: %w", err)
	}

	return &Curve25519Encryption{
		publicKey: *pub,
		ephemeral: ephemeralPriv,
	}, nil
}
