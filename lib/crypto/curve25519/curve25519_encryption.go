package curve25519

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"io"

	"github.com/samber/oops"
	curve25519 "go.step.sm/crypto/x25519"
)

type Curve25519Encryption struct {
	publicKey curve25519.PublicKey
	ephemeral curve25519.PrivateKey
}

func (c *Curve25519Encryption) Encrypt(data []byte) ([]byte, error) {
	return c.EncryptPadding(data, true)
}

func (c *Curve25519Encryption) EncryptPadding(data []byte, zeroPadding bool) ([]byte, error) {
	log.WithField("data_length", len(data)).Debug("Encrypting data with Curve25519")

	if len(data) > 222 {
		log.Error("Data too big for Curve25519 encryption")
		return nil, Curve25519EncryptTooBig
	}

	// Perform X25519 key exchange
	sharedSecret, err := c.ephemeral.SharedKey(c.publicKey)
	if err != nil {
		return nil, oops.Errorf("failed to derive shared secret: %w", err)
	}

	// Derive encryption key using SHA-256
	key := sha256.Sum256(sharedSecret)

	// Create AES-GCM cipher
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, oops.Errorf("failed to create AES cipher: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, oops.Errorf("failed to create GCM: %w", err)
	}

	// Create nonce
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, oops.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt data
	ciphertext := aesGCM.Seal(nil, nonce, data, nil)

	// Format output as: [ephemeral public key][nonce][ciphertext]
	ephemeralPub := c.ephemeral.Public().(curve25519.PublicKey)
	result := make([]byte, 0, curve25519.PublicKeySize+len(nonce)+len(ciphertext))
	result = append(result, ephemeralPub...)
	result = append(result, nonce...)
	result = append(result, ciphertext...)

	if zeroPadding {
		// Add a zero byte prefix if requested
		paddedResult := make([]byte, 1+len(result))
		paddedResult[0] = 0x00
		copy(paddedResult[1:], result)
		result = paddedResult
	}

	log.WithField("encrypted_length", len(result)).Debug("Data encrypted successfully")
	return result, nil
}

func createCurve25519Encryption(pub *curve25519.PublicKey, rand io.Reader) (*Curve25519Encryption, error) {
	log.Debug("Creating Curve25519 encryption session")

	if pub == nil || len(*pub) != curve25519.PublicKeySize {
		return nil, oops.Errorf("invalid Curve25519 public key")
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
