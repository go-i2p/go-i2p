package chacha20

import (
	"github.com/samber/oops"
	"golang.org/x/crypto/chacha20poly1305"
)

// ChaCha20PolyDecrypter implements the Decrypter interface using ChaCha20-Poly1305
type ChaCha20PolyDecrypter struct {
	Key ChaCha20Key
}

// Decrypt decrypts data encrypted with ChaCha20-Poly1305
// The format should be: [12-byte nonce][ciphertext+tag]
func (d *ChaCha20PolyDecrypter) Decrypt(data []byte) ([]byte, error) {
	return d.DecryptWithAd(data, nil)
}

// DecryptWithAd decrypts data encrypted with ChaCha20-Poly1305 using additional data
func (d *ChaCha20PolyDecrypter) DecryptWithAd(data, ad []byte) ([]byte, error) {
	log.WithField("data_length", len(data)).Debug("Decrypting data with ChaCha20-Poly1305")

	// Validate data length
	if len(data) < NonceSize+TagSize {
		return nil, oops.Errorf("encrypted data too short: %d bytes", len(data))
	}

	// Create AEAD cipher
	aead, err := chacha20poly1305.New(d.Key[:])
	if err != nil {
		return nil, oops.Errorf("failed to create ChaCha20-Poly1305 cipher: %w", err)
	}

	// Extract nonce and ciphertext
	nonce := data[:NonceSize]
	ciphertext := data[NonceSize:]

	// Decrypt data
	plaintext, err := aead.Open(nil, nonce, ciphertext, ad)
	if err != nil {
		log.WithError(err).Error("ChaCha20-Poly1305 decryption failed")
		return nil, ErrAuthFailed
	}

	log.WithField("plaintext_length", len(plaintext)).Debug("ChaCha20-Poly1305 decryption successful")
	return plaintext, nil
}
