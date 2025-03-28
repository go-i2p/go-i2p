package chacha20

import (
	"github.com/samber/oops"
	"golang.org/x/crypto/chacha20poly1305"
)

// ChaCha20PolyEncrypter implements the Encrypter interface using ChaCha20-Poly1305
type ChaCha20PolyEncrypter struct {
	Key ChaCha20Key
}

// Encrypt encrypts data using ChaCha20-Poly1305 with a random nonce
// The format is: [12-byte nonce][ciphertext+tag]
func (e *ChaCha20PolyEncrypter) Encrypt(data []byte) ([]byte, error) {
	return e.EncryptWithAd(data, nil)
}

// EncryptWithAd encrypts data using ChaCha20-Poly1305 with a random nonce
// and additional authenticated data
func (e *ChaCha20PolyEncrypter) EncryptWithAd(data, ad []byte) ([]byte, error) {
	log.WithField("data_length", len(data)).Debug("Encrypting data with ChaCha20-Poly1305")

	// Create AEAD cipher
	aead, err := chacha20poly1305.New(e.Key[:])
	if err != nil {
		return nil, oops.Errorf("failed to create ChaCha20-Poly1305 cipher: %w", err)
	}

	// Generate random nonce
	nonce, err := NewRandomNonce()
	if err != nil {
		return nil, err
	}

	// Encrypt data
	ciphertext := aead.Seal(nil, nonce[:], data, ad)

	// Combine nonce and ciphertext in the result
	result := make([]byte, NonceSize+len(ciphertext))
	copy(result[:NonceSize], nonce[:])
	copy(result[NonceSize:], ciphertext)

	log.WithField("result_length", len(result)).Debug("ChaCha20-Poly1305 encryption successful")
	return result, nil
}
