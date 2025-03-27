package curve25519

import (
	"crypto/rand"
	"crypto/sha512"

	"github.com/samber/oops"
	"go.step.sm/crypto/x25519"
)

// Curve25519Signer handles Curve25519-based signing operations
type Curve25519Signer struct {
	k []byte
}

// Sign signs data using Curve25519
func (s *Curve25519Signer) Sign(data []byte) ([]byte, error) {
	log.WithField("data_length", len(data)).Debug("Signing data with Curve25519")

	if len(s.k) != x25519.PrivateKeySize {
		log.Error("Invalid Curve25519 private key size")
		return nil, ErrInvalidPrivateKey
	}

	// Hash the data using SHA-512
	h := sha512.Sum512(data)
	return s.SignHash(h[:])
}

// SignHash signs a pre-computed hash using Curve25519
func (s *Curve25519Signer) SignHash(h []byte) ([]byte, error) {
	log.WithField("hash_length", len(h)).Debug("Signing hash with Curve25519")

	sig, err := x25519.Sign(rand.Reader, s.k, h)
	if err != nil {
		log.WithError(err).Error("Failed to sign hash")
		return nil, oops.Errorf("failed to sign: %w", err)
	}

	log.WithField("signature_length", len(sig)).Debug("Hash signed successfully")
	return sig, nil
}
