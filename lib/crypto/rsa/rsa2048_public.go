package rsa

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"

	"github.com/go-i2p/go-i2p/lib/crypto/types"
	"github.com/samber/oops"
)

type (
	RSA2048PublicKey [256]byte
)

// Verify implements types.Verifier.
// This method hashes the data with SHA-256 and verifies the signature
func (r RSA2048PublicKey) Verify(data []byte, sig []byte) error {
	// Hash the data with SHA-256 (appropriate for RSA-2048)
	hash := sha256.Sum256(data)
	return r.VerifyHash(hash[:], sig)
}

// VerifyHash implements types.Verifier.
// This method verifies a pre-computed hash against the signature
func (r RSA2048PublicKey) VerifyHash(h []byte, sig []byte) error {
	pubKey, err := rsaPublicKeyFromBytes(r[:], 2048)
	if err != nil {
		return oops.Errorf("failed to parse RSA2048 public key: %w", err)
	}

	// For RSA2048, we use SHA-256
	if len(h) != sha256.Size {
		return oops.Errorf("RSA2048 verification requires SHA-256 hash (expected %d bytes, got %d)",
			sha256.Size, len(h))
	}

	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, h, sig)
	if err != nil {
		return oops.Errorf("RSA signature verification failed: %w", err)
	}

	return nil
}

// Bytes implements SigningPublicKey.
// Returns the raw bytes of the public key
func (r RSA2048PublicKey) Bytes() []byte {
	return r[:]
}

// Len implements SigningPublicKey.
// Returns the length of the public key in bytes
func (r RSA2048PublicKey) Len() int {
	return len(r)
}

// NewVerifier implements SigningPublicKey.
// Creates a new verifier object that can be used to verify signatures
func (r RSA2048PublicKey) NewVerifier() (types.Verifier, error) {
	log.Debug("Creating new RSA-2048 verifier")
	return r, nil
}

var (
	_ types.PublicKey = RSA2048PublicKey{}
	_ types.Verifier  = RSA2048PublicKey{}
)
