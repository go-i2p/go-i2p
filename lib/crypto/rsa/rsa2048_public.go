package rsa

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"math/big"

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
	pubKey, err := rsaPublicKeyFromBytes2048(r[:])
	if err != nil {
		return oops.Errorf("failed to parse RSA2048 public key: %w", err)
	}

	// For RSA2048, we use SHA-256
	hashed := h
	if len(h) != sha256.Size {
		// If we received a different hash size, warn but continue
		log.Warnf("RSA2048 verification received unexpected hash size: %d", len(h))
	}

	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hashed, sig)
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

// rsaPublicKeyFromBytes2048 converts raw bytes to an rsa.PublicKey
func rsaPublicKeyFromBytes2048(data []byte) (*rsa.PublicKey, error) {
	if len(data) != 256 {
		return nil, oops.Errorf("invalid RSA2048 public key length: %d", len(data))
	}

	// The format is expected to be a big-endian modulus
	modulus := new(big.Int).SetBytes(data)

	return &rsa.PublicKey{
		N: modulus,
		E: 65537, // Standard RSA public exponent
	}, nil
}

var _ types.PublicKey = RSA2048PublicKey{}
var _ types.Verifier = RSA2048PublicKey{}
