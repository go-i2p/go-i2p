package rsa

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha512"
	"math/big"

	"github.com/go-i2p/go-i2p/lib/crypto/types"
	"github.com/samber/oops"
)

type (
	RSA3072PublicKey [384]byte
)

// Verify implements types.Verifier.
func (r RSA3072PublicKey) Verify(data []byte, sig []byte) error {
	// Hash the data with SHA512 (commonly used with RSA3072 in I2P)
	hash := sha512.Sum512(data)
	return r.VerifyHash(hash[:], sig)
}

// VerifyHash implements types.Verifier.
func (r RSA3072PublicKey) VerifyHash(h []byte, sig []byte) error {
	pubKey, err := rsaPublicKeyFromBytes(r[:])
	if err != nil {
		return oops.Errorf("failed to parse RSA3072 public key: %w", err)
	}

	// For RSA3072, SHA512 is often used
	hashed := h
	if len(h) != sha512.Size {
		// If we received a different hash size, warn but continue
		log.Warnf("RSA3072 verification received unexpected hash size: %d", len(h))
	}

	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA512, hashed, sig)
	if err != nil {
		return oops.Errorf("RSA signature verification failed: %w", err)
	}

	return nil
}

// Bytes implements SigningPublicKey.
func (r RSA3072PublicKey) Bytes() []byte {
	return r[:]
}

// Len implements SigningPublicKey.
func (r RSA3072PublicKey) Len() int {
	return len(r)
}

// NewVerifier implements SigningPublicKey.
func (r RSA3072PublicKey) NewVerifier() (types.Verifier, error) {
	// The RSA3072PublicKey itself implements the Verifier interface
	return r, nil
}

// rsaPublicKeyFromBytes converts raw bytes to an rsa.PublicKey
func rsaPublicKeyFromBytes(data []byte) (*rsa.PublicKey, error) {
	// For RSA3072, the public exponent is typically 65537 (0x10001)
	e := int(65537)

	// The modulus is the full key
	n := new(big.Int).SetBytes(data)

	pubKey := &rsa.PublicKey{
		N: n,
		E: e,
	}

	// Validate key size
	bitSize := pubKey.Size() * 8
	if bitSize < 3072 {
		return nil, oops.Errorf("invalid RSA key size: %d (expected 3072)", bitSize)
	}

	return pubKey, nil
}

var _ types.PublicKey = RSA3072PublicKey{}
var _ types.Verifier = RSA3072PublicKey{}
