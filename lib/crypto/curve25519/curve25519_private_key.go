package curve25519

import (
	"github.com/go-i2p/go-i2p/lib/crypto/types"
	"go.step.sm/crypto/x25519"
)

// Curve25519PrivateKey represents a Curve25519 private key
type Curve25519PrivateKey []byte

// NewDecrypter creates a new Curve25519 decrypter
func (k Curve25519PrivateKey) NewDecrypter() (types.Decrypter, error) {
	log.Debug("Creating new Curve25519 Decrypter")
	if len(k) != x25519.PrivateKeySize {
		log.Error("Invalid Curve25519 private key size")
		return nil, ErrInvalidPrivateKey
	}

	// Create a proper x25519.PrivateKey from the byte slice
	privKey := make(x25519.PrivateKey, x25519.PrivateKeySize)
	copy(privKey, k)

	return &Curve25519Decrypter{
		privateKey: privKey,
	}, nil
}

// NewSigner creates a new Curve25519 signer
func (k Curve25519PrivateKey) NewSigner() (types.Signer, error) {
	log.Debug("Creating new Curve25519 Signer")
	if len(k) != x25519.PrivateKeySize {
		log.Error("Invalid Curve25519 private key size")
		return nil, ErrInvalidPrivateKey
	}
	return &Curve25519Signer{k: k}, nil
}
