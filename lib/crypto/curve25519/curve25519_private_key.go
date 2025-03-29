package curve25519

import (
	"github.com/go-i2p/go-i2p/lib/crypto/types"
	"go.step.sm/crypto/x25519"
	curve25519 "go.step.sm/crypto/x25519"
)

// Curve25519PrivateKey represents a Curve25519 private key
type Curve25519PrivateKey []byte

// Bytes implements types.PrivateKey.
func (k *Curve25519PrivateKey) Bytes() []byte {
	return []byte(*k) // Return the byte slice representation of the private key
}

// Public implements types.PrivateKey.
func (k *Curve25519PrivateKey) Public() (types.SigningPublicKey, error) {
	// Create a proper x25519.PrivateKey from the byte slice
	if len(*k) != x25519.PrivateKeySize {
		// Handle invalid private key length
		return nil, ErrInvalidPrivateKey
	}
	// Create a proper x25519.PrivateKey from the byte slice
	privKey := make(x25519.PrivateKey, x25519.PrivateKeySize)
	copy(privKey, *k)
	// Derive the public key from the private key
	pubKey := privKey.Public() // This will return the corresponding public key
	x25519PubKey := pubKey.(curve25519.PublicKey)
	curve25519PubKey := Curve25519PublicKey(x25519PubKey)
	return &curve25519PubKey, nil
}

// Zero implements types.PrivateKey.
func (k *Curve25519PrivateKey) Zero() {
	// replace the slice with zeroes
	for _, i := range k {

	}
}

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

var _ types.PrivateKey = &Curve25519PrivateKey{}
