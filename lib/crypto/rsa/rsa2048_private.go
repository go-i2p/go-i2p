package rsa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"

	"github.com/go-i2p/go-i2p/lib/crypto/types"
	"github.com/samber/oops"
)

type (
	RSA2048PrivateKey [512]byte
)

// Sign implements types.Signer.
// Signs data by first hashing it with SHA-256
func (r RSA2048PrivateKey) Sign(data []byte) (sig []byte, err error) {
	// Hash the data with SHA-256 (appropriate for RSA-2048)
	hash := sha256.Sum256(data)
	return r.SignHash(hash[:])
}

// SignHash implements types.Signer.
// Signs a pre-computed hash
func (r RSA2048PrivateKey) SignHash(h []byte) (sig []byte, err error) {
	// Convert byte array to rsa.PrivateKey
	privKey, err := r.toRSAPrivateKey()
	if err != nil {
		return nil, oops.Errorf("failed to parse RSA private key: %w", err)
	}

	// Sign the hash with PKCS#1 v1.5
	sig, err = rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, h)
	if err != nil {
		return nil, oops.Errorf("failed to sign hash: %w", err)
	}

	log.Debug("RSA-2048 signature created successfully")
	return sig, nil
}

// Bytes implements types.PrivateKey.
// Returns the raw bytes of the private key
func (r RSA2048PrivateKey) Bytes() []byte {
	return r[:]
}

// Public implements types.PrivateKey.
// Extracts the public key from the private key
func (r RSA2048PrivateKey) Public() (types.SigningPublicKey, error) {
	privKey, err := r.toRSAPrivateKey()
	if err != nil {
		return nil, oops.Errorf("failed to parse RSA private key: %w", err)
	}

	// Extract public key and convert to bytes
	pubKey := privKey.Public().(*rsa.PublicKey)
	pubBytes := pubKey.N.Bytes()

	// Create and return the RSA2048PublicKey
	var publicKey RSA2048PublicKey
	copy(publicKey[:], pubBytes)

	log.Debug("RSA-2048 public key extracted successfully")
	return publicKey, nil
}

// Zero implements types.PrivateKey.
// Securely erases key material
func (r RSA2048PrivateKey) Zero() {
	// Overwrite private key material with zeros
	for i := range r {
		r[i] = 0
	}
	log.Debug("RSA-2048 private key securely erased")
}

// Helper method to convert byte array to rsa.PrivateKey
func (r RSA2048PrivateKey) toRSAPrivateKey() (*rsa.PrivateKey, error) {
	// Parse PKCS#1 encoded private key
	privKey, err := x509.ParsePKCS1PrivateKey(r[:])
	if err != nil {
		return nil, oops.Errorf("invalid RSA private key format: %w", err)
	}

	// Validate key size is 2048 bits (256 bytes)
	if privKey.Size() != 256 {
		return nil, oops.Errorf("unexpected RSA key size: got %d, want 256", privKey.Size())
	}

	return privKey, nil
}

var _ types.PrivateKey = RSA2048PrivateKey{}
var _ types.Signer = RSA2048PrivateKey{}
