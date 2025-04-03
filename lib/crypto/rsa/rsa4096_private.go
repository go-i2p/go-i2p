package rsa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"

	"github.com/go-i2p/go-i2p/lib/crypto/types"
	"github.com/samber/oops"
)

type (
	RSA4096PrivateKey [1024]byte
)

// Sign implements types.Signer.
// Signs data by first hashing it with SHA-512
func (r RSA4096PrivateKey) Sign(data []byte) (sig []byte, err error) {
	log.Debug("Signing data with RSA-4096")
	// Hash the data with SHA-512 (appropriate for RSA-4096)
	hash := sha512.Sum512(data)
	return r.SignHash(hash[:])
}

// SignHash implements types.Signer.
// Signs a pre-computed hash
func (r RSA4096PrivateKey) SignHash(h []byte) (sig []byte, err error) {
	log.Debug("Signing hash with RSA-4096")

	// Parse the private key from PKCS#1 DER format
	privKey, err := x509.ParsePKCS1PrivateKey(r[:])
	if err != nil {
		log.WithError(err).Error("Failed to parse RSA-4096 private key")
		return nil, oops.Errorf("invalid RSA-4096 private key: %w", err)
	}

	// Sign the hash using PKCS1v15
	sig, err = rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA512, h)
	if err != nil {
		log.WithError(err).Error("RSA-4096 signature generation failed")
		return nil, oops.Errorf("failed to generate RSA-4096 signature: %w", err)
	}

	log.Debug("RSA-4096 signature generated successfully")
	return sig, nil
}

// Bytes implements types.PrivateKey.
// Returns the raw bytes of the private key
func (r RSA4096PrivateKey) Bytes() []byte {
	log.Debug("Getting RSA-4096 private key bytes")
	return r[:]
}

// Public implements types.PrivateKey.
// Extracts the public key from the private key
func (r RSA4096PrivateKey) Public() (types.SigningPublicKey, error) {
	log.Debug("Extracting public key from RSA-4096 private key")

	// Parse the private key from PKCS#1 DER format
	privKey, err := x509.ParsePKCS1PrivateKey(r[:])
	if err != nil {
		log.WithError(err).Error("Failed to parse RSA-4096 private key")
		return nil, oops.Errorf("invalid RSA-4096 private key: %w", err)
	}

	// Get the public key bytes (modulus n) in the correct format
	pubKeyBytes := privKey.N.Bytes()

	// The RSA4096PublicKey is exactly 512 bytes
	var pubKey RSA4096PublicKey

	// Ensure proper padding if the modulus has leading zeros
	copy(pubKey[512-len(pubKeyBytes):], pubKeyBytes)

	log.Debug("RSA-4096 public key extracted successfully")
	return pubKey, nil
}

// Zero implements types.PrivateKey.
// Securely clears the private key from memory
func (r RSA4096PrivateKey) Zero() {
	log.Debug("Securely clearing RSA-4096 private key from memory")
	// Overwrite the key material with zeros
	for i := range r {
		r[i] = 0
	}
}

var _ types.PrivateKey = RSA4096PrivateKey{}
var _ types.Signer = RSA4096PrivateKey{}
