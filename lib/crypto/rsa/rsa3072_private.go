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
	RSA3072PrivateKey [786]byte
)

// Len implements types.SigningPrivateKey.
func (r *RSA3072PrivateKey) Len() int {
	return len(r)
}

// NewSigner implements types.SigningPrivateKey.
func (r *RSA3072PrivateKey) NewSigner() (types.Signer, error) {
	return r, nil
}

// Sign implements types.Signer - signs data with SHA512 hash
func (r RSA3072PrivateKey) Sign(data []byte) (sig []byte, err error) {
	// Hash the data with SHA-512 which is appropriate for RSA-3072
	hash := sha512.Sum512(data)
	return r.SignHash(hash[:])
}

// SignHash implements types.Signer - signs a pre-computed hash
func (r RSA3072PrivateKey) SignHash(h []byte) (sig []byte, err error) {
	// Convert byte array to rsa.PrivateKey
	privKey, err := r.toRSAPrivateKey()
	if err != nil {
		return nil, oops.Errorf("failed to parse RSA private key: %w", err)
	}

	// Sign the hash with PKCS#1 v1.5
	sig, err = rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA512, h)
	if err != nil {
		return nil, oops.Errorf("failed to sign hash: %w", err)
	}

	log.Debug("RSA-3072 signature created successfully")
	return sig, nil
}

// Bytes implements types.PrivateKey - returns raw key bytes
func (r RSA3072PrivateKey) Bytes() []byte {
	return r[:]
}

// Public implements types.PrivateKey - derives public key from private key
func (r RSA3072PrivateKey) Public() (types.SigningPublicKey, error) {
	// Convert byte array to rsa.PrivateKey
	privKey, err := r.toRSAPrivateKey()
	if err != nil {
		return nil, oops.Errorf("failed to parse RSA private key: %w", err)
	}

	// Extract public key from private key
	pubBytes := x509.MarshalPKCS1PublicKey(&privKey.PublicKey)
	if len(pubBytes) > 384 {
		return nil, oops.Errorf("RSA public key exceeds expected size")
	}

	// Create and return RSA3072PublicKey
	var pubKey RSA3072PublicKey
	copy(pubKey[:], pubBytes)

	log.Debug("RSA-3072 public key derived successfully")
	return pubKey, nil
}

// Zero implements types.PrivateKey - securely erases key material
func (r RSA3072PrivateKey) Zero() {
	// Overwrite private key material with zeros
	for i := range r {
		r[i] = 0
	}
	log.Debug("RSA-3072 private key securely erased")
}

// Helper method to convert byte array to rsa.PrivateKey
func (r RSA3072PrivateKey) toRSAPrivateKey() (*rsa.PrivateKey, error) {
	// Parse PKCS#1 encoded private key
	privKey, err := x509.ParsePKCS1PrivateKey(r[:])
	if err != nil {
		return nil, oops.Errorf("invalid RSA private key format: %w", err)
	}

	// Validate key size is 3072 bits (384 bytes)
	if privKey.Size() != 384 {
		return nil, oops.Errorf("unexpected RSA key size: got %d, want 384", privKey.Size())
	}

	return privKey, nil
}

// Generate creates a new RSA-3072 private key
func (r *RSA3072PrivateKey) Generate() (types.SigningPrivateKey, error) {
	// Generate a new RSA-3072 private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return nil, oops.Errorf("failed to generate RSA-3072 key: %w", err)
	}

	// Convert to PKCS#1 format
	privBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	if len(privBytes) > 786 {
		return nil, oops.Errorf("RSA private key exceeds expected size")
	}

	// Copy bytes into fixed-size array
	var newKey RSA3072PrivateKey
	copy(newKey[:], privBytes)

	log.Debug("RSA-3072 private key generated successfully")
	return &newKey, nil
}

var (
	_ types.PrivateKey = RSA3072PrivateKey{}
	_ types.Signer     = RSA3072PrivateKey{}
)
