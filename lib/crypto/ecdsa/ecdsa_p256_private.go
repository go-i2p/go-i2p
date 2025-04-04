package ecdsa

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"math/big"

	"github.com/go-i2p/go-i2p/lib/crypto/types"
	"github.com/samber/oops"
)

type (
	ECP256PrivateKey [32]byte
)

// Len implements types.SigningPrivateKey.
func (e *ECP256PrivateKey) Len() int {
	panic("unimplemented")
}

// Sign implements types.Signer.
func (e *ECP256PrivateKey) Sign(data []byte) (sig []byte, err error) {
	// Hash the data first using SHA-256
	hash := sha256.Sum256(data)
	return e.SignHash(hash[:])
}

// SignHash implements types.Signer.
func (e *ECP256PrivateKey) SignHash(h []byte) (sig []byte, err error) {
	// Convert byte array to ECDSA private key
	curve := elliptic.P256()
	privateKey := new(ecdsa.PrivateKey)
	privateKey.PublicKey.Curve = curve
	privateKey.D = new(big.Int).SetBytes(e[:])

	// Calculate public key coordinates
	privateKey.PublicKey.X, privateKey.PublicKey.Y = curve.ScalarBaseMult(e[:])

	// Sign the hash
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, h)
	if err != nil {
		return nil, oops.Errorf("failed to sign hash: %w", err)
	}

	// Format the signature as R || S
	sigR := r.Bytes()
	sigS := s.Bytes()

	// Ensure each component is padded to 32 bytes
	sig = make([]byte, 64)
	copy(sig[32-len(sigR):32], sigR)
	copy(sig[64-len(sigS):], sigS)

	log.Debug("Generated ECDSA-P256 signature")
	return sig, nil
}

// Decrypt implements types.Decrypter.
func (e *ECP256PrivateKey) Decrypt(data []byte) ([]byte, error) {
	// ECDSA doesn't typically provide decryption functionality
	// This would require ECDH key derivation + symmetric decryption
	// Implementing this for simplicity/compatibility
	return nil, oops.Errorf("decryption not supported with ECDSA keys")
}

// Bytes implements types.PrivateKey.
func (e *ECP256PrivateKey) Bytes() []byte {
	return e[:]
}

// Public implements types.PrivateKey.
func (e *ECP256PrivateKey) Public() (types.SigningPublicKey, error) {
	curve := elliptic.P256()

	// Calculate public key
	x, y := curve.ScalarBaseMult(e[:])
	if x == nil || y == nil {
		return nil, oops.Errorf("failed to generate public key from private key")
	}

	// Encode public key as compressed point
	publicKey := ECP256PublicKey{}

	// Format as uncompressed point (0x04 || x || y)
	xBytes := x.Bytes()
	yBytes := y.Bytes()

	// Copy coordinates to the public key
	// P-256 coordinates are 32 bytes each
	copy(publicKey[0:32], xBytes)
	copy(publicKey[32:64], yBytes)

	log.Debug("Generated ECDSA-P256 public key from private key")
	return publicKey, nil
}

// Zero implements types.PrivateKey.
func (e *ECP256PrivateKey) Zero() {
	// Securely erase the private key material
	for i := range e {
		e[i] = 0
	}
	log.Debug("Zeroed ECDSA-P256 private key")
}

// Generate implements SigningPrivateKey.Generate
func (e *ECP256PrivateKey) Generate() (types.SigningPrivateKey, error) {
	// Generate a new private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, oops.Errorf("failed to generate ECDSA-P256 key: %w", err)
	}

	// Convert to our format
	result := &ECP256PrivateKey{}

	// Copy private key bytes with proper padding
	dBytes := privateKey.D.Bytes()
	copy(result[32-len(dBytes):], dBytes)

	log.Debug("Generated new ECDSA-P256 private key")
	return result, nil
}

// NewSigner implements SigningPrivateKey.NewSigner
func (e *ECP256PrivateKey) NewSigner() (types.Signer, error) {
	// This key already implements the Signer interface
	return e, nil
}
