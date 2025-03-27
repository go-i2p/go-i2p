package curve25519

import (
	"crypto/sha512"

	"github.com/go-i2p/go-i2p/lib/crypto/types"
	"github.com/sirupsen/logrus"
	"go.step.sm/crypto/x25519"
)

// Curve25519Verifier handles Curve25519-based verification operations
type Curve25519Verifier struct {
	k []byte
}

// VerifyHash verifies a signature against a pre-computed hash
func (v *Curve25519Verifier) VerifyHash(h, sig []byte) error {
	log.WithFields(logrus.Fields{
		"hash_length":      len(h),
		"signature_length": len(sig),
	}).Debug("Verifying hash with Curve25519")

	if len(sig) != x25519.SignatureSize {
		log.Error("Bad signature size")
		return types.ErrBadSignatureSize
	}

	if len(v.k) != x25519.PublicKeySize {
		log.Error("Invalid Curve25519 public key size")
		return ErrInvalidPublicKey
	}

	if !x25519.Verify(v.k, h, sig) {
		log.Error("Invalid signature")
		return ErrInvalidSignature
	}

	log.Debug("Hash verified successfully")
	return nil
}

// Verify verifies a signature against the provided data
func (v *Curve25519Verifier) Verify(data, sig []byte) error {
	log.WithFields(logrus.Fields{
		"data_length":      len(data),
		"signature_length": len(sig),
	}).Debug("Verifying data with Curve25519")

	h := sha512.Sum512(data)
	return v.VerifyHash(h[:], sig)
}
