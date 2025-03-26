package curve25519

import (
	"crypto/sha512"

	"github.com/go-i2p/go-i2p/lib/crypto/types"
	"github.com/samber/oops"
	"github.com/sirupsen/logrus"

	curve25519 "go.step.sm/crypto/x25519"
)

type Curve25519Verifier struct {
	k []byte
}

func (v *Curve25519Verifier) VerifyHash(h, sig []byte) (err error) {
	log.WithFields(logrus.Fields{
		"hash_length":      len(h),
		"signature_length": len(sig),
	}).Debug("Verifying hash with Curve25519")

	if len(sig) != curve25519.SignatureSize {
		log.Error("Bad signature size")
		err = types.ErrBadSignatureSize
		return
	}
	if len(v.k) != curve25519.PublicKeySize {
		log.Error("Invalid Curve25519 public key size")
		err = oops.Errorf("failed to verify: invalid curve25519 public key size")
		return
	}

	ok := curve25519.Verify(v.k, h, sig)
	if !ok {
		log.Error("Invalid signature")
		err = oops.Errorf("failed to verify: invalid signature")
	} else {
		log.Debug("Hash verified successfully")
	}
	return
}

func (v *Curve25519Verifier) Verify(data, sig []byte) (err error) {
	log.WithFields(logrus.Fields{
		"data_length":      len(data),
		"signature_length": len(sig),
	}).Debug("Verifying data with Curve25519")

	h := sha512.Sum512(data)
	err = v.VerifyHash(h[:], sig)
	return
}
