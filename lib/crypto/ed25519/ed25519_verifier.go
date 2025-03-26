package ed25519

import (
	"crypto/ed25519"
	"crypto/sha512"

	"github.com/go-i2p/go-i2p/lib/crypto/types"
	"github.com/samber/oops"
	"github.com/sirupsen/logrus"
)

type Ed25519Verifier struct {
	k []byte
}

func (v *Ed25519Verifier) VerifyHash(h, sig []byte) (err error) {
	log.WithFields(logrus.Fields{
		"hash_length": len(h),
		"sig_length":  len(sig),
	}).Debug("Verifying Ed25519 signature hash")

	if len(sig) != ed25519.SignatureSize {
		log.Error("Bad Ed25519 signature size")
		err = types.ErrBadSignatureSize
		return
	}
	if len(v.k) != ed25519.PublicKeySize {
		log.Error("Invalid Ed25519 public key size")
		err = oops.Errorf("failed to verify: invalid ed25519 public key size")
		return
	}

	ok := ed25519.Verify(v.k, h, sig)
	if !ok {
		log.Warn("Invalid Ed25519 signature")
		err = oops.Errorf("failed to verify: invalid signature")
	} else {
		log.Debug("Ed25519 signature verified successfully")
	}
	return
}

func (v *Ed25519Verifier) Verify(data, sig []byte) (err error) {
	log.WithFields(logrus.Fields{
		"data_length": len(data),
		"sig_length":  len(sig),
	}).Debug("Verifying Ed25519 signature")

	h := sha512.Sum512(data)
	err = v.VerifyHash(h[:], sig)
	return
}
