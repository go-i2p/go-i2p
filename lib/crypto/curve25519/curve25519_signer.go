package curve25519

import (
	"crypto/rand"
	"crypto/sha512"

	"github.com/samber/oops"

	curve25519 "go.step.sm/crypto/x25519"
)

type Curve25519Signer struct {
	k []byte
}

func (s *Curve25519Signer) Sign(data []byte) (sig []byte, err error) {
	log.WithField("data_length", len(data)).Debug("Signing data with Curve25519")

	if len(s.k) != curve25519.PrivateKeySize {
		log.Error("Invalid Curve25519 private key size")
		err = oops.Errorf("failed to sign: invalid curve25519 private key size")
		return
	}
	h := sha512.Sum512(data)
	sig, err = s.SignHash(h[:])
	if err != nil {
		log.WithError(err).Error("Failed to sign data")
	} else {
		log.WithField("signature_length", len(sig)).Debug("Data signed successfully")
	}
	return
}

func (s *Curve25519Signer) SignHash(h []byte) (sig []byte, err error) {
	log.WithField("hash_length", len(h)).Debug("Signing hash with Curve25519")
	sig, err = curve25519.Sign(rand.Reader, s.k, h)
	if err != nil {
		log.WithError(err).Error("Failed to sign hash")
	} else {
		log.WithField("signature_length", len(sig)).Debug("Hash signed successfully")
	}
	// return curve25519.Sign(rand.Reader, s.k, h)
	return
}
