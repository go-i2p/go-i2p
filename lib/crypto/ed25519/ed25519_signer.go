package ed25519

import (
	"crypto/ed25519"
	"crypto/sha512"

	"github.com/samber/oops"
)

type Ed25519Signer struct {
	k []byte
}

func (s *Ed25519Signer) Sign(data []byte) (sig []byte, err error) {
	log.WithField("data_length", len(data)).Debug("Signing data with Ed25519")

	if len(s.k) != ed25519.PrivateKeySize {
		log.Error("Invalid Ed25519 private key size")
		err = oops.Errorf("failed to sign: invalid ed25519 private key size")
		return
	}
	h := sha512.Sum512(data)
	sig, err = s.SignHash(h[:])
	return
}

func (s *Ed25519Signer) SignHash(h []byte) (sig []byte, err error) {
	log.WithField("hash_length", len(h)).Debug("Signing hash with Ed25519")
	sig = ed25519.Sign(s.k, h)
	log.WithField("signature_length", len(sig)).Debug("Ed25519 signature created successfully")
	return
}
