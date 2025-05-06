package ecdsa

import (
	"crypto"
	"crypto/elliptic"

	"github.com/go-i2p/go-i2p/lib/crypto/types"
)

type (
	ECP384PublicKey [96]byte
)

// Verify implements types.Verifier.
func (k ECP384PublicKey) Verify(data []byte, sig []byte) error {
	log.WithField("data_length", len(data)).Debug("Verifying data with ECDSA-P384")
	verifier, err := k.NewVerifier()
	if err != nil {
		log.WithError(err).Error("Failed to create verifier")
		return err
	}
	return verifier.Verify(data, sig)
}

// VerifyHash implements types.Verifier.
func (k ECP384PublicKey) VerifyHash(h []byte, sig []byte) error {
	log.WithField("hash_length", len(h)).Debug("Verifying hash with ECDSA-P384")
	verifier, err := k.NewVerifier()
	if err != nil {
		log.WithError(err).Error("Failed to create verifier")
		return err
	}
	return verifier.VerifyHash(h, sig)
}

func (k ECP384PublicKey) Bytes() []byte {
	return k[:]
}

func (k ECP384PublicKey) Len() int {
	return len(k)
}

func (k ECP384PublicKey) NewVerifier() (types.Verifier, error) {
	log.Debug("Creating new P384 ECDSA verifier")
	v, err := CreateECVerifier(elliptic.P384(), crypto.SHA384, k[:])
	if err != nil {
		log.WithError(err).Error("Failed to create P384 ECDSA verifier")
	}
	return v, err
	// return createECVerifier(elliptic.P384(), crypto.SHA384, k[:])
}

var _ types.Verifier = ECP384PublicKey{}
