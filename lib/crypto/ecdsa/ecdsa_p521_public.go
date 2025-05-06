package ecdsa

import (
	"crypto"
	"crypto/elliptic"

	"github.com/go-i2p/go-i2p/lib/crypto/types"
)

type (
	ECP521PublicKey [132]byte
)

// Verify implements types.Verifier.
func (k ECP521PublicKey) Verify(data []byte, sig []byte) error {
	log.WithField("data_length", len(data)).Debug("Verifying data with ECDSA-P521")
	verifier, err := k.NewVerifier()
	if err != nil {
		log.WithError(err).Error("Failed to create verifier")
		return err
	}
	return verifier.Verify(data, sig)
}

// VerifyHash implements types.Verifier.
func (k ECP521PublicKey) VerifyHash(h []byte, sig []byte) error {
	log.WithField("hash_length", len(h)).Debug("Verifying hash with ECDSA-P521")
	verifier, err := k.NewVerifier()
	if err != nil {
		log.WithError(err).Error("Failed to create verifier")
		return err
	}
	return verifier.VerifyHash(h, sig)
}

func (k ECP521PublicKey) Bytes() []byte {
	return k[:]
}

func (k ECP521PublicKey) Len() int {
	return len(k)
}

func (k ECP521PublicKey) NewVerifier() (types.Verifier, error) {
	log.Debug("Creating new P521 ECDSA verifier")
	v, err := CreateECVerifier(elliptic.P521(), crypto.SHA512, k[:])
	if err != nil {
		log.WithError(err).Error("Failed to create P521 ECDSA verifier")
	}
	return v, err
	// return createECVerifier(elliptic.P521(), crypto.SHA512, k[:])
}
