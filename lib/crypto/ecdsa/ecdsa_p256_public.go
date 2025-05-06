package ecdsa

import (
	"crypto"
	"crypto/elliptic"

	"github.com/go-i2p/go-i2p/lib/crypto/types"
	"github.com/samber/oops"
)

type (
	ECP256PublicKey [64]byte
)

// Verify implements types.Verifier.
func (k ECP256PublicKey) Verify(data []byte, sig []byte) error {
	log.WithField("data_length", len(data)).Debug("Verifying data with ECDSA-P256")
	verifier, err := k.NewVerifier()
	if err != nil {
		log.WithError(err).Error("Failed to create verifier")
		return err
	}
	return verifier.Verify(data, sig)
}

// VerifyHash implements types.Verifier.
func (k ECP256PublicKey) VerifyHash(h []byte, sig []byte) error {
	log.WithField("hash_length", len(h)).Debug("Verifying hash with ECDSA-P256")
	verifier, err := k.NewVerifier()
	if err != nil {
		log.WithError(err).Error("Failed to create verifier")
		return err
	}
	return verifier.VerifyHash(h, sig)
}

// Encrypt implements types.Encrypter.
func (k *ECP256PublicKey) Encrypt(data []byte) (enc []byte, err error) {
	log.Error("Encryption not supported with ECDSA keys")
	return nil, oops.Errorf("encryption not supported with ECDSA keys; ECDSA is for signing/verification only")
}

func (k ECP256PublicKey) Len() int {
	return len(k)
}

func (k ECP256PublicKey) Bytes() []byte {
	return k[:]
}

func (k ECP256PublicKey) NewVerifier() (types.Verifier, error) {
	log.Debug("Creating new P256 ECDSA verifier")
	// return createECVerifier(elliptic.P256(), crypto.SHA256, k[:])
	v, err := CreateECVerifier(elliptic.P256(), crypto.SHA256, k[:])
	if err != nil {
		log.WithError(err).Error("Failed to create P256 ECDSA verifier")
	}
	return v, err
}

var _ types.Verifier = ECP256PublicKey{}
