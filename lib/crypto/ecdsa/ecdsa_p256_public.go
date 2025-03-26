package ecdsa

import (
	"crypto"
	"crypto/elliptic"

	"github.com/go-i2p/go-i2p/lib/crypto/types"
)

type (
	ECP256PublicKey  [64]byte
	ECP256PrivateKey [32]byte
)

func (k ECP256PublicKey) Len() int {
	return len(k)
}

func (k ECP256PublicKey) Bytes() []byte {
	return k[:]
}

func (k ECP256PublicKey) NewVerifier() (types.Verifier, error) {
	log.Debug("Creating new P256 ECDSA verifier")
	// return createECVerifier(elliptic.P256(), crypto.SHA256, k[:])
	v, err := createECVerifier(elliptic.P256(), crypto.SHA256, k[:])
	if err != nil {
		log.WithError(err).Error("Failed to create P256 ECDSA verifier")
	}
	return v, err
}
