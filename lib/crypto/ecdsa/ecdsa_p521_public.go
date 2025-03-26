package ecdsa

import (
	"crypto"
	"crypto/elliptic"

	"github.com/go-i2p/go-i2p/lib/crypto/types"
)

type (
	ECP521PublicKey [132]byte
)

func (k ECP521PublicKey) Bytes() []byte {
	return k[:]
}

func (k ECP521PublicKey) Len() int {
	return len(k)
}

func (k ECP521PublicKey) NewVerifier() (types.Verifier, error) {
	log.Debug("Creating new P521 ECDSA verifier")
	v, err := createECVerifier(elliptic.P521(), crypto.SHA512, k[:])
	if err != nil {
		log.WithError(err).Error("Failed to create P521 ECDSA verifier")
	}
	return v, err
	// return createECVerifier(elliptic.P521(), crypto.SHA512, k[:])
}
