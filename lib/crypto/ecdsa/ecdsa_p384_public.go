package ecdsa

import (
	"crypto"
	"crypto/elliptic"

	"github.com/go-i2p/go-i2p/lib/crypto/types"
)

type (
	ECP384PublicKey  [96]byte
	ECP384PrivateKey [48]byte
)

func (k ECP384PublicKey) Bytes() []byte {
	return k[:]
}

func (k ECP384PublicKey) Len() int {
	return len(k)
}

func (k ECP384PublicKey) NewVerifier() (types.Verifier, error) {
	log.Debug("Creating new P384 ECDSA verifier")
	v, err := createECVerifier(elliptic.P384(), crypto.SHA384, k[:])
	if err != nil {
		log.WithError(err).Error("Failed to create P384 ECDSA verifier")
	}
	return v, err
	// return createECVerifier(elliptic.P384(), crypto.SHA384, k[:])
}
