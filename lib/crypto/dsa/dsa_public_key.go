package dsa

import (
	"crypto/dsa"
	"crypto/rand"
	"math/big"

	"github.com/go-i2p/go-i2p/lib/crypto/types"
)

type DSAPublicKey [128]byte

func (k DSAPublicKey) Bytes() []byte {
	return k[:]
}

// create a new dsa verifier
func (k DSAPublicKey) NewVerifier() (v types.Verifier, err error) {
	log.Debug("Creating new DSA verifier")
	v = &DSAVerifier{
		k: createDSAPublicKey(new(big.Int).SetBytes(k[:])),
	}
	return
}

func (k DSAPrivateKey) Generate() (s DSAPrivateKey, err error) {
	log.Debug("Generating new DSA private key")
	dk := new(dsa.PrivateKey)
	err = generateDSA(dk, rand.Reader)
	if err == nil {
		copy(k[:], dk.X.Bytes())
		s = k
		log.Debug("New DSA private key generated successfully")
	} else {
		log.WithError(err).Error("Failed to generate new DSA private key")
	}
	return
}

func (k DSAPublicKey) Len() int {
	return len(k)
}
