package dsa

import (
	"math/big"

	"github.com/go-i2p/go-i2p/lib/crypto/types"
)

type DSAPrivateKey [20]byte

// create a new dsa signer
func (k DSAPrivateKey) NewSigner() (s types.Signer, err error) {
	log.Debug("Creating new DSA signer")
	s = &DSASigner{
		k: createDSAPrivkey(new(big.Int).SetBytes(k[:])),
	}
	return
}

func (k DSAPrivateKey) Public() (pk DSAPublicKey, err error) {
	p := createDSAPrivkey(new(big.Int).SetBytes(k[:]))
	if p == nil {
		log.Error("Invalid DSA private key format")
		err = types.ErrInvalidKeyFormat
	} else {
		copy(pk[:], p.Y.Bytes())
		log.Debug("DSA public key derived successfully")
	}
	return
}

func (k DSAPrivateKey) Len() int {
	return len(k)
}
