package elgamal

import (
	"math/big"

	"github.com/go-i2p/go-i2p/lib/crypto/types"
	"golang.org/x/crypto/openpgp/elgamal"
)

type (
	ElgPrivateKey [256]byte
)

func (elg ElgPrivateKey) Len() int {
	return len(elg)
}

func (elg ElgPrivateKey) NewDecrypter() (dec types.Decrypter, err error) {
	log.Debug("Creating new ElGamal decrypter")
	dec = &elgDecrypter{
		k: createElgamalPrivateKey(elg[:]),
	}
	log.Debug("ElGamal decrypter created successfully")
	return
}

// create an elgamal private key from byte slice
func createElgamalPrivateKey(data []byte) (k *elgamal.PrivateKey) {
	log.WithField("data_length", len(data)).Debug("Creating ElGamal private key")
	if len(data) == 256 {
		x := new(big.Int).SetBytes(data)
		y := new(big.Int).Exp(elgg, x, elgp)
		k = &elgamal.PrivateKey{
			PublicKey: elgamal.PublicKey{
				Y: y,
				G: elgg,
				P: elgp,
			},
			X: x,
		}
		log.Debug("ElGamal private key created successfully")
	} else {
		log.Warn("Invalid data length for ElGamal private key")
	}
	return
}
