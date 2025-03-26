package elgamal

import (
	"crypto/rand"
	"math/big"

	"github.com/go-i2p/go-i2p/lib/crypto/types"
	"golang.org/x/crypto/openpgp/elgamal"
)

type (
	ElgPublicKey [256]byte
)

func (elg ElgPublicKey) Len() int {
	return len(elg)
}

func (elg ElgPublicKey) Bytes() []byte {
	return elg[:]
}

func (elg ElgPublicKey) NewEncrypter() (enc types.Encrypter, err error) {
	log.Debug("Creating new ElGamal encrypter")
	k := createElgamalPublicKey(elg[:])
	enc, err = createElgamalEncryption(k, rand.Reader)
	if err != nil {
		log.WithError(err).Error("Failed to create ElGamal encrypter")
	} else {
		log.Debug("ElGamal encrypter created successfully")
	}
	return
}

// create an elgamal public key from byte slice
func createElgamalPublicKey(data []byte) (k *elgamal.PublicKey) {
	log.WithField("data_length", len(data)).Debug("Creating ElGamal public key")
	if len(data) == 256 {
		k = &elgamal.PublicKey{
			G: elgg,
			P: elgp,
			Y: new(big.Int).SetBytes(data),
		}
		log.Debug("ElGamal public key created successfully")
	} else {
		log.Warn("Invalid data length for ElGamal public key")
	}

	return
}
