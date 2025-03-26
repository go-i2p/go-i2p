package curve25519

import (
	"crypto/rand"

	"github.com/go-i2p/go-i2p/lib/crypto/types"
	curve25519 "go.step.sm/crypto/x25519"
)

type Curve25519PublicKey []byte

func (k Curve25519PublicKey) NewVerifier() (v types.Verifier, err error) {
	temp := new(Curve25519Verifier)
	temp.k = k
	v = temp
	return temp, nil
}

func (k Curve25519PublicKey) Len() int {
	length := len(k)
	log.WithField("length", length).Debug("Retrieved Curve25519PublicKey length")
	return length
}

func (elg Curve25519PublicKey) NewEncrypter() (enc types.Encrypter, err error) {
	log.Debug("Creating new Curve25519 Encrypter")
	k := createCurve25519PublicKey(elg[:])
	enc, err = createCurve25519Encryption(k, rand.Reader)
	if err != nil {
		log.WithError(err).Error("Failed to create Curve25519 Encrypter")
	} else {
		log.Debug("Curve25519 Encrypter created successfully")
	}
	return
}

func createCurve25519PublicKey(data []byte) (k *curve25519.PublicKey) {
	log.WithField("data_length", len(data)).Debug("Creating Curve25519PublicKey")
	if len(data) == 256 {
		k2 := curve25519.PublicKey{}
		copy(k2[:], data)
		k = &k2
		log.Debug("Curve25519PublicKey created successfully")
	} else {
		log.Warn("Invalid data length for Curve25519PublicKey")
	}
	return
}
