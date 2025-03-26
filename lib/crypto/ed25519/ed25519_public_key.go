package ed25519

import (
	"crypto/ed25519"
	"crypto/rand"

	"github.com/go-i2p/go-i2p/lib/crypto/types"
	"github.com/samber/oops"
)

type Ed25519PublicKey []byte

func (k Ed25519PublicKey) NewVerifier() (v types.Verifier, err error) {
	temp := new(Ed25519Verifier)
	temp.k = k
	v = temp
	return temp, nil
}

func (k Ed25519PublicKey) Len() int {
	return len(k)
}

func (k Ed25519PublicKey) Bytes() []byte {
	return k
}

func (elg Ed25519PublicKey) NewEncrypter() (enc types.Encrypter, err error) {
	log.Debug("Creating new Ed25519 encrypter")
	k := createEd25519PublicKey(elg[:])
	if k == nil {
		return nil, oops.Errorf("invalid public key format")
	}

	enc, err = createEd25519Encryption(k, rand.Reader)
	if err != nil {
		log.WithError(err).Error("Failed to create Ed25519 encrypter")
		return nil, err
	}

	log.Debug("Ed25519 encrypter created successfully")
	return enc, nil
}

func createEd25519PublicKey(data []byte) (k *ed25519.PublicKey) {
	log.WithField("data_length", len(data)).Debug("Creating Ed25519 public key")
	if len(data) == 256 {
		k2 := ed25519.PublicKey{}
		copy(k2[:], data)
		k = &k2
		log.Debug("Ed25519 public key created successfully")
	} else {
		log.Warn("Invalid data length for Ed25519 public key")
	}
	return
}

func CreateEd25519PublicKeyFromBytes(data []byte) (Ed25519PublicKey, error) {
	log.WithField("data_length", len(data)).Debug("Creating Ed25519 public key")

	if len(data) != ed25519.PublicKeySize {
		log.WithField("data_length", len(data)).Error("Invalid Ed25519 public key size")
		return nil, ErrInvalidPublicKeySize
	}

	// Return the Ed25519 public key
	log.Debug("Ed25519 public key created successfully")
	return Ed25519PublicKey(data), nil
}
