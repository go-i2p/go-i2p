package curve25519

import (
	"crypto/rand"

	"github.com/go-i2p/go-i2p/lib/crypto/types"
	"go.step.sm/crypto/x25519"
	curve25519 "go.step.sm/crypto/x25519"
)

// Curve25519PublicKey represents a Curve25519 public key
type Curve25519PublicKey []byte

func (k Curve25519PublicKey) Bytes() []byte {
	return k
}

// NewVerifier creates a Curve25519 verifier
func (k Curve25519PublicKey) NewVerifier() (types.Verifier, error) {
	log.Debug("Creating Curve25519 verifier")
	if len(k) != x25519.PublicKeySize {
		log.Error("Invalid public key size")
		return nil, ErrInvalidPublicKey
	}
	return &Curve25519Verifier{k: k}, nil
}

// Len returns the length of the public key
func (k Curve25519PublicKey) Len() int {
	length := len(k)
	log.WithField("length", length).Debug("Retrieved Curve25519PublicKey length")
	return length
}

// NewEncrypter creates a new Curve25519 encrypter
func (k Curve25519PublicKey) NewEncrypter() (types.Encrypter, error) {
	log.Debug("Creating new Curve25519 Encrypter")

	if len(k) != x25519.PublicKeySize {
		log.Error("Invalid public key size")
		return nil, ErrInvalidPublicKey
	}

	// Create a proper x25519.PublicKey from the byte slice
	var pubKey x25519.PublicKey
	copy(pubKey[:], k)

	enc, err := NewCurve25519Encryption(&pubKey, rand.Reader)
	if err != nil {
		log.WithError(err).Error("Failed to create Curve25519 Encrypter")
		return nil, err
	}

	log.Debug("Curve25519 Encrypter created successfully")
	return enc, nil
}

func CreateCurve25519PublicKey(data []byte) (k *curve25519.PublicKey) {
	log.WithField("data_length", len(data)).Debug("Creating Curve25519PublicKey")
	if len(data) == curve25519.PublicKeySize { // 32 bytes
		k2 := curve25519.PublicKey{}
		copy(k2[:], data)
		k = &k2
		log.Debug("Curve25519PublicKey created successfully")
	} else {
		log.WithField("expected_length", curve25519.PublicKeySize).
			Warn("Invalid data length for Curve25519PublicKey")
	}
	return
}
