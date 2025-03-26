package curve25519

import (
	"github.com/go-i2p/go-i2p/lib/crypto/types"
	"github.com/samber/oops"
	curve25519 "go.step.sm/crypto/x25519"
)

type Curve25519PrivateKey curve25519.PrivateKey

// NewDecrypter implements PrivateEncryptionKey.
func (c Curve25519PrivateKey) NewDecrypter() (types.Decrypter, error) {
	log.Debug("Creating new Curve25519 Decrypter")
	if len(c) != curve25519.PrivateKeySize {
		log.Error("Invalid Curve25519 private key size")
		return nil, oops.Errorf("invalid curve25519 private key size")
	}
	return &Curve25519Decrypter{
		privateKey: c,
	}, nil
}
