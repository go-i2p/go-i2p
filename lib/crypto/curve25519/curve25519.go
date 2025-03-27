package curve25519

import (
	"crypto/rand"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"

	"github.com/go-i2p/go-i2p/lib/crypto/types"
	curve25519 "go.step.sm/crypto/x25519"
)

var log = logger.GetGoI2PLogger()

var Curve25519EncryptTooBig = oops.Errorf("failed to encrypt data, too big for Curve25519")

func GenerateX25519KeyPair() (types.PublicEncryptionKey, types.PrivateEncryptionKey, error) {
	pub, priv, err := curve25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, oops.Errorf("failed to generate curve25519 key pair: %w", err)
	}
	return Curve25519PublicKey(pub), Curve25519PrivateKey(priv), nil
}
