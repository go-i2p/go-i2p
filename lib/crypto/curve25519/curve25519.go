package curve25519

import (
	"crypto/rand"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"

	"github.com/go-i2p/go-i2p/lib/crypto/types"
	"go.step.sm/crypto/x25519"
)

var log = logger.GetGoI2PLogger()

var (
	ErrDataTooBig        = oops.Errorf("data too big for Curve25519 encryption")
	ErrInvalidPublicKey  = oops.Errorf("invalid public key for Curve25519")
	ErrInvalidPrivateKey = oops.Errorf("invalid private key for Curve25519")
	ErrInvalidSignature  = oops.Errorf("invalid signature for Curve25519")
	ErrDecryptionFailed  = oops.Errorf("failed to decrypt data with Curve25519")
)

// GenerateKeyPair generates a new Curve25519 key pair
func GenerateKeyPair() (types.PublicEncryptionKey, types.PrivateEncryptionKey, error) {
	log.Debug("Generating new Curve25519 key pair")
	pub, priv, err := x25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, oops.Errorf("failed to generate Curve25519 key pair: %w", err)
	}
	return Curve25519PublicKey(pub[:]), Curve25519PrivateKey(priv), nil
}
