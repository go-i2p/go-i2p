package ed25519

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"math/big"

	"github.com/go-i2p/go-i2p/lib/crypto/types"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

var log = logger.GetGoI2PLogger()

var (
	Ed25519EncryptTooBig    = oops.Errorf("failed to encrypt data, too big for Ed25519")
	ErrInvalidPublicKeySize = oops.Errorf("failed to verify: invalid ed25519 public key size")
)

func GenerateEd25519Key() (types.SigningPrivateKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, oops.Errorf("failed to generate ed25519")
	}
	return Ed25519PrivateKey(priv), nil
}

// createEd25519Encryption initializes the Ed25519Encryption struct using the public key.
func createEd25519Encryption(pub *ed25519.PublicKey, randReader io.Reader) (*Ed25519Encryption, error) {
	// Define p = 2^255 - 19
	p := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))

	// Validate public key length
	if len(*pub) != ed25519.PublicKeySize {
		log.WithField("pub_length", len(*pub)).Error("Invalid Ed25519 public key size")
		return nil, ErrInvalidPublicKeySize
	}

	// Convert public key bytes to big.Int
	a := new(big.Int).SetBytes(*pub)

	// Generate a random scalar b1 in [0, p)
	b1, err := rand.Int(randReader, p)
	if err != nil {
		log.WithError(err).Error("Failed to generate b1 for Ed25519Encryption")
		return nil, err
	}

	// Initialize Ed25519Encryption struct
	enc := &Ed25519Encryption{
		p:  p,
		a:  a,
		b1: b1,
	}

	log.Debug("Ed25519Encryption created successfully")
	return enc, nil
}
