package rsa

import (
	"crypto/rsa"
	"fmt"
	"math/big"

	"github.com/go-i2p/logger"
)

var log = logger.GetGoI2PLogger()

// rsaPublicKeyFromBytes converts raw bytes to an rsa.PublicKey
func rsaPublicKeyFromBytes(data []byte, expectedSize int) (*rsa.PublicKey, error) {
	if len(data) != expectedSize {
		return nil, fmt.Errorf("invalid RSA public key length: expected %d, got %d",
			expectedSize, len(data))
	}
	e := int(65537)

	// The modulus is the full key
	n := new(big.Int).SetBytes(data)

	pubKey := &rsa.PublicKey{
		N: n,
		E: e,
	}

	return pubKey, nil
}
