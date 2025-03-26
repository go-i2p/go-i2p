package dsa

import (
	"crypto/dsa"
	"io"
	"math/big"

	"github.com/go-i2p/logger"
)

var log = logger.GetGoI2PLogger()

// generate a dsa keypair
func generateDSA(priv *dsa.PrivateKey, rand io.Reader) error {
	log.Debug("Generating DSA key pair")
	// put our paramters in
	priv.P = param.P
	priv.Q = param.Q
	priv.G = param.G
	// generate the keypair
	err := dsa.GenerateKey(priv, rand)
	if err != nil {
		log.WithError(err).Error("Failed to generate DSA key pair")
	} else {
		log.Debug("DSA key pair generated successfully")
	}
	return err
}

// create i2p dsa public key given its public component
func createDSAPublicKey(Y *big.Int) *dsa.PublicKey {
	log.Debug("Creating DSA public key")
	return &dsa.PublicKey{
		Parameters: param,
		Y:          Y,
	}
}

// createa i2p dsa private key given its public component
func createDSAPrivkey(X *big.Int) (k *dsa.PrivateKey) {
	log.Debug("Creating DSA private key")
	if X.Cmp(dsap) == -1 {
		Y := new(big.Int)
		Y.Exp(dsag, X, dsap)
		k = &dsa.PrivateKey{
			PublicKey: dsa.PublicKey{
				Parameters: param,
				Y:          Y,
			},
			X: X,
		}
		log.Debug("DSA private key created successfully")
	} else {
		log.Warn("Failed to create DSA private key: X is not less than p")
	}
	return
}
