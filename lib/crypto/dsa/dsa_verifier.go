package dsa

import (
	"crypto/dsa"
	"crypto/sha1"
	"math/big"

	"github.com/go-i2p/go-i2p/lib/crypto/types"
	"github.com/sirupsen/logrus"
)

type DSAVerifier struct {
	k *dsa.PublicKey
}

// verify data with a dsa public key
func (v *DSAVerifier) Verify(data, sig []byte) (err error) {
	log.WithFields(logrus.Fields{
		"data_length": len(data),
		"sig_length":  len(sig),
	}).Debug("Verifying DSA signature")
	h := sha1.Sum(data)
	err = v.VerifyHash(h[:], sig)
	return
}

// verify hash of data with a dsa public key
func (v *DSAVerifier) VerifyHash(h, sig []byte) (err error) {
	log.WithFields(logrus.Fields{
		"hash_length": len(h),
		"sig_length":  len(sig),
	}).Debug("Verifying DSA signature hash")
	if len(sig) == 40 {
		r := new(big.Int).SetBytes(sig[:20])
		s := new(big.Int).SetBytes(sig[20:])
		if dsa.Verify(v.k, h, r, s) {
			// valid signature
			log.Debug("DSA signature verified successfully")
		} else {
			// invalid signature
			log.Warn("Invalid DSA signature")
			err = types.ErrInvalidSignature
		}
	} else {
		log.Error("Bad DSA signature size")
		err = types.ErrBadSignatureSize
	}
	return
}
