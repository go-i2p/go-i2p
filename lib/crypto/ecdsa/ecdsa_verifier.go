package ecdsa

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"

	"github.com/go-i2p/go-i2p/lib/crypto/types"
	"github.com/sirupsen/logrus"
)

type ECDSAVerifier struct {
	k *ecdsa.PublicKey
	c elliptic.Curve
	h crypto.Hash
}

// verify a signature given the hash
func (v *ECDSAVerifier) VerifyHash(h, sig []byte) (err error) {
	log.WithFields(logrus.Fields{
		"hash_length": len(h),
		"sig_length":  len(sig),
	}).Debug("Verifying ECDSA signature hash")

	r, s := elliptic.Unmarshal(v.c, sig)
	if r == nil || s == nil || !ecdsa.Verify(v.k, h, r, s) {
		log.Warn("Invalid ECDSA signature")
		err = types.ErrInvalidSignature
	} else {
		log.Debug("ECDSA signature verified successfully")
	}
	return
}

// verify a block of data by hashing it and comparing the hash against the signature
func (v *ECDSAVerifier) Verify(data, sig []byte) (err error) {
	log.WithFields(logrus.Fields{
		"data_length": len(data),
		"sig_length":  len(sig),
	}).Debug("Verifying ECDSA signature")
	// sum the data and get the hash
	h := v.h.New().Sum(data)[len(data):]
	// verify
	err = v.VerifyHash(h, sig)
	return
}

func CreateECVerifier(c elliptic.Curve, h crypto.Hash, k []byte) (ev *ECDSAVerifier, err error) {
	log.WithFields(logrus.Fields{
		"curve": c.Params().Name,
		"hash":  h.String(),
	}).Debug("Creating ECDSA verifier")
	x, y := elliptic.Unmarshal(c, k[:])
	if x == nil {
		log.Error("Invalid ECDSA key format")
		err = types.ErrInvalidKeyFormat
	} else {
		ev = &ECDSAVerifier{
			c: c,
			h: h,
		}
		ev.k = &ecdsa.PublicKey{c, x, y}
		log.Debug("ECDSA verifier created successfully")
	}
	return
}
