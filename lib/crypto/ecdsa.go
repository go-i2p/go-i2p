package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"

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
		err = ErrInvalidSignature
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

func createECVerifier(c elliptic.Curve, h crypto.Hash, k []byte) (ev *ECDSAVerifier, err error) {
	log.WithFields(logrus.Fields{
		"curve": c.Params().Name,
		"hash":  h.String(),
	}).Debug("Creating ECDSA verifier")
	x, y := elliptic.Unmarshal(c, k[:])
	if x == nil {
		log.Error("Invalid ECDSA key format")
		err = ErrInvalidKeyFormat
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

type (
	ECP256PublicKey  [64]byte
	ECP256PrivateKey [32]byte
)

func (k ECP256PublicKey) Len() int {
	return len(k)
}

func (k ECP256PublicKey) Bytes() []byte {
	return k[:]
}

func (k ECP256PublicKey) NewVerifier() (Verifier, error) {
	log.Debug("Creating new P256 ECDSA verifier")
	// return createECVerifier(elliptic.P256(), crypto.SHA256, k[:])
	v, err := createECVerifier(elliptic.P256(), crypto.SHA256, k[:])
	if err != nil {
		log.WithError(err).Error("Failed to create P256 ECDSA verifier")
	}
	return v, err
}

type (
	ECP384PublicKey  [96]byte
	ECP384PrivateKey [48]byte
)

func (k ECP384PublicKey) Bytes() []byte {
	return k[:]
}

func (k ECP384PublicKey) Len() int {
	return len(k)
}

func (k ECP384PublicKey) NewVerifier() (Verifier, error) {
	log.Debug("Creating new P384 ECDSA verifier")
	v, err := createECVerifier(elliptic.P384(), crypto.SHA384, k[:])
	if err != nil {
		log.WithError(err).Error("Failed to create P384 ECDSA verifier")
	}
	return v, err
	// return createECVerifier(elliptic.P384(), crypto.SHA384, k[:])
}

type (
	ECP521PublicKey  [132]byte
	ECP521PrivateKey [66]byte
)

func (k ECP521PublicKey) Bytes() []byte {
	return k[:]
}

func (k ECP521PublicKey) Len() int {
	return len(k)
}

func (k ECP521PublicKey) NewVerifier() (Verifier, error) {
	log.Debug("Creating new P521 ECDSA verifier")
	v, err := createECVerifier(elliptic.P521(), crypto.SHA512, k[:])
	if err != nil {
		log.WithError(err).Error("Failed to create P521 ECDSA verifier")
	}
	return v, err
	// return createECVerifier(elliptic.P521(), crypto.SHA512, k[:])
}
