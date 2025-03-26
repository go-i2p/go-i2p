package curve25519

import (
	"crypto/sha256"
	"io"
	"math/big"

	"github.com/samber/oops"
	"github.com/sirupsen/logrus"
	curve25519 "go.step.sm/crypto/x25519"
)

type Curve25519Encryption struct {
	p, a, b1 *big.Int
}

func (curve25519 *Curve25519Encryption) Encrypt(data []byte) (enc []byte, err error) {
	log.WithField("data_length", len(data)).Debug("Encrypting data with Curve25519")
	return curve25519.EncryptPadding(data, true)
}

func (curve25519 *Curve25519Encryption) EncryptPadding(data []byte, zeroPadding bool) (encrypted []byte, err error) {
	log.WithFields(logrus.Fields{
		"data_length":  len(data),
		"zero_padding": zeroPadding,
	}).Debug("Encrypting data with padding using Curve25519")
	if len(data) > 222 {
		log.Error("Data too big for Curve25519 encryption")
		err = Curve25519EncryptTooBig
		return
	}
	mbytes := make([]byte, 255)
	mbytes[0] = 0xFF
	copy(mbytes[33:], data)
	// do sha256 of payload
	d := sha256.Sum256(mbytes[33 : len(data)+33])
	copy(mbytes[1:], d[:])
	m := new(big.Int).SetBytes(mbytes)
	// do encryption
	b := new(big.Int).Mod(new(big.Int).Mul(curve25519.b1, m), curve25519.p).Bytes()

	if zeroPadding {
		encrypted = make([]byte, 514)
		copy(encrypted[1:], curve25519.a.Bytes())
		copy(encrypted[258:], b)
	} else {
		encrypted = make([]byte, 512)
		copy(encrypted, curve25519.a.Bytes())
		copy(encrypted[256:], b)
	}
	log.WithField("encrypted_length", len(encrypted)).Debug("Data encrypted successfully")
	return
}

func createCurve25519Encryption(pub *curve25519.PublicKey, rand io.Reader) (enc *Curve25519Encryption, err error) {
	log.Debug("Creating Curve25519 encryption session")

	// Define p = 2^255 - 19 (the prime used in Curve25519)
	p := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))

	// Validate public key
	if pub == nil || len(*pub) != curve25519.PublicKeySize {
		return nil, oops.Errorf("invalid Curve25519 public key")
	}

	// Convert public key bytes to big.Int
	a := new(big.Int).SetBytes(*pub)

	// Generate random scalar for encryption
	kbytes := make([]byte, 32)
	if _, err = io.ReadFull(rand, kbytes); err != nil {
		log.WithError(err).Error("Failed to generate random scalar for Curve25519")
		return nil, err
	}

	k := new(big.Int).SetBytes(kbytes)
	k = k.Mod(k, p)

	// Ensure k is not zero
	if k.Sign() == 0 {
		return nil, oops.Errorf("generated zero scalar")
	}

	// Calculate b1 = k * pubKey mod p
	b1 := new(big.Int).Exp(a, k, p)

	enc = &Curve25519Encryption{
		p:  p,
		a:  new(big.Int).Exp(new(big.Int).SetInt64(9), k, p), // Base point for Curve25519
		b1: b1,
	}

	log.Debug("Curve25519 encryption session created successfully")
	return enc, nil
}
