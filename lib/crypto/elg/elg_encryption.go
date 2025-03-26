package elgamal

import (
	"crypto/sha256"
	"io"
	"math/big"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/openpgp/elgamal"
)

type ElgamalEncryption struct {
	p, a, b1 *big.Int
}

func (elg *ElgamalEncryption) Encrypt(data []byte) (enc []byte, err error) {
	log.WithField("data_length", len(data)).Debug("Encrypting data with ElGamal")
	return elg.EncryptPadding(data, true)
}

func (elg *ElgamalEncryption) EncryptPadding(data []byte, zeroPadding bool) (encrypted []byte, err error) {
	log.WithFields(logrus.Fields{
		"data_length":  len(data),
		"zero_padding": zeroPadding,
	}).Debug("Encrypting data with ElGamal padding")

	if len(data) > 222 {
		err = ElgEncryptTooBig
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
	b := new(big.Int).Mod(new(big.Int).Mul(elg.b1, m), elg.p).Bytes()

	if zeroPadding {
		encrypted = make([]byte, 514)
		copy(encrypted[1:], elg.a.Bytes())
		copy(encrypted[258:], b)
	} else {
		encrypted = make([]byte, 512)
		copy(encrypted, elg.a.Bytes())
		copy(encrypted[256:], b)
	}

	log.WithField("encrypted_length", len(encrypted)).Debug("Data encrypted successfully with ElGamal")
	return
}

// create a new elgamal encryption session
func createElgamalEncryption(pub *elgamal.PublicKey, rand io.Reader) (enc *ElgamalEncryption, err error) {
	log.Debug("Creating ElGamal encryption session")
	kbytes := make([]byte, 256)
	k := new(big.Int)
	for err == nil {
		_, err = io.ReadFull(rand, kbytes)
		k = new(big.Int).SetBytes(kbytes)
		k = k.Mod(k, pub.P)
		if k.Sign() != 0 {
			break
		}
	}
	if err == nil {
		enc = &ElgamalEncryption{
			p:  pub.P,
			a:  new(big.Int).Exp(pub.G, k, pub.P),
			b1: new(big.Int).Exp(pub.Y, k, pub.P),
		}
		log.Debug("ElGamal encryption session created successfully")
	} else {
		log.WithError(err).Error("Failed to create ElGamal encryption session")
	}
	return
}
