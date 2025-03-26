package ed25519

import (
	"crypto/sha256"
	"math/big"

	"github.com/sirupsen/logrus"
)

type Ed25519Encryption struct {
	p, a, b1 *big.Int
}

func (ed25519 *Ed25519Encryption) Encrypt(data []byte) (enc []byte, err error) {
	log.Warn("createEd25519Encryption is not implemented")
	return ed25519.EncryptPadding(data, true)
}

func (ed25519 *Ed25519Encryption) EncryptPadding(data []byte, zeroPadding bool) (encrypted []byte, err error) {
	log.WithFields(logrus.Fields{
		"data_length":  len(data),
		"zero_padding": zeroPadding,
	}).Debug("Encrypting data with padding using Ed25519")

	if len(data) > 222 {
		log.Error("Data too big for Ed25519 encryption")
		err = Ed25519EncryptTooBig
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
	b := new(big.Int).Mod(new(big.Int).Mul(ed25519.b1, m), ed25519.p).Bytes()

	if zeroPadding {
		encrypted = make([]byte, 514)
		copy(encrypted[1:], ed25519.a.Bytes())
		copy(encrypted[258:], b)
	} else {
		encrypted = make([]byte, 512)
		copy(encrypted, ed25519.a.Bytes())
		copy(encrypted[256:], b)
	}

	log.WithField("encrypted_length", len(encrypted)).Debug("Data encrypted successfully with Ed25519")
	return
}
