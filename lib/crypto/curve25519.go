package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"io"
	"math/big"

	"github.com/samber/oops"
	"github.com/sirupsen/logrus"

	curve25519 "go.step.sm/crypto/x25519"
)

var Curve25519EncryptTooBig = oops.Errorf("failed to encrypt data, too big for Curve25519")

type Curve25519PublicKey []byte

type Curve25519Verifier struct {
	k []byte
}

func (k Curve25519PublicKey) NewVerifier() (v Verifier, err error) {
	temp := new(Curve25519Verifier)
	temp.k = k
	v = temp
	return temp, nil
}

func (k Curve25519PublicKey) Len() int {
	length := len(k)
	log.WithField("length", length).Debug("Retrieved Curve25519PublicKey length")
	return length
}

func createCurve25519PublicKey(data []byte) (k *curve25519.PublicKey) {
	log.WithField("data_length", len(data)).Debug("Creating Curve25519PublicKey")
	if len(data) == 256 {
		k2 := curve25519.PublicKey{}
		copy(k2[:], data)
		k = &k2
		log.Debug("Curve25519PublicKey created successfully")
	} else {
		log.Warn("Invalid data length for Curve25519PublicKey")
	}
	return
}

func createCurve25519Encryption(pub *curve25519.PublicKey, rand io.Reader) (enc *Curve25519Encryption, err error) {
	/*kbytes := make([]byte, 256)
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
		enc = &Curve25519Encryption{}
	}*/
	log.Warn("createCurve25519Encryption is not implemented")
	return
}

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

func (elg Curve25519PublicKey) NewEncrypter() (enc Encrypter, err error) {
	log.Debug("Creating new Curve25519 Encrypter")
	k := createCurve25519PublicKey(elg[:])
	enc, err = createCurve25519Encryption(k, rand.Reader)
	if err != nil {
		log.WithError(err).Error("Failed to create Curve25519 Encrypter")
	} else {
		log.Debug("Curve25519 Encrypter created successfully")
	}
	return
}

func (v *Curve25519Verifier) VerifyHash(h, sig []byte) (err error) {
	log.WithFields(logrus.Fields{
		"hash_length":      len(h),
		"signature_length": len(sig),
	}).Debug("Verifying hash with Curve25519")

	if len(sig) != curve25519.SignatureSize {
		log.Error("Bad signature size")
		err = ErrBadSignatureSize
		return
	}
	if len(v.k) != curve25519.PublicKeySize {
		log.Error("Invalid Curve25519 public key size")
		err = oops.Errorf("failed to verify: invalid curve25519 public key size")
		return
	}

	ok := curve25519.Verify(v.k, h, sig)
	if !ok {
		log.Error("Invalid signature")
		err = oops.Errorf("failed to verify: invalid signature")
	} else {
		log.Debug("Hash verified successfully")
	}
	return
}

func (v *Curve25519Verifier) Verify(data, sig []byte) (err error) {
	log.WithFields(logrus.Fields{
		"data_length":      len(data),
		"signature_length": len(sig),
	}).Debug("Verifying data with Curve25519")

	h := sha512.Sum512(data)
	err = v.VerifyHash(h[:], sig)
	return
}

type Curve25519PrivateKey curve25519.PrivateKey

type Curve25519Signer struct {
	k []byte
}

func (s *Curve25519Signer) Sign(data []byte) (sig []byte, err error) {
	log.WithField("data_length", len(data)).Debug("Signing data with Curve25519")

	if len(s.k) != curve25519.PrivateKeySize {
		log.Error("Invalid Curve25519 private key size")
		err = oops.Errorf("failed to sign: invalid curve25519 private key size")
		return
	}
	h := sha512.Sum512(data)
	sig, err = s.SignHash(h[:])
	if err != nil {
		log.WithError(err).Error("Failed to sign data")
	} else {
		log.WithField("signature_length", len(sig)).Debug("Data signed successfully")
	}
	return
}

func (s *Curve25519Signer) SignHash(h []byte) (sig []byte, err error) {
	log.WithField("hash_length", len(h)).Debug("Signing hash with Curve25519")
	sig, err = curve25519.Sign(rand.Reader, s.k, h)
	if err != nil {
		log.WithError(err).Error("Failed to sign hash")
	} else {
		log.WithField("signature_length", len(sig)).Debug("Hash signed successfully")
	}
	// return curve25519.Sign(rand.Reader, s.k, h)
	return
}
