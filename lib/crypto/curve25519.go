package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"math/big"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/curve25519"
)

var Curve25519EncryptTooBig = errors.New("failed to encrypt data, too big for Curve25519")

const (
	Curve25519PublicKeySize = 32
)

type Curve25519PublicKey []byte

// createCurve25519PublicKey ensures the public key is 32 bytes.
func createCurve25519PublicKey(data []byte) (k *[Curve25519PublicKeySize]byte) {
	log.WithField("data_length", len(data)).Debug("Creating Curve25519PublicKey")
	if len(data) == Curve25519PublicKeySize {
		var k2 [Curve25519PublicKeySize]byte
		copy(k2[:], data)
		k = &k2
		log.Debug("Curve25519PublicKey created successfully")
	} else {
		log.Warn("Invalid data length for Curve25519PublicKey")
	}
	return
}

// generateEphemeralKey generates a new ephemeral private/public key pair for X25519.
func generateEphemeralKey(randReader io.Reader) (ephemeralPriv, ephemeralPub []byte, err error) {
	ephemeralPriv = make([]byte, 32)
	_, err = io.ReadFull(randReader, ephemeralPriv)
	if err != nil {
		return nil, nil, err
	}

	// Clamp the private key per X25519 spec
	ephemeralPriv[0] &= 248
	ephemeralPriv[31] &= 127
	ephemeralPriv[31] |= 64

	basepoint := [32]byte{9}
	ephemeralPub, err = curve25519.X25519(ephemeralPriv, basepoint[:])
	if err != nil {
		return nil, nil, err
	}

	return ephemeralPriv, ephemeralPub, nil
}

// createCurve25519Encryption performs a Diffie-Hellman exchange with an ephemeral key and the provided remote public key.
// It returns a structure that can perform the "encryption" as per the given scheme.
func createCurve25519Encryption(remotePubBytes []byte) (*Curve25519Encryption, error) {
	if len(remotePubBytes) != Curve25519PublicKeySize {
		return nil, errors.New("invalid Curve25519 public key length")
	}

	ephemeralPriv, ephemeralPub, err := generateEphemeralKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	// Compute shared secret: X25519(ephemeralPriv, remotePub)
	sharedSecret, err := curve25519.X25519(ephemeralPriv, remotePubBytes)
	if err != nil {
		return nil, err
	}

	// p = 2^255 - 19
	p := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))

	a := new(big.Int).SetBytes(ephemeralPub)
	b1 := new(big.Int).SetBytes(sharedSecret[:])

	return &Curve25519Encryption{
		p:  p,
		a:  a,
		b1: b1,
	}, nil
}

type Curve25519Encryption struct {
	p, a, b1 *big.Int
}

func (curve *Curve25519Encryption) Encrypt(data []byte) ([]byte, error) {
	log.WithField("data_length", len(data)).Debug("Encrypting data with Curve25519")
	return curve.EncryptPadding(data, true)
}

func (curve *Curve25519Encryption) EncryptPadding(data []byte, zeroPadding bool) (encrypted []byte, err error) {
	log.WithFields(logrus.Fields{
		"data_length":  len(data),
		"zero_padding": zeroPadding,
	}).Debug("Encrypting data with padding using Curve25519")

	if len(data) > 222 {
		log.Error("Data too big for Curve25519 encryption")
		return nil, Curve25519EncryptTooBig
	}

	mbytes := make([]byte, 255)
	mbytes[0] = 0xFF
	copy(mbytes[33:], data)

	// do sha256 of payload
	d := sha256.Sum256(mbytes[33 : len(data)+33])
	copy(mbytes[1:], d[:])
	m := new(big.Int).SetBytes(mbytes)

	// "encryption"
	b := new(big.Int).Mod(new(big.Int).Mul(curve.b1, m), curve.p).Bytes()

	if zeroPadding {
		encrypted = make([]byte, 514)
		copy(encrypted[1:], curve.a.Bytes())
		copy(encrypted[258:], b)
	} else {
		encrypted = make([]byte, 512)
		copy(encrypted, curve.a.Bytes())
		copy(encrypted[256:], b)
	}
	log.WithField("encrypted_length", len(encrypted)).Debug("Data encrypted successfully")
	return encrypted, nil
}

func (k Curve25519PublicKey) Len() int {
	return len(k)
}

func (k Curve25519PublicKey) Bytes() []byte {
	return k
}

// NewEncrypter creates a new Curve25519-based encrypter using the provided public key.
func (k Curve25519PublicKey) NewEncrypter() (Encrypter, error) {
	log.Debug("Creating new Curve25519 Encrypter")
	enc, err := createCurve25519Encryption(k)
	if err != nil {
		log.WithError(err).Error("Failed to create Curve25519 Encrypter")
		return nil, err
	}
	log.Debug("Curve25519 Encrypter created successfully")
	return enc, nil
}
