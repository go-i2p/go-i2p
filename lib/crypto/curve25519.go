package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"io"
	"math/big"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/curve25519"
)

var (
	Curve25519EncryptTooBig = errors.New("failed to encrypt data, too big for Curve25519")
)

const (
	Curve25519PublicKeySize = 32

	// Ed25519 size constants
	PublicKeySize  = ed25519.PublicKeySize  // 32 bytes
	PrivateKeySize = ed25519.PrivateKeySize // 64 bytes
	SignatureSize  = ed25519.SignatureSize  // 64 bytes
)

type Curve25519PublicKey []byte

// createCurve25519PublicKey ensures the public key is 32 bytes.
func createCurve25519PublicKey(data []byte) *[Curve25519PublicKeySize]byte {
	log.WithField("data_length", len(data)).Debug("Creating Curve25519PublicKey")
	if len(data) == Curve25519PublicKeySize {
		var k2 [Curve25519PublicKeySize]byte
		copy(k2[:], data)
		log.Debug("Curve25519PublicKey created successfully")
		return &k2
	}
	log.Warn("Invalid data length for Curve25519PublicKey")
	return nil
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

// Curve25519PrivateKey is a 32-byte seed we will interpret as an Ed25519 seed to create a signer.
type Curve25519PrivateKey [32]byte

// Curve25519Signer holds an Ed25519 private key for signing.
type Curve25519Signer struct {
	k ed25519.PrivateKey
}

// Curve25519Verifier holds an Ed25519 public key for verification.
type Curve25519Verifier struct {
	k ed25519.PublicKey
}

// NewSigner creates a new Curve25519Signer from a 32-byte private key seed by generating an Ed25519 key pair.
func (priv Curve25519PrivateKey) NewSigner() (*Curve25519Signer, error) {
	if len(priv) != 32 {
		log.Error("Invalid Curve25519 private key size for signing")
		return nil, ErrInvalidKeyFormat
	}
	edPrivKey := ed25519.NewKeyFromSeed(priv[:])
	return &Curve25519Signer{k: edPrivKey}, nil
}

// Public returns the corresponding public key for the given private key.
func (priv Curve25519PrivateKey) Public() (Curve25519PublicKey, error) {
	if len(priv) != 32 {
		log.Error("Invalid Curve25519 private key size for public key derivation")
		return nil, ErrInvalidKeyFormat
	}
	edPrivKey := ed25519.NewKeyFromSeed(priv[:])
	pubKey := edPrivKey.Public().(ed25519.PublicKey)
	return Curve25519PublicKey(pubKey), nil
}

// Sign signs the given data by hashing it (sha512) then calling SignHash.
func (s *Curve25519Signer) Sign(data []byte) (sig []byte, err error) {
	log.WithField("data_length", len(data)).Debug("Signing data")
	h := sha512.Sum512(data)
	return s.SignHash(h[:])
}

// SignHash signs the given hash directly using Ed25519.
func (s *Curve25519Signer) SignHash(h []byte) (sig []byte, err error) {
	log.WithField("hash_length", len(h)).Debug("Signing hash")
	if len(s.k) != PrivateKeySize {
		log.Error("Invalid private key size for signing hash")
		return nil, errors.New("invalid private key size")
	}
	sig = ed25519.Sign(s.k, h)
	log.WithField("signature_length", len(sig)).Debug("Hash signed successfully")
	return sig, nil
}

// NewVerifier creates a verifier from a Curve25519PublicKey interpreted as Ed25519 public key.
func (k Curve25519PublicKey) NewVerifier() (*Curve25519Verifier, error) {
	if len(k) != PublicKeySize {
		log.Error("Invalid public key size for verifier")
		return nil, ErrInvalidKeyFormat
	}
	return &Curve25519Verifier{k: ed25519.PublicKey(k)}, nil
}

// Verify verifies the given data by hashing it and calling VerifyHash.
func (v *Curve25519Verifier) Verify(data, sig []byte) error {
	log.WithFields(logrus.Fields{
		"data_length":      len(data),
		"signature_length": len(sig),
	}).Debug("Verifying data")
	h := sha512.Sum512(data)
	return v.VerifyHash(h[:], sig)
}

// VerifyHash verifies a hash directly using the Ed25519 public key.
func (v *Curve25519Verifier) VerifyHash(h, sig []byte) error {
	log.WithFields(logrus.Fields{
		"hash_length":      len(h),
		"signature_length": len(sig),
	}).Debug("Verifying hash")

	if len(sig) != SignatureSize {
		log.Error("Bad signature size")
		return ErrBadSignatureSize
	}

	if len(v.k) != PublicKeySize {
		log.Error("Invalid public key size")
		return ErrInvalidKeyFormat
	}

	if !ed25519.Verify(v.k, h, sig) {
		log.Error("Invalid signature")
		return ErrInvalidSignature
	}
	log.Debug("Hash verified successfully")
	return nil
}
