package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/sirupsen/logrus"
)

var (
	Ed25519EncryptTooBig    = errors.New("failed to encrypt data, too big for Ed25519")
	ErrInvalidPublicKeySize = errors.New("failed to verify: invalid ed25519 public key size")
)

type Ed25519PublicKey []byte

type Ed25519Verifier struct {
	k []byte
}

func (k Ed25519PublicKey) NewVerifier() (v Verifier, err error) {
	temp := new(Ed25519Verifier)
	temp.k = k
	v = temp
	return temp, nil
}

func (k Ed25519PublicKey) Len() int {
	return len(k)
}

func (k Ed25519PublicKey) Bytes() []byte {
	return k
}

func createEd25519PublicKey(data []byte) (k *ed25519.PublicKey) {
	log.WithField("data_length", len(data)).Debug("Creating Ed25519 public key")
	if len(data) == 256 {
		k2 := ed25519.PublicKey{}
		copy(k2[:], data)
		k = &k2
		log.Debug("Ed25519 public key created successfully")
	} else {
		log.Warn("Invalid data length for Ed25519 public key")
	}
	return
}

// createEd25519Encryption initializes the Ed25519Encryption struct using the public key.
func createEd25519Encryption(pub *ed25519.PublicKey, randReader io.Reader) (*Ed25519Encryption, error) {
	// Define p = 2^255 - 19
	p := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))

	// Validate public key length
	if len(*pub) != ed25519.PublicKeySize {
		log.WithField("pub_length", len(*pub)).Error("Invalid Ed25519 public key size")
		return nil, ErrInvalidPublicKeySize
	}

	// Convert public key bytes to big.Int
	a := new(big.Int).SetBytes(*pub)

	// Generate a random scalar b1 in [0, p)
	b1, err := rand.Int(randReader, p)
	if err != nil {
		log.WithError(err).Error("Failed to generate b1 for Ed25519Encryption")
		return nil, err
	}

	// Initialize Ed25519Encryption struct
	enc := &Ed25519Encryption{
		p:  p,
		a:  a,
		b1: b1,
	}

	log.Debug("Ed25519Encryption created successfully")
	return enc, nil
}

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

func (elg Ed25519PublicKey) NewEncrypter() (enc Encrypter, err error) {
	log.Debug("Creating new Ed25519 encrypter")
	k := createEd25519PublicKey(elg[:])
	if k == nil {
		return nil, errors.New("invalid public key format")
	}

	enc, err = createEd25519Encryption(k, rand.Reader)
	if err != nil {
		log.WithError(err).Error("Failed to create Ed25519 encrypter")
		return nil, err
	}

	log.Debug("Ed25519 encrypter created successfully")
	return enc, nil
}

func (v *Ed25519Verifier) VerifyHash(h, sig []byte) (err error) {
	log.WithFields(logrus.Fields{
		"hash_length": len(h),
		"sig_length":  len(sig),
	}).Debug("Verifying Ed25519 signature hash")

	if len(sig) != ed25519.SignatureSize {
		log.Error("Bad Ed25519 signature size")
		err = ErrBadSignatureSize
		return
	}
	if len(v.k) != ed25519.PublicKeySize {
		log.Error("Invalid Ed25519 public key size")
		err = errors.New("failed to verify: invalid ed25519 public key size")
		return
	}

	ok := ed25519.Verify(v.k, h, sig)
	if !ok {
		log.Warn("Invalid Ed25519 signature")
		err = errors.New("failed to verify: invalid signature")
	} else {
		log.Debug("Ed25519 signature verified successfully")
	}
	return
}

func (v *Ed25519Verifier) Verify(data, sig []byte) (err error) {
	log.WithFields(logrus.Fields{
		"data_length": len(data),
		"sig_length":  len(sig),
	}).Debug("Verifying Ed25519 signature")

	h := sha512.Sum512(data)
	err = v.VerifyHash(h[:], sig)
	return
}

type Ed25519PrivateKey ed25519.PrivateKey

func (k Ed25519PrivateKey) NewDecrypter() (Decrypter, error) {
	// TODO implement me
	panic("implement me")
}

func (k Ed25519PrivateKey) NewSigner() (Signer, error) {
	if len(k) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid ed25519 private key size")
	}
	return &Ed25519Signer{k: k}, nil
}

func (k Ed25519PrivateKey) Len() int {
	return len(k)
}

func (k *Ed25519PrivateKey) Generate() (SigningPrivateKey, error) {
	// Generate a new Ed25519 key pair
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	// Assign the generated private key to the receiver
	*k = Ed25519PrivateKey(priv)
	return k, nil
}

func (k Ed25519PrivateKey) Public() (SigningPublicKey, error) {
	fmt.Printf("Ed25519PrivateKey.Public(): len(k) = %d\n", len(k))
	if len(k) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid ed25519 private key size: expected %d, got %d", ed25519.PrivateKeySize, len(k))
	}
	pubKey := k[32:]
	fmt.Printf("Ed25519PrivateKey.Public(): extracted pubKey length: %d\n", len(pubKey))
	return Ed25519PublicKey(pubKey), nil
}

type Ed25519Signer struct {
	k []byte
}

func (s *Ed25519Signer) Sign(data []byte) (sig []byte, err error) {
	log.WithField("data_length", len(data)).Debug("Signing data with Ed25519")

	if len(s.k) != ed25519.PrivateKeySize {
		log.Error("Invalid Ed25519 private key size")
		err = errors.New("failed to sign: invalid ed25519 private key size")
		return
	}
	h := sha512.Sum512(data)
	sig, err = s.SignHash(h[:])
	return
}

func (s *Ed25519Signer) SignHash(h []byte) (sig []byte, err error) {
	log.WithField("hash_length", len(h)).Debug("Signing hash with Ed25519")
	sig = ed25519.Sign(s.k, h)
	log.WithField("signature_length", len(sig)).Debug("Ed25519 signature created successfully")
	return
}

func CreateEd25519PublicKeyFromBytes(data []byte) (Ed25519PublicKey, error) {
	log.WithField("data_length", len(data)).Debug("Creating Ed25519 public key")

	if len(data) != ed25519.PublicKeySize {
		log.WithField("data_length", len(data)).Error("Invalid Ed25519 public key size")
		return nil, ErrInvalidPublicKeySize
	}

	// Return the Ed25519 public key
	log.Debug("Ed25519 public key created successfully")
	return Ed25519PublicKey(data), nil
}
