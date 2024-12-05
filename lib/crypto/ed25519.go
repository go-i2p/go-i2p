package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"io"
	"math/big"

	"github.com/sirupsen/logrus"
)

var (
	Ed25519EncryptTooBig      = errors.New("failed to encrypt data, too big for Ed25519")
	ErrInvalidPublicKeySize   = errors.New("failed to verify: invalid ed25519 public key size")
	ErrInvalidPrivateKeySize  = errors.New("invalid Ed25519 private key size")
	ErrInvalidPublicKeyFormat = errors.New("invalid public key format")
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
	if len(data) == ed25519.PublicKeySize {
		pubKey := make(ed25519.PublicKey, ed25519.PublicKeySize)
		copy(pubKey, data)
		k = &pubKey
		log.Debug("Ed25519 public key created successfully")
	} else {
		log.WithField("expected_size", ed25519.PublicKeySize).
			Warn("Invalid data length for Ed25519 public key")
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

// Ed25519Decrypter handles decryption using Ed25519.
type Ed25519Decrypter struct {
	p    *big.Int // The prime modulus p = 2^255 - 19
	xInv *big.Int // The modular inverse of the private scalar x mod p
}

// Decrypt decrypts the ciphertext and returns the original data.
func (d *Ed25519Decrypter) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) != 512 && len(ciphertext) != 514 {
		return nil, errors.New("invalid ciphertext length")
	}

	var bBytes []byte
	if len(ciphertext) == 514 {
		bBytes = ciphertext[258:514]
	} else {
		bBytes = ciphertext[256:512]
	}

	b := new(big.Int).SetBytes(bBytes)

	m := new(big.Int).Mul(b, d.xInv)
	m.Mod(m, d.p)

	mBytes := m.Bytes()
	if len(mBytes) < 255 {
		padded := make([]byte, 255)
		copy(padded[255-len(mBytes):], mBytes)
		mBytes = padded
	} else if len(mBytes) > 255 {
		return nil, errors.New("decrypted message exceeds expected length")
	}

	// Validate padding
	if mBytes[0] != 0xFF {
		return nil, errors.New("invalid padding prefix")
	}

	receivedHash := mBytes[1:33]
	data := mBytes[33:]

	expectedHash := sha256.Sum256(data)
	if !bytes.Equal(receivedHash, expectedHash[:]) {
		return nil, errors.New("hash mismatch after decryption")
	}

	return data, nil
}

// NewDecrypter creates a new Decrypter instance for Ed25519PrivateKey.
func (k Ed25519PrivateKey) NewDecrypter() (Decrypter, error) {
	if len(k) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid Ed25519 private key size")
	}

	// Extract the seed (first 32 bytes)
	seed := k[:32]

	// Hash the seed using SHA-512
	hash := sha512.Sum512(seed)

	// Clamp the private scalar as per Ed25519 specifications
	hash[0] &= 248
	hash[31] &= 63
	hash[31] |= 64

	// Convert the first 32 bytes of the hash to a big.Int (private scalar x)
	x := new(big.Int).SetBytes(hash[:32])

	// Define p = 2^255 - 19
	p := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))

	// Compute the modular inverse of x mod p (xInv)
	xInv := new(big.Int).ModInverse(x, p)
	if xInv == nil {
		return nil, errors.New("failed to compute inverse of private scalar")
	}

	// Create and return the Decrypter
	return &Ed25519Decrypter{
		p:    p,
		xInv: xInv,
	}, nil
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

// Public returns the corresponding SigningPublicKey for the Ed25519PrivateKey.
func (k Ed25519PrivateKey) Public() (SigningPublicKey, error) {
	log.Println("Ed25519PrivateKey.Public(): len(k) =", len(k))

	if len(k) != ed25519.PrivateKeySize {
		log.Println("Ed25519PrivateKey.Public(): invalid private key size:", len(k))
		return nil, ErrInvalidPrivateKeySize
	}

	// Extract the public key part from the private key
	pubKeyBytes := ed25519.PrivateKey(k).Public().(ed25519.PublicKey)
	log.Println("Ed25519PrivateKey.Public(): extracted pubKey length:", len(pubKeyBytes))

	// Create Ed25519PublicKey from bytes
	edPubKey, err := CreateEd25519PublicKeyFromBytes(pubKeyBytes)
	if err != nil {
		return nil, err
	}

	return edPubKey, nil
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
	return data, nil
}
