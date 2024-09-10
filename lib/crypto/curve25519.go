package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"io"
	"math/big"

	curve25519 "go.step.sm/crypto/x25519"
)

var Curve25519EncryptTooBig = errors.New("failed to encrypt data, too big for Curve25519")

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
	return len(k)
}

func createCurve25519PublicKey(data []byte) (k *curve25519.PublicKey) {
	if len(data) == 256 {
		k2 := curve25519.PublicKey{}
		copy(k2[:], data)
		k = &k2
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
	return
}

type Curve25519Encryption struct {
	p, a, b1 *big.Int
}

func (curve25519 *Curve25519Encryption) Encrypt(data []byte) (enc []byte, err error) {
	return curve25519.EncryptPadding(data, true)
}

func (curve25519 *Curve25519Encryption) EncryptPadding(data []byte, zeroPadding bool) (encrypted []byte, err error) {
	if len(data) > 222 {
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
	return
}

func (elg Curve25519PublicKey) NewEncrypter() (enc Encrypter, err error) {
	k := createCurve25519PublicKey(elg[:])
	enc, err = createCurve25519Encryption(k, rand.Reader)
	return
}

func (v *Curve25519Verifier) VerifyHash(h, sig []byte) (err error) {
	if len(sig) != curve25519.SignatureSize {
		err = ErrBadSignatureSize
		return
	}
	if len(v.k) != curve25519.PublicKeySize {
		err = errors.New("failed to verify: invalid curve25519 public key size")
		return
	}

	ok := curve25519.Verify(v.k, h, sig)
	if !ok {
		err = errors.New("failed to verify: invalid signature")
	}
	return
}

func (v *Curve25519Verifier) Verify(data, sig []byte) (err error) {
	h := sha512.Sum512(data)
	err = v.VerifyHash(h[:], sig)
	return
}

type Curve25519PrivateKey curve25519.PrivateKey

type Curve25519Signer struct {
	k []byte
}

func (s *Curve25519Signer) Sign(data []byte) (sig []byte, err error) {
	if len(s.k) != curve25519.PrivateKeySize {
		err = errors.New("failed to sign: invalid curve25519 private key size")
		return
	}
	h := sha512.Sum512(data)
	sig, err = s.SignHash(h[:])
	return
}

func (s *Curve25519Signer) SignHash(h []byte) (sig []byte, err error) {
	return curve25519.Sign(rand.Reader, s.k, h)
}
