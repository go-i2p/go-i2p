package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"io"
	"math/big"
)

var Ed25519EncryptTooBig = errors.New("failed to encrypt data, too big for Ed25519")

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

func createEd25519PublicKey(data []byte) (k *ed25519.PublicKey) {
	if len(data) == 256 {
		k2 := ed25519.PublicKey{}
		copy(k2[:], data)
		k = &k2
	}
	return
}

func createEd25519Encryption(pub *ed25519.PublicKey, rand io.Reader) (enc *Ed25519Encryption, err error) {
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
		enc = &Ed25519Encryption{}
	}*/
	return
}

type Ed25519Encryption struct {
	p, a, b1 *big.Int
}

func (ed25519 *Ed25519Encryption) Encrypt(data []byte) (enc []byte, err error) {
	return ed25519.EncryptPadding(data, true)
}

func (ed25519 *Ed25519Encryption) EncryptPadding(data []byte, zeroPadding bool) (encrypted []byte, err error) {
	if len(data) > 222 {
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
	return
}

func (elg Ed25519PublicKey) NewEncrypter() (enc Encrypter, err error) {
	k := createEd25519PublicKey(elg[:])
	enc, err = createEd25519Encryption(k, rand.Reader)
	return
}

func (v *Ed25519Verifier) VerifyHash(h, sig []byte) (err error) {
	if len(sig) != ed25519.SignatureSize {
		err = ErrBadSignatureSize
		return
	}
	if len(v.k) != ed25519.PublicKeySize {
		err = errors.New("failed to verify: invalid ed25519 public key size")
		return
	}

	ok := ed25519.Verify(v.k, h, sig)
	if !ok {
		err = errors.New("failed to verify: invalid signature")
	}
	return
}

func (v *Ed25519Verifier) Verify(data, sig []byte) (err error) {
	h := sha512.Sum512(data)
	err = v.VerifyHash(h[:], sig)
	return
}

type Ed25519PrivateKey ed25519.PrivateKey

type Ed25519Signer struct {
	k []byte
}

func (s *Ed25519Signer) Sign(data []byte) (sig []byte, err error) {
	if len(s.k) != ed25519.PrivateKeySize {
		err = errors.New("failed to sign: invalid ed25519 private key size")
		return
	}
	h := sha512.Sum512(data)
	sig, err = s.SignHash(h[:])
	return
}

func (s *Ed25519Signer) SignHash(h []byte) (sig []byte, err error) {
	sig = ed25519.Sign(s.k, h)
	return
}
