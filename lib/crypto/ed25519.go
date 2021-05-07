package crypto

import (
	"crypto/ed25519"
	"crypto/sha512"
	"errors"
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
