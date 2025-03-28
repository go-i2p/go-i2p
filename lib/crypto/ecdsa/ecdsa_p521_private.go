package ecdsa

import "github.com/go-i2p/go-i2p/lib/crypto/types"

type (
	ECP521PrivateKey [66]byte
)

// Sign implements types.Signer.
func (e *ECP521PrivateKey) Sign(data []byte) (sig []byte, err error) {
	panic("unimplemented")
}

// SignHash implements types.Signer.
func (e *ECP521PrivateKey) SignHash(h []byte) (sig []byte, err error) {
	panic("unimplemented")
}

// Decrypt implements types.Decrypter.
func (e *ECP521PrivateKey) Decrypt(data []byte) ([]byte, error) {
	panic("unimplemented")
}

// Bytes implements types.PrivateKey.
func (e *ECP521PrivateKey) Bytes() []byte {
	panic("unimplemented")
}

// Public implements types.PrivateKey.
func (e *ECP521PrivateKey) Public() (types.SigningPublicKey, error) {
	panic("unimplemented")
}

// Zero implements types.PrivateKey.
func (e *ECP521PrivateKey) Zero() {
	panic("unimplemented")
}
