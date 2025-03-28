package ecdsa

import "github.com/go-i2p/go-i2p/lib/crypto/types"

type (
	ECP384PrivateKey [48]byte
)

// Sign implements types.Signer.
func (e *ECP384PrivateKey) Sign(data []byte) (sig []byte, err error) {
	panic("unimplemented")
}

// SignHash implements types.Signer.
func (e *ECP384PrivateKey) SignHash(h []byte) (sig []byte, err error) {
	panic("unimplemented")
}

// Decrypt implements types.Decrypter.
func (e *ECP384PrivateKey) Decrypt(data []byte) ([]byte, error) {
	panic("unimplemented")
}

// Bytes implements types.PrivateKey.
func (e *ECP384PrivateKey) Bytes() []byte {
	panic("unimplemented")
}

// Public implements types.PrivateKey.
func (e *ECP384PrivateKey) Public() (types.SigningPublicKey, error) {
	panic("unimplemented")
}

// Zero implements types.PrivateKey.
func (e *ECP384PrivateKey) Zero() {
	panic("unimplemented")
}
