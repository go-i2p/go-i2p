package ecdsa

import "github.com/go-i2p/go-i2p/lib/crypto/types"

type (
	ECP256PrivateKey [32]byte
)

// Sign implements types.Signer.
func (e *ECP256PrivateKey) Sign(data []byte) (sig []byte, err error) {
	panic("unimplemented")
}

// SignHash implements types.Signer.
func (e *ECP256PrivateKey) SignHash(h []byte) (sig []byte, err error) {
	panic("unimplemented")
}

// Decrypt implements types.Decrypter.
func (e *ECP256PrivateKey) Decrypt(data []byte) ([]byte, error) {
	panic("unimplemented")
}

// Bytes implements types.PrivateKey.
func (e *ECP256PrivateKey) Bytes() []byte {
	panic("unimplemented")
}

// Public implements types.PrivateKey.
func (e *ECP256PrivateKey) Public() (types.SigningPublicKey, error) {
	panic("unimplemented")
}

// Zero implements types.PrivateKey.
func (e *ECP256PrivateKey) Zero() {
	panic("unimplemented")
}
