package rsa

import "github.com/go-i2p/go-i2p/lib/crypto/types"

type (
	RSA2048PrivateKey [512]byte
)

// Sign implements types.Signer.
func (r RSA2048PrivateKey) Sign(data []byte) (sig []byte, err error) {
	panic("unimplemented")
}

// SignHash implements types.Signer.
func (r RSA2048PrivateKey) SignHash(h []byte) (sig []byte, err error) {
	panic("unimplemented")
}

// Bytes implements types.PrivateKey.
func (r RSA2048PrivateKey) Bytes() []byte {
	panic("unimplemented")
}

// Public implements types.PrivateKey.
func (r RSA2048PrivateKey) Public() (types.SigningPublicKey, error) {
	panic("unimplemented")
}

// Zero implements types.PrivateKey.
func (r RSA2048PrivateKey) Zero() {
	panic("unimplemented")
}

var _ types.PrivateKey = RSA2048PrivateKey{}
var _ types.Signer = RSA2048PrivateKey{}
