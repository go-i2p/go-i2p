package rsa

import "github.com/go-i2p/go-i2p/lib/crypto/types"

type (
	RSA4096PrivateKey [1024]byte
)

// Sign implements types.Signer.
func (r RSA4096PrivateKey) Sign(data []byte) (sig []byte, err error) {
	panic("unimplemented")
}

// SignHash implements types.Signer.
func (r RSA4096PrivateKey) SignHash(h []byte) (sig []byte, err error) {
	panic("unimplemented")
}

// Bytes implements types.PrivateKey.
func (r RSA4096PrivateKey) Bytes() []byte {
	panic("unimplemented")
}

// Public implements types.PrivateKey.
func (r RSA4096PrivateKey) Public() (types.SigningPublicKey, error) {
	panic("unimplemented")
}

// Zero implements types.PrivateKey.
func (r RSA4096PrivateKey) Zero() {
	panic("unimplemented")
}

var _ types.PrivateKey = RSA4096PrivateKey{}
var _ types.Signer = RSA4096PrivateKey{}
