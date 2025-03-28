package rsa

import "github.com/go-i2p/go-i2p/lib/crypto/types"

type (
	RSA3072PrivateKey [786]byte
)

// Sign implements types.Signer.
func (r RSA3072PrivateKey) Sign(data []byte) (sig []byte, err error) {
	panic("unimplemented")
}

// SignHash implements types.Signer.
func (r RSA3072PrivateKey) SignHash(h []byte) (sig []byte, err error) {
	panic("unimplemented")
}

// Bytes implements types.PrivateKey.
func (r RSA3072PrivateKey) Bytes() []byte {
	panic("unimplemented")
}

// Public implements types.PrivateKey.
func (r RSA3072PrivateKey) Public() (types.SigningPublicKey, error) {
	panic("unimplemented")
}

// Zero implements types.PrivateKey.
func (r RSA3072PrivateKey) Zero() {
	panic("unimplemented")
}

var _ types.PrivateKey = RSA3072PrivateKey{}
var _ types.Signer = RSA3072PrivateKey{}
