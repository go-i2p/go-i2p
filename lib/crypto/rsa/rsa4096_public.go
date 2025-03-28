package rsa

import "github.com/go-i2p/go-i2p/lib/crypto/types"

type (
	RSA4096PublicKey [512]byte
)

// Verify implements types.Verifier.
func (r RSA4096PublicKey) Verify(data []byte, sig []byte) error {
	panic("unimplemented")
}

// VerifyHash implements types.Verifier.
func (r RSA4096PublicKey) VerifyHash(h []byte, sig []byte) error {
	panic("unimplemented")
}

// Bytes implements SigningPublicKey.
func (r RSA4096PublicKey) Bytes() []byte {
	panic("unimplemented")
}

// Len implements SigningPublicKey.
func (r RSA4096PublicKey) Len() int {
	panic("unimplemented")
}

// NewVerifier implements SigningPublicKey.
func (r RSA4096PublicKey) NewVerifier() (types.Verifier, error) {
	panic("unimplemented")
}

var _ types.PublicKey = RSA4096PublicKey{}
var _ types.Verifier = RSA4096PublicKey{}
