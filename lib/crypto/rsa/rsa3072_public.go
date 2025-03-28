package rsa

import "github.com/go-i2p/go-i2p/lib/crypto/types"

type (
	RSA3072PublicKey [384]byte
)

// Verify implements types.Verifier.
func (r RSA3072PublicKey) Verify(data []byte, sig []byte) error {
	panic("unimplemented")
}

// VerifyHash implements types.Verifier.
func (r RSA3072PublicKey) VerifyHash(h []byte, sig []byte) error {
	panic("unimplemented")
}

// Bytes implements SigningPublicKey.
func (r RSA3072PublicKey) Bytes() []byte {
	panic("unimplemented")
}

// Len implements SigningPublicKey.
func (r RSA3072PublicKey) Len() int {
	panic("unimplemented")
}

// NewVerifier implements SigningPublicKey.
func (r RSA3072PublicKey) NewVerifier() (types.Verifier, error) {
	panic("unimplemented")
}

var _ types.PublicKey = RSA3072PublicKey{}
var _ types.Verifier = RSA3072PublicKey{}
