package rsa

import "github.com/go-i2p/go-i2p/lib/crypto/types"

type (
	RSA2048PublicKey [256]byte
)

// Verify implements types.Verifier.
func (r RSA2048PublicKey) Verify(data []byte, sig []byte) error {
	panic("unimplemented")
}

// VerifyHash implements types.Verifier.
func (r RSA2048PublicKey) VerifyHash(h []byte, sig []byte) error {
	panic("unimplemented")
}

// Bytes implements SigningPublicKey.
func (r RSA2048PublicKey) Bytes() []byte {
	panic("unimplemented")
}

// Len implements SigningPublicKey.
func (r RSA2048PublicKey) Len() int {
	panic("unimplemented")
}

// NewVerifier implements SigningPublicKey.
func (r RSA2048PublicKey) NewVerifier() (types.Verifier, error) {
	panic("unimplemented")
}

var _ types.PublicKey = RSA2048PublicKey{}
var _ types.Verifier = RSA2048PublicKey{}
