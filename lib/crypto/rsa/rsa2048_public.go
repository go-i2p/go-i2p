package rsa

import "github.com/go-i2p/go-i2p/lib/crypto/types"

type (
	RSA2048PublicKey [256]byte
)

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
