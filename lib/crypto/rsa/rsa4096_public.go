package rsa

import "github.com/go-i2p/go-i2p/lib/crypto/types"

type (
	RSA4096PublicKey [512]byte
)

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
