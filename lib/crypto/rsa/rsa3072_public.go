package rsa

import "github.com/go-i2p/go-i2p/lib/crypto/types"

type (
	RSA3072PublicKey [384]byte
)

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
