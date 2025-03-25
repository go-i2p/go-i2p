package rsa

import "github.com/go-i2p/go-i2p/lib/crypto/types"

type (
	RSA2048PublicKey  [256]byte
	RSA2048PrivateKey [512]byte
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

type (
	RSA3072PublicKey  [384]byte
	RSA3072PrivateKey [786]byte
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

type (
	RSA4096PublicKey  [512]byte
	RSA4096PrivateKey [1024]byte
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
