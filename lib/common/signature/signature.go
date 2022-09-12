// Package signature implements the I2P Signature common data structure
package signature

// Lengths of signature keys
const (
	DSA_SHA1_SIZE               = 40
	ECDSA_SHA256_P256_SIZE      = 64
	ECDSA_SHA384_P384_SIZE      = 96
	ECDSA_SHA512_P512_SIZE      = 132
	RSA_SHA256_2048_SIZE        = 256
	RSA_SHA384_3072_SIZE        = 384
	RSA_SHA512_4096_SIZE        = 512
	EdDSA_SHA512_Ed25519_SIZE   = 64
	EdDSA_SHA512_Ed25519ph_SIZE = 64
	RedDSA_SHA512_Ed25519_SIZE  = 64
)

/*
[Signature]
Accurate for version 0.9.49

Description
This structure represents the signature of some data.

Contents
Signature type and length are inferred from the type of key used. The default type is
DSA_SHA1. As of release 0.9.12, other types may be supported, depending on context.
*/

// Signature is the represenation of an I2P Signature.
//
// https://geti2p.net/spec/common-structures#signature
type Signature []byte

// ReadSignature returns Signature from a []byte.
// The remaining bytes after the specified length are also returned.
// Returns a list of errors that occurred during parsing.
func ReadSignature(bytes []byte) (info Signature, remainder []byte, err error) {
	// TODO: stub
	return
}

// NewSignature creates a new *Signature from []byte using ReadSignature.
// Returns a pointer to Signature unlike ReadSignature.
func NewSignature(data []byte) (session_tag *Signature, remainder []byte, err error) {
	sessionTag, remainder, err := ReadSignature(data)
	session_tag = &sessionTag
	return
}
