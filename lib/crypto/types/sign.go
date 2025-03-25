package types

import "github.com/samber/oops"

var (
	ErrBadSignatureSize = oops.Errorf("bad signature size")
	ErrInvalidKeyFormat = oops.Errorf("invalid key format")
	ErrInvalidSignature = oops.Errorf("invalid signature")
)

// type for verifying signatures
type Verifier interface {
	// verify hashed data with this signing key
	// return nil on valid signature otherwise error
	VerifyHash(h, sig []byte) error
	// verify an unhashed piece of data by hashing it and calling VerifyHash
	Verify(data, sig []byte) error
}

// key for verifying data
type SigningPublicKey interface {
	// create new Verifier to verify the validity of signatures
	// return verifier or nil and error if key format is invalid
	NewVerifier() (Verifier, error)
	// get the size of this public key
	Len() int
	Bytes() []byte
}
type RecievingPublicKey interface {
	Len() int
	Bytes() []byte
	NewEncrypter() (Encrypter, error)
}

// type for signing data
type Signer interface {
	// sign data with our private key by calling SignHash after hashing the data we are given
	// return signature or nil signature and error if an error happened
	Sign(data []byte) (sig []byte, err error)

	// sign hash of data with our private key
	// return signature or nil signature and error if an error happened
	SignHash(h []byte) (sig []byte, err error)
}

// key for signing data
type SigningPrivateKey interface {
	// create a new signer to sign data
	// return signer or nil and error if key format is invalid
	NewSigner() (Signer, error)
	// length of this private key
	Len() int
	// get public key or return nil and error if invalid key data in private key
	Public() (SigningPublicKey, error)
	// generate a new private key, put it into itself
	// returns itself or nil and error if an error occurs
	Generate() (SigningPrivateKey, error)
}
