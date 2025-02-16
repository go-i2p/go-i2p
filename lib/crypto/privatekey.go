package crypto

// PrivateKey is an interface for private keys
type PrivateKey interface {
	// Public returns the public key corresponding to this private key
	Public() (SigningPublicKey, error)
	// Bytes returns the raw bytes of this private key
	Bytes() []byte
	// Zero clears all sensitive data from the private key
	Zero()
}
