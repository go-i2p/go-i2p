package ed25519

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"

	"github.com/go-i2p/go-i2p/lib/crypto/types"
	"github.com/samber/oops"
)

type Ed25519PrivateKey ed25519.PrivateKey

// NewVerifier implements types.SigningPublicKey.
func (k *Ed25519PrivateKey) NewVerifier() (types.Verifier, error) {
	panic("unimplemented")
}

func (k Ed25519PrivateKey) Bytes() []byte {
	return k
}

func (k Ed25519PrivateKey) Zero() {
	for i := range k {
		k[i] = 0
	}
}

func (k Ed25519PrivateKey) NewDecrypter() (types.Decrypter, error) {
	if len(k) != ed25519.PrivateKeySize {
		return nil, oops.Errorf("invalid ed25519 private key size")
	}
	d := &Ed25519Decrypter{
		privateKey: k,
	}
	return d, nil
}

func (k Ed25519PrivateKey) NewSigner() (types.Signer, error) {
	if len(k) != ed25519.PrivateKeySize {
		return nil, oops.Errorf("invalid ed25519 private key size")
	}
	return &Ed25519Signer{k: k}, nil
}

func (k Ed25519PrivateKey) Len() int {
	return len(k)
}

func (k Ed25519PrivateKey) Generate() (types.SigningPrivateKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, oops.Errorf("failed to generate ed25519 key: %v", err)
	}
	// Copy the full private key (includes public key)
	newKey := make(Ed25519PrivateKey, ed25519.PrivateKeySize)
	copy(newKey, priv)
	return newKey, nil
}

func (k Ed25519PrivateKey) Public() (types.SigningPublicKey, error) {
	fmt.Printf("Ed25519PrivateKey.Public(): len(k) = %d\n", len(k))
	if len(k) != ed25519.PrivateKeySize {
		return nil, oops.Errorf("invalid ed25519 private key size: expected %d, got %d",
			ed25519.PrivateKeySize, len(k))
	}
	// Extract public key portion (last 32 bytes)
	pubKey := ed25519.PrivateKey(k).Public().(ed25519.PublicKey)
	fmt.Printf("Ed25519PrivateKey.Public(): extracted pubKey length: %d\n", len(pubKey))
	return Ed25519PublicKey(pubKey), nil
}

func CreateEd25519PrivateKeyFromBytes(data []byte) (Ed25519PrivateKey, error) {
	if len(data) != ed25519.PrivateKeySize {
		return nil, oops.Errorf("invalid ed25519 private key size: expected %d, got %d",
			ed25519.PrivateKeySize, len(data))
	}
	privKey := make(Ed25519PrivateKey, ed25519.PrivateKeySize)
	copy(privKey, data)
	return privKey, nil
}
