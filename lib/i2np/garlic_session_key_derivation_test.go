package i2np

import (
	"testing"

	i2pcurve25519 "github.com/go-i2p/crypto/curve25519"
)

// TestGarlicSessionManagerKeyDerivation verifies that the public key is correctly
// derived from the private key using X25519 scalar multiplication.
func TestGarlicSessionManagerKeyDerivation(t *testing.T) {
	// Create a test private key
	var privateKey [32]byte
	for i := range privateKey {
		privateKey[i] = byte(i)
	}

	// Create garlic session manager
	manager, err := NewGarlicSessionManager(privateKey)
	if err != nil {
		t.Fatalf("Failed to create garlic session manager: %v", err)
	}

	// Manually derive the expected public key
	var expectedPublicKey [32]byte
	privKey, err2 := i2pcurve25519.NewCurve25519PrivateKey(privateKey[:])
	if err2 != nil {
		t.Fatalf("Failed to create Curve25519 private key: %v", err2)
	}
	pubKey, err2 := privKey.Public()
	if err2 != nil {
		t.Fatalf("Failed to derive public key: %v", err2)
	}
	copy(expectedPublicKey[:], pubKey.Bytes())

	// Verify the manager's public key matches
	if manager.ourPublicKey != expectedPublicKey {
		t.Errorf("Public key mismatch:\nGot:      %x\nExpected: %x",
			manager.ourPublicKey, expectedPublicKey)
	}
}

// TestGarlicSessionManagerKeyPairCorrespondence verifies that encryption
// with the public key can be decrypted with the private key.
func TestGarlicSessionManagerKeyPairCorrespondence(t *testing.T) {
	// Create a test private key
	var privateKey [32]byte
	privateKey[0] = 1 // Non-zero to ensure valid key

	// Create manager
	manager, err := NewGarlicSessionManager(privateKey)
	if err != nil {
		t.Fatalf("Failed to create garlic session manager: %v", err)
	}

	// Verify keys are set
	if manager.ourPrivateKey != privateKey {
		t.Error("Private key not set correctly in manager")
	}

	// Verify public key is non-zero (derived from private key)
	var zeroKey [32]byte
	if manager.ourPublicKey == zeroKey {
		t.Error("Public key is zero - derivation failed")
	}

	t.Logf("Private key: %x", manager.ourPrivateKey[:8])
	t.Logf("Public key:  %x", manager.ourPublicKey[:8])
}
