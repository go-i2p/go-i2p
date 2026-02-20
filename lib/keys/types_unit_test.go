package keys

import (
	"testing"

	"github.com/go-i2p/crypto/ed25519"
)

// TestKeyStoreImpl_Close_ZeroesKeyMaterial verifies that Close() zeroes
// private key bytes from the base KeyStoreImpl.
func TestKeyStoreImpl_Close_ZeroesKeyMaterial(t *testing.T) {
	_, privateKey, err := ed25519.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	ks := NewKeyStoreImpl(t.TempDir(), "close-test", privateKey)

	// Verify key is not all zeros before close
	keyBytes := privateKey.Bytes()
	allZero := true
	for _, b := range keyBytes {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatal("Private key should not be all zeros before Close")
	}

	ks.Close()

	// After Close, key should be zeroed
	postCloseBytes := privateKey.Bytes()
	allZeroPost := true
	for _, b := range postCloseBytes {
		if b != 0 {
			allZeroPost = false
			break
		}
	}
	if !allZeroPost {
		t.Error("Private key should be all zeros after Close()")
	}
}
