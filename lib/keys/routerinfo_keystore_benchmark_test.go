package keys

import (
	"os"
	"testing"

	"github.com/go-i2p/crypto/ed25519"
)

// BenchmarkKeyGeneration measures key generation performance.
func BenchmarkKeyGeneration(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _, err := ed25519.GenerateEd25519KeyPair()
		if err != nil {
			b.Fatalf("Key generation failed: %v", err)
		}
	}
}

// BenchmarkKeyStore measures key storage performance.
func BenchmarkKeyStore(b *testing.B) {
	tmpDir, err := os.MkdirTemp("", "keys_bench")
	if err != nil {
		b.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	_, privKey, err := ed25519.GenerateEd25519KeyPair()
	if err != nil {
		b.Fatalf("Failed to generate key: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ks := &RouterInfoKeystore{
			dir:        tmpDir,
			name:       "bench-key",
			privateKey: privKey,
		}
		err := ks.StoreKeys()
		if err != nil {
			b.Fatalf("StoreKeys failed: %v", err)
		}
	}
}

// BenchmarkKeyID_WithCache measures performance of KeyID with caching
func BenchmarkKeyID_WithCache(b *testing.B) {
	ks := &RouterInfoKeystore{
		privateKey:  nil,
		name:        "",
		cachedKeyID: "", // Will be populated on first call
	}

	// First call to populate cache
	_ = ks.KeyID()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ks.KeyID()
	}
}

// BenchmarkKeyID_NormalOperation measures performance with valid private key
func BenchmarkKeyID_NormalOperation(b *testing.B) {
	_, privateKey, err := ed25519.GenerateEd25519KeyPair()
	if err != nil {
		b.Fatalf("Failed to generate private key: %v", err)
	}

	ks := &RouterInfoKeystore{
		privateKey: privateKey,
		name:       "",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ks.KeyID()
	}
}
