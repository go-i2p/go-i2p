package crypto

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestCurve25519KeyCreation(t *testing.T) {
	pubKeyBytes := make([]byte, Curve25519PublicKeySize)
	_, err := rand.Read(pubKeyBytes)
	if err != nil {
		t.Fatalf("Failed to generate random public key bytes: %v", err)
	}

	k := createCurve25519PublicKey(pubKeyBytes)
	if k == nil {
		t.Fatalf("Failed to create a valid Curve25519 public key")
	}

	if len(k) != Curve25519PublicKeySize {
		t.Fatalf("Public key length mismatch: expected %d, got %d", Curve25519PublicKeySize, len(k))
	}
}

func TestCurve25519EncryptionSession(t *testing.T) {
	pubKeyBytes := make([]byte, Curve25519PublicKeySize)
	_, err := rand.Read(pubKeyBytes)
	if err != nil {
		t.Fatalf("Failed to generate random public key: %v", err)
	}

	enc, err := createCurve25519Encryption(pubKeyBytes)
	if err != nil {
		t.Fatalf("Failed to create Curve25519 encryption session: %v", err)
	}

	if enc.p == nil || enc.a == nil || enc.b1 == nil {
		t.Fatal("Curve25519 encryption session has nil parameters")
	}
}

func TestCurve25519Encrypt(t *testing.T) {
	pubKeyBytes := make([]byte, Curve25519PublicKeySize)
	_, err := rand.Read(pubKeyBytes)
	if err != nil {
		t.Fatalf("Failed to generate random public key: %v", err)
	}

	encrypter, err := Curve25519PublicKey(pubKeyBytes).NewEncrypter()
	if err != nil {
		t.Fatalf("Failed to create Curve25519 encrypter: %v", err)
	}

	data := []byte("test message")
	ciphertext, err := encrypter.Encrypt(data)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// With zero padding, ciphertext should be 514 bytes.
	if len(ciphertext) != 514 {
		t.Errorf("Unexpected ciphertext length: got %d, want 514", len(ciphertext))
	}

	// Attempt to encrypt too large data
	tooLargeData := bytes.Repeat([]byte("A"), 223)
	_, err = encrypter.Encrypt(tooLargeData)
	if err == nil {
		t.Fatal("Expected encryption to fail with data too large, but it succeeded")
	}
	if err != Curve25519EncryptTooBig {
		t.Fatalf("Unexpected error: got %v, want %v", err, Curve25519EncryptTooBig)
	}
}

func TestCurve25519EncryptNoPadding(t *testing.T) {
	pubKeyBytes := make([]byte, Curve25519PublicKeySize)
	_, err := rand.Read(pubKeyBytes)
	if err != nil {
		t.Fatalf("Failed to generate random public key: %v", err)
	}

	enc, err := createCurve25519Encryption(pubKeyBytes)
	if err != nil {
		t.Fatalf("Failed to create Curve25519 encryption session: %v", err)
	}

	data := []byte("another test message")
	ciphertext, err := enc.EncryptPadding(data, false)
	if err != nil {
		t.Fatalf("Encryption without zero padding failed: %v", err)
	}

	// Without zero padding, ciphertext should be 512 bytes.
	if len(ciphertext) != 512 {
		t.Errorf("Unexpected ciphertext length for no zero padding: got %d, want 512", len(ciphertext))
	}
}
