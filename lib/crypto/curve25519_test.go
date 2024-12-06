package crypto

import (
	"bytes"
	"crypto/rand"
	"crypto/sha512"
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

	if len(ciphertext) != 514 {
		t.Errorf("Unexpected ciphertext length: got %d, want 514", len(ciphertext))
	}

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

	if len(ciphertext) != 512 {
		t.Errorf("Unexpected ciphertext length for no zero padding: got %d, want 512", len(ciphertext))
	}
}

func TestCurve25519SignVerify(t *testing.T) {
	var priv Curve25519PrivateKey
	_, err := rand.Read(priv[:])
	if err != nil {
		t.Fatalf("Failed to generate private key seed: %v", err)
	}

	signer, err := priv.NewSigner()
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	pub, err := priv.Public()
	if err != nil {
		t.Fatalf("Failed to derive public key: %v", err)
	}

	verifier, err := pub.NewVerifier()
	if err != nil {
		t.Fatalf("Failed to create verifier: %v", err)
	}

	message := []byte("This is a test message for signing.")
	sig, err := signer.Sign(message)
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}

	err = verifier.Verify(message, sig)
	if err != nil {
		t.Fatalf("Failed to verify signature: %v", err)
	}

	alteredMessage := []byte("This is a tampered message!")
	err = verifier.Verify(alteredMessage, sig)
	if err == nil {
		t.Fatal("Expected verification to fail for altered message, but it succeeded")
	}
}

func TestCurve25519SignVerifyHash(t *testing.T) {
	var priv Curve25519PrivateKey
	_, err := rand.Read(priv[:])
	if err != nil {
		t.Fatalf("Failed to generate private key seed: %v", err)
	}

	signer, err := priv.NewSigner()
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	pub, err := priv.Public()
	if err != nil {
		t.Fatalf("Failed to derive public key: %v", err)
	}

	verifier, err := pub.NewVerifier()
	if err != nil {
		t.Fatalf("Failed to create verifier: %v", err)
	}

	data := []byte("Data to sign using SignHash and VerifyHash.")
	hash := sha512.Sum512(data)

	sig, err := signer.SignHash(hash[:])
	if err != nil {
		t.Fatalf("Failed to sign hash: %v", err)
	}

	err = verifier.VerifyHash(hash[:], sig)
	if err != nil {
		t.Fatalf("Failed to verify signed hash: %v", err)
	}

	sig[0] ^= 0xFF
	err = verifier.VerifyHash(hash[:], sig)
	if err == nil {
		t.Fatal("Expected verification to fail for tampered signature, but it succeeded")
	}
}
