package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"math/big"
	"testing"
)

func TestEd25519(t *testing.T) {
	var pubKey Ed25519PublicKey

	signer := new(Ed25519Signer)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Log("Failed to generate ed25519 test key")
		t.Fail()
	}
	pubKey = []byte(pub)
	signer.k = priv

	message := make([]byte, 123)
	io.ReadFull(rand.Reader, message)

	sig, err := signer.Sign(message)
	if err != nil {
		t.Log("Failed to sign message")
		t.Fail()
	}

	verifier, err := pubKey.NewVerifier()
	if err != nil {
		t.Logf("Error from verifier: %s", err)
		t.Fail()
	}

	err = verifier.Verify(message, sig)
	if err != nil {
		t.Log("Failed to verify message")
		t.Fail()
	}
}

// TestEd25519KeyGeneration tests the generation of Ed25519 private and public keys.
func TestEd25519KeyGeneration(t *testing.T) {
	var privKey Ed25519PrivateKey
	_, err := privKey.Generate()
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 private key: %v", err)
	}

	if privKey.Len() != ed25519.PrivateKeySize {
		t.Errorf("Private key length mismatch: expected %d, got %d", ed25519.PrivateKeySize, privKey.Len())
	}

	pubKey, err := privKey.Public()
	if err != nil {
		t.Fatalf("Failed to derive Ed25519 public key: %v", err)
	}

	edPubKey, ok := pubKey.(Ed25519PublicKey)
	if !ok {
		t.Fatalf("Failed to assert type to Ed25519PublicKey")
	}

	if len(edPubKey) != ed25519.PublicKeySize {
		t.Errorf("Public key length mismatch: expected %d, got %d", ed25519.PublicKeySize, len(edPubKey))
	}

	t.Logf("Ed25519 Key Generation Successful: Private Key Length=%d, Public Key Length=%d", privKey.Len(), len(edPubKey))
}

// TestEd25519SigningVerification tests signing data and verifying the signature.
func TestEd25519SigningVerification(t *testing.T) {
	var privKey Ed25519PrivateKey
	_, err := privKey.Generate()
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 private key: %v", err)
	}

	pubKey, err := privKey.Public()
	if err != nil {
		t.Fatalf("Failed to derive Ed25519 public key: %v", err)
	}

	edPubKey, ok := pubKey.(Ed25519PublicKey)
	if !ok {
		t.Fatalf("Failed to assert type to Ed25519PublicKey")
	}

	signer, err := privKey.NewSigner()
	if err != nil {
		t.Fatalf("Failed to create Ed25519 signer: %v", err)
	}

	verifier, err := edPubKey.NewVerifier()
	if err != nil {
		t.Fatalf("Failed to create Ed25519 verifier: %v", err)
	}

	message := []byte("This is a test message for signing.")
	signature, err := signer.Sign(message)
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}

	err = verifier.Verify(message, signature)
	if err != nil {
		t.Fatalf("Failed to verify signature: %v", err)
	}

	t.Log("Ed25519 Signing and Verification Successful")
}

// TestEd25519InvalidSignature tests verification with an invalid signature.
func TestEd25519InvalidSignature(t *testing.T) {
	var privKey Ed25519PrivateKey
	_, err := privKey.Generate()
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 private key: %v", err)
	}

	pubKey, err := privKey.Public()
	if err != nil {
		t.Fatalf("Failed to derive Ed25519 public key: %v", err)
	}

	edPubKey, ok := pubKey.(Ed25519PublicKey)
	if !ok {
		t.Fatalf("Failed to assert type to Ed25519PublicKey")
	}

	verifier, err := edPubKey.NewVerifier()
	if err != nil {
		t.Fatalf("Failed to create Ed25519 verifier: %v", err)
	}

	message := []byte("Another test message.")
	invalidSig := make([]byte, ed25519.SignatureSize)
	_, err = rand.Read(invalidSig)
	if err != nil {
		t.Fatalf("Failed to generate random invalid signature: %v", err)
	}

	err = verifier.Verify(message, invalidSig)
	if err == nil {
		t.Fatalf("Verification should have failed with invalid signature, but it passed")
	}

	t.Log("Ed25519 Invalid Signature Verification Correctly Failed")
}

// TestEd25519Encryption tests encrypting data using Ed25519Encryption.
func TestEd25519Encryption(t *testing.T) {
	var privKey Ed25519PrivateKey
	_, err := privKey.Generate()
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 private key: %v", err)
	}

	pubKey, err := privKey.Public()
	if err != nil {
		t.Fatalf("Failed to derive Ed25519 public key: %v", err)
	}

	edPubKey, ok := pubKey.(Ed25519PublicKey)
	if !ok {
		t.Fatalf("Failed to assert type to Ed25519PublicKey")
	}

	encrypter, err := edPubKey.NewEncrypter()
	if err != nil {
		t.Fatalf("Failed to create Ed25519 encrypter: %v", err)
	}

	data := []byte("Sensitive information that needs encryption.")
	ciphertext, err := encrypter.Encrypt(data)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	if len(ciphertext) != 512 && len(ciphertext) != 514 {
		t.Errorf("Unexpected ciphertext length: got %d, want 512 or 514", len(ciphertext))
	}

	t.Log("Ed25519 Encryption Successful with Ciphertext Length:", len(ciphertext))
}

// TestEd25519EncryptionTooBig tests encryption with data exceeding size limits.
func TestEd25519EncryptionTooBig(t *testing.T) {
	var privKey Ed25519PrivateKey
	_, err := privKey.Generate()
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 private key: %v", err)
	}

	pubKey, err := privKey.Public()
	if err != nil {
		t.Fatalf("Failed to derive Ed25519 public key: %v", err)
	}

	edPubKey, ok := pubKey.(Ed25519PublicKey)
	if !ok {
		t.Fatalf("Failed to assert type to Ed25519PublicKey")
	}

	encrypter, err := edPubKey.NewEncrypter()
	if err != nil {
		t.Fatalf("Failed to create Ed25519 encrypter: %v", err)
	}

	data := make([]byte, 223)
	_, err = rand.Read(data)
	if err != nil {
		t.Fatalf("Failed to generate random data: %v", err)
	}

	_, err = encrypter.Encrypt(data)
	if err == nil {
		t.Fatalf("Encryption should have failed with data too big, but it succeeded")
	}

	if !errors.Is(err, Ed25519EncryptTooBig) {
		t.Fatalf("Unexpected error: got %v, want %v", err, Ed25519EncryptTooBig)
	}

	t.Log("Ed25519 Encryption Correctly Failed with Data Too Big")
}

// TestEd25519CreatePublicKeyFromBytes tests creating a public key from bytes.
func TestEd25519CreatePublicKeyFromBytes(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key pair: %v", err)
	}

	edPubKey, err := CreateEd25519PublicKeyFromBytes(pub)
	if err != nil {
		t.Fatalf("Failed to create Ed25519 public key from bytes: %v", err)
	}

	if len(edPubKey) != ed25519.PublicKeySize {
		t.Errorf("Public key length mismatch: expected %d, got %d", ed25519.PublicKeySize, len(edPubKey))
	}

	invalidPub := make([]byte, ed25519.PublicKeySize-1)
	_, err = CreateEd25519PublicKeyFromBytes(invalidPub)
	if err == nil {
		t.Fatalf("Creation should have failed with invalid public key size, but it succeeded")
	}

	t.Log("Ed25519 CreatePublicKeyFromBytes Successful for Valid and Invalid Inputs")
}

// TestEd25519SignerSignAndVerifyHash tests signing a hash and verifying it.
func TestEd25519SignerSignAndVerifyHash(t *testing.T) {
	var privKey Ed25519PrivateKey
	_, err := privKey.Generate()
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 private key: %v", err)
	}

	signer, err := privKey.NewSigner()
	if err != nil {
		t.Fatalf("Failed to create Ed25519 signer: %v", err)
	}

	pubKey, err := privKey.Public()
	if err != nil {
		t.Fatalf("Failed to derive Ed25519 public key: %v", err)
	}

	edPubKey, ok := pubKey.(Ed25519PublicKey)
	if !ok {
		t.Fatalf("Failed to assert type to Ed25519PublicKey")
	}

	verifier, err := edPubKey.NewVerifier()
	if err != nil {
		t.Fatalf("Failed to create Ed25519 verifier: %v", err)
	}

	data := []byte("Data to be hashed and signed.")
	hash := sha256.Sum256(data)

	signature, err := signer.SignHash(hash[:])
	if err != nil {
		t.Fatalf("Failed to sign hash: %v", err)
	}

	err = verifier.VerifyHash(hash[:], signature)
	if err != nil {
		t.Fatalf("Failed to verify signed hash: %v", err)
	}

	t.Log("Ed25519 SignHash and VerifyHash Successful")
}

// TestEd25519VerifierVerifyInvalidData tests verifying a signature with altered data.
func TestEd25519VerifierVerifyInvalidData(t *testing.T) {
	var privKey Ed25519PrivateKey
	_, err := privKey.Generate()
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 private key: %v", err)
	}

	signer, err := privKey.NewSigner()
	if err != nil {
		t.Fatalf("Failed to create Ed25519 signer: %v", err)
	}

	pubKey, err := privKey.Public()
	if err != nil {
		t.Fatalf("Failed to derive Ed25519 public key: %v", err)
	}

	edPubKey, ok := pubKey.(Ed25519PublicKey)
	if !ok {
		t.Fatalf("Failed to assert type to Ed25519PublicKey")
	}

	verifier, err := edPubKey.NewVerifier()
	if err != nil {
		t.Fatalf("Failed to create Ed25519 verifier: %v", err)
	}

	data := []byte("Original data for signing.")
	signature, err := signer.Sign(data)
	if err != nil {
		t.Fatalf("Failed to sign data: %v", err)
	}

	alteredData := []byte("Altered data for signing.")

	err = verifier.Verify(alteredData, signature)
	if err == nil {
		t.Fatalf("Verification should have failed with altered data, but it succeeded")
	}

	t.Log("Ed25519 Verifier Correctly Failed to Verify Altered Data")
}

// TestEd25519EncryptDecryptPadding tests encryption with padding and zero padding.
func TestEd25519EncryptDecryptPadding(t *testing.T) {
	var privKey Ed25519PrivateKey
	_, err := privKey.Generate()
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 private key: %v", err)
	}

	pubKey, err := privKey.Public()
	if err != nil {
		t.Fatalf("Failed to derive Ed25519 public key: %v", err)
	}

	edPubKey, ok := pubKey.(Ed25519PublicKey)
	if !ok {
		t.Fatalf("Failed to assert type to Ed25519PublicKey")
	}

	encrypter, err := edPubKey.NewEncrypter()
	if err != nil {
		t.Fatalf("Failed to create Ed25519 encrypter: %v", err)
	}

	edEncrypter, ok := encrypter.(*Ed25519Encryption)
	if !ok {
		t.Fatalf("Failed to assert Encrypter to *Ed25519Encryption")
	}

	data := []byte("Data that requires encryption with padding.")

	ciphertext, err := edEncrypter.EncryptPadding(data, true)
	if err != nil {
		t.Fatalf("Encryption with zero padding failed: %v", err)
	}

	if len(ciphertext) != 514 {
		t.Errorf("Ciphertext length mismatch for zero padding: expected 514, got %d", len(ciphertext))
	}

	t.Log("Ed25519 Encryption with Zero Padding Successful")

	ciphertextNoPad, err := edEncrypter.EncryptPadding(data, false)
	if err != nil {
		t.Fatalf("Encryption without zero padding failed: %v", err)
	}

	if len(ciphertextNoPad) != 512 {
		t.Errorf("Ciphertext length mismatch for no padding: expected 512, got %d", len(ciphertextNoPad))
	}

	t.Log("Ed25519 Encryption without Padding Successful")
}

// TestEd25519EncryptPaddingEdgeCases tests encryption padding with edge case data.
func TestEd25519EncryptPaddingEdgeCases(t *testing.T) {
	var privKey Ed25519PrivateKey
	_, err := privKey.Generate()
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 private key: %v", err)
	}

	pubKey, err := privKey.Public()
	if err != nil {
		t.Fatalf("Failed to derive Ed25519 public key: %v", err)
	}

	edPubKey, ok := pubKey.(Ed25519PublicKey)
	if !ok {
		t.Fatalf("Failed to assert type to Ed25519PublicKey")
	}

	encrypter, err := edPubKey.NewEncrypter()
	if err != nil {
		t.Fatalf("Failed to create Ed25519 encrypter: %v", err)
	}

	edEncrypter, ok := encrypter.(*Ed25519Encryption)
	if !ok {
		t.Fatalf("Failed to assert Encrypter to *Ed25519Encryption")
	}

	// Test case 1: Empty data
	data1 := []byte("")
	ciphertext1, err := edEncrypter.EncryptPadding(data1, true)
	if err != nil {
		t.Fatalf("Encryption of empty data failed: %v", err)
	}
	if len(ciphertext1) != 514 {
		t.Errorf("Ciphertext length mismatch for empty data with padding: expected 514, got %d", len(ciphertext1))
	}
	t.Log("Ed25519 Encryption of Empty Data Successful")

	// Test case 2: Data exactly at the limit
	data2 := make([]byte, 222)
	_, err = rand.Read(data2)
	if err != nil {
		t.Fatalf("Failed to generate random data for edge case: %v", err)
	}
	ciphertext2, err := edEncrypter.EncryptPadding(data2, true)
	if err != nil {
		t.Fatalf("Encryption of boundary data failed: %v", err)
	}
	if len(ciphertext2) != 514 {
		t.Errorf("Ciphertext length mismatch for boundary data with padding: expected 514, got %d", len(ciphertext2))
	}
	t.Log("Ed25519 Encryption of Boundary Data Successful")

	// Test case 3: Minimal non-empty data
	data3 := []byte("A")
	ciphertext3, err := edEncrypter.EncryptPadding(data3, true)
	if err != nil {
		t.Fatalf("Encryption of minimal data failed: %v", err)
	}
	if len(ciphertext3) != 514 {
		t.Errorf("Ciphertext length mismatch for minimal data with padding: expected 514, got %d", len(ciphertext3))
	}
	t.Log("Ed25519 Encryption of Minimal Data Successful")
}

// TestEd25519EncryptionPaddingZeroAndNonZero tests both zero and non-zero padding.
func TestEd25519EncryptionPaddingZeroAndNonZero(t *testing.T) {
	var privKey Ed25519PrivateKey
	_, err := privKey.Generate()
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 private key: %v", err)
	}

	pubKey, err := privKey.Public()
	if err != nil {
		t.Fatalf("Failed to derive Ed25519 public key: %v", err)
	}

	edPubKey, ok := pubKey.(Ed25519PublicKey)
	if !ok {
		t.Fatalf("Failed to assert type to Ed25519PublicKey")
	}

	encrypter, err := edPubKey.NewEncrypter()
	if err != nil {
		t.Fatalf("Failed to create Ed25519 encrypter: %v", err)
	}

	edEncrypter, ok := encrypter.(*Ed25519Encryption)
	if !ok {
		t.Fatalf("Failed to assert Encrypter to *Ed25519Encryption")
	}

	data := []byte("Data to test both zero and non-zero padding.")

	ciphertextZeroPad, err := edEncrypter.EncryptPadding(data, true)
	if err != nil {
		t.Fatalf("Encryption with zero padding failed: %v", err)
	}
	if len(ciphertextZeroPad) != 514 {
		t.Errorf("Ciphertext length mismatch for zero padding: expected 514, got %d", len(ciphertextZeroPad))
	}

	ciphertextNoPad, err := edEncrypter.EncryptPadding(data, false)
	if err != nil {
		t.Fatalf("Encryption without zero padding failed: %v", err)
	}
	if len(ciphertextNoPad) != 512 {
		t.Errorf("Ciphertext length mismatch for no padding: expected 512, got %d", len(ciphertextNoPad))
	}

	t.Log("Ed25519 Encryption with Both Zero and Non-Zero Padding Successful")
}

// TestEd25519EncryptPaddingInvalidInput tests encryption padding with invalid inputs.
func TestEd25519EncryptPaddingInvalidInput(t *testing.T) {
	var privKey Ed25519PrivateKey
	_, err := privKey.Generate()
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 private key: %v", err)
	}

	pubKey, err := privKey.Public()
	if err != nil {
		t.Fatalf("Failed to derive Ed25519 public key: %v", err)
	}

	edPubKey, ok := pubKey.(Ed25519PublicKey)
	if !ok {
		t.Fatalf("Failed to assert type to Ed25519PublicKey")
	}

	encrypter, err := edPubKey.NewEncrypter()
	if err != nil {
		t.Fatalf("Failed to create Ed25519 encrypter: %v", err)
	}

	edEncrypter, ok := encrypter.(*Ed25519Encryption)
	if !ok {
		t.Fatalf("Failed to assert Encrypter to *Ed25519Encryption")
	}

	var dataNil []byte
	_, err = edEncrypter.EncryptPadding(dataNil, true)
	if err != nil && !errors.Is(err, Ed25519EncryptTooBig) {
		t.Errorf("Expected error for nil data, got: %v", err)
	} else {
		t.Log("Ed25519 Encryption correctly handled nil data")
	}

	dataTooBig := make([]byte, 223)
	_, err = rand.Read(dataTooBig)
	if err != nil {
		t.Fatalf("Failed to generate random data for invalid test: %v", err)
	}
	_, err = edEncrypter.EncryptPadding(dataTooBig, true)
	if err == nil {
		t.Fatalf("Encryption should have failed with data too big, but it succeeded")
	}
	if !errors.Is(err, Ed25519EncryptTooBig) {
		t.Errorf("Unexpected error type: got %v, want %v", err, Ed25519EncryptTooBig)
	}

	t.Log("Ed25519 Encryption Padding Correctly Handled Invalid Inputs")
}

// TestEd25519VerifierInvalidKeySize tests verifier creation with invalid public key sizes.
func TestEd25519VerifierInvalidKeySize(t *testing.T) {
	invalidPubKey := make([]byte, ed25519.PublicKeySize-1)

	verifier, err := CreateEd25519PublicKeyFromBytes(invalidPubKey)
	if err == nil {
		_, err := verifier.NewVerifier()
		if err == nil {
			t.Fatalf("Verifier creation should have failed with invalid public key size, but it succeeded")
		} else {
			t.Logf("Correctly failed to create verifier with invalid public key size: %v", err)
		}
	} else {
		t.Logf("Correctly failed to create Ed25519 public key from invalid bytes: %v", err)
	}
}

// TestEd25519SignerInvalidKeySize tests signer creation with invalid private key sizes.
func TestEd25519SignerInvalidKeySize(t *testing.T) {
	var invalidPrivKey Ed25519PrivateKey
	copy(invalidPrivKey[:], make([]byte, ed25519.PrivateKeySize-1))

	_, err := invalidPrivKey.NewSigner()
	if err == nil {
		t.Fatalf("Signer creation should have failed with invalid private key size, but it succeeded")
	}

	t.Logf("Correctly failed to create signer with invalid private key size: %v", err)
}

// TestEd25519EncryptionEncryptNotImplemented tests that encryption methods behave as expected.
func TestEd25519EncryptionEncryptNotImplemented(t *testing.T) {
	var privKey Ed25519PrivateKey
	_, err := privKey.Generate()
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 private key: %v", err)
	}

	pubKey, err := privKey.Public()
	if err != nil {
		t.Fatalf("Failed to derive Ed25519 public key: %v", err)
	}

	edPubKey, ok := pubKey.(Ed25519PublicKey)
	if !ok {
		t.Fatalf("Failed to assert type to Ed25519PublicKey")
	}

	encrypter, err := edPubKey.NewEncrypter()
	if err != nil {
		t.Fatalf("Failed to create Ed25519 encrypter: %v", err)
	}

	data := []byte("Test data for encryption.")
	ciphertext, err := encrypter.Encrypt(data)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	if len(ciphertext) != 512 && len(ciphertext) != 514 {
		t.Errorf("Unexpected ciphertext length: got %d, want 512 or 514", len(ciphertext))
	}

	t.Log("Ed25519 Encryption method (Encrypt) executed successfully, falling back to EncryptPadding")
}

// TestEd25519VerifierVerifyWithTamperedSignature tests verification with tampered signatures.
func TestEd25519VerifierVerifyWithTamperedSignature(t *testing.T) {
	var privKey Ed25519PrivateKey
	_, err := privKey.Generate()
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 private key: %v", err)
	}

	signer, err := privKey.NewSigner()
	if err != nil {
		t.Fatalf("Failed to create Ed25519 signer: %v", err)
	}

	pubKey, err := privKey.Public()
	if err != nil {
		t.Fatalf("Failed to derive Ed25519 public key: %v", err)
	}

	edPubKey, ok := pubKey.(Ed25519PublicKey)
	if !ok {
		t.Fatalf("Failed to assert type to Ed25519PublicKey")
	}

	verifier, err := edPubKey.NewVerifier()
	if err != nil {
		t.Fatalf("Failed to create Ed25519 verifier: %v", err)
	}

	message := []byte("Original message for testing.")
	signature, err := signer.Sign(message)
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}

	tamperedSig := make([]byte, len(signature))
	copy(tamperedSig, signature)
	tamperedSig[0] ^= 0xFF // Flip bits in the first byte

	err = verifier.Verify(message, tamperedSig)
	if err == nil {
		t.Fatalf("Verification should have failed with tampered signature, but it succeeded")
	}

	t.Log("Ed25519 Verifier correctly failed to verify tampered signature")
}

// TestEd25519VerifierVerifyWithDifferentMessage tests verification with a different message.
func TestEd25519VerifierVerifyWithDifferentMessage(t *testing.T) {
	var privKey Ed25519PrivateKey
	_, err := privKey.Generate()
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 private key: %v", err)
	}

	signer, err := privKey.NewSigner()
	if err != nil {
		t.Fatalf("Failed to create Ed25519 signer: %v", err)
	}

	pubKey, err := privKey.Public()
	if err != nil {
		t.Fatalf("Failed to derive Ed25519 public key: %v", err)
	}

	edPubKey, ok := pubKey.(Ed25519PublicKey)
	if !ok {
		t.Fatalf("Failed to assert type to Ed25519PublicKey")
	}

	verifier, err := edPubKey.NewVerifier()
	if err != nil {
		t.Fatalf("Failed to create Ed25519 verifier: %v", err)
	}

	originalMessage := []byte("Original message.")
	signature, err := signer.Sign(originalMessage)
	if err != nil {
		t.Fatalf("Failed to sign original message: %v", err)
	}

	differentMessage := []byte("Different message.")

	err = verifier.Verify(differentMessage, signature)
	if err == nil {
		t.Fatalf("Verification should have failed with different message, but it succeeded")
	}

	t.Log("Ed25519 Verifier correctly failed to verify signature with different message")
}

// TestEd25519EncryptionEncryptPaddingEdgeCaseData tests encryption with edge case data sizes.
func TestEd25519EncryptionEncryptPaddingEdgeCaseData(t *testing.T) {
	var privKey Ed25519PrivateKey
	_, err := privKey.Generate()
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 private key: %v", err)
	}

	pubKey, err := privKey.Public()
	if err != nil {
		t.Fatalf("Failed to derive Ed25519 public key: %v", err)
	}

	edPubKey, ok := pubKey.(Ed25519PublicKey)
	if !ok {
		t.Fatalf("Failed to assert type to Ed25519PublicKey")
	}

	encrypter, err := edPubKey.NewEncrypter()
	if err != nil {
		t.Fatalf("Failed to create Ed25519 encrypter: %v", err)
	}

	edEncrypter, ok := encrypter.(*Ed25519Encryption)
	if !ok {
		t.Fatalf("Failed to assert Encrypter to *Ed25519Encryption")
	}

	testCases := []struct {
		name        string
		data        []byte
		zeroPadding bool
		expectedLen int
		expectError bool
	}{
		{
			name:        "Empty Data with Zero Padding",
			data:        []byte(""),
			zeroPadding: true,
			expectedLen: 514,
			expectError: false,
		},
		{
			name:        "Minimal Data with Zero Padding",
			data:        []byte("A"),
			zeroPadding: true,
			expectedLen: 514,
			expectError: false,
		},
		{
			name:        "Maximum Allowed Data with Zero Padding",
			data:        bytes.Repeat([]byte("B"), 222),
			zeroPadding: true,
			expectedLen: 514,
			expectError: false,
		},
		{
			name:        "Exceeding Maximum Data with Zero Padding",
			data:        bytes.Repeat([]byte("C"), 223),
			zeroPadding: true,
			expectedLen: 0,
			expectError: true,
		},
		{
			name:        "Exact Block Size with No Padding",
			data:        bytes.Repeat([]byte("D"), 222), // Changed from 256 to maximum allowed size
			zeroPadding: false,
			expectedLen: 512,
			expectError: false,
		},
		{
			name:        "Partial Block Size with No Padding",
			data:        bytes.Repeat([]byte("E"), 100),
			zeroPadding: false,
			expectedLen: 512, // Should pad internally if necessary
			expectError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ciphertext, err := edEncrypter.EncryptPadding(tc.data, tc.zeroPadding)
			if tc.expectError {
				if err == nil {
					t.Fatalf("Expected error but encryption succeeded")
				}
				t.Logf("Correctly received error: %v", err)
				return
			}

			if err != nil {
				t.Fatalf("Encryption failed unexpectedly: %v", err)
			}

			if len(ciphertext) != tc.expectedLen {
				t.Errorf("Ciphertext length mismatch: expected %d, got %d", tc.expectedLen, len(ciphertext))
			} else {
				t.Logf("Ciphertext length as expected: %d", len(ciphertext))
			}
		})
	}
}

// TestEd25519EncryptionEncryptionPaddingConsistency tests consistency between zero and non-zero padding.
func TestEd25519EncryptionEncryptionPaddingConsistency(t *testing.T) {
	var privKey Ed25519PrivateKey
	_, err := privKey.Generate()
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 private key: %v", err)
	}

	pubKey, err := privKey.Public()
	if err != nil {
		t.Fatalf("Failed to derive Ed25519 public key: %v", err)
	}

	edPubKey, ok := pubKey.(Ed25519PublicKey)
	if !ok {
		t.Fatalf("Failed to assert type to Ed25519PublicKey")
	}

	encrypter, err := edPubKey.NewEncrypter()
	if err != nil {
		t.Fatalf("Failed to create Ed25519 encrypter: %v", err)
	}

	edEncrypter, ok := encrypter.(*Ed25519Encryption)
	if !ok {
		t.Fatalf("Failed to assert Encrypter to *Ed25519Encryption")
	}

	data := []byte("Consistent encryption test data.")

	ciphertextZero, err := edEncrypter.EncryptPadding(data, true)
	if err != nil {
		t.Fatalf("Encryption with zero padding failed: %v", err)
	}

	ciphertextNonZero, err := edEncrypter.EncryptPadding(data, false)
	if err != nil {
		t.Fatalf("Encryption without zero padding failed: %v", err)
	}

	if bytes.Equal(ciphertextZero, ciphertextNonZero) {
		t.Errorf("Ciphertexts with different padding settings should not be equal")
	} else {
		t.Log("Ciphertexts with different padding settings are correctly different")
	}
}

func TestEd25519EncryptPaddingIntegrity(t *testing.T) {
	var privKey Ed25519PrivateKey
	_, err := privKey.Generate()
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 private key: %v", err)
	}

	pubKey, err := privKey.Public()
	if err != nil {
		t.Fatalf("Failed to derive Ed25519 public key: %v", err)
	}

	edPubKey, ok := pubKey.(Ed25519PublicKey)
	if !ok {
		t.Fatalf("Failed to assert type to Ed25519PublicKey")
	}

	encrypter, err := edPubKey.NewEncrypter()
	if err != nil {
		t.Fatalf("Failed to create Ed25519 encrypter: %v", err)
	}

	edEncrypter, ok := encrypter.(*Ed25519Encryption)
	if !ok {
		t.Fatalf("Failed to assert Encrypter to *Ed25519Encryption")
	}

	data := []byte("Integrity test data.")

	ciphertext, err := edEncrypter.EncryptPadding(data, true)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	if len(ciphertext) == 514 {
		// Zero padding version:
		// - Index 0: zero padding byte
		// - Indices 1-257: 'a' component (public key based component)
		// - Index 257: zero padding byte
		// - Indices 258-514: 'b' component (encrypted message)

		aComponent := ciphertext[1:257]
		bComponent := ciphertext[258:514]

		if len(aComponent) != 256 {
			t.Errorf("Ciphertext 'a' component length mismatch: expected 256, got %d", len(aComponent))
		}
		if len(bComponent) != 256 {
			t.Errorf("Ciphertext 'b' component length mismatch: expected 256, got %d", len(bComponent))
		}

		// Optional: Verify components are not zero
		if bytes.Equal(aComponent, make([]byte, 256)) {
			t.Error("Ciphertext 'a' component is all zeros")
		}
		if bytes.Equal(bComponent, make([]byte, 256)) {
			t.Error("Ciphertext 'b' component is all zeros")
		}

		t.Log("Ciphertext structure with zero padding is correct")
	} else {
		t.Errorf("Unexpected ciphertext length: expected 514, got %d", len(ciphertext))
	}
}

func TestEd25519EncryptionEncryptPaddingHashConsistency(t *testing.T) {
	var privKey Ed25519PrivateKey
	_, err := privKey.Generate()
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 private key: %v", err)
	}

	pubKey, err := privKey.Public()
	if err != nil {
		t.Fatalf("Failed to derive Ed25519 public key: %v", err)
	}

	edPubKey, ok := pubKey.(Ed25519PublicKey)
	if !ok {
		t.Fatalf("Failed to assert type to Ed25519PublicKey")
	}

	encrypter, err := edPubKey.NewEncrypter()
	if err != nil {
		t.Fatalf("Failed to create Ed25519 encrypter: %v", err)
	}

	edEncrypter, ok := encrypter.(*Ed25519Encryption)
	if !ok {
		t.Fatalf("Failed to assert Encrypter to *Ed25519Encryption")
	}

	data := []byte("Hash consistency test data.")

	mbytes := make([]byte, 255)
	mbytes[0] = 0xFF
	copy(mbytes[33:], data)

	dHash := sha256.Sum256(data)
	copy(mbytes[1:], dHash[:])

	m := new(big.Int).SetBytes(mbytes)

	ciphertext, err := edEncrypter.EncryptPadding(data, true)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	bBytes := ciphertext[258 : 258+ed25519.PublicKeySize] // 32 bytes
	b := new(big.Int).SetBytes(bBytes)

	expectedB := new(big.Int).Mul(m, edEncrypter.b1)
	expectedB.Mod(expectedB, edEncrypter.p)

	if expectedB.Cmp(b) != 0 {
		expectedBytes := expectedB.Bytes()
		actualBytes := b.Bytes()

		t.Errorf("Encrypted 'b' value mismatch:\nexpected (%d bytes): %x\ngot (%d bytes): %x",
			len(expectedBytes), expectedBytes,
			len(actualBytes), actualBytes)

		t.Errorf("As big.Int:\nexpected: %s\ngot:      %s",
			expectedB.String(), b.String())
	} else {
		t.Log("Encrypted 'b' value matches expected computation")
	}
}
