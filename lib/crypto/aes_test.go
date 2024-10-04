package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

func TestAESEncryptDecrypt(t *testing.T) {
	key := make([]byte, 32) // 256-bit key
	iv := make([]byte, aes.BlockSize)
	_, err := rand.Read(key)
	if err != nil {
		t.Fatalf("Failed to generate random key: %v", err)
	}
	_, err = rand.Read(iv)
	if err != nil {
		t.Fatalf("Failed to generate random IV: %v", err)
	}

	testCases := []struct {
		name      string
		plaintext []byte
	}{
		{"Empty string", []byte("")},
		{"Short string", []byte("Hello, World!")},
		{"Long string", bytes.Repeat([]byte("A"), 1000)},
		{"Exact block size", bytes.Repeat([]byte("A"), aes.BlockSize)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ciphertext, err := aesEncrypt(key, iv, tc.plaintext)
			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}

			decrypted, err := aesDecrypt(key, iv, ciphertext)
			if err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}

			if !bytes.Equal(tc.plaintext, decrypted) {
				t.Errorf("Decrypted text doesn't match original plaintext.\nOriginal: %s\nDecrypted: %s",
					hex.EncodeToString(tc.plaintext), hex.EncodeToString(decrypted))
			}
		})
	}
}

func TestAESEncryptInvalidKey(t *testing.T) {
	invalidKeys := [][]byte{
		make([]byte, 15), // Too short
		make([]byte, 33), // Too long
		make([]byte, 0),  // Empty
		nil,              // Nil
	}

	plaintext := []byte("Test plaintext")
	iv := make([]byte, aes.BlockSize)

	for _, key := range invalidKeys {
		_, err := aesEncrypt(key, iv, plaintext)
		if err == nil {
			t.Errorf("Expected error for invalid key length %d, but got none", len(key))
		}
	}
}

func TestAESDecryptInvalidInput(t *testing.T) {
	key := make([]byte, 32)
	iv := make([]byte, aes.BlockSize)
	_, _ = rand.Read(key)
	_, _ = rand.Read(iv)

	invalidCiphertexts := [][]byte{
		make([]byte, 15), // Not a multiple of block size
		make([]byte, 0),  // Empty
		nil,              // Nil
	}

	for _, ciphertext := range invalidCiphertexts {
		_, err := aesDecrypt(key, iv, ciphertext)
		if err == nil {
			t.Errorf("Expected error for invalid ciphertext length %d, but got none", len(ciphertext))
		}
	}
}

func TestPKCS7PadUnpad(t *testing.T) {
	testCases := []struct {
		name      string
		input     []byte
		blockSize int
	}{
		{"Empty input", []byte{}, 16},
		{"Exact block size", bytes.Repeat([]byte("A"), 16), 16},
		{"One byte short", bytes.Repeat([]byte("A"), 15), 16},
		{"Multiple blocks", bytes.Repeat([]byte("A"), 32), 16},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			padded := pkcs7Pad(tc.input, tc.blockSize)
			if len(padded)%tc.blockSize != 0 {
				t.Errorf("Padded data length (%d) is not a multiple of block size (%d)", len(padded), tc.blockSize)
			}

			unpadded, err := pkcs7Unpad(padded)
			if err != nil {
				t.Fatalf("Unpadding failed: %v", err)
			}

			if !bytes.Equal(tc.input, unpadded) {
				t.Errorf("Unpadded data doesn't match original input.\nOriginal: %s\nUnpadded: %s",
					hex.EncodeToString(tc.input), hex.EncodeToString(unpadded))
			}
		})
	}
}

func TestPKCS7UnpadInvalidInput(t *testing.T) {
	invalidInputs := []struct {
		name  string
		input []byte
	}{
		{"Empty slice", []byte{}},
		{"Too short", []byte{1, 2, 3}},
		{"Invalid padding value", []byte{1, 2, 3, 4, 5}},
		{"Padding larger than block size", append(bytes.Repeat([]byte{17}, 17))},
		{"Incorrect padding", append(bytes.Repeat([]byte{4}, 12))},
		{"Padding larger than data", []byte{5, 5, 5, 5, 5}},
		{"Valid block size but invalid padding", append(bytes.Repeat([]byte{1}, 15), 3)},
	}

	for _, tc := range invalidInputs {
		t.Run(tc.name, func(t *testing.T) {
			_, err := pkcs7Unpad(tc.input)
			if err == nil {
				t.Errorf("Expected error for invalid input %v, but got none", tc.input)
			}
		})
	}
}
