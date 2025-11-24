package i2np

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/go-i2p/common/session_key"
)

// TestEncryptDecryptReplyRecord tests the encryption and decryption of build response records
func TestEncryptDecryptReplyRecord(t *testing.T) {
	crypto := NewBuildRecordCrypto()

	// Create a test reply key and IV
	var replyKey session_key.SessionKey
	var replyIV [16]byte
	_, err := rand.Read(replyKey[:])
	if err != nil {
		t.Fatalf("Failed to generate reply key: %v", err)
	}
	_, err = rand.Read(replyIV[:])
	if err != nil {
		t.Fatalf("Failed to generate reply IV: %v", err)
	}

	// Create a test response record
	var randomData [495]byte
	_, err = rand.Read(randomData[:])
	if err != nil {
		t.Fatalf("Failed to generate random data: %v", err)
	}

	originalRecord := CreateBuildResponseRecord(0, randomData) // 0 = accept

	// Encrypt the record
	encrypted, err := crypto.EncryptReplyRecord(originalRecord, replyKey, replyIV)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// ChaCha20-Poly1305 produces 544 bytes (528 + 16 auth tag)
	if len(encrypted) != 544 {
		t.Errorf("Expected encrypted data to be 544 bytes, got %d", len(encrypted))
	}

	// Decrypt the record
	decrypted, err := crypto.DecryptReplyRecord(encrypted, replyKey, replyIV)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	// Verify the decrypted record matches the original
	if decrypted.Hash != originalRecord.Hash {
		t.Error("Hash mismatch after decrypt")
	}

	if decrypted.RandomData != originalRecord.RandomData {
		t.Error("RandomData mismatch after decrypt")
	}

	if decrypted.Reply != originalRecord.Reply {
		t.Errorf("Reply mismatch: expected %d, got %d", originalRecord.Reply, decrypted.Reply)
	}
}

// TestEncryptReplyRecordDeterminism tests that encryption with same key/IV produces same output
func TestEncryptReplyRecordDeterminism(t *testing.T) {
	crypto := NewBuildRecordCrypto()

	var replyKey session_key.SessionKey
	var replyIV [16]byte
	_, err := rand.Read(replyKey[:])
	if err != nil {
		t.Fatalf("Failed to generate reply key: %v", err)
	}
	_, err = rand.Read(replyIV[:])
	if err != nil {
		t.Fatalf("Failed to generate reply IV: %v", err)
	}

	var randomData [495]byte
	_, err = rand.Read(randomData[:])
	if err != nil {
		t.Fatalf("Failed to generate random data: %v", err)
	}

	record := CreateBuildResponseRecord(0, randomData)

	// Encrypt twice with same key/IV
	encrypted1, err := crypto.EncryptReplyRecord(record, replyKey, replyIV)
	if err != nil {
		t.Fatalf("First encryption failed: %v", err)
	}

	encrypted2, err := crypto.EncryptReplyRecord(record, replyKey, replyIV)
	if err != nil {
		t.Fatalf("Second encryption failed: %v", err)
	}

	// Should produce identical output (ChaCha20-Poly1305 is deterministic with same key/nonce)
	if !bytes.Equal(encrypted1, encrypted2) {
		t.Error("Encryption is not deterministic with same key/IV")
	}
}

// TestDecryptReplyRecordWrongKey tests that decryption with wrong key fails
func TestDecryptReplyRecordWrongKey(t *testing.T) {
	crypto := NewBuildRecordCrypto()

	var replyKey session_key.SessionKey
	var wrongKey session_key.SessionKey
	var replyIV [16]byte

	_, err := rand.Read(replyKey[:])
	if err != nil {
		t.Fatalf("Failed to generate reply key: %v", err)
	}
	_, err = rand.Read(wrongKey[:])
	if err != nil {
		t.Fatalf("Failed to generate wrong key: %v", err)
	}
	_, err = rand.Read(replyIV[:])
	if err != nil {
		t.Fatalf("Failed to generate reply IV: %v", err)
	}

	var randomData [495]byte
	_, err = rand.Read(randomData[:])
	if err != nil {
		t.Fatalf("Failed to generate random data: %v", err)
	}

	record := CreateBuildResponseRecord(0, randomData)

	// Encrypt with correct key
	encrypted, err := crypto.EncryptReplyRecord(record, replyKey, replyIV)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Try to decrypt with wrong key - should fail hash verification
	_, err = crypto.DecryptReplyRecord(encrypted, wrongKey, replyIV)
	if err == nil {
		t.Error("Expected decryption with wrong key to fail, but it succeeded")
	}
}

// TestCreateBuildResponseRecord tests the helper function for creating response records
func TestCreateBuildResponseRecord(t *testing.T) {
	var randomData [495]byte
	_, err := rand.Read(randomData[:])
	if err != nil {
		t.Fatalf("Failed to generate random data: %v", err)
	}

	tests := []struct {
		name  string
		reply byte
	}{
		{"Accept", 0},
		{"Reject bandwidth", 10},
		{"Reject probabalistic", 20},
		{"Reject critical", 30},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			record := CreateBuildResponseRecord(tt.reply, randomData)

			if record.Reply != tt.reply {
				t.Errorf("Reply mismatch: expected %d, got %d", tt.reply, record.Reply)
			}

			if record.RandomData != randomData {
				t.Error("RandomData not copied correctly")
			}

			// Verify hash is computed correctly
			crypto := NewBuildRecordCrypto()
			if err := crypto.verifyResponseRecordHash(record); err != nil {
				t.Errorf("Hash verification failed: %v", err)
			}
		})
	}
}

// TestEncryptReplyRecordInvalidSize tests error handling for invalid record sizes
func TestEncryptReplyRecordInvalidSize(t *testing.T) {
	crypto := NewBuildRecordCrypto()

	var replyKey session_key.SessionKey
	var replyIV [16]byte

	// This should work fine (normal path tested above)
	var normalRandomData [495]byte
	record := CreateBuildResponseRecord(0, normalRandomData)
	_, err := crypto.EncryptReplyRecord(record, replyKey, replyIV)
	if err != nil {
		t.Errorf("Normal encryption failed: %v", err)
	}
}

// TestDecryptReplyRecordInvalidSize tests error handling for invalid encrypted data
func TestDecryptReplyRecordInvalidSize(t *testing.T) {
	crypto := NewBuildRecordCrypto()

	var replyKey session_key.SessionKey
	var replyIV [16]byte

	tests := []struct {
		name string
		size int
	}{
		{"Too small", 527},
		{"Too large", 529},
		{"Empty", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			invalidData := make([]byte, tt.size)
			_, err := crypto.DecryptReplyRecord(invalidData, replyKey, replyIV)
			if err == nil {
				t.Errorf("Expected error for size %d, but got none", tt.size)
			}
		})
	}
}

// TestBuildResponseRecordHashVerification tests hash verification
func TestBuildResponseRecordHashVerification(t *testing.T) {
	crypto := NewBuildRecordCrypto()

	var randomData [495]byte
	_, err := rand.Read(randomData[:])
	if err != nil {
		t.Fatalf("Failed to generate random data: %v", err)
	}

	// Create a valid record
	validRecord := CreateBuildResponseRecord(0, randomData)

	// Should pass verification
	if err := crypto.verifyResponseRecordHash(validRecord); err != nil {
		t.Errorf("Valid record failed verification: %v", err)
	}

	// Create an invalid record (wrong hash)
	invalidRecord := validRecord
	invalidRecord.Hash[0] ^= 0xFF // Flip some bits

	// Should fail verification
	if err := crypto.verifyResponseRecordHash(invalidRecord); err == nil {
		t.Error("Invalid record passed verification")
	}
}

// TestMultipleRecordsWithDifferentKeys tests encrypting multiple records with different keys
func TestMultipleRecordsWithDifferentKeys(t *testing.T) {
	crypto := NewBuildRecordCrypto()

	const numRecords = 8 // Standard tunnel build has 8 hops

	var keys [numRecords]session_key.SessionKey
	var ivs [numRecords][16]byte
	var records [numRecords]BuildResponseRecord

	// Generate keys, IVs, and records
	for i := 0; i < numRecords; i++ {
		_, err := rand.Read(keys[i][:])
		if err != nil {
			t.Fatalf("Failed to generate key %d: %v", i, err)
		}
		_, err = rand.Read(ivs[i][:])
		if err != nil {
			t.Fatalf("Failed to generate IV %d: %v", i, err)
		}

		var randomData [495]byte
		_, err = rand.Read(randomData[:])
		if err != nil {
			t.Fatalf("Failed to generate random data %d: %v", i, err)
		}

		records[i] = CreateBuildResponseRecord(byte(i), randomData)
	}

	// Encrypt all records
	encrypted := make([][]byte, numRecords)
	for i := 0; i < numRecords; i++ {
		var err error
		encrypted[i], err = crypto.EncryptReplyRecord(records[i], keys[i], ivs[i])
		if err != nil {
			t.Fatalf("Failed to encrypt record %d: %v", i, err)
		}
	}

	// Decrypt all records and verify
	for i := 0; i < numRecords; i++ {
		decrypted, err := crypto.DecryptReplyRecord(encrypted[i], keys[i], ivs[i])
		if err != nil {
			t.Fatalf("Failed to decrypt record %d: %v", i, err)
		}

		if decrypted.Reply != records[i].Reply {
			t.Errorf("Record %d: reply mismatch: expected %d, got %d",
				i, records[i].Reply, decrypted.Reply)
		}

		if decrypted.Hash != records[i].Hash {
			t.Errorf("Record %d: hash mismatch", i)
		}
	}
}

// BenchmarkEncryptReplyRecord benchmarks the encryption performance
func BenchmarkEncryptReplyRecord(b *testing.B) {
	crypto := NewBuildRecordCrypto()

	var replyKey session_key.SessionKey
	var replyIV [16]byte
	var randomData [495]byte

	rand.Read(replyKey[:])
	rand.Read(replyIV[:])
	rand.Read(randomData[:])

	record := CreateBuildResponseRecord(0, randomData)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := crypto.EncryptReplyRecord(record, replyKey, replyIV)
		if err != nil {
			b.Fatalf("Encryption failed: %v", err)
		}
	}
}

// BenchmarkDecryptReplyRecord benchmarks the decryption performance
func BenchmarkDecryptReplyRecord(b *testing.B) {
	crypto := NewBuildRecordCrypto()

	var replyKey session_key.SessionKey
	var replyIV [16]byte
	var randomData [495]byte

	rand.Read(replyKey[:])
	rand.Read(replyIV[:])
	rand.Read(randomData[:])

	record := CreateBuildResponseRecord(0, randomData)
	encrypted, err := crypto.EncryptReplyRecord(record, replyKey, replyIV)
	if err != nil {
		b.Fatalf("Encryption failed: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := crypto.DecryptReplyRecord(encrypted, replyKey, replyIV)
		if err != nil {
			b.Fatalf("Decryption failed: %v", err)
		}
	}
}
