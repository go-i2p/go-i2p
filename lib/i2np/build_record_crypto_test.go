package i2np

import (
	"bytes"
	"github.com/go-i2p/crypto/types"
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/session_key"
	"github.com/go-i2p/crypto/rand"
	"github.com/go-i2p/go-i2p/lib/keys"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

// ============================================================================
// BuildRequestRecord Encryption Tests
// ============================================================================

// TestEncryptDecryptBuildRequestRecord tests the full encryption/decryption cycle
func TestEncryptDecryptBuildRequestRecord(t *testing.T) {
	// Create a router with keys
	keystore, err := keys.NewRouterInfoKeystore(t.TempDir(), "test-router")
	require.NoError(t, err, "Failed to create keystore")

	// Construct RouterInfo
	routerInfo, err := keystore.ConstructRouterInfo(nil)
	require.NoError(t, err, "Failed to construct RouterInfo")

	// Create a test BuildRequestRecord
	originalRecord := createTestBuildRequestRecord(t)

	// Encrypt the record
	encrypted, err := EncryptBuildRequestRecord(originalRecord, *routerInfo)
	require.NoError(t, err, "Encryption should succeed")

	// Verify encrypted size
	assert.Equal(t, 528, len(encrypted), "Encrypted record should be 528 bytes")

	// Get the private key for decryption
	privKey := keystore.GetEncryptionPrivateKey()

	// Decrypt the record
	decrypted, err := DecryptBuildRequestRecord(encrypted, privKey.Bytes())
	require.NoError(t, err, "Decryption should succeed")

	// Verify all fields match
	assert.Equal(t, originalRecord.ReceiveTunnel, decrypted.ReceiveTunnel, "ReceiveTunnel should match")
	assert.Equal(t, originalRecord.OurIdent, decrypted.OurIdent, "OurIdent should match")
	assert.Equal(t, originalRecord.NextTunnel, decrypted.NextTunnel, "NextTunnel should match")
	assert.Equal(t, originalRecord.NextIdent, decrypted.NextIdent, "NextIdent should match")
	assert.Equal(t, originalRecord.LayerKey, decrypted.LayerKey, "LayerKey should match")
	assert.Equal(t, originalRecord.IVKey, decrypted.IVKey, "IVKey should match")
	assert.Equal(t, originalRecord.ReplyKey, decrypted.ReplyKey, "ReplyKey should match")
	assert.Equal(t, originalRecord.ReplyIV, decrypted.ReplyIV, "ReplyIV should match")
	assert.Equal(t, originalRecord.Flag, decrypted.Flag, "Flag should match")
	assert.Equal(t, originalRecord.SendMessageID, decrypted.SendMessageID, "SendMessageID should match")
}

// TestEncryptBuildRequestRecordIdentityHash verifies the identity hash prefix
func TestEncryptBuildRequestRecordIdentityHash(t *testing.T) {
	// Create router with keys
	keystore, err := keys.NewRouterInfoKeystore(t.TempDir(), "test-router")
	require.NoError(t, err)

	routerInfo, err := keystore.ConstructRouterInfo(nil)
	require.NoError(t, err)

	// Create test record
	record := createTestBuildRequestRecord(t)

	// Encrypt
	encrypted, err := EncryptBuildRequestRecord(record, *routerInfo)
	require.NoError(t, err)

	// Calculate expected identity hash
	identity := routerInfo.RouterIdentity()
	identityBytes, _ := identity.KeysAndCert.Bytes()
	expectedHash := types.SHA256(identityBytes)

	// Verify first 16 bytes match
	for i := 0; i < 16; i++ {
		assert.Equal(t, expectedHash[i], encrypted[i], "Identity hash prefix byte %d should match", i)
	}
}

// TestVerifyIdentityHash tests the identity hash verification function
func TestVerifyIdentityHash(t *testing.T) {
	// Create router with keys
	keystore, err := keys.NewRouterInfoKeystore(t.TempDir(), "test-router")
	require.NoError(t, err)

	routerInfo, err := keystore.ConstructRouterInfo(nil)
	require.NoError(t, err)

	// Create and encrypt record
	record := createTestBuildRequestRecord(t)
	encrypted, err := EncryptBuildRequestRecord(record, *routerInfo)
	require.NoError(t, err)

	// Verify with correct RouterInfo
	assert.True(t, VerifyIdentityHash(encrypted, *routerInfo), "Should verify successfully with correct RouterInfo")

	// Create different router
	keystore2, err := keys.NewRouterInfoKeystore(t.TempDir(), "different-router")
	require.NoError(t, err)

	routerInfo2, err := keystore2.ConstructRouterInfo(nil)
	require.NoError(t, err)

	// Verify with wrong RouterInfo
	assert.False(t, VerifyIdentityHash(encrypted, *routerInfo2), "Should fail verification with different RouterInfo")
}

// TestDecryptWithWrongKey verifies decryption fails with wrong key
func TestDecryptWithWrongKey(t *testing.T) {
	// Create first router
	keystore1, err := keys.NewRouterInfoKeystore(t.TempDir(), "router1")
	require.NoError(t, err)

	routerInfo1, err := keystore1.ConstructRouterInfo(nil)
	require.NoError(t, err)

	// Create and encrypt record for router1
	record := createTestBuildRequestRecord(t)
	encrypted, err := EncryptBuildRequestRecord(record, *routerInfo1)
	require.NoError(t, err)

	// Create second router with different key
	keystore2, err := keys.NewRouterInfoKeystore(t.TempDir(), "router2")
	require.NoError(t, err)

	privKey2 := keystore2.GetEncryptionPrivateKey()

	// Attempt to decrypt with wrong key
	_, err = DecryptBuildRequestRecord(encrypted, privKey2.Bytes())
	assert.Error(t, err, "Decryption should fail with wrong key")
}

// TestEncryptBuildRequestRecordNonDeterministic verifies encryption is non-deterministic
func TestEncryptBuildRequestRecordNonDeterministic(t *testing.T) {
	// Create router
	keystore, err := keys.NewRouterInfoKeystore(t.TempDir(), "test-router")
	require.NoError(t, err)

	routerInfo, err := keystore.ConstructRouterInfo(nil)
	require.NoError(t, err)

	// Create same record
	record := createTestBuildRequestRecord(t)

	// Encrypt twice
	encrypted1, err := EncryptBuildRequestRecord(record, *routerInfo)
	require.NoError(t, err)

	encrypted2, err := EncryptBuildRequestRecord(record, *routerInfo)
	require.NoError(t, err)

	// Identity hash prefix should be the same (first 16 bytes)
	assert.Equal(t, encrypted1[:16], encrypted2[:16], "Identity hash prefix should match")

	// Ciphertext should differ due to different ephemeral keys
	assert.NotEqual(t, encrypted1[16:], encrypted2[16:], "Ciphertext should differ (ephemeral keys)")
}

// TestExtractIdentityHashPrefix tests the helper function
func TestExtractIdentityHashPrefix(t *testing.T) {
	// Create router
	keystore, err := keys.NewRouterInfoKeystore(t.TempDir(), "test-router")
	require.NoError(t, err)

	routerInfo, err := keystore.ConstructRouterInfo(nil)
	require.NoError(t, err)

	// Create and encrypt record
	record := createTestBuildRequestRecord(t)
	encrypted, err := EncryptBuildRequestRecord(record, *routerInfo)
	require.NoError(t, err)

	// Extract prefix
	prefix := ExtractIdentityHashPrefix(encrypted)

	// Verify first 16 bytes match
	for i := 0; i < 16; i++ {
		assert.Equal(t, encrypted[i], prefix[i], "Prefix byte %d should match", i)
	}

	// Verify remaining bytes are zero (Hash is 32 bytes)
	for i := 16; i < 32; i++ {
		assert.Equal(t, byte(0), prefix[i], "Remaining byte %d should be zero", i)
	}
}

// TestMultipleEncryptDecryptCycles tests multiple encryption/decryption rounds
func TestMultipleEncryptDecryptCycles(t *testing.T) {
	// Create router
	keystore, err := keys.NewRouterInfoKeystore(t.TempDir(), "test-router")
	require.NoError(t, err)

	routerInfo, err := keystore.ConstructRouterInfo(nil)
	require.NoError(t, err)

	privKey := keystore.GetEncryptionPrivateKey()

	// Test 10 cycles with different records
	for i := 0; i < 10; i++ {
		record := createTestBuildRequestRecord(t)
		record.SendMessageID = i // Make each record unique

		encrypted, err := EncryptBuildRequestRecord(record, *routerInfo)
		require.NoError(t, err, "Encryption cycle %d should succeed", i)

		decrypted, err := DecryptBuildRequestRecord(encrypted, privKey.Bytes())
		require.NoError(t, err, "Decryption cycle %d should succeed", i)

		assert.Equal(t, record.SendMessageID, decrypted.SendMessageID, "Message ID should match in cycle %d", i)
	}
}

// BenchmarkEncryptBuildRequestRecord benchmarks encryption performance
func BenchmarkEncryptBuildRequestRecord(b *testing.B) {
	keystore, err := keys.NewRouterInfoKeystore(b.TempDir(), "bench-router")
	require.NoError(b, err)

	routerInfo, err := keystore.ConstructRouterInfo(nil)
	require.NoError(b, err)

	record := createTestBuildRequestRecord(b)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := EncryptBuildRequestRecord(record, *routerInfo)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkDecryptBuildRequestRecord benchmarks decryption performance
func BenchmarkDecryptBuildRequestRecord(b *testing.B) {
	keystore, err := keys.NewRouterInfoKeystore(b.TempDir(), "bench-router")
	require.NoError(b, err)

	routerInfo, err := keystore.ConstructRouterInfo(nil)
	require.NoError(b, err)

	privKey := keystore.GetEncryptionPrivateKey()

	record := createTestBuildRequestRecord(b)
	encrypted, err := EncryptBuildRequestRecord(record, *routerInfo)
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := DecryptBuildRequestRecord(encrypted, privKey.Bytes())
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Helper function to create a test BuildRequestRecord with randomized data
func createTestBuildRequestRecord(t testing.TB) BuildRequestRecord {
	t.Helper()

	var layerKey, ivKey, replyKey session_key.SessionKey
	var replyIV [16]byte
	var padding [29]byte
	var ourIdent, nextIdent common.Hash

	// Fill with random data
	rand.Read(layerKey[:])
	rand.Read(ivKey[:])
	rand.Read(replyKey[:])
	rand.Read(replyIV[:])
	rand.Read(padding[:])
	rand.Read(ourIdent[:])
	rand.Read(nextIdent[:])

	return BuildRequestRecord{
		ReceiveTunnel: tunnel.TunnelID(12345),
		OurIdent:      ourIdent,
		NextTunnel:    tunnel.TunnelID(67890),
		NextIdent:     nextIdent,
		LayerKey:      layerKey,
		IVKey:         ivKey,
		ReplyKey:      replyKey,
		ReplyIV:       replyIV,
		Flag:          0,
		RequestTime:   time.Now(),
		SendMessageID: 42,
		Padding:       padding,
	}
}
