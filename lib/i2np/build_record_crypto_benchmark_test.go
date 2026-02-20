package i2np

import (
	"testing"

	"github.com/go-i2p/common/session_key"
	"github.com/go-i2p/crypto/rand"
	"github.com/go-i2p/go-i2p/lib/keys"
	"github.com/stretchr/testify/require"
)

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
