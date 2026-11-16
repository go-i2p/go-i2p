package i2np

import (
	"testing"

	"github.com/go-i2p/crypto/ecies"
)

// fuzzPrivateKey returns a valid Curve25519 private key for the STBM record
// decrypt path (a zero key is rejected by key derivation).
func fuzzPrivateKey(tb testing.TB) []byte {
	tb.Helper()
	_, priv, err := ecies.GenerateKeyPair()
	if err != nil {
		tb.Fatalf("GenerateKeyPair failed: %v", err)
	}
	return priv
}

// FuzzBuildRecordCrypto exercises the Short Tunnel Build Request record decrypt
// path (ECIES + AES-256-CBC + SHA-256 over a fixed 218-byte ciphertext). This
// is the build-record crypto the C3 audit flagged as unfuzzed: a panic while
// decrypting a remote-supplied build record would crash the tunnel builder.
// The input is arbitrary bytes copied into the fixed-size ciphertext array, so
// the fuzzer explores malformed ciphertext against the real decrypt chain.
func FuzzBuildRecordCrypto(f *testing.F) {
	f.Add(make([]byte, 218))
	seed := make([]byte, 218)
	for i := range seed {
		seed[i] = byte(i)
	}
	f.Add(seed)
	f.Add(make([]byte, 0))
	f.Add(make([]byte, 64))

	// Generate the key once, outside the fuzz loop (key derivation is expensive).
	priv := fuzzPrivateKey(f)

	f.Fuzz(func(t *testing.T, data []byte) {
		var enc [218]byte
		copy(enc[:], data)
		// Must return an error on malformed ciphertext, not panic.
		_, _ = DecryptShortBuildRequestRecord(enc, priv)
	})
}
