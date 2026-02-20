package bootstrap

import (
	"bytes"
	"testing"
	"time"

	"github.com/go-i2p/crypto/rand"

	"github.com/go-i2p/common/certificate"
	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/keys_and_cert"
	"github.com/go-i2p/common/router_address"
	"github.com/go-i2p/common/router_identity"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/common/signature"
	"github.com/go-i2p/crypto/ed25519"
	elgamal "github.com/go-i2p/crypto/elg"
	"github.com/go-i2p/crypto/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createSignedTestRouterInfo creates a properly signed RouterInfo for testing.
// Uses Ed25519 signing keys and ElGamal encryption keys, matching the I2P standard.
func createSignedTestRouterInfo(t *testing.T, options map[string]string) *router_info.RouterInfo {
	t.Helper()

	// Generate Ed25519 signing key pair
	ed25519PrivKey, err := ed25519.GenerateEd25519Key()
	require.NoError(t, err, "Failed to generate Ed25519 key")

	ed25519PrivKeyTyped := ed25519PrivKey.(ed25519.Ed25519PrivateKey)
	ed25519PubKeyRaw, err := ed25519PrivKeyTyped.Public()
	require.NoError(t, err, "Failed to derive Ed25519 public key")

	ed25519PubKey, ok := ed25519PubKeyRaw.(types.SigningPublicKey)
	require.True(t, ok, "Failed to cast Ed25519 public key")

	// Generate ElGamal encryption key pair
	var elgPrivKey elgamal.PrivateKey
	err = elgamal.ElgamalGenerate(&elgPrivKey.PrivateKey, rand.Reader)
	require.NoError(t, err, "Failed to generate ElGamal key")

	var elgPubKey elgamal.ElgPublicKey
	yBytes := elgPrivKey.PublicKey.Y.Bytes()
	require.LessOrEqual(t, len(yBytes), 256, "ElGamal public key Y too large")
	copy(elgPubKey[256-len(yBytes):], yBytes)

	// Create KEY certificate for Ed25519/ElGamal
	var payload bytes.Buffer
	signingType, err := common.NewIntegerFromInt(7, 2) // Ed25519
	require.NoError(t, err)
	cryptoType, err := common.NewIntegerFromInt(0, 2) // ElGamal
	require.NoError(t, err)
	payload.Write(*signingType)
	payload.Write(*cryptoType)

	cert, err := certificate.NewCertificateWithType(certificate.CERT_KEY, payload.Bytes())
	require.NoError(t, err, "Failed to create certificate")

	keyCert, err := key_certificate.KeyCertificateFromCertificate(cert)
	require.NoError(t, err, "Failed to create key certificate")

	// Create padding
	pubKeySize := keyCert.CryptoSize()
	sigKeySize := keyCert.SigningPublicKeySize()
	paddingSize := keys_and_cert.KEYS_AND_CERT_DATA_SIZE - pubKeySize - sigKeySize
	padding := make([]byte, paddingSize)
	_, err = rand.Read(padding)
	require.NoError(t, err, "Failed to generate padding")

	// Create RouterIdentity
	routerIdentity, err := router_identity.NewRouterIdentity(elgPubKey, ed25519PubKey, cert, padding)
	require.NoError(t, err, "Failed to create router identity")

	// Create router address with NTCP2 and direct connectivity
	routerAddr, err := router_address.NewRouterAddress(3, time.Now().Add(24*time.Hour), "NTCP2", map[string]string{
		"host": "192.168.1.1",
		"port": "12345",
	})
	require.NoError(t, err, "Failed to create router address")

	// Merge default options with provided options
	mergedOptions := map[string]string{"router.version": "0.9.64"}
	for k, v := range options {
		mergedOptions[k] = v
	}

	// Create RouterInfo (this signs it with the private key)
	ri, err := router_info.NewRouterInfo(
		routerIdentity,
		time.Now(),
		[]*router_address.RouterAddress{routerAddr},
		mergedOptions,
		&ed25519PrivKeyTyped,
		signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519,
	)
	require.NoError(t, err, "Failed to create RouterInfo")

	return ri
}

// TestVerifyRouterInfoSignature_ValidSignature verifies that a properly signed
// RouterInfo passes signature verification.
func TestVerifyRouterInfoSignature_ValidSignature(t *testing.T) {
	ri := createSignedTestRouterInfo(t, nil)
	err := VerifyRouterInfoSignature(*ri)
	assert.NoError(t, err, "Valid RouterInfo signature should pass verification")
}

// TestVerifyRouterInfoSignature_ValidWithOptions verifies that RouterInfos with
// various option configurations still pass signature verification.
func TestVerifyRouterInfoSignature_ValidWithOptions(t *testing.T) {
	options := map[string]string{
		"caps":           "fR",
		"netId":          "2",
		"router.version": "0.9.67",
	}
	ri := createSignedTestRouterInfo(t, options)
	err := VerifyRouterInfoSignature(*ri)
	assert.NoError(t, err, "RouterInfo with options should pass signature verification")
}

// TestVerifyRouterInfoSignature_CorruptedSignature verifies that a RouterInfo
// with tampered signature bytes is rejected.
func TestVerifyRouterInfoSignature_CorruptedSignature(t *testing.T) {
	ri := createSignedTestRouterInfo(t, nil)

	// Serialize the RouterInfo, corrupt the signature (last bytes), and re-parse
	riBytes, err := ri.Bytes()
	require.NoError(t, err, "Failed to serialize RouterInfo")

	// Corrupt the last byte of the signature
	riBytes[len(riBytes)-1] ^= 0xFF

	// Re-parse the corrupted bytes
	corruptedRI, _, err := router_info.ReadRouterInfo(riBytes)
	require.NoError(t, err, "Failed to re-parse RouterInfo with corrupted signature")

	err = VerifyRouterInfoSignature(corruptedRI)
	assert.Error(t, err, "RouterInfo with corrupted signature should fail verification")
	assert.Contains(t, err.Error(), "signature verification failed",
		"Error should indicate signature verification failure")
}

// TestVerifyRouterInfoSignature_CorruptedData verifies that a RouterInfo
// with tampered data bytes (but original signature) is rejected.
func TestVerifyRouterInfoSignature_CorruptedData(t *testing.T) {
	ri := createSignedTestRouterInfo(t, nil)

	// Serialize the RouterInfo
	riBytes, err := ri.Bytes()
	require.NoError(t, err, "Failed to serialize RouterInfo")

	// Get signature size so we know where data ends
	sigType := ri.RouterIdentity().KeyCertificate.SigningPublicKeyType()
	sigSize, err := key_certificate.GetSignatureSize(sigType)
	require.NoError(t, err, "Failed to get signature size")

	// Corrupt a byte in the data section (before the signature)
	// Pick a byte well into the data section to avoid breaking the parser
	corruptIndex := len(riBytes) - sigSize - 5
	if corruptIndex < 0 {
		corruptIndex = 10
	}
	riBytes[corruptIndex] ^= 0xFF

	// Re-parse the corrupted bytes
	corruptedRI, _, err := router_info.ReadRouterInfo(riBytes)
	require.NoError(t, err, "Failed to re-parse RouterInfo with corrupted data")

	err = VerifyRouterInfoSignature(corruptedRI)
	assert.Error(t, err, "RouterInfo with corrupted data should fail verification")
}

// TestVerifyRouterInfoSignature_DifferentKeySignature verifies that a RouterInfo
// signed with a different key than the one in the RouterIdentity is rejected.
func TestVerifyRouterInfoSignature_DifferentKeySignature(t *testing.T) {
	// Create two RouterInfos with different keys
	ri1 := createSignedTestRouterInfo(t, map[string]string{"test": "first"})
	ri2 := createSignedTestRouterInfo(t, map[string]string{"test": "second"})

	// Serialize ri1, replace its signature with ri2's signature
	ri1Bytes, err := ri1.Bytes()
	require.NoError(t, err)
	ri2Sig := ri2.Signature()

	sigType := ri1.RouterIdentity().KeyCertificate.SigningPublicKeyType()
	sigSize, err := key_certificate.GetSignatureSize(sigType)
	require.NoError(t, err)

	// Replace ri1's signature with ri2's signature
	ri2SigBytes := ri2Sig.Bytes()
	require.Equal(t, sigSize, len(ri2SigBytes), "Signature sizes should match")
	copy(ri1Bytes[len(ri1Bytes)-sigSize:], ri2SigBytes)

	// Re-parse
	crossSignedRI, _, err := router_info.ReadRouterInfo(ri1Bytes)
	require.NoError(t, err)

	err = VerifyRouterInfoSignature(crossSignedRI)
	assert.Error(t, err, "RouterInfo with wrong key's signature should fail verification")
}

// TestVerifyRouterInfoSignature_MultipleValidRouterInfos verifies that multiple
// independently created RouterInfos all pass verification, ensuring the function
// works consistently across different keys.
func TestVerifyRouterInfoSignature_MultipleValidRouterInfos(t *testing.T) {
	for i := 0; i < 5; i++ {
		ri := createSignedTestRouterInfo(t, map[string]string{
			"test.iteration": string(rune('0' + i)),
		})
		err := VerifyRouterInfoSignature(*ri)
		assert.NoError(t, err, "RouterInfo %d should pass signature verification", i)
	}
}

// TestVerifyRouterInfoSignature_EmptySignature verifies that a RouterInfo
// with zero-length signature bytes is rejected.
func TestVerifyRouterInfoSignature_EmptySignature(t *testing.T) {
	ri := createSignedTestRouterInfo(t, nil)

	// Serialize and truncate the signature
	riBytes, err := ri.Bytes()
	require.NoError(t, err)

	sigType := ri.RouterIdentity().KeyCertificate.SigningPublicKeyType()
	sigSize, err := key_certificate.GetSignatureSize(sigType)
	require.NoError(t, err)

	// Zero out the signature bytes
	for i := len(riBytes) - sigSize; i < len(riBytes); i++ {
		riBytes[i] = 0
	}

	// Re-parse
	zeroedRI, _, err := router_info.ReadRouterInfo(riBytes)
	require.NoError(t, err)

	err = VerifyRouterInfoSignature(zeroedRI)
	assert.Error(t, err, "RouterInfo with zeroed signature should fail verification")
}

// TestVerifyRouterInfoSignature_RoundTrip verifies that serialization and
// deserialization preserves the ability to verify signatures.
func TestVerifyRouterInfoSignature_RoundTrip(t *testing.T) {
	ri := createSignedTestRouterInfo(t, map[string]string{
		"caps":           "fR",
		"router.version": "0.9.67",
	})

	// Verify original
	err := VerifyRouterInfoSignature(*ri)
	require.NoError(t, err, "Original RouterInfo should verify")

	// Serialize
	riBytes, err := ri.Bytes()
	require.NoError(t, err, "Serialization should succeed")

	// Deserialize
	parsedRI, _, err := router_info.ReadRouterInfo(riBytes)
	require.NoError(t, err, "Deserialization should succeed")

	// Verify round-tripped
	err = VerifyRouterInfoSignature(parsedRI)
	assert.NoError(t, err, "Round-tripped RouterInfo should still verify")
}

// BenchmarkVerifyRouterInfoSignature benchmarks signature verification performance.
func BenchmarkVerifyRouterInfoSignature(b *testing.B) {
	// Create a signed RouterInfo outside the benchmark loop
	ri := func() *router_info.RouterInfo {
		// Generate Ed25519 signing key pair
		ed25519PrivKey, err := ed25519.GenerateEd25519Key()
		if err != nil {
			b.Fatal(err)
		}
		ed25519PrivKeyTyped := ed25519PrivKey.(ed25519.Ed25519PrivateKey)
		ed25519PubKeyRaw, _ := ed25519PrivKeyTyped.Public()
		ed25519PubKey := ed25519PubKeyRaw.(types.SigningPublicKey)

		var elgPrivKey elgamal.PrivateKey
		_ = elgamal.ElgamalGenerate(&elgPrivKey.PrivateKey, rand.Reader)
		var elgPubKey elgamal.ElgPublicKey
		yBytes := elgPrivKey.PublicKey.Y.Bytes()
		copy(elgPubKey[256-len(yBytes):], yBytes)

		var payload bytes.Buffer
		signingType, _ := common.NewIntegerFromInt(7, 2)
		cryptoType, _ := common.NewIntegerFromInt(0, 2)
		payload.Write(*signingType)
		payload.Write(*cryptoType)

		cert, _ := certificate.NewCertificateWithType(certificate.CERT_KEY, payload.Bytes())
		keyCert, _ := key_certificate.KeyCertificateFromCertificate(cert)

		pubKeySize := keyCert.CryptoSize()
		sigKeySize := keyCert.SigningPublicKeySize()
		paddingSize := keys_and_cert.KEYS_AND_CERT_DATA_SIZE - pubKeySize - sigKeySize
		padding := make([]byte, paddingSize)
		_, _ = rand.Read(padding)

		routerIdentity, _ := router_identity.NewRouterIdentity(elgPubKey, ed25519PubKey, cert, padding)
		routerAddr, _ := router_address.NewRouterAddress(3, time.Now().Add(24*time.Hour), "NTCP2", map[string]string{
			"host": "192.168.1.1",
			"port": "12345",
		})

		ri, err := router_info.NewRouterInfo(
			routerIdentity,
			time.Now(),
			[]*router_address.RouterAddress{routerAddr},
			map[string]string{"router.version": "0.9.64"},
			&ed25519PrivKeyTyped,
			signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519,
		)
		if err != nil {
			b.Fatal(err)
		}
		return ri
	}()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = VerifyRouterInfoSignature(*ri)
	}
}
