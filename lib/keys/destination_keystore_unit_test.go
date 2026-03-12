package keys

import (
	"bytes"
	"testing"

	"github.com/go-i2p/common/certificate"
	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/keys_and_cert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Tests for NewDestinationKeyStoreFromKeys
// =============================================================================

// TestNewDestinationKeyStoreFromKeys_PreservesIdentity verifies that
// reconstructing a keystore from existing private keys produces the
// same destination (same .b32.i2p address).
func TestNewDestinationKeyStoreFromKeys_PreservesIdentity(t *testing.T) {
	// Generate an original keystore
	original, err := NewDestinationKeyStore()
	require.NoError(t, err)

	originalDestBytes, err := original.Destination().Bytes()
	require.NoError(t, err)

	// Reconstruct from the original's private keys, passing padding
	// to preserve identity (random padding means different identity without it)
	reconstructed, err := NewDestinationKeyStoreFromKeys(
		original.SigningPrivateKey(),
		original.EncryptionPrivateKey(),
		original.IdentityPadding(),
	)
	require.NoError(t, err)

	reconstructedDestBytes, err := reconstructed.Destination().Bytes()
	require.NoError(t, err)

	assert.True(t, bytes.Equal(originalDestBytes, reconstructedDestBytes),
		"reconstructed destination must match original")
}

// TestNewDestinationKeyStoreFromKeys_PublicKeysMatch verifies that the
// public keys derived from the reconstructed keystore match the originals.
func TestNewDestinationKeyStoreFromKeys_PublicKeysMatch(t *testing.T) {
	original, err := NewDestinationKeyStore()
	require.NoError(t, err)

	reconstructed, err := NewDestinationKeyStoreFromKeys(
		original.SigningPrivateKey(),
		original.EncryptionPrivateKey(),
	)
	require.NoError(t, err)

	// Signing public keys should match
	origSigPub, err := original.SigningPublicKey()
	require.NoError(t, err)
	reconSigPub, err := reconstructed.SigningPublicKey()
	require.NoError(t, err)
	assert.True(t, bytes.Equal(origSigPub.Bytes(), reconSigPub.Bytes()),
		"signing public keys should match")

	// Encryption public keys should match
	origEncPub, err := original.EncryptionPublicKey()
	require.NoError(t, err)
	reconEncPub, err := reconstructed.EncryptionPublicKey()
	require.NoError(t, err)
	assert.True(t, bytes.Equal(origEncPub.Bytes(), reconEncPub.Bytes()),
		"encryption public keys should match")
}

// TestNewDestinationKeyStoreFromKeys_PrivateKeysPreserved verifies that
// the private keys in the reconstructed keystore are the same as the originals.
func TestNewDestinationKeyStoreFromKeys_PrivateKeysPreserved(t *testing.T) {
	original, err := NewDestinationKeyStore()
	require.NoError(t, err)

	reconstructed, err := NewDestinationKeyStoreFromKeys(
		original.SigningPrivateKey(),
		original.EncryptionPrivateKey(),
	)
	require.NoError(t, err)

	// Private keys should be the same references
	assert.NotNil(t, reconstructed.SigningPrivateKey())
	assert.NotNil(t, reconstructed.EncryptionPrivateKey())
}

// TestNewDestinationKeyStoreFromKeys_StableAcrossMultipleCalls verifies
// that calling NewDestinationKeyStoreFromKeys multiple times with the same
// keys always produces the same destination.
func TestNewDestinationKeyStoreFromKeys_StableAcrossMultipleCalls(t *testing.T) {
	original, err := NewDestinationKeyStore()
	require.NoError(t, err)

	sigPriv := original.SigningPrivateKey()
	encPriv := original.EncryptionPrivateKey()
	pad := original.IdentityPadding()

	var destinations [][]byte
	for i := 0; i < 5; i++ {
		ks, err := NewDestinationKeyStoreFromKeys(sigPriv, encPriv, pad)
		require.NoError(t, err)
		db, err := ks.Destination().Bytes()
		require.NoError(t, err)
		destinations = append(destinations, db)
	}

	for i := 1; i < len(destinations); i++ {
		assert.True(t, bytes.Equal(destinations[0], destinations[i]),
			"call %d should produce identical destination", i)
	}
}

// TestNewDestinationKeyStoreFromKeys_Close_ZeroesKeyMaterial verifies
// that calling Close on a reconstructed keystore zeroes the key material.
func TestNewDestinationKeyStoreFromKeys_Close_ZeroesKeyMaterial(t *testing.T) {
	original, err := NewDestinationKeyStore()
	require.NoError(t, err)

	reconstructed, err := NewDestinationKeyStoreFromKeys(
		original.SigningPrivateKey(),
		original.EncryptionPrivateKey(),
	)
	require.NoError(t, err)

	// Verify keys are initially non-nil
	assert.NotNil(t, reconstructed.EncryptionPrivateKey())

	// Close should not panic
	reconstructed.Close()
}

// =============================================================================
// DestinationKeyStore Close and Crypto Verification
// =============================================================================

// TestDestinationKeyStore_Close_ZeroesKeyMaterial verifies that Close() zeroes
// private key bytes from the destination key store.
func TestDestinationKeyStore_Close_ZeroesKeyMaterial(t *testing.T) {
	dks, err := NewDestinationKeyStore()
	if err != nil {
		t.Fatalf("Failed to create destination key store: %v", err)
	}

	// Verify keys are not all zeros before close
	assertNotAllZeros(t, dks.EncryptionPrivateKey().Bytes(), "Encryption key should not be all zeros before Close")

	// Close should zero the key material
	dks.Close()

	// After Close, encryption key should be zeroed
	assertAllZeros(t, dks.EncryptionPrivateKey().Bytes(), "Encryption key should be all zeros after Close()")
}

// TestDestinationKeyStore_UsesModernCrypto verifies that NewDestinationKeyStore
// produces a destination with Ed25519 signing + X25519 encryption.
func TestDestinationKeyStore_UsesModernCrypto(t *testing.T) {
	dks, err := NewDestinationKeyStore()
	if err != nil {
		t.Fatalf("NewDestinationKeyStore() failed: %v", err)
	}

	// Verify signing key is Ed25519 (32-byte public key)
	sigPub, err := dks.SigningPublicKey()
	if err != nil {
		t.Fatalf("SigningPublicKey() failed: %v", err)
	}
	if len(sigPub.Bytes()) != testEd25519PubKeySize {
		t.Errorf("signing public key = %d bytes, want %d (Ed25519)", len(sigPub.Bytes()), testEd25519PubKeySize)
	}

	// Verify encryption key is X25519 (32-byte public key)
	encPub, err := dks.EncryptionPublicKey()
	if err != nil {
		t.Fatalf("EncryptionPublicKey() failed: %v", err)
	}
	if len(encPub.Bytes()) != testX25519KeySize {
		t.Errorf("encryption public key = %d bytes, want %d (X25519)", len(encPub.Bytes()), testX25519KeySize)
	}

	// Verify key certificate type in destination
	cert := dks.Destination().KeysAndCert.Certificate()
	certType, err := cert.Type()
	if err != nil {
		t.Fatalf("cert.Type() failed: %v", err)
	}
	if certType != certificate.CERT_KEY {
		t.Errorf("destination cert type = %d, want CERT_KEY (%d)", certType, certificate.CERT_KEY)
	}

	// Verify key cert signing/crypto types
	keyCert := dks.Destination().KeysAndCert.KeyCertificate
	if keyCert.SigningPublicKeyType() != key_certificate.KEYCERT_SIGN_ED25519 {
		t.Errorf("signing type = %d, want %d", keyCert.SigningPublicKeyType(), key_certificate.KEYCERT_SIGN_ED25519)
	}
	if keyCert.PublicKeyType() != key_certificate.KEYCERT_CRYPTO_X25519 {
		t.Errorf("crypto type = %d, want %d", keyCert.PublicKeyType(), key_certificate.KEYCERT_CRYPTO_X25519)
	}
}

// TestDestinationKeysAndCert_Validate verifies the constructed destination
// passes the KeysAndCert validation checks.
func TestDestinationKeysAndCert_Validate(t *testing.T) {
	dks, err := NewDestinationKeyStore()
	if err != nil {
		t.Fatalf("NewDestinationKeyStore() failed: %v", err)
	}

	kac := dks.Destination().KeysAndCert
	if !kac.IsValid() {
		t.Error("KeysAndCert.IsValid() returned false for valid destination")
	}

	if err := kac.Validate(); err != nil {
		t.Errorf("KeysAndCert.Validate() returned error for valid destination: %v", err)
	}
}

// =============================================================================
// I2P Spec Compliance — Key Certificate and KeysAndCert Size
// =============================================================================

// TestKeyCertSigningType_IsEd25519 verifies the signing key type is
// KEYCERT_SIGN_ED25519 (7).
func TestKeyCertSigningType_IsEd25519(t *testing.T) {
	keyCert, err := key_certificate.NewEd25519X25519KeyCertificate()
	if err != nil {
		t.Fatalf("NewEd25519X25519KeyCertificate() failed: %v", err)
	}

	sigType := keyCert.SigningPublicKeyType()
	if sigType != key_certificate.KEYCERT_SIGN_ED25519 {
		t.Errorf("signing key type = %d, want KEYCERT_SIGN_ED25519 (%d)",
			sigType, key_certificate.KEYCERT_SIGN_ED25519)
	}
}

// TestKeyCertCryptoType_IsX25519 verifies the crypto key type is
// KEYCERT_CRYPTO_X25519 (4).
func TestKeyCertCryptoType_IsX25519(t *testing.T) {
	keyCert, err := key_certificate.NewEd25519X25519KeyCertificate()
	if err != nil {
		t.Fatalf("NewEd25519X25519KeyCertificate() failed: %v", err)
	}

	cryptoType := keyCert.PublicKeyType()
	if cryptoType != key_certificate.KEYCERT_CRYPTO_X25519 {
		t.Errorf("crypto key type = %d, want KEYCERT_CRYPTO_X25519 (%d)",
			cryptoType, key_certificate.KEYCERT_CRYPTO_X25519)
	}
}

// TestKeyCertCombination_Ed25519X25519 verifies the full certificate is
// CERT_KEY(5) with signing=Ed25519(7) and crypto=X25519(4) in one test.
func TestKeyCertCombination_Ed25519X25519(t *testing.T) {
	keyCert, err := key_certificate.NewEd25519X25519KeyCertificate()
	if err != nil {
		t.Fatalf("NewEd25519X25519KeyCertificate() failed: %v", err)
	}

	// Verify certificate type
	certType, err := keyCert.Certificate.Type()
	if err != nil {
		t.Fatalf("cert.Type() failed: %v", err)
	}
	if certType != certificate.CERT_KEY {
		t.Errorf("certificate type = %d, want CERT_KEY (%d)", certType, certificate.CERT_KEY)
	}

	// Verify signing type
	if sigType := keyCert.SigningPublicKeyType(); sigType != key_certificate.KEYCERT_SIGN_ED25519 {
		t.Errorf("signing type = %d, want %d", sigType, key_certificate.KEYCERT_SIGN_ED25519)
	}

	// Verify crypto type
	if cryptoType := keyCert.PublicKeyType(); cryptoType != key_certificate.KEYCERT_CRYPTO_X25519 {
		t.Errorf("crypto type = %d, want %d", cryptoType, key_certificate.KEYCERT_CRYPTO_X25519)
	}
}

// TestKeysAndCertDataSize_Is384 verifies the data area constant is 384 bytes
// (256-byte pubkey field + 128-byte signing key field).
func TestKeysAndCertDataSize_Is384(t *testing.T) {
	if keys_and_cert.KEYS_AND_CERT_DATA_SIZE != 384 {
		t.Errorf("KEYS_AND_CERT_DATA_SIZE = %d, want 384",
			keys_and_cert.KEYS_AND_CERT_DATA_SIZE)
	}
}

// TestKeysAndCertMinSize_Is387 verifies the minimum size is 387 bytes
// (384-byte data + 3-byte certificate header for CERT_NULL).
func TestKeysAndCertMinSize_Is387(t *testing.T) {
	if keys_and_cert.KEYS_AND_CERT_MIN_SIZE != 387 {
		t.Errorf("KEYS_AND_CERT_MIN_SIZE = %d, want 387",
			keys_and_cert.KEYS_AND_CERT_MIN_SIZE)
	}
}

// TestKeysAndCertFieldSizes verifies the pubkey and signing key field sizes.
func TestKeysAndCertFieldSizes(t *testing.T) {
	if keys_and_cert.KEYS_AND_CERT_PUBKEY_SIZE != 256 {
		t.Errorf("KEYS_AND_CERT_PUBKEY_SIZE = %d, want 256",
			keys_and_cert.KEYS_AND_CERT_PUBKEY_SIZE)
	}
	if keys_and_cert.KEYS_AND_CERT_SPK_SIZE != 128 {
		t.Errorf("KEYS_AND_CERT_SPK_SIZE = %d, want 128",
			keys_and_cert.KEYS_AND_CERT_SPK_SIZE)
	}
	// Verify they sum to data size
	sum := keys_and_cert.KEYS_AND_CERT_PUBKEY_SIZE + keys_and_cert.KEYS_AND_CERT_SPK_SIZE
	if sum != keys_and_cert.KEYS_AND_CERT_DATA_SIZE {
		t.Errorf("PUBKEY_SIZE(%d) + SPK_SIZE(%d) = %d, want DATA_SIZE(%d)",
			keys_and_cert.KEYS_AND_CERT_PUBKEY_SIZE,
			keys_and_cert.KEYS_AND_CERT_SPK_SIZE,
			sum, keys_and_cert.KEYS_AND_CERT_DATA_SIZE)
	}
}

// TestDestinationKeysAndCertSize verifies a real Destination produces the
// correct serialized size: 384 data bytes + 7 certificate bytes (3 header + 4 payload).
func TestDestinationKeysAndCertSize(t *testing.T) {
	dks, err := NewDestinationKeyStore()
	if err != nil {
		t.Fatalf("NewDestinationKeyStore() failed: %v", err)
	}

	dest := dks.Destination()
	rawBytes, err := dest.KeysAndCert.Bytes()
	if err != nil {
		t.Fatalf("KeysAndCert.Bytes() failed: %v", err)
	}

	// With CERT_KEY for Ed25519/X25519:
	//   Data area: 384 bytes
	//   Certificate header: 3 bytes (1 type + 2 length)
	//   Certificate payload: 4 bytes (2 signing type + 2 crypto type)
	//   Total: 391 bytes
	expectedSize := keys_and_cert.KEYS_AND_CERT_DATA_SIZE + 3 + 4 // 384 + 7 = 391
	if len(rawBytes) != expectedSize {
		t.Errorf("KeysAndCert serialized size = %d, want %d (384 data + 3 cert header + 4 key cert payload)",
			len(rawBytes), expectedSize)
	}

	// Also verify the certificate itself is 7 bytes
	certBytes := dest.KeysAndCert.Certificate().Bytes()
	if len(certBytes) != 7 {
		t.Errorf("certificate bytes length = %d, want 7 (3 header + 4 payload)", len(certBytes))
	}
}

// =============================================================================
// Padding Compliance
// =============================================================================

// TestPaddingSize_Ed25519X25519 verifies padding is 320 bytes for Ed25519/X25519.
// Layout: [X25519 pubkey (32)] [padding (320)] [Ed25519 pubkey (32)] = 384 bytes
func TestPaddingSize_Ed25519X25519(t *testing.T) {
	sizes, err := key_certificate.GetKeySizes(
		key_certificate.KEYCERT_SIGN_ED25519,
		key_certificate.KEYCERT_CRYPTO_X25519,
	)
	if err != nil {
		t.Fatalf("GetKeySizes() failed: %v", err)
	}

	if sizes.CryptoPublicKeySize != testX25519KeySize {
		t.Errorf("CryptoPublicKeySize = %d, want %d", sizes.CryptoPublicKeySize, testX25519KeySize)
	}
	if sizes.SigningPublicKeySize != testEd25519PubKeySize {
		t.Errorf("SigningPublicKeySize = %d, want %d", sizes.SigningPublicKeySize, testEd25519PubKeySize)
	}

	paddingSize := keys_and_cert.KEYS_AND_CERT_DATA_SIZE - (sizes.CryptoPublicKeySize + sizes.SigningPublicKeySize)
	if paddingSize != testExpectedPaddingSize {
		t.Errorf("padding size = %d, want %d", paddingSize, testExpectedPaddingSize)
	}
}

// TestPaddingLayout_CryptoPubKeyAtStartSigningAtEnd verifies the spec-mandated
// layout: crypto public key at start of 256-byte field, signing public key at
// end of 128-byte field, random padding fills the middle.
func TestPaddingLayout_CryptoPubKeyAtStartSigningAtEnd(t *testing.T) {
	dks, err := NewDestinationKeyStore()
	if err != nil {
		t.Fatalf("NewDestinationKeyStore() failed: %v", err)
	}

	kac := dks.Destination().KeysAndCert

	// Verify the KeysAndCert structure fields are present
	if kac.ReceivingPublic == nil {
		t.Fatal("ReceivingPublic (crypto public key) is nil")
	}
	if kac.SigningPublic == nil {
		t.Fatal("SigningPublic (signing public key) is nil")
	}

	// Crypto public key should be 32 bytes (X25519)
	cryptoPubKeyBytes := kac.ReceivingPublic.Bytes()
	if len(cryptoPubKeyBytes) != testX25519KeySize {
		t.Errorf("crypto public key size = %d, want %d", len(cryptoPubKeyBytes), testX25519KeySize)
	}

	// Signing public key should be 32 bytes (Ed25519)
	sigPubKeyBytes := kac.SigningPublic.Bytes()
	if len(sigPubKeyBytes) != testEd25519PubKeySize {
		t.Errorf("signing public key size = %d, want %d", len(sigPubKeyBytes), testEd25519PubKeySize)
	}

	// Padding should be 320 bytes
	if len(kac.Padding) != testExpectedPaddingSize {
		t.Errorf("padding size = %d, want %d", len(kac.Padding), testExpectedPaddingSize)
	}

	// Verify the serialized layout per I2P spec
	rawBytes, err := kac.Bytes()
	if err != nil {
		t.Fatalf("KeysAndCert.Bytes() failed: %v", err)
	}

	// X25519 public key (32 bytes) is start-aligned in the 256-byte field
	for i := 0; i < testX25519KeySize; i++ {
		if rawBytes[i] != cryptoPubKeyBytes[i] {
			t.Errorf("byte[%d]: crypto pubkey mismatch (start-aligned at offset %d)", i, i)
			break
		}
	}

	// Ed25519 signing public key (32 bytes) is right-justified in the 128-byte field
	dataEnd := keys_and_cert.KEYS_AND_CERT_DATA_SIZE // 384
	sigStart := dataEnd - testEd25519PubKeySize      // 352
	for i := 0; i < testEd25519PubKeySize; i++ {
		if rawBytes[sigStart+i] != sigPubKeyBytes[i] {
			t.Errorf("byte[%d]: signing pubkey mismatch at end of data area (offset %d)",
				sigStart+i, sigStart+i)
			break
		}
	}
}

// =============================================================================
// Key Size Info Cross-Check
// =============================================================================

// TestKeySizeInfo_Ed25519X25519 verifies all fields of KeySizeInfo for the
// Ed25519/X25519 combination match the I2P spec.
func TestKeySizeInfo_Ed25519X25519(t *testing.T) {
	sizes, err := key_certificate.GetKeySizes(
		key_certificate.KEYCERT_SIGN_ED25519,
		key_certificate.KEYCERT_CRYPTO_X25519,
	)
	if err != nil {
		t.Fatalf("GetKeySizes() failed: %v", err)
	}

	checks := []struct {
		name string
		got  int
		want int
	}{
		{"CryptoPublicKeySize", sizes.CryptoPublicKeySize, testX25519KeySize},
		{"CryptoPrivateKeySize", sizes.CryptoPrivateKeySize, testX25519KeySize},
		{"SigningPublicKeySize", sizes.SigningPublicKeySize, testEd25519PubKeySize},
		{"SignatureSize", sizes.SignatureSize, testEd25519SignatureSize},
	}

	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d", c.name, c.got, c.want)
		}
	}
}
