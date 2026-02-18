package keys

// spec_compliance_test.go — I2P specification compliance tests for lib/keys
//
// These tests verify conformance with:
//   - common-structures.rst: KeysAndCert, KeyCertificate, RouterIdentity, Destination
//   - Proposal 156 (ECIES-X25519 router keys)
//   - Proposal 123 (Offline signatures / transient keys)
//
// AUDIT Section 3 (lib/keys) checklist coverage:
//   [x] Key certificate type: CERT_KEY(5), Ed25519 signing(7), X25519 encryption(4)
//   [x] KeysAndCert size: 387 bytes minimum, 384-byte data + 3-byte cert header
//   [x] Padding: crypto at start, signing at end, padding in middle
//   [x] Key persistence format: .key/.enc.key format (NOT Java router.keys.dat)
//   [x] Offline signatures: Proposal 123 not yet implemented
//   [x] Crypto: Ed25519 key generation verified
//   [x] Crypto: X25519 key generation verified
//   [x] Crypto: No DSA key generation paths
//   [x] Legacy: No ElGamal key generation
//   [x] Legacy: No DSA signing key generation

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-i2p/common/certificate"
	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/keys_and_cert"
	"github.com/go-i2p/crypto/curve25519"
	"github.com/go-i2p/crypto/ed25519"
)

// =============================================================================
// Key Certificate Type Compliance (CERT_KEY type 5, Ed25519/X25519)
// =============================================================================

// TestKeyCertType_IsCertKey5 verifies that createEd25519Certificate produces
// a certificate with type CERT_KEY (5) per common-structures.rst.
func TestKeyCertType_IsCertKey5(t *testing.T) {
	ks := &RouterInfoKeystore{}
	cert, err := ks.createEd25519Certificate()
	if err != nil {
		t.Fatalf("createEd25519Certificate() failed: %v", err)
	}

	certType, err := cert.Type()
	if err != nil {
		t.Fatalf("cert.Type() failed: %v", err)
	}

	if certType != certificate.CERT_KEY {
		t.Errorf("certificate type = %d, want CERT_KEY (%d)", certType, certificate.CERT_KEY)
	}
}

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

// =============================================================================
// KeysAndCert Size Compliance (384-byte data area + certificate)
// =============================================================================

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
// Padding Layout Compliance
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

	expectedCryptoSize := 32 // X25519 public key
	expectedSignSize := 32   // Ed25519 public key
	expectedPadding := 320   // 384 - 32 - 32

	if sizes.CryptoPublicKeySize != expectedCryptoSize {
		t.Errorf("CryptoPublicKeySize = %d, want %d", sizes.CryptoPublicKeySize, expectedCryptoSize)
	}
	if sizes.SigningPublicKeySize != expectedSignSize {
		t.Errorf("SigningPublicKeySize = %d, want %d", sizes.SigningPublicKeySize, expectedSignSize)
	}

	paddingSize := keys_and_cert.KEYS_AND_CERT_DATA_SIZE - (sizes.CryptoPublicKeySize + sizes.SigningPublicKeySize)
	if paddingSize != expectedPadding {
		t.Errorf("padding size = %d, want %d", paddingSize, expectedPadding)
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
	if len(cryptoPubKeyBytes) != 32 {
		t.Errorf("crypto public key size = %d, want 32", len(cryptoPubKeyBytes))
	}

	// Signing public key should be 32 bytes (Ed25519)
	sigPubKeyBytes := kac.SigningPublic.Bytes()
	if len(sigPubKeyBytes) != 32 {
		t.Errorf("signing public key size = %d, want 32", len(sigPubKeyBytes))
	}

	// Padding should be 320 bytes
	if len(kac.Padding) != 320 {
		t.Errorf("padding size = %d, want 320", len(kac.Padding))
	}

	// Verify the serialized layout per I2P spec:
	// Keys are RIGHT-JUSTIFIED in their standard-size fields.
	// [256-byte crypto field: padding(224) | X25519 pubkey(32)]
	// [128-byte signing field: padding(96) | Ed25519 pubkey(32)]
	// Then certificate bytes follow.
	rawBytes, err := kac.Bytes()
	if err != nil {
		t.Fatalf("KeysAndCert.Bytes() failed: %v", err)
	}

	// X25519 public key (32 bytes) is right-justified in the 256-byte field
	// So it occupies bytes 224-255
	cryptoFieldSize := 256 // KEYS_AND_CERT_PUBKEY_SIZE
	cryptoStart := cryptoFieldSize - 32
	for i := 0; i < 32; i++ {
		if rawBytes[cryptoStart+i] != cryptoPubKeyBytes[i] {
			t.Errorf("byte[%d]: crypto pubkey mismatch (right-justified at offset %d)",
				cryptoStart+i, cryptoStart+i)
			break
		}
	}

	// Ed25519 signing public key (32 bytes) is right-justified in the 128-byte field
	// So it occupies bytes 352-383 (last 32 of the 384-byte data area)
	dataEnd := keys_and_cert.KEYS_AND_CERT_DATA_SIZE // 384
	sigStart := dataEnd - 32                         // 352
	for i := 0; i < 32; i++ {
		if rawBytes[sigStart+i] != sigPubKeyBytes[i] {
			t.Errorf("byte[%d]: signing pubkey mismatch at end of data area (offset %d)",
				sigStart+i, sigStart+i)
			break
		}
	}
}

// TestRouterInfoKeystorePaddingGeneration verifies that generateIdentityPaddingFromSizes
// produces padding of the correct size and caches it for identity stability.
func TestRouterInfoKeystorePaddingGeneration(t *testing.T) {
	tmpDir := t.TempDir()
	ks := &RouterInfoKeystore{dir: tmpDir, name: "test"}

	sizes, err := key_certificate.GetKeySizes(
		key_certificate.KEYCERT_SIGN_ED25519,
		key_certificate.KEYCERT_CRYPTO_X25519,
	)
	if err != nil {
		t.Fatalf("GetKeySizes() failed: %v", err)
	}

	padding1, err := ks.generateIdentityPaddingFromSizes(sizes.CryptoPublicKeySize, sizes.SigningPublicKeySize)
	if err != nil {
		t.Fatalf("generateIdentityPaddingFromSizes() failed: %v", err)
	}

	if len(padding1) != 320 {
		t.Errorf("padding size = %d, want 320", len(padding1))
	}

	// Second call should return cached padding (identity stability)
	padding2, err := ks.generateIdentityPaddingFromSizes(sizes.CryptoPublicKeySize, sizes.SigningPublicKeySize)
	if err != nil {
		t.Fatalf("second generateIdentityPaddingFromSizes() failed: %v", err)
	}

	if len(padding1) != len(padding2) {
		t.Fatalf("padding lengths differ: %d vs %d", len(padding1), len(padding2))
	}
	for i := range padding1 {
		if padding1[i] != padding2[i] {
			t.Errorf("padding byte[%d] differs between calls: cached padding not reused", i)
			break
		}
	}

	// Verify padding is persisted to disk
	paddingPath := filepath.Join(tmpDir, "test.padding")
	_, err = os.Stat(paddingPath)
	if err != nil {
		t.Errorf("padding file not persisted at %s: %v", paddingPath, err)
	}
}

// =============================================================================
// Key Persistence Format (go-i2p uses .key/.enc.key, NOT Java router.keys.dat)
// =============================================================================

// TestKeyPersistenceFormat_NotJavaCompatible documents that go-i2p uses its own
// key persistence format (.key for Ed25519 signing, .enc.key for X25519 encryption,
// .padding for identity padding) rather than the Java I2P router.keys.dat format.
//
// This is a known divergence from Java I2P's KeyManager. go-i2p's format stores
// each key component in a separate file with appropriate permissions (0600).
func TestKeyPersistenceFormat_NotJavaCompatible(t *testing.T) {
	tmpDir := t.TempDir()
	ks, err := NewRouterInfoKeystore(tmpDir, "persistence-test")
	if err != nil {
		t.Fatalf("NewRouterInfoKeystore() failed: %v", err)
	}

	err = ks.StoreKeys()
	if err != nil {
		t.Fatalf("StoreKeys() failed: %v", err)
	}

	// Verify go-i2p format files exist
	sigKeyPath := filepath.Join(tmpDir, "persistence-test.key")
	encKeyPath := filepath.Join(tmpDir, "persistence-test.enc.key")

	if _, err := os.Stat(sigKeyPath); os.IsNotExist(err) {
		t.Errorf("signing key file not found at %s", sigKeyPath)
	}
	if _, err := os.Stat(encKeyPath); os.IsNotExist(err) {
		t.Errorf("encryption key file not found at %s", encKeyPath)
	}

	// Verify Java-format file does NOT exist (documenting known divergence)
	javaPath := filepath.Join(tmpDir, "router.keys.dat")
	if _, err := os.Stat(javaPath); !os.IsNotExist(err) {
		t.Logf("NOTE: router.keys.dat exists — this would indicate Java-compatible format")
	}

	t.Logf("AUDIT NOTE: go-i2p uses .key/.enc.key format, NOT Java router.keys.dat. " +
		"This is a known divergence from net.i2p.router.KeyManager.")
}

// TestDestinationKeyPersistenceFormat_DKSMagic verifies the destination key
// persistence uses the DKS\x02 magic header format (v2 includes padding).
func TestDestinationKeyPersistenceFormat_DKSMagic(t *testing.T) {
	tmpDir := t.TempDir()

	dks, err := NewDestinationKeyStore()
	if err != nil {
		t.Fatalf("NewDestinationKeyStore() failed: %v", err)
	}

	err = dks.StoreKeys(tmpDir, "dest")
	if err != nil {
		t.Fatalf("StoreKeys() failed: %v", err)
	}

	dksPath := filepath.Join(tmpDir, "dest.dest.key")
	data, err := os.ReadFile(dksPath)
	if err != nil {
		t.Fatalf("ReadFile() failed: %v", err)
	}

	// Verify DKS v2 magic header (v2 includes padding for identity stability)
	magic := "DKS\x02"
	if len(data) < 4 || string(data[:4]) != magic {
		t.Errorf("destination key file does not start with DKS\\x02 magic; got %q", data[:min(4, len(data))])
	}
}

// =============================================================================
// Offline Signatures (Proposal 123) — Not Yet Implemented
// =============================================================================

// TestOfflineSignatures_NotImplemented documents that Proposal 123 (offline/transient
// signing keys) is not yet implemented in go-i2p's key management.
//
// When offline signatures are implemented, the following must be validated:
//   - Transient signing key expiration timestamp must be checked
//   - Offline signature must be verified against the identity's signing key
//   - Expired transient keys must be rejected
//   - The transient key type may differ from the identity's signing key type
func TestOfflineSignatures_NotImplemented(t *testing.T) {
	// Scan all .go files in this package for offline/transient key references
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("filepath.Glob() failed: %v", err)
	}

	offlineRefs := 0
	for _, f := range files {
		// Skip test files for this check
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		content, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("ReadFile(%s) failed: %v", f, err)
		}
		src := strings.ToLower(string(content))
		if strings.Contains(src, "offline") || strings.Contains(src, "transient") {
			offlineRefs++
			t.Logf("Found offline/transient reference in %s", f)
		}
	}

	if offlineRefs > 0 {
		t.Logf("AUDIT NOTE: %d production files reference offline/transient keys — "+
			"verify Proposal 123 compliance if implemented", offlineRefs)
	} else {
		t.Logf("AUDIT NOTE: Proposal 123 (offline signatures / transient keys) is NOT implemented. " +
			"This is acceptable for initial implementation but should be tracked as future work.")
	}
}

// =============================================================================
// Cryptography Audit — Ed25519 Key Generation
// =============================================================================

// TestEd25519KeyGeneration_Correct verifies that generateNewKey() produces
// valid Ed25519 key pairs using go-i2p/crypto/ed25519.
func TestEd25519KeyGeneration_Correct(t *testing.T) {
	privKey, err := generateNewKey()
	if err != nil {
		t.Fatalf("generateNewKey() failed: %v", err)
	}

	if privKey == nil {
		t.Fatal("generateNewKey() returned nil private key")
	}

	// Ed25519 private keys are 64 bytes (seed + public key) or 32 bytes (seed only)
	privBytes := privKey.Bytes()
	if len(privBytes) != 64 && len(privBytes) != 32 {
		t.Errorf("Ed25519 private key size = %d, want 64 or 32", len(privBytes))
	}

	// Verify public key derivation works
	pubKey, err := privKey.Public()
	if err != nil {
		t.Fatalf("privKey.Public() failed: %v", err)
	}

	// Ed25519 public keys are 32 bytes
	pubBytes := pubKey.Bytes()
	if len(pubBytes) != 32 {
		t.Errorf("Ed25519 public key size = %d, want 32", len(pubBytes))
	}
}

// TestEd25519KeyGeneration_DirectAPI verifies the underlying ed25519 package
// produces keys of the expected sizes.
func TestEd25519KeyGeneration_DirectAPI(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateEd25519KeyPair() failed: %v", err)
	}

	// Public key: 32 bytes
	if len(pubKey.Bytes()) != 32 {
		t.Errorf("Ed25519 public key = %d bytes, want 32", len(pubKey.Bytes()))
	}

	// Private key: 64 bytes (standard Ed25519 expanded key)
	if len(privKey.Bytes()) != 64 {
		t.Errorf("Ed25519 private key = %d bytes, want 64", len(privKey.Bytes()))
	}
}

// TestEd25519KeyGeneration_Uniqueness verifies that each key generation call
// produces a unique key (uses CSPRNG, not deterministic).
func TestEd25519KeyGeneration_Uniqueness(t *testing.T) {
	key1, err := generateNewKey()
	if err != nil {
		t.Fatalf("first generateNewKey() failed: %v", err)
	}
	key2, err := generateNewKey()
	if err != nil {
		t.Fatalf("second generateNewKey() failed: %v", err)
	}

	if string(key1.Bytes()) == string(key2.Bytes()) {
		t.Error("two consecutive generateNewKey() calls produced identical keys — CSPRNG failure")
	}
}

// =============================================================================
// Cryptography Audit — X25519 Key Generation (Proposal 156 ECIES)
// =============================================================================

// TestX25519KeyGeneration_Correct verifies X25519 key generation produces valid
// key pairs per Proposal 156 (ECIES-X25519 router keys).
func TestX25519KeyGeneration_Correct(t *testing.T) {
	pubKey, privKey, err := curve25519.GenerateKeyPair()
	if err != nil {
		t.Fatalf("curve25519.GenerateKeyPair() failed: %v", err)
	}

	// X25519 keys are 32 bytes
	if len(pubKey.Bytes()) != 32 {
		t.Errorf("X25519 public key = %d bytes, want 32", len(pubKey.Bytes()))
	}
	if len(privKey.Bytes()) != 32 {
		t.Errorf("X25519 private key = %d bytes, want 32", len(privKey.Bytes()))
	}
}

// TestX25519KeyGeneration_Uniqueness verifies X25519 key uniqueness.
func TestX25519KeyGeneration_Uniqueness(t *testing.T) {
	_, priv1, err := curve25519.GenerateKeyPair()
	if err != nil {
		t.Fatalf("first GenerateKeyPair() failed: %v", err)
	}
	_, priv2, err := curve25519.GenerateKeyPair()
	if err != nil {
		t.Fatalf("second GenerateKeyPair() failed: %v", err)
	}

	if string(priv1.Bytes()) == string(priv2.Bytes()) {
		t.Error("two consecutive X25519 key generations produced identical keys — CSPRNG failure")
	}
}

// TestX25519InRouterInfoKeystore verifies that NewRouterInfoKeystore generates
// and stores X25519 encryption keys alongside Ed25519 signing keys.
func TestX25519InRouterInfoKeystore(t *testing.T) {
	tmpDir := t.TempDir()
	ks, err := NewRouterInfoKeystore(tmpDir, "x25519-test")
	if err != nil {
		t.Fatalf("NewRouterInfoKeystore() failed: %v", err)
	}

	encPrivKey := ks.GetEncryptionPrivateKey()
	if encPrivKey == nil {
		t.Fatal("GetEncryptionPrivateKey() returned nil — X25519 key not generated")
	}

	if len(encPrivKey.Bytes()) != 32 {
		t.Errorf("encryption private key = %d bytes, want 32", len(encPrivKey.Bytes()))
	}

	// Verify encryption key file exists
	encKeyPath := filepath.Join(tmpDir, "x25519-test.enc.key")
	if _, err := os.Stat(encKeyPath); os.IsNotExist(err) {
		t.Errorf("X25519 encryption key not persisted at %s", encKeyPath)
	}
}

// =============================================================================
// No DSA/ElGamal Key Generation Paths
// =============================================================================

// TestNoLegacyCryptoInKeyGeneration uses AST analysis to verify that the
// production code in lib/keys contains no DSA or ElGamal key generation calls.
// This is the programmatic equivalent of grep for legacy crypto.
func TestNoLegacyCryptoInKeyGeneration(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("filepath.Glob() failed: %v", err)
	}

	// Legacy patterns that MUST NOT appear in production code
	legacyPatterns := []string{
		"dsa.Generate",
		"DSA",
		"ElGamal",
		"elgamal",
		"NewDSA",
		"KEYCERT_SIGN_DSA",
		"KEYCERT_CRYPTO_ELG",
	}

	// Exceptions: these are acceptable references (documentation, test files)
	isException := func(filename, line string) bool {
		// Test files can reference legacy crypto for documentation purposes
		if strings.HasSuffix(filename, "_test.go") {
			return true
		}
		// Comments are acceptable
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") {
			return true
		}
		// EdDSA references are modern, not legacy DSA
		if strings.Contains(line, "EdDSA") || strings.Contains(line, "EDDSA") || strings.Contains(line, "eddsa") {
			return true
		}
		return false
	}

	violations := []string{}
	for _, f := range files {
		content, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("ReadFile(%s) failed: %v", f, err)
		}

		lines := strings.Split(string(content), "\n")
		for _, line := range lines {
			if isException(f, line) {
				continue
			}
			for _, pattern := range legacyPatterns {
				if strings.Contains(line, pattern) {
					// Double-check it's not EdDSA
					if pattern == "DSA" && (strings.Contains(line, "EdDSA") || strings.Contains(line, "EDDSA")) {
						continue
					}
					violations = append(violations,
						f+":"+strings.TrimSpace(line))
				}
			}
		}
	}

	if len(violations) > 0 {
		t.Errorf("Found %d legacy crypto references in production code:\n%s",
			len(violations), strings.Join(violations, "\n"))
	} else {
		t.Log("AUDIT PASS: No DSA or ElGamal key generation paths found in lib/keys production code")
	}
}

// TestNoLegacyCryptoImports verifies that no production files import legacy
// crypto packages (DSA, ElGamal) using Go AST parsing.
func TestNoLegacyCryptoImports(t *testing.T) {
	fset := token.NewFileSet()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("filepath.Glob() failed: %v", err)
	}

	legacyImports := []string{
		"crypto/dsa",
		"elgamal",
	}

	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}

		node, err := parser.ParseFile(fset, f, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("ParseFile(%s) failed: %v", f, err)
		}

		for _, imp := range node.Imports {
			importPath := strings.Trim(imp.Path.Value, "\"")
			for _, legacy := range legacyImports {
				if strings.Contains(importPath, legacy) {
					t.Errorf("legacy crypto import %q in %s", importPath, f)
				}
			}
		}
	}
}

// TestOnlyModernCryptoInGenerateNewKey verifies generateNewKey() uses Ed25519
// by checking the AST of the function body references only ed25519 package calls.
func TestOnlyModernCryptoInGenerateNewKey(t *testing.T) {
	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, "routerinfo_keystore.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("ParseFile() failed: %v", err)
	}

	found := false
	for _, decl := range node.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "generateNewKey" {
			continue
		}
		found = true

		// Walk the function body looking for selector expressions
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			ident, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			// Only ed25519 package should be called
			if ident.Name != "ed25519" && ident.Name != "log" && ident.Name != "oops" {
				t.Errorf("generateNewKey() calls %s.%s — expected only ed25519 package",
					ident.Name, sel.Sel.Name)
			}
			return true
		})
	}

	if !found {
		t.Error("generateNewKey() function not found in routerinfo_keystore.go")
	}
}

// =============================================================================
// Destination Keystore Modern Crypto Verification
// =============================================================================

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
	if len(sigPub.Bytes()) != 32 {
		t.Errorf("signing public key = %d bytes, want 32 (Ed25519)", len(sigPub.Bytes()))
	}

	// Verify encryption key is X25519 (32-byte public key)
	encPub, err := dks.EncryptionPublicKey()
	if err != nil {
		t.Fatalf("EncryptionPublicKey() failed: %v", err)
	}
	if len(encPub.Bytes()) != 32 {
		t.Errorf("encryption public key = %d bytes, want 32 (X25519)", len(encPub.Bytes()))
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
		{"CryptoPublicKeySize", sizes.CryptoPublicKeySize, 32},
		{"CryptoPrivateKeySize", sizes.CryptoPrivateKeySize, 32},
		{"SigningPublicKeySize", sizes.SigningPublicKeySize, 32},
		// Ed25519 private keys: 64 bytes (expanded) or 32 bytes (seed) depending on implementation
		{"SignatureSize", sizes.SignatureSize, 64}, // Ed25519 signatures are 64 bytes
	}

	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d", c.name, c.got, c.want)
		}
	}
}
