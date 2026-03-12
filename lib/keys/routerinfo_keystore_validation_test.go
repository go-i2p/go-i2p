package keys

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/go-i2p/common/certificate"
	"github.com/go-i2p/common/keys_and_cert"
	"github.com/go-i2p/crypto/ed25519"
	"github.com/go-i2p/crypto/types"
)

// =============================================================================
// Mock types for type assertion safety tests
// =============================================================================

// mockPublicKeyNotSigning implements types.PublicKey but NOT types.SigningPublicKey.
type mockPublicKeyNotSigning struct{}

func (m *mockPublicKeyNotSigning) Len() int      { return testEd25519PubKeySize }
func (m *mockPublicKeyNotSigning) Bytes() []byte { return make([]byte, testEd25519PubKeySize) }

// mockPrivateKeyNotSigning implements types.PrivateKey but NOT types.SigningPrivateKey.
type mockPrivateKeyNotSigning struct{}

func (m *mockPrivateKeyNotSigning) Public() (types.SigningPublicKey, error) { return nil, nil }
func (m *mockPrivateKeyNotSigning) Bytes() []byte                           { return make([]byte, testEd25519PubKeySize) }
func (m *mockPrivateKeyNotSigning) Zero()                                   {}

type mockEncryptionPublicKey struct{}

func (m *mockEncryptionPublicKey) Len() int                               { return testEd25519PubKeySize }
func (m *mockEncryptionPublicKey) Bytes() []byte                          { return make([]byte, testEd25519PubKeySize) }
func (m *mockEncryptionPublicKey) NewEncrypter() (types.Encrypter, error) { return nil, nil }

// containsString checks if s contains substr without importing strings.
func containsString(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// =============================================================================
// Type Assertion Safety
// =============================================================================

// TestBuildRouterIdentity_NonSigningPublicKey verifies that buildRouterIdentity
// returns a descriptive error instead of panicking when the public key does not
// implement types.SigningPublicKey.
func TestBuildRouterIdentity_NonSigningPublicKey(t *testing.T) {
	ks := &RouterInfoKeystore{
		encryptionPubKey: &mockEncryptionPublicKey{},
	}
	cert := &certificate.Certificate{}

	_, err := ks.buildRouterIdentity(&mockPublicKeyNotSigning{}, cert)
	if err == nil {
		t.Fatal("expected error for non-SigningPublicKey, got nil")
	}
	if !containsString(err.Error(), "SigningPublicKey") {
		t.Errorf("error should mention SigningPublicKey, got: %v", err)
	}
}

// TestAssembleRouterInfo_NonSigningPrivateKey verifies that assembleRouterInfo
// returns a descriptive error instead of panicking when the private key does not
// implement types.SigningPrivateKey.
func TestAssembleRouterInfo_NonSigningPrivateKey(t *testing.T) {
	ks := &RouterInfoKeystore{}

	_, err := ks.assembleRouterInfo(nil, nil, &mockPrivateKeyNotSigning{}, RouterInfoOptions{})
	if err == nil {
		t.Fatal("expected error for non-SigningPrivateKey, got nil")
	}
	if !containsString(err.Error(), "SigningPrivateKey") {
		t.Errorf("error should mention SigningPrivateKey, got: %v", err)
	}
}

// TestGenerateIdentityPaddingFromSizes_NegativePadding verifies that
// generateIdentityPaddingFromSizes returns an error instead of panicking
// when key sizes exceed KEYS_AND_CERT_DATA_SIZE.
func TestGenerateIdentityPaddingFromSizes_NegativePadding(t *testing.T) {
	ks := &RouterInfoKeystore{}

	oversized := keys_and_cert.KEYS_AND_CERT_DATA_SIZE + 1
	_, err := ks.generateIdentityPaddingFromSizes(oversized, 1)
	if err == nil {
		t.Fatal("expected error for oversized keys, got nil")
	}
	if !containsString(err.Error(), "exceed") {
		t.Errorf("error should mention exceeding size limit, got: %v", err)
	}
}

// =============================================================================
// File Permission Security
// =============================================================================

func TestRouterInfoKeystore_StoreKeys_SecurePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping file permission test on Windows")
	}

	tmpDir, err := os.MkdirTemp("", "routerinfo_keys_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	_, privateKey, err := ed25519.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to create private key: %v", err)
	}

	ks := &RouterInfoKeystore{
		dir:        tmpDir,
		privateKey: privateKey,
		name:       "test-router",
	}

	err = ks.StoreKeys()
	if err != nil {
		t.Fatalf("StoreKeys failed: %v", err)
	}

	expectedPath := filepath.Join(tmpDir, "test-router.key")
	assertKeyFilePermissions(t, expectedPath, testKeyFilePerms)
}

// TestDirectoryPermissions verifies that keystore directories are created with
// secure permissions (0700).
func TestDirectoryPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping file permission test on Windows")
	}

	tmpDir, err := os.MkdirTemp("", "keys_security_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	keystoreDir := filepath.Join(tmpDir, "keystore")

	err = ensureDirectoryExists(keystoreDir)
	if err != nil {
		t.Fatalf("ensureDirectoryExists failed: %v", err)
	}

	info, err := os.Stat(keystoreDir)
	if err != nil {
		t.Fatalf("Failed to stat keystore directory: %v", err)
	}

	perm := info.Mode().Perm()
	if perm != testDirPerms {
		t.Errorf("Keystore directory has insecure permissions %o, expected %o", perm, testDirPerms)
	}
}

// TestKeyFilePermissions verifies that key files are written with secure
// permissions (0600).
func TestKeyFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping file permission test on Windows")
	}

	tmpDir, err := os.MkdirTemp("", "keys_security_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	_, privKey, err := ed25519.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	ks := &RouterInfoKeystore{
		dir:        tmpDir,
		name:       "test-security",
		privateKey: privKey,
	}

	err = ks.StoreKeys()
	if err != nil {
		t.Fatalf("StoreKeys failed: %v", err)
	}

	keyFile := filepath.Join(tmpDir, "test-security.key")
	info, err := os.Stat(keyFile)
	if err != nil {
		t.Fatalf("Failed to stat key file: %v", err)
	}

	perm := info.Mode().Perm()
	if perm != testKeyFilePerms {
		t.Errorf("Key file has insecure permissions %o, expected %o", perm, testKeyFilePerms)
	}
}

// TestLoadOrGenerateEncryptionKey_CorruptedFile verifies that a corrupted
// encryption key file returns an error rather than silently using bad data.
func TestLoadOrGenerateEncryptionKey_CorruptedFile(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "enckey_corrupt_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Write a corrupted key file (wrong length — curve25519 expects exactly 32 bytes)
	keyPath := filepath.Join(tmpDir, "corrupt.enc.key")
	if err := os.WriteFile(keyPath, []byte("too-short"), testKeyFilePerms); err != nil {
		t.Fatalf("Failed to write corrupted key file: %v", err)
	}

	_, _, err = loadOrGenerateEncryptionKey(tmpDir, "corrupt")
	if err == nil {
		t.Error("Expected error loading corrupted key file, got nil")
	}
}

// TestRouterInfoKeystore_Close_NilKeysNoPanic verifies that Close() does not
// panic when called on a keystore with nil keys.
func TestRouterInfoKeystore_Close_NilKeysNoPanic(t *testing.T) {
	ks := &RouterInfoKeystore{
		privateKey:        nil,
		encryptionPrivKey: nil,
	}

	// Should not panic
	ks.Close()
}

// =============================================================================
// Legacy Crypto Audit
// =============================================================================

// TestNoLegacyCryptoInKeyGeneration uses AST analysis to verify that the
// production code in lib/keys contains no DSA or ElGamal key generation calls.
func TestNoLegacyCryptoInKeyGeneration(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("filepath.Glob() failed: %v", err)
	}

	legacyPatterns := []string{
		"dsa.Generate",
		"DSA",
		"ElGamal",
		"elgamal",
		"NewDSA",
		"KEYCERT_SIGN_DSA",
		"KEYCERT_CRYPTO_ELG",
	}

	isException := func(filename, line string) bool {
		if strings.HasSuffix(filename, "_test.go") {
			return true
		}
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") {
			return true
		}
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
// by checking the AST of the function body.
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

		ast.Inspect(fn.Body, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			ident, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
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

// TestOfflineSignatures_NotImplemented documents that Proposal 123 (offline/transient
// signing keys) is not yet implemented in go-i2p's key management.
func TestOfflineSignatures_NotImplemented(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("filepath.Glob() failed: %v", err)
	}

	offlineRefs := 0
	for _, f := range files {
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
