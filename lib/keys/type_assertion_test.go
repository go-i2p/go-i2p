package keys

import (
	"testing"

	"github.com/go-i2p/common/certificate"
	"github.com/go-i2p/common/keys_and_cert"
	"github.com/go-i2p/crypto/types"
)

// mockPublicKeyNotSigning implements types.PublicKey but NOT types.SigningPublicKey.
// Used to test the checked type assertion in buildRouterIdentity.
type mockPublicKeyNotSigning struct{}

func (m *mockPublicKeyNotSigning) Len() int      { return 32 }
func (m *mockPublicKeyNotSigning) Bytes() []byte { return make([]byte, 32) }

// mockPrivateKeyNotSigning implements types.PrivateKey but NOT types.SigningPrivateKey.
// Used to test the checked type assertion in assembleRouterInfo.
type mockPrivateKeyNotSigning struct{}

func (m *mockPrivateKeyNotSigning) Public() (types.SigningPublicKey, error) { return nil, nil }
func (m *mockPrivateKeyNotSigning) Bytes() []byte                           { return make([]byte, 32) }
func (m *mockPrivateKeyNotSigning) Zero()                                   {}

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

	// Use sizes that sum to more than KEYS_AND_CERT_DATA_SIZE
	oversized := keys_and_cert.KEYS_AND_CERT_DATA_SIZE + 1
	_, err := ks.generateIdentityPaddingFromSizes(oversized, 1)
	if err == nil {
		t.Fatal("expected error for oversized keys, got nil")
	}
	if !containsString(err.Error(), "exceed") {
		t.Errorf("error should mention exceeding size limit, got: %v", err)
	}
}

// TestGenerateIdentityPaddingFromSizes_ValidSizes verifies normal operation.
func TestGenerateIdentityPaddingFromSizes_ValidSizes(t *testing.T) {
	ks := &RouterInfoKeystore{}

	padding, err := ks.generateIdentityPaddingFromSizes(32, 32)
	if err != nil {
		t.Fatalf("unexpected error for valid sizes: %v", err)
	}
	expectedLen := keys_and_cert.KEYS_AND_CERT_DATA_SIZE - 64
	if len(padding) != expectedLen {
		t.Errorf("padding length = %d, want %d", len(padding), expectedLen)
	}
}

// helper types for tests

type mockEncryptionPublicKey struct{}

func (m *mockEncryptionPublicKey) Len() int                               { return 32 }
func (m *mockEncryptionPublicKey) Bytes() []byte                          { return make([]byte, 32) }
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
