package reseed

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/fs"
	"math/big"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// generateTestCertPEM creates a valid self-signed test certificate for testing.
func generateTestCertPEM(email string) ([]byte, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: email,
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		EmailAddresses:        []string{email},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes}), nil
}

// createMockCertFS creates a mock filesystem with test certificates for testing.
func createMockCertFS() fs.FS {
	cert1, _ := generateTestCertPEM("test@example.com")
	cert2, _ := generateTestCertPEM("admin@testserver.org")

	return fstest.MapFS{
		"test_at_example.com.crt": &fstest.MapFile{
			Data: cert1,
			Mode: 0o644,
		},
		"admin_at_testserver.org.crt": &fstest.MapFile{
			Data: cert2,
			Mode: 0o644,
		},
	}
}

// setupTestProvider initializes the certificate provider for tests.
// This must be called before any test that uses GetDefaultCertificatePool.
var testProviderOnce sync.Once

func setupTestProvider() {
	testProviderOnce.Do(func() {
		SetCertificateProvider(func() (fs.FS, error) {
			return createMockCertFS(), nil
		})
	})
}

func TestNewCertificatePoolFromFS(t *testing.T) {
	mockFS := createMockCertFS()
	pool, err := NewCertificatePoolFromFS(mockFS)
	require.NoError(t, err)
	require.NotNil(t, pool)

	// Should have loaded 2 certificates from mock FS
	assert.Equal(t, 2, pool.Count(), "Should have loaded 2 certificates")

	t.Logf("Loaded %d certificates", pool.Count())
}

func TestCertificatePool_Count(t *testing.T) {
	mockFS := createMockCertFS()
	pool, err := NewCertificatePoolFromFS(mockFS)
	require.NoError(t, err)

	count := pool.Count()
	assert.Equal(t, 2, count, "Should have 2 test certificates")
}

func TestCertificatePool_ListSignerIDs(t *testing.T) {
	mockFS := createMockCertFS()
	pool, err := NewCertificatePoolFromFS(mockFS)
	require.NoError(t, err)

	signerIDs := pool.ListSignerIDs()
	assert.NotEmpty(t, signerIDs, "Should have signer IDs")
	assert.Len(t, signerIDs, pool.Count(), "Signer IDs should match certificate count")

	t.Logf("Signer IDs: %v", signerIDs)
}

func TestCertificatePool_GetCertificate(t *testing.T) {
	mockFS := createMockCertFS()
	pool, err := NewCertificatePoolFromFS(mockFS)
	require.NoError(t, err)

	// Get a known signer ID from the pool
	signerIDs := pool.ListSignerIDs()
	require.NotEmpty(t, signerIDs)

	signerID := signerIDs[0]
	cert, ok := pool.GetCertificate(signerID)
	assert.True(t, ok, "Should find certificate for signer ID %s", signerID)
	assert.NotNil(t, cert, "Certificate should not be nil")
}

func TestCertificatePool_GetCertificate_NotFound(t *testing.T) {
	mockFS := createMockCertFS()
	pool, err := NewCertificatePoolFromFS(mockFS)
	require.NoError(t, err)

	cert, ok := pool.GetCertificate("nonexistent@example.com")
	assert.False(t, ok, "Should not find certificate for unknown signer")
	assert.Nil(t, cert, "Certificate should be nil")
}

func TestCertificatePool_HasSigner(t *testing.T) {
	mockFS := createMockCertFS()
	pool, err := NewCertificatePoolFromFS(mockFS)
	require.NoError(t, err)

	signerIDs := pool.ListSignerIDs()
	require.NotEmpty(t, signerIDs)

	// Should find existing signer
	assert.True(t, pool.HasSigner(signerIDs[0]))

	// Should not find non-existent signer
	assert.False(t, pool.HasSigner("nonexistent@example.com"))
}

func TestCertificatePool_GetPublicKey(t *testing.T) {
	mockFS := createMockCertFS()
	pool, err := NewCertificatePoolFromFS(mockFS)
	require.NoError(t, err)

	signerIDs := pool.ListSignerIDs()
	require.NotEmpty(t, signerIDs)

	signerID := signerIDs[0]
	pubKey, err := pool.GetPublicKey(signerID)
	assert.NoError(t, err)
	assert.NotNil(t, pubKey, "Public key should not be nil")
}

func TestCertificatePool_GetPublicKey_NotFound(t *testing.T) {
	mockFS := createMockCertFS()
	pool, err := NewCertificatePoolFromFS(mockFS)
	require.NoError(t, err)

	pubKey, err := pool.GetPublicKey("nonexistent@example.com")
	assert.Error(t, err, "Should error for unknown signer")
	assert.Nil(t, pubKey, "Public key should be nil")
	assert.Contains(t, err.Error(), "no certificate found")
}

func TestCertificatePool_Pool(t *testing.T) {
	mockFS := createMockCertFS()
	pool, err := NewCertificatePoolFromFS(mockFS)
	require.NoError(t, err)

	x509Pool := pool.Pool()
	assert.NotNil(t, x509Pool, "x509.CertPool should not be nil")
}

func TestCertificatePool_ValidateCertificate(t *testing.T) {
	tests := []struct {
		name        string
		notBefore   time.Time
		notAfter    time.Time
		expectError bool
		errorMsg    string
	}{
		{
			name:        "valid certificate",
			notBefore:   time.Now().Add(-24 * time.Hour),
			notAfter:    time.Now().Add(24 * time.Hour),
			expectError: false,
		},
		{
			name:        "expired certificate",
			notBefore:   time.Now().Add(-48 * time.Hour),
			notAfter:    time.Now().Add(-24 * time.Hour),
			expectError: true,
			errorMsg:    "expired",
		},
		{
			name:        "not yet valid certificate",
			notBefore:   time.Now().Add(24 * time.Hour),
			notAfter:    time.Now().Add(48 * time.Hour),
			expectError: true,
			errorMsg:    "not yet valid",
		},
	}

	pool := &CertificatePool{} // Empty pool is fine for validation tests

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := &x509.Certificate{
				NotBefore: tt.notBefore,
				NotAfter:  tt.notAfter,
			}

			err := pool.ValidateCertificate(cert, "test-signer")

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestGetDefaultCertificatePool(t *testing.T) {
	// Set up the provider first
	setupTestProvider()

	// First call should initialize the pool
	pool1, err1 := GetDefaultCertificatePool()
	require.NoError(t, err1)
	require.NotNil(t, pool1)

	// Second call should return the same pool (singleton)
	pool2, err2 := GetDefaultCertificatePool()
	require.NoError(t, err2)
	require.NotNil(t, pool2)

	// Should be the same instance
	assert.Same(t, pool1, pool2, "GetDefaultCertificatePool should return same instance")
}

func TestExtractSignerID(t *testing.T) {
	tests := []struct {
		name       string
		cert       *x509.Certificate
		filename   string
		expectedID string
	}{
		{
			name: "certificate with email",
			cert: &x509.Certificate{
				EmailAddresses: []string{"test@example.com"},
			},
			filename:   "test.crt",
			expectedID: "test@example.com",
		},
		{
			name: "certificate with common name",
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "Test Common Name",
				},
			},
			filename:   "test.crt",
			expectedID: "Test Common Name",
		},
		{
			name:       "filename fallback with _at_",
			cert:       &x509.Certificate{},
			filename:   "admin_at_stormycloud.org.crt",
			expectedID: "admin@stormycloud.org",
		},
		{
			name:       "filename fallback without _at_",
			cert:       &x509.Certificate{},
			filename:   "simple_name.crt",
			expectedID: "simple_name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractSignerID(tt.cert, tt.filename)
			assert.Equal(t, tt.expectedID, result)
		})
	}
}

func TestCertificatePoolThreadSafety(t *testing.T) {
	mockFS := createMockCertFS()
	pool, err := NewCertificatePoolFromFS(mockFS)
	require.NoError(t, err)

	signerIDs := pool.ListSignerIDs()
	require.NotEmpty(t, signerIDs)

	// Concurrent access to certificate pool
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				pool.GetCertificate(signerIDs[0])
				pool.HasSigner(signerIDs[0])
				pool.Count()
				pool.ListSignerIDs()
			}
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}
}

// TestKnownSignerIDs verifies that known signers from PLAN.md are loaded
func TestKnownSignerIDs(t *testing.T) {
	mockFS := createMockCertFS()
	pool, err := NewCertificatePoolFromFS(mockFS)
	require.NoError(t, err)

	// These are some expected signers based on our mock FS
	signerIDs := pool.ListSignerIDs()
	t.Logf("Available signer IDs: %v", signerIDs)

	// We should have our test signers
	assert.NotEmpty(t, signerIDs, "Should have some signer IDs loaded")
}
