package reseed

import (
	"bytes"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewReseed verifies that a new Reseed instance is created correctly
func TestNewReseed(t *testing.T) {
	r := NewReseed()
	assert.NotNil(t, r)
}

// TestCreateReseedHTTPClient verifies HTTP client configuration
func TestCreateReseedHTTPClient(t *testing.T) {
	client := createReseedHTTPClient(nil)
	require.NotNil(t, client)

	// Verify timeout is set to 30 seconds
	assert.Equal(t, 30*time.Second, client.Timeout)

	// Verify transport is configured
	transport, ok := client.Transport.(*http.Transport)
	require.True(t, ok)
	require.NotNil(t, transport.TLSClientConfig)

	// Verify TLS 1.2 minimum
	assert.Equal(t, uint16(0x0303), transport.TLSClientConfig.MinVersion) // TLS 1.2

	// Verify InsecureSkipVerify is NOT set
	assert.False(t, transport.TLSClientConfig.InsecureSkipVerify)
}

// TestBuildReseedHTTPRequest verifies request construction
func TestBuildReseedHTTPRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Just needed for URL parsing
	}))
	defer server.Close()

	testURL, err := url.Parse(server.URL + "/i2pseeds.su3")
	require.NoError(t, err)

	request := buildReseedHTTPRequest(testURL)

	assert.Equal(t, "GET", request.Method)
	assert.Equal(t, I2pUserAgent, request.Header.Get("User-Agent"))
	assert.Equal(t, "*/*", request.Header.Get("Accept"))
	assert.Equal(t, "HTTP/1.1", request.Proto)
}

// TestValidateReseedResponse verifies response validation
func TestValidateReseedResponse(t *testing.T) {
	tests := []struct {
		name          string
		statusCode    int
		contentLength int64
		expectError   bool
		errorContains string
	}{
		{
			name:          "valid response",
			statusCode:    200,
			contentLength: 1000,
			expectError:   false,
		},
		{
			name:          "error status code",
			statusCode:    404,
			contentLength: 100,
			expectError:   true,
			errorContains: "status 404",
		},
		{
			name:          "internal server error",
			statusCode:    500,
			contentLength: 100,
			expectError:   true,
			errorContains: "status 500",
		},
		{
			name:          "content too small",
			statusCode:    200,
			contentLength: 50, // Less than 100 bytes minimum
			expectError:   true,
			errorContains: "too small",
		},
		{
			name:          "no content length header - should pass",
			statusCode:    200,
			contentLength: -1, // -1 means no Content-Length header
			expectError:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response := &http.Response{
				StatusCode:    tt.statusCode,
				ContentLength: tt.contentLength,
				Header:        http.Header{},
				Body:          http.NoBody,
			}

			err := validateReseedResponse(response, "https://test.example.com")

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestGetPublicKeyForSigner verifies signer certificate handling
// Note: This test uses a mock certificate pool set up by setupTestProvider.
func TestGetPublicKeyForSigner(t *testing.T) {
	// Set up the mock certificate provider
	setupTestProvider()

	r := NewReseed()

	tests := []struct {
		name        string
		signerID    string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "known signer from mock pool",
			signerID:    "test@example.com",
			expectError: false,
		},
		{
			name:        "another known signer from mock pool",
			signerID:    "admin@testserver.org",
			expectError: false,
		},
		{
			name:        "unknown signer - should be rejected",
			signerID:    "unknown@attacker.com",
			expectError: true,
			errorMsg:    "unknown or untrusted",
		},
		{
			name:        "empty signer - should be rejected",
			signerID:    "",
			expectError: true,
			errorMsg:    "unknown or untrusted",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			publicKey, err := r.getPublicKeyForSigner(tt.signerID)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, publicKey)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, publicKey)
			}
		})
	}
}

// TestValidateCertificate verifies certificate expiration checking
// using the CertificatePool's ValidateCertificate method
func TestValidateCertificate(t *testing.T) {
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

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := &x509.Certificate{
				NotBefore: tt.notBefore,
				NotAfter:  tt.notAfter,
			}

			// Use the CertificatePool's ValidateCertificate method
			cp := &CertificatePool{}
			err := cp.ValidateCertificate(cert, "test-signer")

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

// TestIsRouterInfoFile verifies RouterInfo file detection
func TestIsRouterInfoFile(t *testing.T) {
	r := NewReseed()

	tests := []struct {
		name     string
		filePath string
		expected bool
	}{
		{
			name:     "valid RouterInfo file",
			filePath: "routerInfo-ABC123.dat",
			expected: true,
		},
		{
			name:     "valid RouterInfo with path",
			filePath: "/tmp/netdb/routerInfo-XYZ789.dat",
			expected: true,
		},
		{
			name:     "wrong extension",
			filePath: "routerInfo-ABC123.txt",
			expected: false,
		},
		{
			name:     "wrong prefix",
			filePath: "leaseSet-ABC123.dat",
			expected: false,
		},
		{
			name:     "directory path",
			filePath: "/tmp/netdb/routerInfo-/",
			expected: false,
		},
		{
			name:     "empty filename",
			filePath: "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := r.isRouterInfoFile(tt.filePath)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestWriteZipFile verifies temp file creation and cleanup
func TestWriteZipFile(t *testing.T) {
	r := NewReseed()

	// Create test content
	content := bytes.Repeat([]byte("test"), 100)

	// Write zip file
	zipPath, err := r.writeZipFile(content)
	require.NoError(t, err)
	require.NotEmpty(t, zipPath)

	// Verify file exists
	info, err := os.Stat(zipPath)
	require.NoError(t, err)
	assert.Equal(t, int64(len(content)), info.Size())

	// Verify content
	readContent, err := os.ReadFile(zipPath)
	require.NoError(t, err)
	assert.Equal(t, content, readContent)

	// Clean up
	r.cleanupZipFile(zipPath)

	// Verify file is removed
	_, err = os.Stat(zipPath)
	assert.True(t, os.IsNotExist(err))
}

// TestCleanupTempDirectory verifies temp directory cleanup
func TestCleanupTempDirectory(t *testing.T) {
	r := NewReseed()

	// Create temp directory
	tempDir, err := os.MkdirTemp("", "reseed-test-*")
	require.NoError(t, err)

	// Create some files in it
	testFile := filepath.Join(tempDir, "test.dat")
	err = os.WriteFile(testFile, []byte("test"), 0o644)
	require.NoError(t, err)

	// Verify directory exists
	_, err = os.Stat(tempDir)
	require.NoError(t, err)

	// Clean up
	r.cleanupTempDirectory(tempDir)

	// Verify directory is removed
	_, err = os.Stat(tempDir)
	assert.True(t, os.IsNotExist(err))
}

// TestCleanupTempDirectory_EmptyPath verifies empty path handling
func TestCleanupTempDirectory_EmptyPath(t *testing.T) {
	r := NewReseed()

	// Should not panic or error with empty path
	r.cleanupTempDirectory("")
}

// TestValidateSU3FileType verifies SU3 file type validation
func TestValidateSU3FileType(t *testing.T) {
	// Note: This test is limited because we can't easily construct SU3 objects
	// without actual SU3 files. The function is tested indirectly through
	// integration tests with real reseed files.
	t.Skip("Requires SU3 library mocking or real SU3 files")
}

// TestEnsureReseedPath tests the standard path appending logic
func TestEnsureReseedPath(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "root URL with trailing slash",
			input:    "https://reseed.i2pgit.org/",
			expected: "https://reseed.i2pgit.org/i2pseeds.su3",
		},
		{
			name:     "root URL without trailing slash",
			input:    "https://reseed.i2pgit.org",
			expected: "https://reseed.i2pgit.org/i2pseeds.su3",
		},
		{
			name:     "URL already has SU3 path",
			input:    "https://reseed.i2pgit.org/i2pseeds.su3",
			expected: "https://reseed.i2pgit.org/i2pseeds.su3",
		},
		{
			name:     "URL with custom SU3 path",
			input:    "https://example.com/custom/reseed.su3",
			expected: "https://example.com/custom/reseed.su3",
		},
		{
			name:     "URL with subpath but no SU3",
			input:    "https://example.com/reseed/",
			expected: "https://example.com/reseed/i2pseeds.su3",
		},
		{
			name:     "URL with port",
			input:    "https://i2pseed.creativecowpat.net:8443/",
			expected: "https://i2pseed.creativecowpat.net:8443/i2pseeds.su3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := url.Parse(tt.input)
			require.NoError(t, err)

			result := ensureReseedPath(u)
			assert.Equal(t, tt.expected, result.String())
		})
	}
}

// TestEnsureReseedPath_DoesNotModifyOriginal verifies the original URL is not mutated
func TestEnsureReseedPath_DoesNotModifyOriginal(t *testing.T) {
	u, err := url.Parse("https://reseed.i2pgit.org/")
	require.NoError(t, err)

	original := u.String()
	result := ensureReseedPath(u)

	// Original should be unchanged
	assert.Equal(t, original, u.String())
	// Result should have path appended
	assert.Equal(t, "https://reseed.i2pgit.org/i2pseeds.su3", result.String())
}

// TestCreateReseedHTTPClient_HasRootCAs verifies the TLS config has a custom RootCAs pool
func TestCreateReseedHTTPClient_HasRootCAs(t *testing.T) {
	client := createReseedHTTPClient(nil)
	require.NotNil(t, client)

	transport, ok := client.Transport.(*http.Transport)
	require.True(t, ok)
	require.NotNil(t, transport.TLSClientConfig)

	// The RootCAs pool should be set (system pool, possibly with embedded certs)
	assert.NotNil(t, transport.TLSClientConfig.RootCAs)
}
