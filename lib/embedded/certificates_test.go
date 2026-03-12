package embedded

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// expectedReseedCerts lists the certificates we expect to be embedded from PLAN.md
var expectedReseedCerts = []string{
	"admin_at_stormycloud.org.crt",
	"creativecowpat_at_mail.i2p.crt",
	"diyarciftci_at_protonmail.com.crt",
	"echelon3_at_mail.i2p.crt",
	"hankhill19580_at_gmail.com.crt",
	"i2p-reseed_at_mk16.de.crt",
	"igor_at_novg.net.crt",
	"lazygravy_at_mail.i2p.crt",
	"r4sas-reseed_at_mail.i2p.crt",
	"rambler_at_mail.i2p.crt",
	"reseed_at_diva.exchange.crt",
	"sahil_at_mail.i2p.crt",
}

func TestCertificatesFS_EmbeddedCorrectly(t *testing.T) {
	entries, err := fs.ReadDir(CertificatesFS, "certificates")
	require.NoError(t, err)
	require.NotEmpty(t, entries, "certificates directory is empty")

	foundDirs := make(map[string]bool)
	for _, entry := range entries {
		if entry.IsDir() {
			foundDirs[entry.Name()] = true
		}
	}

	for _, dir := range []string{"reseed", "family", "ssl"} {
		assert.True(t, foundDirs[dir], "expected directory %q not found in embedded certificates", dir)
	}
}

func TestGetReseedCertificates(t *testing.T) {
	reseedFS, err := GetReseedCertificates()
	require.NoError(t, err)

	entries, err := fs.ReadDir(reseedFS, ".")
	require.NoError(t, err)
	require.NotEmpty(t, entries, "no reseed certificates found")

	crtCount := 0
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".crt") {
			crtCount++
		}
	}

	assert.GreaterOrEqual(t, crtCount, 10, "reseed certificate count")
}

func TestGetReseedCertificateByName(t *testing.T) {
	for _, certName := range expectedReseedCerts {
		t.Run(certName, func(t *testing.T) {
			data, err := GetReseedCertificateByName(certName)
			require.NoError(t, err)
			assert.NotEmpty(t, data, "certificate %q is empty", certName)
			assert.Contains(t, string(data), "-----BEGIN CERTIFICATE-----", "certificate %q not PEM format", certName)
			assert.Contains(t, string(data), "-----END CERTIFICATE-----", "certificate %q missing PEM end marker", certName)
		})
	}
}

func TestGetReseedCertificateByName_NotFound(t *testing.T) {
	_, err := GetReseedCertificateByName("nonexistent_cert.crt")
	assert.Error(t, err, "expected error for nonexistent certificate")
}

func TestGetCertificateByPath(t *testing.T) {
	data, err := GetCertificateByPath("reseed/admin_at_stormycloud.org.crt")
	require.NoError(t, err)
	assert.NotEmpty(t, data, "certificate data is empty")
	assert.Contains(t, string(data), "-----BEGIN CERTIFICATE-----", "not PEM format")
}

func TestListReseedCertificates(t *testing.T) {
	certs, err := ListReseedCertificates()
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(certs), 10, "certificate count")

	for _, cert := range certs {
		assert.True(t, strings.HasSuffix(cert, ".crt"), "certificate %q doesn't end with .crt", cert)
	}

	certMap := make(map[string]bool)
	for _, cert := range certs {
		certMap[cert] = true
	}

	for _, expected := range expectedReseedCerts {
		assert.True(t, certMap[expected], "expected certificate %q not found in list", expected)
	}
}

func TestExtractCertificates(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cert-extract-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	require.NoError(t, ExtractCertificates(tmpDir))

	reseedDir := filepath.Join(tmpDir, "reseed")
	info, err := os.Stat(reseedDir)
	require.NoError(t, err, "reseed directory not created")
	assert.True(t, info.IsDir(), "reseed should be a directory")

	entries, err := os.ReadDir(reseedDir)
	require.NoError(t, err)

	crtCount := 0
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".crt") {
			crtCount++
		}
	}
	assert.GreaterOrEqual(t, crtCount, 10, "extracted certificate count")

	extractedPath := filepath.Join(reseedDir, "admin_at_stormycloud.org.crt")
	extractedData, err := os.ReadFile(extractedPath)
	require.NoError(t, err)

	embeddedData, err := GetReseedCertificateByName("admin_at_stormycloud.org.crt")
	require.NoError(t, err)

	assert.Equal(t, string(embeddedData), string(extractedData), "extracted content should match embedded")
}

func TestExtractReseedCertificates(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "reseed-extract-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	require.NoError(t, ExtractReseedCertificates(tmpDir))

	entries, err := os.ReadDir(tmpDir)
	require.NoError(t, err)

	crtCount := 0
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".crt") {
			crtCount++
		}
	}
	assert.GreaterOrEqual(t, crtCount, 10, "reseed certificate count")

	for _, entry := range entries {
		assert.False(t, entry.IsDir(), "unexpected directory %q found", entry.Name())
	}
}

func TestGetFamilyCertificates(t *testing.T) {
	familyFS, err := GetFamilyCertificates()
	require.NoError(t, err)

	_, err = fs.ReadDir(familyFS, ".")
	assert.NoError(t, err, "failed to read family certificates directory")
}

func TestGetSSLCertificates(t *testing.T) {
	sslFS, err := GetSSLCertificates()
	require.NoError(t, err)

	_, err = fs.ReadDir(sslFS, ".")
	assert.NoError(t, err, "failed to read SSL certificates directory")
}
