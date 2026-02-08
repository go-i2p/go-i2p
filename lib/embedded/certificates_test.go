package embedded

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
	// Verify the CertificatesFS contains the certificates directory
	entries, err := fs.ReadDir(CertificatesFS, "certificates")
	if err != nil {
		t.Fatalf("failed to read embedded certificates directory: %v", err)
	}

	if len(entries) == 0 {
		t.Fatal("certificates directory is empty")
	}

	// Check for expected subdirectories
	expectedDirs := []string{"reseed", "family", "ssl"}
	foundDirs := make(map[string]bool)
	for _, entry := range entries {
		if entry.IsDir() {
			foundDirs[entry.Name()] = true
		}
	}

	for _, dir := range expectedDirs {
		if !foundDirs[dir] {
			t.Errorf("expected directory %q not found in embedded certificates", dir)
		}
	}
}

func TestGetReseedCertificates(t *testing.T) {
	reseedFS, err := GetReseedCertificates()
	if err != nil {
		t.Fatalf("GetReseedCertificates() error: %v", err)
	}

	entries, err := fs.ReadDir(reseedFS, ".")
	if err != nil {
		t.Fatalf("failed to read reseed certificates: %v", err)
	}

	if len(entries) == 0 {
		t.Fatal("no reseed certificates found")
	}

	// Count .crt files
	crtCount := 0
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".crt") {
			crtCount++
		}
	}

	if crtCount < 10 {
		t.Errorf("expected at least 10 reseed certificates, got %d", crtCount)
	}
}

func TestGetReseedCertificateByName(t *testing.T) {
	for _, certName := range expectedReseedCerts {
		t.Run(certName, func(t *testing.T) {
			data, err := GetReseedCertificateByName(certName)
			if err != nil {
				t.Fatalf("GetReseedCertificateByName(%q) error: %v", certName, err)
			}

			if len(data) == 0 {
				t.Errorf("certificate %q is empty", certName)
			}

			// Verify it's PEM format
			if !strings.Contains(string(data), "-----BEGIN CERTIFICATE-----") {
				t.Errorf("certificate %q doesn't appear to be PEM format", certName)
			}

			if !strings.Contains(string(data), "-----END CERTIFICATE-----") {
				t.Errorf("certificate %q missing PEM end marker", certName)
			}
		})
	}
}

func TestGetReseedCertificateByName_NotFound(t *testing.T) {
	_, err := GetReseedCertificateByName("nonexistent_cert.crt")
	if err == nil {
		t.Error("expected error for nonexistent certificate, got nil")
	}
}

func TestGetCertificateByPath(t *testing.T) {
	// Test with full path
	data, err := GetCertificateByPath("reseed/admin_at_stormycloud.org.crt")
	if err != nil {
		t.Fatalf("GetCertificateByPath() error: %v", err)
	}

	if len(data) == 0 {
		t.Error("certificate data is empty")
	}

	if !strings.Contains(string(data), "-----BEGIN CERTIFICATE-----") {
		t.Error("certificate doesn't appear to be PEM format")
	}
}

func TestListReseedCertificates(t *testing.T) {
	certs, err := ListReseedCertificates()
	if err != nil {
		t.Fatalf("ListReseedCertificates() error: %v", err)
	}

	if len(certs) < 10 {
		t.Errorf("expected at least 10 certificates, got %d", len(certs))
	}

	// Verify all returned names end with .crt
	for _, cert := range certs {
		if !strings.HasSuffix(cert, ".crt") {
			t.Errorf("certificate %q doesn't end with .crt", cert)
		}
	}

	// Check that expected certs are present
	certMap := make(map[string]bool)
	for _, cert := range certs {
		certMap[cert] = true
	}

	for _, expected := range expectedReseedCerts {
		if !certMap[expected] {
			t.Errorf("expected certificate %q not found in list", expected)
		}
	}
}

func TestExtractCertificates(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "cert-extract-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Extract certificates
	if err := ExtractCertificates(tmpDir); err != nil {
		t.Fatalf("ExtractCertificates() error: %v", err)
	}

	// Verify reseed directory was created
	reseedDir := filepath.Join(tmpDir, "reseed")
	info, err := os.Stat(reseedDir)
	if err != nil {
		t.Fatalf("reseed directory not created: %v", err)
	}
	if !info.IsDir() {
		t.Error("reseed should be a directory")
	}

	// Verify at least one certificate was extracted
	entries, err := os.ReadDir(reseedDir)
	if err != nil {
		t.Fatalf("failed to read extracted reseed dir: %v", err)
	}

	crtCount := 0
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".crt") {
			crtCount++
		}
	}

	if crtCount < 10 {
		t.Errorf("expected at least 10 extracted certificates, got %d", crtCount)
	}

	// Verify a specific certificate's content matches embedded version
	extractedPath := filepath.Join(reseedDir, "admin_at_stormycloud.org.crt")
	extractedData, err := os.ReadFile(extractedPath)
	if err != nil {
		t.Fatalf("failed to read extracted certificate: %v", err)
	}

	embeddedData, err := GetReseedCertificateByName("admin_at_stormycloud.org.crt")
	if err != nil {
		t.Fatalf("failed to read embedded certificate: %v", err)
	}

	if string(extractedData) != string(embeddedData) {
		t.Error("extracted certificate content doesn't match embedded version")
	}
}

func TestExtractReseedCertificates(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "reseed-extract-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Extract reseed certificates only
	if err := ExtractReseedCertificates(tmpDir); err != nil {
		t.Fatalf("ExtractReseedCertificates() error: %v", err)
	}

	// Verify certificates are directly in tmpDir (not in subdirectory)
	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatalf("failed to read temp dir: %v", err)
	}

	crtCount := 0
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".crt") {
			crtCount++
		}
	}

	if crtCount < 10 {
		t.Errorf("expected at least 10 certificates in root of temp dir, got %d", crtCount)
	}

	// Verify no subdirectories were created
	for _, entry := range entries {
		if entry.IsDir() {
			t.Errorf("unexpected directory %q found", entry.Name())
		}
	}
}

func TestGetFamilyCertificates(t *testing.T) {
	familyFS, err := GetFamilyCertificates()
	if err != nil {
		t.Fatalf("GetFamilyCertificates() error: %v", err)
	}

	// Just verify we can read from it (may be empty)
	_, err = fs.ReadDir(familyFS, ".")
	if err != nil {
		t.Errorf("failed to read family certificates directory: %v", err)
	}
}

func TestGetSSLCertificates(t *testing.T) {
	sslFS, err := GetSSLCertificates()
	if err != nil {
		t.Fatalf("GetSSLCertificates() error: %v", err)
	}

	// Just verify we can read from it (may be empty)
	_, err = fs.ReadDir(sslFS, ".")
	if err != nil {
		t.Errorf("failed to read SSL certificates directory: %v", err)
	}
}
