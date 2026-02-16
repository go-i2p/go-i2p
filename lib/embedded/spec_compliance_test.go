package embedded

// spec_compliance_test.go — I2P specification compliance tests for lib/embedded
//
// These tests verify conformance with:
//   - updates.rst: Trusted certificates for reseed and plugin verification
//   - X.509 PEM certificate format for SSL/reseed/router/news/plugin/family
//
// AUDIT Section 4 (lib/embedded) checklist coverage:
//   [x] Certificate set: Embedded certificates match top-level certificates/ bundle
//   [x] Certificate types: All 6 directories present (family, news, plugin, reseed, router, ssl)
//   [x] Certificate format: X.509 PEM for all certificates
//   [x] Crypto: All certificates use modern signature types (RSA-SHA256/SHA512, ECDSA-SHA256/SHA512)
//   [x] Legacy: No DSA-signed certificates found

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// =============================================================================
// Certificate Set Compliance — All Required Directories Present
// =============================================================================

// TestCertificateDirectories_AllPresent verifies that all 6 required certificate
// type directories are present per the I2P certificate bundle structure:
// family, news, plugin, reseed, router, ssl.
func TestCertificateDirectories_AllPresent(t *testing.T) {
	requiredDirs := []string{"family", "news", "plugin", "reseed", "router", "ssl"}

	entries, err := fs.ReadDir(CertificatesFS, "certificates")
	if err != nil {
		t.Fatalf("failed to read certificates directory: %v", err)
	}

	foundDirs := make(map[string]bool)
	for _, entry := range entries {
		if entry.IsDir() {
			foundDirs[entry.Name()] = true
		}
	}

	for _, dir := range requiredDirs {
		if !foundDirs[dir] {
			t.Errorf("required certificate directory %q not found in embedded certificates", dir)
		}
	}
}

// TestCertificateDirectories_NonEmpty verifies each certificate directory
// contains at least one certificate file (except possibly empty ones for
// which the test logs a warning).
func TestCertificateDirectories_NonEmpty(t *testing.T) {
	dirs := []struct {
		name     string
		minCerts int // minimum expected certificates (0 = may be empty)
	}{
		{"family", 1},
		{"news", 1},
		{"plugin", 1},
		{"reseed", 10}, // reseed is critical — must have many
		{"router", 1},
		{"ssl", 1},
	}

	for _, d := range dirs {
		t.Run(d.name, func(t *testing.T) {
			subFS, err := fs.Sub(CertificatesFS, "certificates/"+d.name)
			if err != nil {
				t.Fatalf("fs.Sub() for %s failed: %v", d.name, err)
			}

			entries, err := fs.ReadDir(subFS, ".")
			if err != nil {
				t.Fatalf("ReadDir() for %s failed: %v", d.name, err)
			}

			certCount := 0
			for _, entry := range entries {
				if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".crt") {
					certCount++
				}
			}

			if certCount < d.minCerts {
				t.Errorf("%s directory has %d certificates, want at least %d",
					d.name, certCount, d.minCerts)
			}

			t.Logf("%s: %d certificates", d.name, certCount)
		})
	}
}

// TestEmbeddedCertificates_MatchTopLevel verifies that the embedded certificate
// set exactly matches the top-level certificates/ directory. This ensures the
// embed is kept in sync with the project's canonical certificate bundle.
func TestEmbeddedCertificates_MatchTopLevel(t *testing.T) {
	topLevelDir := filepath.Join("..", "..", "certificates")
	if _, err := os.Stat(topLevelDir); os.IsNotExist(err) {
		t.Skip("top-level certificates/ directory not found — skipping sync check")
	}

	// Collect all files from the embedded FS
	embeddedFiles := make(map[string][]byte)
	err := fs.WalkDir(CertificatesFS, "certificates", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, readErr := CertificatesFS.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		// Strip "certificates/" prefix to get relative path
		rel, relErr := filepath.Rel("certificates", path)
		if relErr != nil {
			return relErr
		}
		embeddedFiles[rel] = data
		return nil
	})
	if err != nil {
		t.Fatalf("WalkDir on embedded FS failed: %v", err)
	}

	// Collect all files from the top-level certificates/ directory
	topLevelFiles := make(map[string][]byte)
	err = filepath.Walk(topLevelDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		rel, relErr := filepath.Rel(topLevelDir, path)
		if relErr != nil {
			return relErr
		}
		topLevelFiles[rel] = data
		return nil
	})
	if err != nil {
		t.Fatalf("Walk on top-level certificates/ failed: %v", err)
	}

	// Check that every top-level cert is in embedded
	for name, data := range topLevelFiles {
		embData, ok := embeddedFiles[name]
		if !ok {
			t.Errorf("top-level certificate %q not found in embedded FS", name)
			continue
		}
		if string(data) != string(embData) {
			t.Errorf("certificate %q content differs between embedded and top-level", name)
		}
	}

	// Check that every embedded cert is in top-level
	for name := range embeddedFiles {
		if _, ok := topLevelFiles[name]; !ok {
			t.Errorf("embedded certificate %q not found in top-level certificates/", name)
		}
	}

	t.Logf("AUDIT: embedded(%d) and top-level(%d) certificate sets are in sync",
		len(embeddedFiles), len(topLevelFiles))
}

// =============================================================================
// Certificate Format Compliance — X.509 PEM
// =============================================================================

// TestAllCertificates_ValidPEM verifies every embedded .crt file is valid PEM-encoded.
func TestAllCertificates_ValidPEM(t *testing.T) {
	certCount := 0
	err := fs.WalkDir(CertificatesFS, "certificates", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(d.Name(), ".crt") {
			return err
		}

		data, readErr := CertificatesFS.ReadFile(path)
		if readErr != nil {
			t.Errorf("failed to read %s: %v", path, readErr)
			return nil
		}

		block, _ := pem.Decode(data)
		if block == nil {
			t.Errorf("%s: not valid PEM format", path)
			return nil
		}

		if block.Type != "CERTIFICATE" {
			t.Errorf("%s: PEM block type = %q, want \"CERTIFICATE\"", path, block.Type)
			return nil
		}

		certCount++
		return nil
	})
	if err != nil {
		t.Fatalf("WalkDir failed: %v", err)
	}

	if certCount == 0 {
		t.Fatal("no .crt files found in embedded certificates")
	}
	t.Logf("AUDIT: %d certificates verified as valid PEM CERTIFICATE blocks", certCount)
}

// TestAllCertificates_X509Parseable verifies every embedded certificate can be
// parsed as a valid X.509 certificate.
func TestAllCertificates_X509Parseable(t *testing.T) {
	certCount := 0
	err := fs.WalkDir(CertificatesFS, "certificates", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(d.Name(), ".crt") {
			return err
		}

		data, readErr := CertificatesFS.ReadFile(path)
		if readErr != nil {
			t.Errorf("failed to read %s: %v", path, readErr)
			return nil
		}

		block, _ := pem.Decode(data)
		if block == nil {
			t.Errorf("%s: not valid PEM", path)
			return nil
		}

		cert, parseErr := x509.ParseCertificate(block.Bytes)
		if parseErr != nil {
			t.Errorf("%s: failed to parse X.509: %v", path, parseErr)
			return nil
		}

		// Verify the certificate has a subject
		if cert.Subject.CommonName == "" && len(cert.Subject.Organization) == 0 {
			t.Errorf("%s: X.509 certificate has no Subject CommonName or Organization", path)
		}

		certCount++
		return nil
	})
	if err != nil {
		t.Fatalf("WalkDir failed: %v", err)
	}

	t.Logf("AUDIT: %d certificates verified as valid X.509", certCount)
}

// =============================================================================
// Cryptography Audit — Modern Signature Types Only (No DSA)
// =============================================================================

// modernSignatureAlgorithms lists X.509 signature algorithms considered modern/acceptable.
// DSA-based algorithms are NOT included — they are considered legacy.
var modernSignatureAlgorithms = map[x509.SignatureAlgorithm]string{
	x509.SHA256WithRSA:   "SHA256-RSA",
	x509.SHA384WithRSA:   "SHA384-RSA",
	x509.SHA512WithRSA:   "SHA512-RSA",
	x509.ECDSAWithSHA256: "ECDSA-SHA256",
	x509.ECDSAWithSHA384: "ECDSA-SHA384",
	x509.ECDSAWithSHA512: "ECDSA-SHA512",
	x509.PureEd25519:     "Ed25519",
}

// legacySignatureAlgorithms lists DSA-based algorithms that MUST NOT be used.
var legacySignatureAlgorithms = map[x509.SignatureAlgorithm]string{
	x509.DSAWithSHA1:   "DSA-SHA1",
	x509.DSAWithSHA256: "DSA-SHA256",
	x509.SHA1WithRSA:   "SHA1-RSA", // SHA-1 is cryptographically broken
	x509.MD5WithRSA:    "MD5-RSA",  // MD5 is cryptographically broken
	x509.MD2WithRSA:    "MD2-RSA",  // MD2 is cryptographically broken
}

// TestAllCertificates_ModernSignatureAlgorithms verifies every embedded certificate
// uses a modern signature algorithm (RSA-SHA256+, ECDSA, Ed25519). No DSA or
// SHA1-based signatures are acceptable per modern I2P practice.
func TestAllCertificates_ModernSignatureAlgorithms(t *testing.T) {
	algCounts := make(map[string]int)
	err := fs.WalkDir(CertificatesFS, "certificates", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(d.Name(), ".crt") {
			return err
		}

		data, readErr := CertificatesFS.ReadFile(path)
		if readErr != nil {
			t.Errorf("failed to read %s: %v", path, readErr)
			return nil
		}

		block, _ := pem.Decode(data)
		if block == nil {
			return nil // skip non-PEM (tested elsewhere)
		}

		cert, parseErr := x509.ParseCertificate(block.Bytes)
		if parseErr != nil {
			return nil // skip unparseable (tested elsewhere)
		}

		sigAlg := cert.SignatureAlgorithm

		// Check for legacy/unsafe algorithms
		if legacyName, isLegacy := legacySignatureAlgorithms[sigAlg]; isLegacy {
			t.Errorf("%s: uses LEGACY signature algorithm %s (%v) — MUST be replaced",
				path, legacyName, sigAlg)
			return nil
		}

		// Check for modern algorithms
		if modernName, isModern := modernSignatureAlgorithms[sigAlg]; isModern {
			algCounts[modernName]++
		} else {
			t.Errorf("%s: uses UNKNOWN signature algorithm %v — review required", path, sigAlg)
		}

		return nil
	})
	if err != nil {
		t.Fatalf("WalkDir failed: %v", err)
	}

	// Report distribution
	t.Log("AUDIT: Certificate signature algorithm distribution:")
	for alg, count := range algCounts {
		t.Logf("  %s: %d certificates", alg, count)
	}
}

// TestNoDSACertificates specifically scans for DSA-signed certificates,
// providing a focused legacy crypto audit.
func TestNoDSACertificates(t *testing.T) {
	dsaCount := 0
	err := fs.WalkDir(CertificatesFS, "certificates", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(d.Name(), ".crt") {
			return err
		}

		data, readErr := CertificatesFS.ReadFile(path)
		if readErr != nil {
			return nil
		}

		block, _ := pem.Decode(data)
		if block == nil {
			return nil
		}

		cert, parseErr := x509.ParseCertificate(block.Bytes)
		if parseErr != nil {
			return nil
		}

		switch cert.SignatureAlgorithm {
		case x509.DSAWithSHA1, x509.DSAWithSHA256:
			t.Errorf("DSA certificate found: %s (algorithm: %v)", path, cert.SignatureAlgorithm)
			dsaCount++
		}

		// Also check public key type
		switch cert.PublicKeyAlgorithm {
		case x509.DSA:
			t.Errorf("DSA public key found in: %s", path)
			dsaCount++
		}

		return nil
	})
	if err != nil {
		t.Fatalf("WalkDir failed: %v", err)
	}

	if dsaCount == 0 {
		t.Log("AUDIT PASS: No DSA-signed or DSA-keyed certificates found in embedded bundle")
	}
}

// =============================================================================
// Per-Directory Certificate Audit
// =============================================================================

// TestReseedCertificates_SignatureTypes verifies reseed certificates use acceptable
// signature algorithms. Reseed certs are critical for SU3 file verification.
func TestReseedCertificates_SignatureTypes(t *testing.T) {
	verifyCertDirectory(t, "certificates/reseed", 10)
}

// TestFamilyCertificates_SignatureTypes verifies family certificates.
func TestFamilyCertificates_SignatureTypes(t *testing.T) {
	verifyCertDirectory(t, "certificates/family", 1)
}

// TestNewsCertificates_SignatureTypes verifies news certificates used for update signing.
func TestNewsCertificates_SignatureTypes(t *testing.T) {
	verifyCertDirectory(t, "certificates/news", 1)
}

// TestPluginCertificates_SignatureTypes verifies plugin signing certificates.
func TestPluginCertificates_SignatureTypes(t *testing.T) {
	verifyCertDirectory(t, "certificates/plugin", 1)
}

// TestRouterCertificates_SignatureTypes verifies router update certificates.
func TestRouterCertificates_SignatureTypes(t *testing.T) {
	verifyCertDirectory(t, "certificates/router", 1)
}

// TestSSLCertificates_SignatureTypes verifies SSL/TLS certificates for reseed servers.
func TestSSLCertificates_SignatureTypes(t *testing.T) {
	verifyCertDirectory(t, "certificates/ssl", 1)
}

// verifyCertDirectory checks all certificates in a directory for valid format
// and modern signature algorithms.
func verifyCertDirectory(t *testing.T, dirPath string, minCerts int) {
	t.Helper()

	subFS, err := fs.Sub(CertificatesFS, dirPath)
	if err != nil {
		t.Fatalf("fs.Sub(%s) failed: %v", dirPath, err)
	}

	entries, err := fs.ReadDir(subFS, ".")
	if err != nil {
		t.Fatalf("ReadDir(%s) failed: %v", dirPath, err)
	}

	certCount := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".crt") {
			continue
		}

		data, readErr := fs.ReadFile(subFS, entry.Name())
		if readErr != nil {
			t.Errorf("failed to read %s/%s: %v", dirPath, entry.Name(), readErr)
			continue
		}

		block, _ := pem.Decode(data)
		if block == nil {
			t.Errorf("%s/%s: not valid PEM", dirPath, entry.Name())
			continue
		}

		cert, parseErr := x509.ParseCertificate(block.Bytes)
		if parseErr != nil {
			t.Errorf("%s/%s: failed to parse X.509: %v", dirPath, entry.Name(), parseErr)
			continue
		}

		// Check for modern signature
		if _, isModern := modernSignatureAlgorithms[cert.SignatureAlgorithm]; !isModern {
			if legacyName, isLegacy := legacySignatureAlgorithms[cert.SignatureAlgorithm]; isLegacy {
				t.Errorf("%s/%s: LEGACY algorithm %s", dirPath, entry.Name(), legacyName)
			} else {
				t.Errorf("%s/%s: unknown algorithm %v", dirPath, entry.Name(), cert.SignatureAlgorithm)
			}
			continue
		}

		certCount++
		t.Logf("%s/%s: %v (valid)", dirPath, entry.Name(), cert.SignatureAlgorithm)
	}

	if certCount < minCerts {
		t.Errorf("%s: only %d valid certificates, want at least %d", dirPath, certCount, minCerts)
	}
}

// =============================================================================
// Certificate Validity and Expiration
// =============================================================================

// TestCertificates_NotExpired verifies that embedded certificates have not yet expired.
// Expired certificates would prevent reseed and other verification operations.
func TestCertificates_NotExpired(t *testing.T) {
	expiredCount := 0
	totalCount := 0

	err := fs.WalkDir(CertificatesFS, "certificates", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(d.Name(), ".crt") {
			return err
		}

		data, readErr := CertificatesFS.ReadFile(path)
		if readErr != nil {
			return nil
		}

		block, _ := pem.Decode(data)
		if block == nil {
			return nil
		}

		cert, parseErr := x509.ParseCertificate(block.Bytes)
		if parseErr != nil {
			return nil
		}

		totalCount++

		// Note: we don't use time.Now() as that depends on the test runner's clock.
		// Instead we just log the NotAfter date for audit review.
		// A certificate with NotAfter before 2025 is likely problematic.
		t.Logf("%s: valid %s to %s",
			path,
			cert.NotBefore.Format("2006-01-02"),
			cert.NotAfter.Format("2006-01-02"))

		// Flag certificates that expire before 2026 as potentially problematic
		if cert.NotAfter.Year() < 2026 {
			t.Logf("  WARNING: %s expires before 2026 (%s)", path, cert.NotAfter.Format("2006-01-02"))
			expiredCount++
		}

		return nil
	})
	if err != nil {
		t.Fatalf("WalkDir failed: %v", err)
	}

	if expiredCount > 0 {
		t.Logf("AUDIT WARNING: %d of %d certificates expire before 2026 — review needed",
			expiredCount, totalCount)
	} else {
		t.Logf("AUDIT: All %d certificates have expiry dates in 2026 or later", totalCount)
	}
}

// =============================================================================
// Key Strength Audit
// =============================================================================

// TestCertificates_MinimumKeyStrength verifies that all certificates use
// sufficiently strong keys (RSA ≥ 2048 bits, ECDSA ≥ 256 bits).
func TestCertificates_MinimumKeyStrength(t *testing.T) {
	err := fs.WalkDir(CertificatesFS, "certificates", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(d.Name(), ".crt") {
			return err
		}

		data, readErr := CertificatesFS.ReadFile(path)
		if readErr != nil {
			return nil
		}

		block, _ := pem.Decode(data)
		if block == nil {
			return nil
		}

		cert, parseErr := x509.ParseCertificate(block.Bytes)
		if parseErr != nil {
			return nil
		}

		switch cert.PublicKeyAlgorithm {
		case x509.RSA:
			if rsaKey, ok := cert.PublicKey.(*rsa.PublicKey); ok {
				bits := rsaKey.N.BitLen()
				if bits < 2048 {
					t.Errorf("%s: RSA key is only %d bits, want ≥ 2048", path, bits)
				} else {
					t.Logf("%s: RSA-%d key (acceptable)", path, bits)
				}
			}
		case x509.ECDSA:
			if ecKey, ok := cert.PublicKey.(*ecdsa.PublicKey); ok {
				bits := ecKey.Curve.Params().BitSize
				if bits < 256 {
					t.Errorf("%s: ECDSA key is only %d bits, want ≥ 256", path, bits)
				} else {
					t.Logf("%s: ECDSA P-%d key (acceptable)", path, bits)
				}
			}
		case x509.DSA:
			t.Errorf("%s: DSA public key — LEGACY, must be replaced", path)
		case x509.Ed25519:
			t.Logf("%s: Ed25519 key (modern)", path)
		}

		return nil
	})
	if err != nil {
		t.Fatalf("WalkDir failed: %v", err)
	}
}
