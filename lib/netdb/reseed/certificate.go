package reseed

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-i2p/logger"
)

// CertificatePool holds trusted reseed signing certificates loaded from embedded files.
// It provides thread-safe access to certificates by signer ID (email address).
type CertificatePool struct {
	// certMap maps signer ID (e.g., "admin@stormycloud.org") to the parsed certificate
	certMap map[string]*x509.Certificate
	// x509Pool is the underlying x509.CertPool for TLS verification
	x509Pool *x509.CertPool
	// mu protects concurrent access to the maps
	mu sync.RWMutex
}

// CertificateFSProvider is a function type that returns the reseed certificate filesystem.
// This allows breaking the import cycle by injecting the filesystem at runtime.
type CertificateFSProvider func() (fs.FS, error)

// defaultCertProvider is set during initialization to provide the certificate filesystem.
// This is set by the embedded package when it initializes.
var defaultCertProvider CertificateFSProvider

// defaultPool is the lazily-initialized global certificate pool
var (
	defaultPool     *CertificatePool
	defaultPoolOnce sync.Once
	defaultPoolErr  error
)

// SetCertificateProvider sets the function that provides the reseed certificate filesystem.
// This must be called before GetDefaultCertificatePool is called for the first time.
// Typically called by the embedded package during initialization.
func SetCertificateProvider(provider CertificateFSProvider) {
	defaultCertProvider = provider
}

// GetDefaultCertificatePool returns the default certificate pool loaded from embedded certificates.
// The pool is initialized once on first call (lazy initialization).
// Returns the cached pool on subsequent calls.
func GetDefaultCertificatePool() (*CertificatePool, error) {
	defaultPoolOnce.Do(func() {
		if defaultCertProvider == nil {
			defaultPoolErr = fmt.Errorf("certificate provider not initialized - call SetCertificateProvider first")
			return
		}
		defaultPool, defaultPoolErr = NewCertificatePoolFromProvider(defaultCertProvider)
	})
	return defaultPool, defaultPoolErr
}

// NewCertificatePoolFromProvider creates a new certificate pool using the provided filesystem provider.
func NewCertificatePoolFromProvider(provider CertificateFSProvider) (*CertificatePool, error) {
	certFS, err := provider()
	if err != nil {
		return nil, fmt.Errorf("failed to get certificate filesystem: %w", err)
	}
	return NewCertificatePoolFromFS(certFS)
}

// NewCertificatePoolFromFS creates a new certificate pool from a filesystem containing .crt files.
func NewCertificatePoolFromFS(certFS fs.FS) (*CertificatePool, error) {
	cp := &CertificatePool{
		certMap:  make(map[string]*x509.Certificate),
		x509Pool: x509.NewCertPool(),
	}

	entries, err := fs.ReadDir(certFS, ".")
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate directory: %w", err)
	}

	loadedCount := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".crt") {
			continue
		}

		if err := cp.loadCertificateFromFS(certFS, entry.Name()); err != nil {
			log.WithError(err).WithField("filename", entry.Name()).Warn("Failed to load certificate, skipping")
			continue
		}
		loadedCount++
	}

	if loadedCount == 0 {
		return nil, fmt.Errorf("no valid reseed certificates loaded")
	}

	log.WithFields(logger.Fields{
		"loaded_certificates": loadedCount,
		"total_files":         len(entries),
	}).Info("Successfully loaded reseed certificates")

	return cp, nil
}

// loadCertificateFromFS loads a single certificate file from the provided filesystem.
func (cp *CertificatePool) loadCertificateFromFS(certFS fs.FS, filename string) error {
	data, err := fs.ReadFile(certFS, filename)
	if err != nil {
		return fmt.Errorf("failed to read certificate file %s: %w", filename, err)
	}

	return cp.loadCertificateFromPEM(data, filename)
}

// loadCertificateFromPEM parses PEM-encoded certificate data and adds it to the pool.
func (cp *CertificatePool) loadCertificateFromPEM(pemData []byte, filename string) error {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return fmt.Errorf("failed to decode PEM data from %s", filename)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate from %s: %w", filename, err)
	}

	// Extract signer ID from certificate
	signerID := extractSignerID(cert, filename)
	if signerID == "" {
		return fmt.Errorf("could not determine signer ID from certificate %s", filename)
	}

	cp.mu.Lock()
	defer cp.mu.Unlock()

	cp.certMap[signerID] = cert
	cp.x509Pool.AddCert(cert)

	log.WithFields(logger.Fields{
		"filename":  filename,
		"signer_id": signerID,
		"not_after": cert.NotAfter.Format(time.RFC3339),
	}).Debug("Loaded reseed certificate")

	return nil
}

// extractSignerID extracts the signer identifier from a certificate.
// It tries multiple sources in order: email addresses, common name, filename.
func extractSignerID(cert *x509.Certificate, filename string) string {
	// Try email addresses first (most common for I2P reseed certs)
	if len(cert.EmailAddresses) > 0 {
		return cert.EmailAddresses[0]
	}

	// Try subject common name
	if cert.Subject.CommonName != "" {
		return cert.Subject.CommonName
	}

	// Fall back to filename without extension
	// e.g., "admin_at_stormycloud.org.crt" -> "admin_at_stormycloud.org"
	name := filepath.Base(filename)
	if ext := filepath.Ext(name); ext != "" {
		name = strings.TrimSuffix(name, ext)
	}

	// Convert filename format to email format
	// e.g., "admin_at_stormycloud.org" -> "admin@stormycloud.org"
	if strings.Contains(name, "_at_") {
		name = strings.Replace(name, "_at_", "@", 1)
	}

	return name
}

// GetCertificate returns the certificate for the given signer ID.
// Returns nil and false if no certificate is found for the signer.
func (cp *CertificatePool) GetCertificate(signerID string) (*x509.Certificate, bool) {
	cp.mu.RLock()
	defer cp.mu.RUnlock()

	cert, ok := cp.certMap[signerID]
	return cert, ok
}

// GetPublicKey returns the public key for the given signer ID.
// Returns nil and an error if no certificate is found or if the certificate is invalid.
func (cp *CertificatePool) GetPublicKey(signerID string) (interface{}, error) {
	cert, ok := cp.GetCertificate(signerID)
	if !ok {
		return nil, fmt.Errorf("no certificate found for signer: %s", signerID)
	}

	// Validate certificate is not expired
	if err := cp.ValidateCertificate(cert, signerID); err != nil {
		return nil, err
	}

	return cert.PublicKey, nil
}

// ValidateCertificate checks that a certificate is valid (not expired, not before valid).
func (cp *CertificatePool) ValidateCertificate(cert *x509.Certificate, signerID string) error {
	now := time.Now()

	if now.Before(cert.NotBefore) {
		return fmt.Errorf("certificate for signer %s not yet valid (NotBefore: %v)", signerID, cert.NotBefore)
	}

	if now.After(cert.NotAfter) {
		return fmt.Errorf("certificate for signer %s expired (NotAfter: %v)", signerID, cert.NotAfter)
	}

	return nil
}

// Pool returns the underlying x509.CertPool for TLS verification.
func (cp *CertificatePool) Pool() *x509.CertPool {
	cp.mu.RLock()
	defer cp.mu.RUnlock()
	return cp.x509Pool
}

// Count returns the number of certificates in the pool.
func (cp *CertificatePool) Count() int {
	cp.mu.RLock()
	defer cp.mu.RUnlock()
	return len(cp.certMap)
}

// ListSignerIDs returns a list of all signer IDs in the pool.
func (cp *CertificatePool) ListSignerIDs() []string {
	cp.mu.RLock()
	defer cp.mu.RUnlock()

	ids := make([]string, 0, len(cp.certMap))
	for id := range cp.certMap {
		ids = append(ids, id)
	}
	return ids
}

// HasSigner returns true if the pool contains a certificate for the given signer ID.
func (cp *CertificatePool) HasSigner(signerID string) bool {
	cp.mu.RLock()
	defer cp.mu.RUnlock()
	_, ok := cp.certMap[signerID]
	return ok
}
