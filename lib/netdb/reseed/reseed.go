package reseed

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"

	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-unzip/pkg/unzip"
	"github.com/go-i2p/su3"
)

const (
	// I2pUserAgent is the default User-Agent header used for reseed HTTP requests.
	I2pUserAgent = "Wget/1.11.4"
	// ReseedSU3Path is the standard I2P reseed path for SU3 files.
	// Reseed servers expect clients to request the SU3 file at this path.
	ReseedSU3Path = "i2pseeds.su3"
)

// Reseed provides methods for bootstrapping the NetDB by fetching RouterInfo bundles from reseed servers.
type Reseed struct {
	net.Dialer
	// httpClient is a persistent HTTP client with connection pooling enabled.
	// Reusing the same client across multiple reseed operations allows TCP connection
	// reuse and reduces TLS handshake overhead.
	httpClient *http.Client
}

// SingleReseed fetches and parses an SU3 reseed bundle from the given URI, returning the extracted RouterInfos.
func (r *Reseed) SingleReseed(uri string) ([]router_info.RouterInfo, error) {
	return r.SingleReseedWithContext(context.Background(), uri)
}

// SingleReseedWithContext fetches and parses an SU3 reseed bundle from the given URI with the provided context,
// returning the extracted RouterInfos. The context can be used to set timeouts and cancellation.
func (r *Reseed) SingleReseedWithContext(ctx context.Context, uri string) ([]router_info.RouterInfo, error) {
	log.WithField("uri", uri).Debug("Starting single reseed operation")

	response, err := r.performReseedRequestWithContext(ctx, uri)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	su3file, err := r.readSU3File(response.Body)
	if err != nil {
		return nil, err
	}

	content, err := r.validateAndExtractSU3(su3file)
	if err != nil {
		return nil, err
	}

	routerInfos, err := r.processReseedZip(content)
	if err != nil {
		return nil, err
	}

	log.WithField("router_info_count", len(routerInfos)).Debug("Successfully processed reseed data")
	return routerInfos, nil
}

// ProcessLocalSU3File reads and processes a local SU3 reseed file
func (r *Reseed) ProcessLocalSU3File(filePath string) ([]router_info.RouterInfo, error) {
	return r.ProcessLocalSU3FileWithLimit(filePath, 0)
}

// ProcessLocalSU3FileWithLimit reads and processes a local SU3 reseed file with a limit on RouterInfos parsed.
// If limit <= 0, all RouterInfos are parsed (same as ProcessLocalSU3File).
// This prevents loading excessive RouterInfos into memory when only a small number is needed.
func (r *Reseed) ProcessLocalSU3FileWithLimit(filePath string, limit int) ([]router_info.RouterInfo, error) {
	unwrap := func(data []byte) ([]byte, error) {
		return r.parseSU3File(data)
	}
	return r.processLocalFileWithLimit(filePath, "SU3", unwrap, limit)
}

// validateAndExtractSU3 validates the SU3 file type and extracts its content.
// This helper is used by both SingleReseed and parseSU3File to avoid duplication.
func (r *Reseed) validateAndExtractSU3(su3file *su3.SU3) ([]byte, error) {
	if err := r.validateSU3FileType(su3file); err != nil {
		return nil, err
	}
	return r.extractSU3Content(su3file)
}

// parseSU3File parses SU3 data and extracts the content.
func (r *Reseed) parseSU3File(data []byte) ([]byte, error) {
	su3file, err := r.readSU3File(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	return r.validateAndExtractSU3(su3file)
}

// ProcessLocalZipFile reads and processes a local zip reseed file
func (r *Reseed) ProcessLocalZipFile(filePath string) ([]router_info.RouterInfo, error) {
	return r.ProcessLocalZipFileWithLimit(filePath, 0)
}

// ProcessLocalZipFileWithLimit reads and processes a local zip reseed file with a limit on RouterInfos parsed.
// If limit <= 0, all RouterInfos are parsed (same as ProcessLocalZipFile).
// This prevents loading excessive RouterInfos into memory when only a small number is needed.
func (r *Reseed) ProcessLocalZipFileWithLimit(filePath string, limit int) ([]router_info.RouterInfo, error) {
	unwrap := func(data []byte) ([]byte, error) {
		return data, nil // zip data needs no unwrapping
	}
	return r.processLocalFileWithLimit(filePath, "zip", unwrap, limit)
}

// processLocalFileWithLimit is a shared helper for reading and processing local reseed files.
// fileType is for logging purposes (e.g., "SU3" or "zip").
// unwrap is a callback that transforms raw file data into zip content
// (e.g., parsing and extracting SU3 files, or identity for raw zip files).
// This eliminates duplication between ProcessLocalSU3FileWithLimit and ProcessLocalZipFileWithLimit.
func (r *Reseed) processLocalFileWithLimit(filePath, fileType string, unwrap func([]byte) ([]byte, error), limit int) ([]router_info.RouterInfo, error) {
	log.WithFields(logger.Fields{
		"file_path": filePath,
		"file_type": fileType,
		"limit":     limit,
	}).Info("Processing local reseed file")

	// Read the file from disk
	data, err := os.ReadFile(filePath)
	if err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"file_path": filePath,
		}).Error("Failed to read reseed file")
		return nil, oops.Errorf("failed to read %s file: %w", fileType, err)
	}

	log.WithFields(logger.Fields{
		"file_path":  filePath,
		"size_bytes": len(data),
	}).Debug("Read reseed file from disk")

	// Transform file data (parse SU3, or pass-through for zip)
	content, err := unwrap(data)
	if err != nil {
		return nil, err
	}

	// Process the reseed zip content with limit
	routerInfos, err := r.processReseedZipWithLimit(content, limit)
	if err != nil {
		return nil, err
	}

	log.WithFields(logger.Fields{
		"file_path":         filePath,
		"router_info_count": len(routerInfos),
	}).Info("Successfully processed local reseed file")

	return routerInfos, nil
}

// performReseedRequest creates and executes an HTTP request to the reseed server.
// If the URL does not already include the standard SU3 path, it is appended automatically.
// SECURITY: Only HTTPS URLs are accepted. Plain HTTP would expose the reseed
// request to network observers, enabling traffic analysis and MITM attacks.
func (r *Reseed) performReseedRequest(uri string) (*http.Response, error) {
	return r.performReseedRequestWithContext(context.Background(), uri)
}

// performReseedRequestWithContext creates and executes an HTTP request to the reseed server with the provided context.
// If the URL does not already include the standard SU3 path, it is appended automatically.
// SECURITY: Only HTTPS URLs are accepted. Plain HTTP would expose the reseed
// request to network observers, enabling traffic analysis and MITM attacks.
func (r *Reseed) performReseedRequestWithContext(ctx context.Context, uri string) (*http.Response, error) {
	log.WithField("uri", uri).Info("Initiating reseed HTTP request")

	// Validate that we have an HTTP client (should be initialized in NewReseed)
	if r.httpClient == nil {
		return nil, oops.Errorf("HTTP client not initialized")
	}
	client := r.httpClient
	URL, err := url.Parse(uri)
	if err != nil {
		log.WithError(err).WithField("uri", uri).Error("Failed to parse reseed URI")
		return nil, err
	}

	// Reject non-HTTPS schemes to prevent sending reseed requests in the clear.
	// Plain HTTP would allow network observers to identify I2P users and
	// potentially inject malicious RouterInfos via MITM.
	if URL.Scheme != "https" {
		log.WithFields(logger.Fields{
			"uri":    uri,
			"scheme": URL.Scheme,
		}).Error("Refusing reseed over insecure scheme — only HTTPS is allowed")
		return nil, oops.Errorf("reseed requires HTTPS, got scheme %q for %s", URL.Scheme, uri)
	}

	// Append standard reseed path if not already present
	URL = ensureReseedPath(URL)

	request := buildReseedHTTPRequest(URL)
	// Apply the provided context to the request for timeout/cancellation support
	request = *request.WithContext(ctx)
	response, err := client.Do(&request)
	if err != nil {
		log.WithError(err).WithField("uri", uri).Error("Failed to perform HTTP request")
		return nil, err
	}

	if err := validateReseedResponse(response, uri); err != nil {
		// Drain and close the body so the underlying TCP connection can be
		// reused by the http transport pool. Without this, repeated reseed
		// failures (e.g. 403/503) leak one buffered body + connection per
		// failed attempt.
		_ = response.Body.Close()
		return nil, err
	}

	return response, nil
}

// createReseedHTTPClient creates an HTTP client configured for reseed operations.
// The TLS configuration uses the system certificate pool merged with embedded
// reseed certificates, so connections to reseed servers with non-standard CAs succeed.
//
// Note: The 30-second request timeout is appropriate for desktop/server deployments.
// On mobile platforms (Android, iOS), OS background suspension may interrupt requests
// before completion, causing reseed to fail silently. Mobile support would require:
// 1. Reducing the per-request timeout to 10 seconds
// 2. Accepting a context.Context representing the application lifecycle
// 3. Implementing automatic resumption logic when the app returns to foreground
// This is a future enhancement, not currently implemented.
func createReseedHTTPClient(dialContext func(ctx context.Context, network, addr string) (net.Conn, error)) (*http.Client, error) {
	rootCAs, err := buildReseedCertPool()
	if err != nil {
		return nil, err
	}

	transport := http.Transport{
		DialContext: dialContext,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    rootCAs,
		},
		TLSHandshakeTimeout: 10 * time.Second,
		// Enable connection pooling to reuse TCP connections across reseed operations.
		// This significantly reduces TLS handshake overhead (20-30% latency improvement).
		MaxIdleConns:        10,
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     90 * time.Second,
	}

	return &http.Client{
		Transport: &transport,
		Timeout:   30 * time.Second,
	}, nil
}

// buildReseedCertPool creates a certificate pool containing both system certificates
// and embedded reseed certificates for TLS verification.
// Reseed operators commonly use the same certificate for both SU3 content signing
// and as their TLS server certificate (self-signed). Without merging the embedded
// certs into the TLS pool, connections to these self-signed reseed servers would fail.
func buildReseedCertPool() (*x509.CertPool, error) {
	rootCAs, err := x509.SystemCertPool()
	if err != nil {
		log.WithError(err).Error("Failed to load system cert pool; cannot create reseed HTTP client")
		return nil, oops.Wrapf(err, "system cert pool unavailable")
	}

	mergeEmbeddedCerts(rootCAs)
	return rootCAs, nil
}

// mergeEmbeddedCerts adds embedded reseed and SSL certificates to the provided certificate pool.
// addReseedCertsToPool adds embedded reseed signing certificates to rootCAs.
// Some operators use their signing certificate as TLS cert too.
func addReseedCertsToPool(rootCAs *x509.CertPool) {
	certPool, err := GetDefaultCertificatePool()
	if err != nil {
		log.WithError(err).Warn("Failed to load embedded reseed certificates for TLS")
		return
	}
	if certPool == nil {
		return
	}
	for _, signerID := range certPool.ListSignerIDs() {
		cert, ok := certPool.GetCertificate(signerID)
		if ok && cert != nil {
			rootCAs.AddCert(cert)
		}
	}
	log.WithFields(logger.Fields{"at": "mergeEmbeddedCerts"}).Debug("Added embedded reseed certificates to TLS root CA pool")
}

// addSSLCertsToPool adds embedded SSL root CA certificates (e.g., ISRG Root
// X1) to rootCAs.
func addSSLCertsToPool(rootCAs *x509.CertPool) {
	sslCerts, err := GetSSLCertificates()
	if err != nil {
		log.WithError(err).Warn("Failed to load embedded SSL certificates for TLS")
	}
	for _, cert := range sslCerts {
		rootCAs.AddCert(cert)
	}
	if len(sslCerts) > 0 {
		log.WithFields(logger.Fields{
			"at":    "mergeEmbeddedCerts",
			"count": len(sslCerts),
		}).Debug("Added embedded SSL certificates to TLS root CA pool")
	}
}

// This ensures connections to reseed servers whose TLS certificates are self-signed
// (using the same key as their SU3 signing certificate) will still succeed.
// It also adds SSL root CA certificates (e.g., ISRG Root X1 for Let's Encrypt)
// so connections to reseed servers using standard CAs succeed even in minimal
// environments without a complete system certificate store.
func mergeEmbeddedCerts(rootCAs *x509.CertPool) {
	addReseedCertsToPool(rootCAs)
	addSSLCertsToPool(rootCAs)
}

// buildReseedHTTPRequest constructs the HTTP request for reseed operations.
func buildReseedHTTPRequest(URL *url.URL) http.Request {
	log.WithFields(logger.Fields{
		"host":       URL.Host,
		"scheme":     URL.Scheme,
		"user_agent": I2pUserAgent,
	}).Debug("Reseed request configured")

	header := http.Header{}
	header.Add("User-Agent", I2pUserAgent)
	header.Add("Accept", "*/*")
	// Note: Accept-Encoding is omitted - Go's HTTP client handles compression automatically
	return http.Request{
		Method:     "GET",
		URL:        URL,
		Header:     header,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Host:       URL.Host,
	}
}

// ensureReseedPath appends the standard I2P reseed SU3 path to the URL if it is not
// already present. This ensures compatibility with reseed servers that expect the
// standard path "/i2pseeds.su3" rather than serving the SU3 file at the root URL.
func ensureReseedPath(u *url.URL) *url.URL {
	// If the path already ends with .su3, assume it's correct
	if strings.HasSuffix(u.Path, ".su3") {
		return u
	}

	// Clone the URL to avoid modifying the original
	result := *u

	// Append the standard reseed path
	if strings.HasSuffix(result.Path, "/") {
		result.Path += ReseedSU3Path
	} else {
		result.Path += "/" + ReseedSU3Path
	}

	log.WithFields(logger.Fields{
		"original_path": u.Path,
		"resolved_path": result.Path,
	}).Debug("Appended standard reseed SU3 path")

	return &result
}

// validateReseedResponse validates the HTTP response from reseed server.
func validateReseedResponse(response *http.Response, uri string) error {
	log.WithFields(logger.Fields{
		"status_code":    response.StatusCode,
		"content_length": response.ContentLength,
		"content_type":   response.Header.Get("Content-Type"),
		"uri":            uri,
	}).Info("Successfully received response from reseed server")

	// Check if we got an error page instead of SU3 file
	if response.StatusCode != 200 {
		response.Body.Close()
		log.WithField("status_code", response.StatusCode).Error("Reseed server returned error status")
		return oops.Errorf("reseed server returned status %d", response.StatusCode)
	}

	// Validate content length if provided
	if response.ContentLength > 0 {
		log.WithField("content_length", response.ContentLength).Debug("Response content length")
		if response.ContentLength < 100 {
			response.Body.Close()
			log.WithField("content_length", response.ContentLength).Error("Response too small to be valid SU3 file")
			return oops.Errorf("response too small to be valid SU3 file: %d bytes", response.ContentLength)
		}
	} else {
		log.WithFields(logger.Fields{"at": "validateReseedResponse"}).Warn("Response content length not provided by server")
	}

	return nil
}

// readSU3File reads and parses the SU3 file from the response body.
// Limits reads to 10 MB to prevent memory exhaustion from malicious servers.
func (r *Reseed) readSU3File(body io.Reader) (*su3.SU3, error) {
	// Buffer the entire response to ensure complete data is available.
	// This prevents issues with streaming/incomplete reads that can cause
	// "Signature shorter than expected" errors when the su3 library tries
	// to read the signature bytes from the end of the file.
	//
	// Limit to 10 MB — reseed bundles are typically a few MB. This caps the
	// memory a malicious server can force us to allocate before signature
	// verification runs.
	const maxReseedSize = 10 << 20 // 10 MB
	log.WithFields(logger.Fields{"at": "readSU3File"}).Debug("Buffering complete SU3 response")
	limitedReader := io.LimitReader(body, maxReseedSize+1)
	bufferedData, err := io.ReadAll(limitedReader)
	if err != nil {
		log.WithError(err).Error("Failed to buffer SU3 response")
		return nil, oops.Errorf("failed to buffer SU3 response: %w", err)
	}
	if len(bufferedData) > maxReseedSize {
		log.WithField("size_bytes", len(bufferedData)).Error("SU3 response exceeds maximum allowed size")
		return nil, oops.Errorf("SU3 response exceeds maximum allowed size of %d bytes", maxReseedSize)
	}
	log.WithField("size_bytes", len(bufferedData)).Debug("Buffered SU3 response")

	// Validate that we received a reasonable amount of data
	if len(bufferedData) < 100 {
		log.WithField("size_bytes", len(bufferedData)).Error("SU3 response too small")
		return nil, oops.Errorf("SU3 response too small: %d bytes", len(bufferedData))
	}

	// Parse from the buffered data
	su3file, err := su3.Read(bytes.NewReader(bufferedData))
	if err != nil {
		log.WithError(err).Error("Failed to read SU3 file")
		return nil, err
	}

	log.WithFields(logger.Fields{
		"file_type":    su3file.FileType,
		"content_type": su3file.ContentType,
	}).Debug("Successfully read SU3 file")

	return su3file, nil
}

// validateSU3FileType checks if the SU3 file is a valid ZIP reseed file.
func (r *Reseed) validateSU3FileType(su3file *su3.SU3) error {
	log.WithFields(logger.Fields{
		"file_type":             su3file.FileType,
		"content_type":          su3file.ContentType,
		"expected_file_type":    su3.ZIP,
		"expected_content_type": su3.RESEED,
	}).Debug("Validating SU3 file type")

	if su3file.FileType != su3.ZIP || su3file.ContentType != su3.RESEED {
		log.WithFields(logger.Fields{
			"file_type":    su3file.FileType,
			"content_type": su3file.ContentType,
		}).Error("Invalid SU3 file type or content type")
		return oops.Errorf("error: invalid SU3 file type (%v) or content type (%v)", su3file.FileType, su3file.ContentType)
	}
	log.WithFields(logger.Fields{"at": "validateSU3FileType"}).Debug("SU3 file validation successful")
	return nil
}

// getPublicKeyForSigner returns the public key for a known reseed signer.
// It uses the embedded certificate pool to look up certificates by signer ID.
// Returns an error if the signer is not recognized (fail-closed security).
func (r *Reseed) getPublicKeyForSigner(signerID string) (interface{}, error) {
	// Get the default certificate pool (loaded from embedded certificates)
	certPool, err := GetDefaultCertificatePool()
	if err != nil {
		log.WithError(err).Error("Failed to load certificate pool")
		return nil, oops.Errorf("failed to load certificate pool: %w", err)
	}

	// Look up the certificate by signer ID
	publicKey, err := certPool.GetPublicKey(signerID)
	if err != nil {
		// SECURITY: Reject unknown signers instead of allowing them
		// This prevents use of untrusted/malicious certificates
		log.WithError(err).WithField("signer_id", signerID).Error("Unknown or invalid reseed signer - rejecting for security")
		return nil, oops.Errorf("unknown or untrusted reseed signer %s: %w", signerID, err)
	}

	log.WithField("signer_id", signerID).Info("Successfully loaded and validated certificate for reseed signer")
	return publicKey, nil
}

// extractSU3Content extracts the content from the SU3 file with signature verification.
// SECURITY: This function enforces signature verification - content is rejected if
// verification fails or if the signer is unknown/untrusted.
func (r *Reseed) extractSU3Content(su3file *su3.SU3) ([]byte, error) {
	log.WithFields(logger.Fields{"at": "extractSU3Content"}).Debug("Extracting content from SU3 file")

	// Get the public key for the signer - this will fail for unknown signers
	publicKey, err := r.getPublicKeyForSigner(su3file.SignerID)
	if err != nil {
		log.WithError(err).Error("Failed to get public key for signer")
		return nil, err
	}

	// At this point, publicKey should never be nil (we reject unknown signers)
	if publicKey == nil {
		log.WithFields(logger.Fields{"at": "extractSU3Content"}).Error("Internal error: publicKey is nil after successful getPublicKeyForSigner")
		return nil, oops.Errorf("internal error: no public key available for verified signer")
	}

	// Read content with signature verification
	contentReader := su3file.Content(publicKey)
	content, readErr := io.ReadAll(contentReader)

	// SECURITY: Signature verification failure is a hard error
	if readErr != nil {
		log.WithError(readErr).Error("Signature verification failed - rejecting SU3 content")
		return nil, oops.Errorf("signature verification failed: %w", readErr)
	}

	log.WithFields(logger.Fields{
		"content_size_bytes": len(content),
		"signer_id":          su3file.SignerID,
	}).Info("Successfully extracted and verified SU3 content")

	return content, nil
}

// processReseedZip writes the zip content to disk, extracts it, and parses router infos.
func (r *Reseed) processReseedZip(content []byte) ([]router_info.RouterInfo, error) {
	return r.processReseedZipWithLimit(content, 0)
}

// processReseedZipWithLimit writes the zip content to disk, extracts it, and parses router infos with a limit.
// If limit <= 0, all RouterInfos are parsed.
func (r *Reseed) processReseedZipWithLimit(content []byte, limit int) ([]router_info.RouterInfo, error) {
	zipPath, err := r.writeZipFile(content)
	if err != nil {
		return nil, err
	}
	defer r.cleanupZipFile(zipPath)

	tempDir, files, err := r.extractZipFile(zipPath)
	if err != nil {
		return nil, err
	}
	defer r.cleanupTempDirectory(tempDir)

	return r.parseRouterInfoFilesWithLimit(files, limit)
}

// writeZipFile writes the zip content to a temporary file on disk.
func (r *Reseed) writeZipFile(content []byte) (string, error) {
	// Create temporary file in system temp directory with restrictive
	// permissions. Write content directly to avoid TOCTOU races — do
	// not close and reopen the file.
	tempFile, err := os.CreateTemp("", "reseed-*.zip")
	if err != nil {
		log.WithError(err).Error("Failed to create temporary file for reseed zip")
		return "", oops.Errorf("failed to create temp file: %w", err)
	}
	zipPath := tempFile.Name()

	// Restrict permissions to owner-only (0600) before writing content.
	if err := tempFile.Chmod(0o600); err != nil {
		tempFile.Close()
		os.Remove(zipPath)
		return "", oops.Errorf("failed to set temp file permissions: %w", err)
	}

	log.WithFields(logger.Fields{
		"path":       zipPath,
		"size_bytes": len(content),
	}).Debug("Writing reseed zip file to temporary location")

	if _, err := tempFile.Write(content); err != nil {
		tempFile.Close()
		os.Remove(zipPath)
		log.WithError(err).WithField("path", zipPath).Error("Failed to write reseed zip file")
		return "", err
	}
	if err := tempFile.Close(); err != nil {
		os.Remove(zipPath)
		return "", oops.Errorf("failed to close temp file: %w", err)
	}
	log.WithField("path", zipPath).Info("Successfully wrote reseed zip file to temporary location")
	return zipPath, nil
}

// extractZipFile extracts the zip file to a temporary directory and returns the temp directory path and list of extracted file paths.
// The caller is responsible for cleaning up the temporary directory after use.
// Validates that no entry exceeds maxPerEntrySize and total decompressed size does not exceed maxDecompressedSize to prevent zip bombs.
func (r *Reseed) extractZipFile(zipPath string) (string, []string, error) {
	tempDir, err := r.createExtractionDir()
	if err != nil {
		return "", nil, err
	}

	log.WithFields(logger.Fields{
		"zip_path": zipPath,
		"temp_dir": tempDir,
	}).Info("Extracting reseed zip file to temporary directory")

	files, err := r.extractAndValidateZip(zipPath, tempDir)
	if err != nil {
		os.RemoveAll(tempDir)
		return "", nil, err
	}

	// Validate per-entry size to prevent individual entries from bloating filesystem
	if err := r.validatePerEntrySize(tempDir, files); err != nil {
		os.RemoveAll(tempDir)
		return "", nil, err
	}

	// Validate total decompressed size to prevent zip bomb attacks
	if err := r.validateDecompressedSize(tempDir, files); err != nil {
		os.RemoveAll(tempDir)
		return "", nil, err
	}

	fullPaths, err := buildFullPaths(tempDir, files)
	if err != nil {
		os.RemoveAll(tempDir)
		return "", nil, err
	}

	log.WithFields(logger.Fields{
		"file_count": len(fullPaths),
		"temp_dir":   tempDir,
	}).Info("Successfully extracted reseed files to temporary directory")
	return tempDir, fullPaths, nil
}

// createExtractionDir creates a temporary directory for zip extraction.
func (r *Reseed) createExtractionDir() (string, error) {
	tempDir, err := os.MkdirTemp("", "reseed-extract-*")
	if err != nil {
		log.WithError(err).Error("Failed to create temporary directory for reseed extraction")
		return "", oops.Errorf("failed to create temp directory: %w", err)
	}

	// Explicitly enforce owner-only permissions (0700) to prevent local users
	// from reading metadata about reseed timing and RouterInfo arrival order.
	if err := os.Chmod(tempDir, 0o700); err != nil {
		os.RemoveAll(tempDir)
		return "", oops.Errorf("failed to set temp directory permissions: %w", err)
	}

	return tempDir, nil
}

// extractAndValidateZip extracts the zip and validates it has content.
// Panics from the unzip library are recovered and converted to errors.
func (r *Reseed) extractAndValidateZip(zipPath, tempDir string) (retFiles []string, retErr error) {
	// Recover from any panic in unzip library to prevent router crash
	defer func() {
		if rec := recover(); rec != nil {
			retErr = oops.Errorf("unzip library panic: %v", rec)
			log.WithError(retErr).WithFields(logger.Fields{
				"zip_path": zipPath,
				"panic":    rec,
			}).Error("Recovered from panic in zip extraction")
		}
	}()

	files, err := unzip.New().Extract(zipPath, tempDir)
	if err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"zip_path": zipPath,
			"temp_dir": tempDir,
		}).Error("Failed to extract reseed zip file")
		return nil, err
	}
	if len(files) <= 0 {
		log.WithField("zip_path", zipPath).Error("Reseed zip file appears to have no content")
		return nil, oops.Errorf("error: reseed appears to have no content")
	}
	// Defence in depth: reject archives whose entry count is grossly above
	// what a legitimate reseed bundle requires. A normal bundle carries a
	// few hundred RouterInfos. Rejecting archives larger than
	// maxReseedEntries prevents a malicious server from forcing us to
	// walk an enormous file list even when each entry is tiny.
	if len(files) > maxReseedEntries {
		log.WithFields(logger.Fields{
			"zip_path":    zipPath,
			"entry_count": len(files),
			"max_entries": maxReseedEntries,
		}).Error("Reseed zip entry count exceeds ceiling")
		return nil, oops.Errorf("reseed archive has %d entries, exceeds maximum of %d", len(files), maxReseedEntries)
	}
	return files, nil
}

// maxReseedEntries caps the number of files accepted from a reseed archive.
// Sized at 5x the default Bootstrap.MinimumReseedPeers (50) to leave generous
// headroom for legitimate bundles while preventing pathological archives.
const maxReseedEntries = 250

// maxPerEntrySize is the maximum uncompressed size per zip entry (1 MiB).
// With post-quantum signatures (ML-DSA, etc.), RouterInfos will be significantly
// larger than classical ECDSA. This generous limit accommodates PQ key material
// while remaining small enough to prevent zip-bomb entries.
const maxPerEntrySize int64 = 1024 * 1024

// maxDecompressedSize is the maximum total decompressed output size (50 MB).
// Legitimate reseed bundles are typically well under 1 MB uncompressed
// (a few hundred RouterInfos at ~2 KB each). 50 MB leaves generous headroom
// while preventing zip-bomb attacks from exhausting disk on constrained hosts.
const maxDecompressedSize int64 = 50 * 1024 * 1024

// reseedSafePath joins base and name and verifies the result is still under base.
// H-NEW-3 FIX: zip archive entries can contain "../" path components; filepath.Join
// cleans those, so an entry like "../evil" resolves outside the temp directory.
// This function returns an error if the resolved path escapes base.
func reseedSafePath(base, name string) (string, error) {
	joined := filepath.Join(base, name)
	rel, err := filepath.Rel(base, joined)
	if err != nil || strings.HasPrefix(rel, "..") {
		return "", oops.Errorf("reseed archive entry %q path traversal detected (escapes extraction directory)", name)
	}
	return joined, nil
}

// validatePerEntrySize checks that no extracted file exceeds the per-entry size limit.
func (r *Reseed) validatePerEntrySize(tempDir string, files []string) error {
	for _, filename := range files {
		fullPath, err := reseedSafePath(tempDir, filename)
		if err != nil {
			return err
		}
		info, err := os.Stat(fullPath)
		if err != nil {
			continue
		}
		if info.Size() > maxPerEntrySize {
			return oops.Errorf("reseed entry %q exceeds %d KB size limit (possible zip bomb)", filename, maxPerEntrySize/1024)
		}
	}
	return nil
}

// validateDecompressedSize checks that extracted files don't exceed the size limit.
func (r *Reseed) validateDecompressedSize(tempDir string, files []string) error {
	var totalSize int64
	for _, filename := range files {
		fullPath, err := reseedSafePath(tempDir, filename)
		if err != nil {
			return err
		}
		info, err := os.Stat(fullPath)
		if err != nil {
			continue
		}
		totalSize += info.Size()
		if totalSize > maxDecompressedSize {
			return oops.Errorf("decompressed reseed data exceeds %d MB size limit (possible zip bomb)", maxDecompressedSize/(1024*1024))
		}
	}
	return nil
}

// buildFullPaths prepends the directory path to each filename.
// H-NEW-3 FIX: each filename is validated against the base directory via
// reseedSafePath to prevent path traversal from malicious archive entries.
func buildFullPaths(tempDir string, files []string) ([]string, error) {
	fullPaths := make([]string, 0, len(files))
	for _, filename := range files {
		full, err := reseedSafePath(tempDir, filename)
		if err != nil {
			return nil, err
		}
		fullPaths = append(fullPaths, full)
	}
	return fullPaths, nil
}

// parseRouterInfoFilesWithLimit reads and parses router info files from the extracted files with a limit.
// If limit <= 0, all files are parsed. Otherwise, parsing stops after successfully parsing 'limit' RouterInfos.
// This minimizes memory usage when only a small number of RouterInfos is needed.
func (r *Reseed) parseRouterInfoFilesWithLimit(files []string, limit int) ([]router_info.RouterInfo, error) {
	r.logParseStart(len(files), limit)

	stats := &parseStats{}
	routerInfos := r.parseFilesUntilLimit(files, limit, stats)

	r.logParseComplete(len(files), stats, len(routerInfos))

	// If we had files to parse but produced zero RouterInfos, report an error
	// so callers can distinguish total parse failure from an empty file list.
	if len(files) > 0 && len(routerInfos) == 0 {
		return routerInfos, oops.Errorf("failed to parse any RouterInfo from %d files (%d parse errors, %d read errors, %d skipped)",
			len(files), stats.parseErrors, stats.readErrors, stats.skippedFiles)
	}

	return routerInfos, nil
}

// parseStats tracks statistics during router info file parsing.
type parseStats struct {
	parseErrors  int
	readErrors   int
	skippedFiles int
}

// logParseStart logs the start of the parsing operation.
func (r *Reseed) logParseStart(totalFiles, limit int) {
	log.WithFields(logger.Fields{
		"total_files": totalFiles,
		"limit":       limit,
	}).Info("Parsing router info files")
}

// parseFilesUntilLimit iterates through files and parses them until the limit is reached.
func (r *Reseed) parseFilesUntilLimit(files []string, limit int, stats *parseStats) []router_info.RouterInfo {
	var routerInfos []router_info.RouterInfo

	for _, f := range files {
		if r.hasReachedLimit(len(routerInfos), limit, len(files)) {
			break
		}

		if !r.isRouterInfoFile(f) {
			stats.skippedFiles++
			log.WithField("file", f).Debug("Skipping non-RouterInfo file")
			continue
		}

		ri, ok := r.tryParseRouterInfoFile(f, stats)
		if ok {
			routerInfos = append(routerInfos, ri)
		}
	}

	return routerInfos
}

// hasReachedLimit checks if the parsing limit has been reached.
func (r *Reseed) hasReachedLimit(parsed, limit, totalFiles int) bool {
	if limit > 0 && parsed >= limit {
		log.WithFields(logger.Fields{
			"parsed":      parsed,
			"limit":       limit,
			"total_files": totalFiles,
		}).Debug("Reached RouterInfo limit, stopping parse")
		return true
	}
	return false
}

// tryParseRouterInfoFile attempts to read and parse a single router info file.
// Returns the parsed RouterInfo and a boolean indicating success.
func (r *Reseed) tryParseRouterInfoFile(filePath string, stats *parseStats) (router_info.RouterInfo, bool) {
	riB, err := os.ReadFile(filePath)
	if err != nil {
		stats.readErrors++
		log.WithError(err).WithField("file", filePath).Warn("Failed to read router info file")
		return router_info.RouterInfo{}, false
	}

	if len(riB) == 0 {
		stats.skippedFiles++
		log.WithField("file", filePath).Debug("Skipping empty router info file")
		return router_info.RouterInfo{}, false
	}

	ri, _, err := router_info.ReadRouterInfo(riB)
	if err != nil {
		stats.parseErrors++
		log.WithError(err).WithField("file", filePath).Warn("Failed to parse router info")
		return router_info.RouterInfo{}, false
	}

	return ri, true
}

// logParseComplete logs the completion of the parsing operation.
func (r *Reseed) logParseComplete(totalFiles int, stats *parseStats, parsedSuccess int) {
	log.WithFields(logger.Fields{
		"total_files":    totalFiles,
		"skipped_files":  stats.skippedFiles,
		"parsed_success": parsedSuccess,
		"read_errors":    stats.readErrors,
		"parse_errors":   stats.parseErrors,
	}).Info("Completed parsing router info files")
}

// cleanupZipFile removes the temporary zip file from disk.
func (r *Reseed) cleanupZipFile(zipPath string) {
	log.WithField("path", zipPath).Debug("Cleaning up reseed zip file")
	if err := os.Remove(zipPath); err != nil {
		log.WithError(err).WithField("path", zipPath).Warn("Failed to remove reseed zip file")
	} else {
		log.WithField("path", zipPath).Debug("Successfully removed reseed zip file")
	}
}

// cleanupTempDirectory removes the temporary extraction directory from disk.
func (r *Reseed) cleanupTempDirectory(tempDir string) {
	if tempDir == "" {
		return
	}
	log.WithField("path", tempDir).Debug("Cleaning up temporary extraction directory")
	if err := os.RemoveAll(tempDir); err != nil {
		log.WithError(err).WithField("path", tempDir).Warn("Failed to remove temporary extraction directory")
	} else {
		log.WithField("path", tempDir).Debug("Successfully removed temporary extraction directory")
	}
}

// isRouterInfoFile determines if a file path should be processed as a RouterInfo file.
// RouterInfo files should have a .dat extension and contain "routerInfo-" in the filename.
// This filters out directories and other non-RouterInfo files that may be extracted from the zip.
func (r *Reseed) isRouterInfoFile(filePath string) bool {
	// Get just the filename from the path
	filename := filepath.Base(filePath)

	// Check for .dat extension
	if !strings.HasSuffix(filename, ".dat") {
		return false
	}

	// Check for routerInfo- prefix in filename
	// RouterInfo files follow the pattern: routerInfo-<base64hash>.dat
	return strings.HasPrefix(filename, "routerInfo-")
}
