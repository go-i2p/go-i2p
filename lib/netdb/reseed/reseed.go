package reseed

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
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

	"github.com/eyedeekay/go-unzip/pkg/unzip"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/su3"
)

const (
	I2pUserAgent = "Wget/1.11.4"
	// ReseedSU3Path is the standard I2P reseed path for SU3 files.
	// Reseed servers expect clients to request the SU3 file at this path.
	ReseedSU3Path = "i2pseeds.su3"
)

type Reseed struct {
	net.Dialer
}

func (r Reseed) SingleReseed(uri string) ([]router_info.RouterInfo, error) {
	log.WithField("uri", uri).Debug("Starting single reseed operation")

	response, err := r.performReseedRequest(uri)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	su3file, err := r.readSU3File(response.Body)
	if err != nil {
		return nil, err
	}

	if err := r.validateSU3FileType(su3file); err != nil {
		return nil, err
	}

	content, err := r.extractSU3Content(su3file)
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
func (r Reseed) ProcessLocalSU3File(filePath string) ([]router_info.RouterInfo, error) {
	return r.ProcessLocalSU3FileWithLimit(filePath, 0)
}

// ProcessLocalSU3FileWithLimit reads and processes a local SU3 reseed file with a limit on RouterInfos parsed.
// If limit <= 0, all RouterInfos are parsed (same as ProcessLocalSU3File).
// This prevents loading excessive RouterInfos into memory when only a small number is needed.
func (r Reseed) ProcessLocalSU3FileWithLimit(filePath string, limit int) ([]router_info.RouterInfo, error) {
	log.WithFields(logger.Fields{
		"file_path": filePath,
		"limit":     limit,
	}).Info("Processing local SU3 file")

	// Read the SU3 file from disk
	data, err := r.readSU3FileFromDisk(filePath)
	if err != nil {
		return nil, err
	}

	// Parse and extract SU3 content
	content, err := r.parseSU3File(data)
	if err != nil {
		return nil, err
	}

	// Process the reseed zip content with limit
	routerInfos, err := r.processReseedZipWithLimit(content, limit)
	if err != nil {
		return nil, err
	}

	r.logSU3ProcessingSuccess(filePath, len(routerInfos))
	return routerInfos, nil
}

// readSU3FileFromDisk reads a SU3 file from the filesystem.
func (r Reseed) readSU3FileFromDisk(filePath string) ([]byte, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		log.WithError(err).WithField("file_path", filePath).Error("Failed to read SU3 file")
		return nil, fmt.Errorf("failed to read SU3 file: %w", err)
	}

	log.WithFields(logger.Fields{
		"file_path":  filePath,
		"size_bytes": len(data),
	}).Debug("Read SU3 file from disk")

	return data, nil
}

// parseSU3File parses SU3 data and extracts the content.
func (r Reseed) parseSU3File(data []byte) ([]byte, error) {
	su3file, err := r.readSU3File(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}

	if err := r.validateSU3FileType(su3file); err != nil {
		return nil, err
	}

	return r.extractSU3Content(su3file)
}

// logSU3ProcessingSuccess logs successful SU3 file processing.
func (r Reseed) logSU3ProcessingSuccess(filePath string, count int) {
	log.WithFields(logger.Fields{
		"file_path":         filePath,
		"router_info_count": count,
	}).Info("Successfully processed local SU3 file")
}

// ProcessLocalZipFile reads and processes a local zip reseed file
func (r Reseed) ProcessLocalZipFile(filePath string) ([]router_info.RouterInfo, error) {
	return r.ProcessLocalZipFileWithLimit(filePath, 0)
}

// ProcessLocalZipFileWithLimit reads and processes a local zip reseed file with a limit on RouterInfos parsed.
// If limit <= 0, all RouterInfos are parsed (same as ProcessLocalZipFile).
// This prevents loading excessive RouterInfos into memory when only a small number is needed.
func (r Reseed) ProcessLocalZipFileWithLimit(filePath string, limit int) ([]router_info.RouterInfo, error) {
	log.WithFields(logger.Fields{
		"file_path": filePath,
		"limit":     limit,
	}).Info("Processing local zip file")

	// Read the zip file from disk
	data, err := os.ReadFile(filePath)
	if err != nil {
		log.WithError(err).WithField("file_path", filePath).Error("Failed to read zip file")
		return nil, fmt.Errorf("failed to read zip file: %w", err)
	}

	log.WithFields(logger.Fields{
		"file_path":  filePath,
		"size_bytes": len(data),
	}).Debug("Read zip file from disk")

	// Process the zip file with limit
	routerInfos, err := r.processReseedZipWithLimit(data, limit)
	if err != nil {
		return nil, err
	}

	log.WithFields(logger.Fields{
		"file_path":         filePath,
		"router_info_count": len(routerInfos),
	}).Info("Successfully processed local zip file")

	return routerInfos, nil
}

// performReseedRequest creates and executes an HTTP request to the reseed server.
// If the URL does not already include the standard SU3 path, it is appended automatically.
// SECURITY: Only HTTPS URLs are accepted. Plain HTTP would expose the reseed
// request to network observers, enabling traffic analysis and MITM attacks.
func (r Reseed) performReseedRequest(uri string) (*http.Response, error) {
	log.WithField("uri", uri).Info("Initiating reseed HTTP request")

	client := createReseedHTTPClient(r.DialContext)
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
		return nil, fmt.Errorf("reseed requires HTTPS, got scheme %q for %s", URL.Scheme, uri)
	}

	// Append standard reseed path if not already present
	URL = ensureReseedPath(URL)

	request := buildReseedHTTPRequest(URL)
	response, err := client.Do(&request)
	if err != nil {
		log.WithError(err).WithField("uri", uri).Error("Failed to perform HTTP request")
		return nil, err
	}

	if err := validateReseedResponse(response, uri); err != nil {
		return nil, err
	}

	return response, nil
}

// createReseedHTTPClient creates an HTTP client configured for reseed operations.
// The TLS configuration uses the system certificate pool merged with embedded
// reseed certificates, so connections to reseed servers with non-standard CAs succeed.
func createReseedHTTPClient(dialContext func(ctx context.Context, network, addr string) (net.Conn, error)) *http.Client {
	// Start with system certificate pool
	rootCAs, err := x509.SystemCertPool()
	if err != nil {
		log.WithError(err).Warn("Failed to load system cert pool, using empty pool")
		rootCAs = x509.NewCertPool()
	}

	// Add embedded reseed certificates to the TLS root CA pool.
	// This ensures connections to reseed servers whose TLS certificates
	// are signed by CAs not in the system store will still succeed.
	certPool, err := GetDefaultCertificatePool()
	if err != nil {
		log.WithError(err).Warn("Failed to load embedded reseed certificates for TLS")
	} else if certPool != nil {
		// Merge the embedded certificates into the system pool.
		// CertificatePool.Pool() returns an *x509.CertPool with all embedded certs.
		// We add each embedded cert's raw DER to the system pool.
		embeddedPool := certPool.Pool()
		if embeddedPool != nil {
			for _, signerID := range certPool.ListSignerIDs() {
				cert, ok := certPool.GetCertificate(signerID)
				if ok && cert != nil {
					rootCAs.AddCert(cert)
				}
			}
			log.Debug("Added embedded reseed certificates to TLS root CA pool")
		}
	}

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12, // Require TLS 1.2 minimum
		RootCAs:    rootCAs,
	}

	transport := http.Transport{
		DialContext:         dialContext,
		TLSClientConfig:     tlsConfig,
		TLSHandshakeTimeout: 10 * time.Second, // Prevent a hung TLS handshake from consuming the full request timeout
	}

	return &http.Client{
		Transport: &transport,
		Timeout:   30 * time.Second,
	}
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
		return fmt.Errorf("reseed server returned status %d", response.StatusCode)
	}

	// Validate content length if provided
	if response.ContentLength > 0 {
		log.WithField("content_length", response.ContentLength).Debug("Response content length")
		if response.ContentLength < 100 {
			response.Body.Close()
			log.WithField("content_length", response.ContentLength).Error("Response too small to be valid SU3 file")
			return fmt.Errorf("response too small to be valid SU3 file: %d bytes", response.ContentLength)
		}
	} else {
		log.Warn("Response content length not provided by server")
	}

	return nil
}

// readSU3File reads and parses the SU3 file from the response body.
// Limits reads to 50 MB to prevent memory exhaustion from malicious servers.
func (r Reseed) readSU3File(body io.Reader) (*su3.SU3, error) {
	// Buffer the entire response to ensure complete data is available.
	// This prevents issues with streaming/incomplete reads that can cause
	// "Signature shorter than expected" errors when the su3 library tries
	// to read the signature bytes from the end of the file.
	//
	// Limit to 50 MB — reseed bundles are typically a few MB. This prevents
	// a malicious server from sending an unbounded stream.
	const maxReseedSize = 50 << 20 // 50 MB
	log.Debug("Buffering complete SU3 response")
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
func (r Reseed) validateSU3FileType(su3file *su3.SU3) error {
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
	log.Debug("SU3 file validation successful")
	return nil
}

// getPublicKeyForSigner returns the public key for a known reseed signer.
// It uses the embedded certificate pool to look up certificates by signer ID.
// Returns an error if the signer is not recognized (fail-closed security).
func (r Reseed) getPublicKeyForSigner(signerID string) (interface{}, error) {
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
func (r Reseed) extractSU3Content(su3file *su3.SU3) ([]byte, error) {
	log.Debug("Extracting content from SU3 file")

	// Get the public key for the signer - this will fail for unknown signers
	publicKey, err := r.getPublicKeyForSigner(su3file.SignerID)
	if err != nil {
		log.WithError(err).Error("Failed to get public key for signer")
		return nil, err
	}

	// At this point, publicKey should never be nil (we reject unknown signers)
	if publicKey == nil {
		log.Error("Internal error: publicKey is nil after successful getPublicKeyForSigner")
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
func (r Reseed) processReseedZip(content []byte) ([]router_info.RouterInfo, error) {
	return r.processReseedZipWithLimit(content, 0)
}

// processReseedZipWithLimit writes the zip content to disk, extracts it, and parses router infos with a limit.
// If limit <= 0, all RouterInfos are parsed.
func (r Reseed) processReseedZipWithLimit(content []byte, limit int) ([]router_info.RouterInfo, error) {
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
func (r Reseed) writeZipFile(content []byte) (string, error) {
	// Create temporary file in system temp directory with restrictive
	// permissions. Write content directly to avoid TOCTOU races — do
	// not close and reopen the file.
	tempFile, err := os.CreateTemp("", "reseed-*.zip")
	if err != nil {
		log.WithError(err).Error("Failed to create temporary file for reseed zip")
		return "", fmt.Errorf("failed to create temp file: %w", err)
	}
	zipPath := tempFile.Name()

	// Restrict permissions to owner-only (0600) before writing content.
	if err := tempFile.Chmod(0o600); err != nil {
		tempFile.Close()
		os.Remove(zipPath)
		return "", fmt.Errorf("failed to set temp file permissions: %w", err)
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
	tempFile.Close()
	log.WithField("path", zipPath).Info("Successfully wrote reseed zip file to temporary location")
	return zipPath, nil
}

// extractZipFile extracts the zip file to a temporary directory and returns the temp directory path and list of extracted file paths.
// The caller is responsible for cleaning up the temporary directory after use.
func (r Reseed) extractZipFile(zipPath string) (string, []string, error) {
	// Create temporary directory for extraction
	tempDir, err := os.MkdirTemp("", "reseed-extract-*")
	if err != nil {
		log.WithError(err).Error("Failed to create temporary directory for reseed extraction")
		return "", nil, fmt.Errorf("failed to create temp directory: %w", err)
	}

	log.WithFields(logger.Fields{
		"zip_path": zipPath,
		"temp_dir": tempDir,
	}).Info("Extracting reseed zip file to temporary directory")

	files, err := unzip.New().Extract(zipPath, tempDir)
	if err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"zip_path": zipPath,
			"temp_dir": tempDir,
		}).Error("Failed to extract reseed zip file")
		os.RemoveAll(tempDir) // Clean up on error
		return "", nil, err
	}
	if len(files) <= 0 {
		log.WithField("zip_path", zipPath).Error("Reseed zip file appears to have no content")
		os.RemoveAll(tempDir) // Clean up on error
		return "", nil, oops.Errorf("error: reseed appears to have no content")
	}

	// The unzip library returns just the filenames, not full paths
	// We need to prepend the temporary directory path to each filename
	fullPaths := make([]string, len(files))
	for i, filename := range files {
		fullPaths[i] = filepath.Join(tempDir, filename)
	}

	log.WithFields(logger.Fields{
		"file_count": len(fullPaths),
		"temp_dir":   tempDir,
	}).Info("Successfully extracted reseed files to temporary directory")
	return tempDir, fullPaths, nil
}

// parseRouterInfoFiles reads and parses router info files from the extracted files.
func (r Reseed) parseRouterInfoFiles(files []string) ([]router_info.RouterInfo, error) {
	return r.parseRouterInfoFilesWithLimit(files, 0)
}

// parseRouterInfoFilesWithLimit reads and parses router info files from the extracted files with a limit.
// If limit <= 0, all files are parsed. Otherwise, parsing stops after successfully parsing 'limit' RouterInfos.
// This minimizes memory usage when only a small number of RouterInfos is needed.
func (r Reseed) parseRouterInfoFilesWithLimit(files []string, limit int) ([]router_info.RouterInfo, error) {
	r.logParseStart(len(files), limit)

	stats := &parseStats{}
	routerInfos := r.parseFilesUntilLimit(files, limit, stats)

	r.logParseComplete(len(files), stats, len(routerInfos))
	return routerInfos, nil
}

// parseStats tracks statistics during router info file parsing.
type parseStats struct {
	parseErrors  int
	readErrors   int
	skippedFiles int
}

// logParseStart logs the start of the parsing operation.
func (r Reseed) logParseStart(totalFiles, limit int) {
	log.WithFields(logger.Fields{
		"total_files": totalFiles,
		"limit":       limit,
	}).Info("Parsing router info files")
}

// parseFilesUntilLimit iterates through files and parses them until the limit is reached.
func (r Reseed) parseFilesUntilLimit(files []string, limit int, stats *parseStats) []router_info.RouterInfo {
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
func (r Reseed) hasReachedLimit(parsed, limit, totalFiles int) bool {
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
func (r Reseed) tryParseRouterInfoFile(filePath string, stats *parseStats) (router_info.RouterInfo, bool) {
	riB, err := os.ReadFile(filePath)
	if err != nil {
		stats.readErrors++
		log.WithError(err).WithField("file", filePath).Warn("Failed to read router info file")
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
func (r Reseed) logParseComplete(totalFiles int, stats *parseStats, parsedSuccess int) {
	log.WithFields(logger.Fields{
		"total_files":    totalFiles,
		"skipped_files":  stats.skippedFiles,
		"parsed_success": parsedSuccess,
		"read_errors":    stats.readErrors,
		"parse_errors":   stats.parseErrors,
	}).Info("Completed parsing router info files")
}

// cleanupZipFile removes the temporary zip file from disk.
func (r Reseed) cleanupZipFile(zipPath string) {
	log.WithField("path", zipPath).Debug("Cleaning up reseed zip file")
	if err := os.Remove(zipPath); err != nil {
		log.WithError(err).WithField("path", zipPath).Warn("Failed to remove reseed zip file")
	} else {
		log.WithField("path", zipPath).Debug("Successfully removed reseed zip file")
	}
}

// cleanupTempDirectory removes the temporary extraction directory from disk.
func (r Reseed) cleanupTempDirectory(tempDir string) {
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
func (r Reseed) isRouterInfoFile(filePath string) bool {
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
