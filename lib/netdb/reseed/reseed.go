package reseed

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"

	"github.com/eyedeekay/go-unzip/pkg/unzip"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/go-i2p/su3"
)

var log = logger.GetGoI2PLogger()

const (
	I2pUserAgent = "Wget/1.11.4"
)

// Reseed server signing certificates
// These are X.509 certificates used to sign SU3 reseed files
// Only this specific certificate is hard-coded and this is not the normal way to populate it.
// This is done for convenience in testing only, a real implementation should distribute certificates and manage them properly.
const (
	// Certificate for hankhill19580@gmail.com (reseed.i2pgit.org)
	// Valid from: 2020-05-07 to 2030-05-07
	// Source: https://github.com/i2p/i2p.i2p/tree/master/installer/resources/certificates/reseed
	reseedHankhill19580Certificate = `-----BEGIN CERTIFICATE-----
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
CCOJyu3XtyzFf+tAeixOnuQ=
-----END CERTIFICATE-----`
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

// performReseedRequest creates and executes an HTTP request to the reseed server.
func (r Reseed) performReseedRequest(uri string) (*http.Response, error) {
	log.WithField("uri", uri).Info("Initiating reseed HTTP request")

	transport := http.Transport{
		DialContext: r.DialContext,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // I2P reseed servers often use self-signed certificates
			//TODO: implement proper certificate pinning/validation
		},
	}
	client := http.Client{
		Transport: &transport,
	}
	URL, err := url.Parse(uri)
	if err != nil {
		log.WithError(err).WithField("uri", uri).Error("Failed to parse reseed URI")
		return nil, err
	}

	log.WithFields(logger.Fields{
		"host":       URL.Host,
		"scheme":     URL.Scheme,
		"user_agent": I2pUserAgent,
	}).Debug("Reseed request configured")

	header := http.Header{}
	header.Add("User-Agent", I2pUserAgent)
	header.Add("Accept", "*/*")
	// Note: Accept-Encoding is omitted - Go's HTTP client handles compression automatically
	request := http.Request{
		Method:     "GET",
		URL:        URL,
		Header:     header,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Host:       URL.Host,
	}
	response, err := client.Do(&request)
	if err != nil {
		log.WithError(err).WithField("uri", uri).Error("Failed to perform HTTP request")
		return nil, err
	}

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
		return nil, fmt.Errorf("reseed server returned status %d", response.StatusCode)
	}

	// Validate content length if provided
	if response.ContentLength > 0 {
		log.WithField("content_length", response.ContentLength).Debug("Response content length")
		if response.ContentLength < 100 {
			response.Body.Close()
			log.WithField("content_length", response.ContentLength).Error("Response too small to be valid SU3 file")
			return nil, fmt.Errorf("response too small to be valid SU3 file: %d bytes", response.ContentLength)
		}
	} else {
		log.Warn("Response content length not provided by server")
	}

	return response, nil
}

// readSU3File reads and parses the SU3 file from the response body.
func (r Reseed) readSU3File(body io.Reader) (*su3.SU3, error) {
	// Buffer the entire response to ensure complete data is available.
	// This prevents issues with streaming/incomplete reads that can cause
	// "Signature shorter than expected" errors when the su3 library tries
	// to read the signature bytes from the end of the file.
	log.Debug("Buffering complete SU3 response")
	bufferedData, err := io.ReadAll(body)
	if err != nil {
		log.WithError(err).Error("Failed to buffer SU3 response")
		return nil, oops.Errorf("failed to buffer SU3 response: %w", err)
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
// Returns nil if the signer is not recognized.
func (r Reseed) getPublicKeyForSigner(signerID string) (interface{}, error) {
	var certPEM string

	switch signerID {
	case "hankhill19580@gmail.com":
		certPEM = reseedHankhill19580Certificate
	default:
		log.WithField("signer_id", signerID).Warn("Unknown reseed signer, signature verification will be skipped")
		return nil, nil
	}

	// Parse the certificate
	block, _ := decodePEM([]byte(certPEM))
	if block == nil {
		log.WithField("signer_id", signerID).Error("Failed to decode certificate PEM")
		return nil, oops.Errorf("failed to decode certificate PEM for signer %s", signerID)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.WithError(err).WithField("signer_id", signerID).Error("Failed to parse certificate")
		return nil, oops.Errorf("failed to parse certificate for signer %s: %w", signerID, err)
	}

	log.WithField("signer_id", signerID).Info("Successfully loaded certificate for reseed signer")
	return cert.PublicKey, nil
}

// decodePEM is a simple PEM decoder that extracts the first PEM block
func decodePEM(data []byte) (*struct {
	Type  string
	Bytes []byte
}, []byte) {
	// Find BEGIN marker
	beginMarker := []byte("-----BEGIN")
	endMarker := []byte("-----END")

	beginIdx := bytes.Index(data, beginMarker)
	if beginIdx == -1 {
		return nil, data
	}

	// Find end of BEGIN line
	beginLineEnd := bytes.IndexByte(data[beginIdx:], '\n')
	if beginLineEnd == -1 {
		return nil, data
	}
	beginLineEnd += beginIdx

	// Find END marker
	endIdx := bytes.Index(data[beginLineEnd:], endMarker)
	if endIdx == -1 {
		return nil, data
	}
	endIdx += beginLineEnd

	// Find end of END line
	endLineEnd := bytes.IndexByte(data[endIdx:], '\n')
	if endLineEnd == -1 {
		endLineEnd = len(data) - endIdx
	}
	endLineEnd += endIdx

	// Extract base64 content between BEGIN and END
	base64Data := bytes.TrimSpace(data[beginLineEnd+1 : endIdx])
	base64Data = bytes.ReplaceAll(base64Data, []byte("\n"), []byte(""))
	base64Data = bytes.ReplaceAll(base64Data, []byte("\r"), []byte(""))

	// Decode base64
	decoded := make([]byte, len(base64Data)*3/4+3)
	n, err := decodeBase64(decoded, base64Data)
	if err != nil {
		return nil, data
	}

	block := &struct {
		Type  string
		Bytes []byte
	}{
		Type:  "CERTIFICATE",
		Bytes: decoded[:n],
	}

	return block, data[endLineEnd:]
}

// decodeBase64 is a simple base64 decoder
func decodeBase64(dst, src []byte) (int, error) {
	const base64Table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

	n := 0
	for len(src) > 0 {
		// Decode 4 characters into 3 bytes
		var val uint32
		bits := 0

		for i := 0; i < 4 && len(src) > 0; i++ {
			c := src[0]
			src = src[1:]

			if c == '=' {
				break
			}

			idx := bytes.IndexByte([]byte(base64Table), c)
			if idx == -1 {
				continue
			}

			val = (val << 6) | uint32(idx)
			bits += 6
		}

		// Write decoded bytes
		for bits >= 8 {
			bits -= 8
			dst[n] = byte(val >> bits)
			n++
		}
	}

	return n, nil
}

// extractSU3Content extracts the content from the SU3 file with signature verification.
func (r Reseed) extractSU3Content(su3file *su3.SU3) ([]byte, error) {
	log.Debug("Extracting content from SU3 file")

	// Get the public key for the signer
	publicKey, err := r.getPublicKeyForSigner(su3file.SignerID)
	if err != nil {
		log.WithError(err).Error("Failed to get public key for signer")
		return nil, err
	}

	// Read content with signature verification
	contentReader := su3file.Content(publicKey)
	content, readErr := io.ReadAll(contentReader)

	// Check results
	if readErr != nil {
		// If we got content but verification failed, we can still use it
		// (with a warning) if the signer is unknown
		if len(content) > 0 && publicKey == nil {
			log.WithField("content_size_bytes", len(content)).Warn("Successfully extracted SU3 content without signature verification (unknown signer)")
			return content, nil
		}

		// Otherwise, this is a real error
		log.WithError(readErr).Error("Failed to read SU3 content")
		return nil, readErr
	}

	if publicKey != nil {
		log.WithField("content_size_bytes", len(content)).Info("Successfully extracted and verified SU3 content")
	} else {
		log.WithField("content_size_bytes", len(content)).Warn("Successfully extracted SU3 content (signature not verified - unknown signer)")
	}

	return content, nil
}

// processReseedZip writes the zip content to disk, extracts it, and parses router infos.
func (r Reseed) processReseedZip(content []byte) ([]router_info.RouterInfo, error) {
	zipPath, err := r.writeZipFile(content)
	if err != nil {
		return nil, err
	}
	defer r.cleanupZipFile(zipPath)

	files, err := r.extractZipFile(zipPath)
	if err != nil {
		return nil, err
	}

	return r.parseRouterInfoFiles(files)
}

// writeZipFile writes the zip content to a temporary file on disk.
func (r Reseed) writeZipFile(content []byte) (string, error) {
	zipPath := filepath.Join(config.RouterConfigProperties.NetDb.Path, "reseed.zip")
	log.WithFields(logger.Fields{
		"path":       zipPath,
		"size_bytes": len(content),
	}).Debug("Writing reseed zip file to disk")

	err := os.WriteFile(zipPath, content, 0o644)
	if err != nil {
		log.WithError(err).WithField("path", zipPath).Error("Failed to write reseed zip file")
		return "", err
	}
	log.WithField("path", zipPath).Info("Successfully wrote reseed zip file")
	return zipPath, nil
}

// extractZipFile extracts the zip file and returns the list of extracted file paths.
func (r Reseed) extractZipFile(zipPath string) ([]string, error) {
	destPath := config.RouterConfigProperties.NetDb.Path
	log.WithFields(logger.Fields{
		"zip_path":  zipPath,
		"dest_path": destPath,
	}).Info("Extracting reseed zip file")

	files, err := unzip.New().Extract(zipPath, destPath)
	if err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"zip_path":  zipPath,
			"dest_path": destPath,
		}).Error("Failed to extract reseed zip file")
		return nil, err
	}
	if len(files) <= 0 {
		log.WithField("zip_path", zipPath).Error("Reseed zip file appears to have no content")
		return nil, oops.Errorf("error: reseed appears to have no content")
	}

	log.WithField("file_count", len(files)).Info("Successfully extracted reseed files")
	return files, nil
}

// parseRouterInfoFiles reads and parses router info files from the extracted files.
func (r Reseed) parseRouterInfoFiles(files []string) ([]router_info.RouterInfo, error) {
	log.WithField("total_files", len(files)).Info("Parsing router info files")

	var routerInfos []router_info.RouterInfo
	var parseErrors int
	var readErrors int

	for _, f := range files {
		riB, err := os.ReadFile(f)
		if err != nil {
			readErrors++
			log.WithError(err).WithField("file", f).Warn("Failed to read router info file")
			continue
		}
		ri, _, err := router_info.ReadRouterInfo(riB)
		if err != nil {
			parseErrors++
			log.WithError(err).WithField("file", f).Warn("Failed to parse router info")
			continue
		}
		routerInfos = append(routerInfos, ri)
	}

	log.WithFields(logger.Fields{
		"total_files":    len(files),
		"parsed_success": len(routerInfos),
		"read_errors":    readErrors,
		"parse_errors":   parseErrors,
	}).Info("Completed parsing router info files")

	return routerInfos, nil
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
