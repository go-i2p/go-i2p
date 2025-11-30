package reseed

import (
	"crypto/tls"
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
	header.Add("Accept-Encoding", "gzip, deflate")
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

	return response, nil
}

// readSU3File reads and parses the SU3 file from the response body.
func (r Reseed) readSU3File(body io.Reader) (*su3.SU3, error) {
	su3file, err := su3.Read(body)
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

// extractSU3Content extracts the content from the SU3 file.
// Note: Signature validation is not yet implemented.
func (r Reseed) extractSU3Content(su3file *su3.SU3) ([]byte, error) {
	log.Debug("Extracting content from SU3 file")

	content, err := io.ReadAll(su3file.Content(""))
	if err != nil {
		log.WithError(err).Error("Failed to read SU3 content")
		return nil, err
	}
	log.WithField("content_size_bytes", len(content)).Info("Successfully extracted SU3 content")

	// TODO: Implement signature validation
	log.Warn("SU3 signature validation not yet implemented")

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
