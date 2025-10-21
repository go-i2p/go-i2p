package reseed

import (
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
	transport := http.Transport{
		DialContext: r.DialContext,
	}
	client := http.Client{
		Transport: &transport,
	}
	URL, err := url.Parse(uri)
	if err != nil {
		log.WithError(err).Error("Failed to parse reseed URI")
		return nil, err
	}
	header := http.Header{}
	header.Add("user-agent", I2pUserAgent)
	request := http.Request{
		URL:    URL,
		Header: header,
	}
	response, err := client.Do(&request)
	if err != nil {
		log.WithError(err).Error("Failed to perform HTTP request")
		return nil, err
	}

	log.Debug("Successfully received response from reseed server")
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
	if su3file.FileType != su3.ZIP || su3file.ContentType != su3.RESEED {
		log.Error("Undefined reseed error")
		return oops.Errorf("error: undefined reseed error")
	}
	return nil
}

// extractSU3Content extracts the content from the SU3 file and validates the signature.
func (r Reseed) extractSU3Content(su3file *su3.SU3) ([]byte, error) {
	content, err := io.ReadAll(su3file.Content(""))
	if err != nil {
		log.WithError(err).Error("Failed to read SU3 content")
		return nil, err
	}

	signature, err := io.ReadAll(su3file.Signature())
	if err != nil {
		log.WithError(err).Error("Failed to read SU3 file signature")
		return nil, err
	}
	log.Println("warning: this doesn't validate the signature yet", signature)
	log.Warn("Doesn't validate the signature yet", logger.Fields{"signature": signature})

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
	err := os.WriteFile(zipPath, content, 0o644)
	if err != nil {
		log.WithError(err).Error("Failed to write reseed zip file")
		return "", err
	}
	return zipPath, nil
}

// extractZipFile extracts the zip file and returns the list of extracted file paths.
func (r Reseed) extractZipFile(zipPath string) ([]string, error) {
	files, err := unzip.New().Extract(zipPath, config.RouterConfigProperties.NetDb.Path)
	if err != nil {
		log.WithError(err).Error("Failed to extract reseed zip file")
		return nil, err
	}
	if len(files) <= 0 {
		log.Error("Reseed appears to have no content")
		return nil, oops.Errorf("error: reseed appears to have no content")
	}

	log.WithField("file_count", len(files)).Debug("Successfully extracted reseed files")
	return files, nil
}

// parseRouterInfoFiles reads and parses router info files from the extracted files.
func (r Reseed) parseRouterInfoFiles(files []string) ([]router_info.RouterInfo, error) {
	var routerInfos []router_info.RouterInfo
	for _, f := range files {
		riB, err := os.ReadFile(f)
		if err != nil {
			log.WithError(err).WithField("file", f).Warn("Failed to read router info file")
			continue
		}
		ri, _, err := router_info.ReadRouterInfo(riB)
		if err != nil {
			log.WithError(err).WithField("file", f).Warn("Failed to parse router info")
			continue
		}
		routerInfos = append(routerInfos, ri)
	}
	return routerInfos, nil
}

// cleanupZipFile removes the temporary zip file from disk.
func (r Reseed) cleanupZipFile(zipPath string) {
	if err := os.Remove(zipPath); err != nil {
		log.WithError(err).Warn("Failed to remove reseed zip file")
	}
}
