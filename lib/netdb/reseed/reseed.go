package reseed

import (
	"fmt"
	"github.com/go-i2p/go-i2p/lib/util/logger"
	"github.com/sirupsen/logrus"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"

	"github.com/eyedeekay/go-unzip/pkg/unzip"
	"github.com/go-i2p/go-i2p/lib/common/router_info"
	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/go-i2p/go-i2p/lib/su3"
)

var log = logger.GetLogger()

const (
	I2pUserAgent = "Wget/1.11.4"
)

type Reseed struct {
	net.Dialer
}

func (r Reseed) SingleReseed(uri string) ([]router_info.RouterInfo, error) {
	log.WithField("uri", uri).Debug("Starting single reseed operation")

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
	header.Add("user-agent", "Wget/1.11.4")
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

	su3file, err := su3.Read(response.Body)
	if err != nil {
		log.WithError(err).Error("Failed to read SU3 file")
		return nil, err
	}

	log.WithFields(logrus.Fields{
		"file_type":    su3file.FileType,
		"content_type": su3file.ContentType,
	}).Debug("Successfully read SU3 file")

	if su3file.FileType == su3.ZIP {
		if su3file.ContentType == su3.RESEED {
			if err == nil {
				content, err := io.ReadAll(su3file.Content(""))
				if err == nil {
					signature, err := io.ReadAll(su3file.Signature())
					if err != nil {
						return nil, err
					}
					log.Println("warning: this doesn't validate the signature yet", signature)
					log.Warn("Doesn't validate the signature yet", logrus.Fields{"signature": signature})
				}
				zip := filepath.Join(config.RouterConfigProperties.NetDb.Path, "reseed.zip")
				err = os.WriteFile(zip, content, 0o644)
				if err != nil {
					log.WithError(err).Error("Failed to write reseed zip file")
					return nil, err
				}
				// content is a zip file, unzip it and get the files
				files, err := unzip.New().Extract(zip, config.RouterConfigProperties.NetDb.Path)
				if err != nil {
					log.WithError(err).Error("Failed to extract reseed zip file")
					return nil, err
				}
				if len(files) <= 0 {
					log.Error("Reseed appears to have no content")
					return nil, fmt.Errorf("error: reseed appears to have no content")
				}

				log.WithField("file_count", len(files)).Debug("Successfully extracted reseed files")

				var ris []router_info.RouterInfo
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
					ris = append(ris, ri)
				}
				err = os.Remove(zip)
				if err != nil {
					log.WithError(err).Warn("Failed to remove reseed zip file")
				}
				log.WithField("router_info_count", len(ris)).Debug("Successfully processed reseed data")
				return ris, err
			} else {
				log.WithError(err).Error("Failed to read SU3 file signature")
				return nil, err
			}
		}
	}
	log.Error("Undefined reseed error")
	return nil, fmt.Errorf("error: undefined reseed error")
}
