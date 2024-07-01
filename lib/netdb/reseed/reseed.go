package reseed

import (
	"fmt"
	"io"
	"log"
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

const (
	I2pUserAgent = "Wget/1.11.4"
)

type Reseed struct {
	net.Dialer
}

func (r Reseed) SingleReseed(uri string) ([]router_info.RouterInfo, error) {
	transport := http.Transport{
		DialContext: r.DialContext,
	}
	client := http.Client{
		Transport: &transport,
	}
	URL, err := url.Parse(uri)
	if err != nil {
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
		return nil, err
	}
	su3file, err := su3.Read(response.Body)
	if err != nil {
		return nil, err
	}
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
				}
				zip := filepath.Join(config.RouterConfigProperties.NetDb.Path, "reseed.zip")
				err = os.WriteFile(zip, content, 0644)
				if err != nil {
					return nil, err
				}
				//content is a zip file, unzip it and get the files
				files, err := unzip.New().Extract(zip, config.RouterConfigProperties.NetDb.Path)
				if err != nil {
					return nil, err
				}
				if len(files) <= 0 {
					return nil, fmt.Errorf("error: reseed appears to have no content")
				}
				var ris []router_info.RouterInfo
				for _, f := range files {
					riB, err := os.ReadFile(f)
					if err != nil {
						continue
					}
					ri, _, err := router_info.ReadRouterInfo(riB)
					if err != nil {
						continue
					}
					ris = append(ris, ri)
				}
				err = os.Remove(zip)
				return ris, err
			}
		}
	}
	return nil, fmt.Errorf("error: undefined reseed error")
}
