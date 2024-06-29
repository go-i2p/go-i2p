package reseed

import (
	"io/ioutil"
	"net"
	"net/http"
	"net/url"

	"github.com/eyedeekay/go-unzip/pkg/unzip"
	"github.com/go-i2p/go-i2p/lib/common/router_info"
	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/go-i2p/go-i2p/lib/su3"
)

const (
	i2pUserAgent = "Wget/1.11.4"
)

type Reseed struct {
	net.Dialer
}

func (r Reseed) SingleReseed(uri string) ([]router_info.RouterInfo, error) {
	transport := http.Transport {
		DialContext: r.DialContext,
	}
	client := http.Client {
		Transport: &transport,
	}
	URL, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}
	header := http.Header{}
	header.Add("user-agent", "Wget/1.11.4")
	request := http.Request {
		URL: URL,
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
			var content, signature []byte
			if err == nil {
				content, err := ioutil.ReadAll(su3file.Content(test.key))
				if err == nil {
					signature, err = ioutil.ReadAll(su3file.Signature())
					if err != nil {
						return nil, err
					}
					// TODO: validate the signature
				}
				//content is a zip file, unzip it and get the files
				err = unzip.New().Extract(content, config.RouterConfigProperties.NetDb.Path)
			}
		}	
	}
}
