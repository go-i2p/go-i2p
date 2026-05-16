package router

import (
	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_address"
	"github.com/go-i2p/common/router_info"
	ssu2 "github.com/go-i2p/go-i2p/lib/transport/ssu2"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// buildSSU2Transport creates the SSU2 transport, publishes its address to ri, and returns it.
func buildSSU2Transport(r *Router, ri *router_info.RouterInfo) (*ssu2.SSU2Transport, error) {
	addr := resolveTransportPort(r.cfg.Transport, func() int {
		if r.cfg.Transport != nil {
			return r.cfg.Transport.SSU2Port
		}
		return 0
	}())

	ssu2Transport, err := createSSU2TransportInstance(r, ri, addr)
	if err != nil {
		return nil, err
	}

	if err := publishSSU2Address(r, ri, ssu2Transport); err != nil {
		return nil, err
	}

	return ssu2Transport, nil
}

// createSSU2TransportInstance creates and configures the SSU2 transport with peer tracking.
func createSSU2TransportInstance(r *Router, ri *router_info.RouterInfo, addr string) (*ssu2.SSU2Transport, error) {
	ssu2Config, err := ssu2.NewConfig(addr)
	if err != nil {
		log.WithError(err).Error("Failed to create SSU2 config")
		return nil, err
	}
	ssu2Config.WorkingDir = r.cfg.WorkingDir

	ssu2Transport, err := ssu2.NewSSU2Transport(*ri, ssu2Config, r.keystore)
	if err != nil {
		log.WithError(err).Error("Failed to create SSU2 transport")
		return nil, err
	}
	if r.netdb != nil && r.netdb.PeerTracker != nil {
		ssu2Transport.SetPeerConnNotifier(r.netdb.PeerTracker)
	}

	ssu2Config.RouterLookupFunc = func(hash common.Hash) (router_info.RouterInfo, error) {
		ch := r.netdb.GetRouterInfo(hash)
		ri, ok := <-ch
		if !ok {
			return router_info.RouterInfo{}, oops.Errorf("router %x not found in netdb", hash[:4])
		}
		return ri, nil
	}

	log.WithFields(logger.Fields{"at": "buildSSU2Transport"}).Debug("SSU2 transport created successfully")
	return ssu2Transport, nil
}

// publishSSU2Address adds the SSU2 address to RouterInfo and re-signs it.
func publishSSU2Address(r *Router, ri *router_info.RouterInfo, ssu2Transport *ssu2.SSU2Transport) error {
	ssu2addr := ssu2Transport.Addr()
	if err := validateAndAddTransportAddress(ri, ssu2addr, "SSU2", func() (*router_address.RouterAddress, error) {
		return ssu2.ConvertToRouterAddress(ssu2Transport)
	}); err != nil {
		return err
	}

	if err := reSignAndVerifyRouterInfo(ri, r.keystore); err != nil {
		log.WithError(err).Error("Failed to re-sign RouterInfo after adding SSU2 address")
		return err
	}
	return nil
}
