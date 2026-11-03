package router

import (
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_address"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/config"
	ssu2 "github.com/go-i2p/go-i2p/lib/transport/ssu2"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// routerLookupTimeout is the maximum time to wait for a router lookup during tunnel build.
// This prevents goroutine leaks if the lookup channel never returns.
const routerLookupTimeout = 10 * time.Second

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

// applySSU2SessionLimits copies the operator's SSU2 limits into the SSU2
// transport config.
//
// Like the NTCP2 equivalent, a nil transport config leaves every field at zero,
// which the transport resolves to its own documented defaults — lib/config
// cannot import the transport package without a cycle, so restating the numbers
// here is exactly what would let the two drift.
//
// RequireRetry is a plain opt-in copied straight through. It defaults to false in
// both lib/config and the transport, because the pinned go-noise rejects every
// inbound SessionRequest when it is enabled (see ssu2.DefaultRequireRetry); an
// operator who opts in is deliberately overriding that.
func applySSU2SessionLimits(dst *ssu2.Config, src *config.TransportDefaults) {
	if dst == nil || src == nil {
		return
	}
	dst.MaxSessions = src.SSU2MaxConnections
	dst.MaxInflightHandshakes = src.SSU2MaxInflightHandshakes
	dst.MaxHandshakesPerSource = src.SSU2MaxHandshakesPerSource
	dst.RequireRetry = src.SSU2RequireRetry
}

// createSSU2TransportInstance creates and configures the SSU2 transport with peer tracking.
func createSSU2TransportInstance(r *Router, ri *router_info.RouterInfo, addr string) (*ssu2.SSU2Transport, error) {
	ssu2Config, err := ssu2.NewConfig(addr)
	if err != nil {
		log.WithError(err).Error("Failed to create SSU2 config")
		return nil, err
	}
	ssu2Config.WorkingDir = r.cfg.WorkingDir
	applySSU2SessionLimits(ssu2Config, r.cfg.Transport)
	ssu2Config.RouterLookupFunc = func(hash common.Hash) (router_info.RouterInfo, error) {
		ch := r.netdb.GetRouterInfo(hash)
		var ri router_info.RouterInfo
		var ok bool
		select {
		case ri, ok = <-ch:
			if !ok {
				return router_info.RouterInfo{}, oops.Errorf("router %x not found in netdb", hash[:4])
			}
		case <-time.After(routerLookupTimeout):
			return router_info.RouterInfo{}, oops.Errorf("router %x lookup timeout after %v", hash[:4], routerLookupTimeout)
		}
		return ri, nil
	}

	ssu2Config.RouterStoreFunc = func(data []byte) error {
		// Parse RouterInfo from SSU2 block payload (raw RouterInfo bytes).
		ri, _, err := router_info.ReadRouterInfo(data)
		if err != nil {
			return oops.Wrapf(err, "failed to parse RouterInfo from SSU2 block")
		}
		if err := r.netdb.StoreRouterInfoWithError(ri); err != nil {
			return oops.Wrapf(err, "failed to store RouterInfo in NetDB")
		}
		return nil
	}

	ssu2Transport, err := ssu2.NewSSU2Transport(*ri, ssu2Config, r.keystore)
	if err != nil {
		log.WithError(err).Error("Failed to create SSU2 transport")
		return nil, err
	}
	if r.netdb != nil && r.netdb.PeerTracker != nil {
		ssu2Transport.SetPeerConnNotifier(r.netdb.PeerTracker)
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
