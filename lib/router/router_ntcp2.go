package router

import (
	"strings"

	"github.com/go-i2p/common/router_address"
	"github.com/go-i2p/common/router_info"
	ntcp "github.com/go-i2p/go-i2p/lib/transport/ntcp2"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// buildNTCP2Transport creates the NTCP2 transport, publishes its address to ri, and returns it.
func buildNTCP2Transport(r *Router, ri *router_info.RouterInfo) (*ntcp.NTCP2Transport, error) {
	log.WithField("at", "buildNTCP2Transport").Debug("resolving transport port")
	addr := resolveTransportPort(r.cfg.Transport, func() int {
		if r.cfg.Transport != nil {
			return r.cfg.Transport.NTCP2Port
		}
		return 0
	}())

	ntcp2Transport, err := createNTCP2TransportInstance(r, ri, addr)
	if err != nil {
		return nil, err
	}

	if err := publishNTCP2Address(r, ri, ntcp2Transport); err != nil {
		return nil, err
	}

	return ntcp2Transport, nil
}

// createNTCP2TransportInstance creates and configures the NTCP2 transport with peer tracking.
func createNTCP2TransportInstance(r *Router, ri *router_info.RouterInfo, addr string) (*ntcp.NTCP2Transport, error) {
	log.WithFields(logger.Fields{"at": "buildNTCP2Transport", "addr": addr}).Debug("creating NTCP2 config")
	ntcp2Config, err := ntcp.NewConfig(addr)
	if err != nil {
		log.WithError(err).Error("Failed to create NTCP2 config")
		return nil, err
	}
	ntcp2Config.WorkingDir = r.cfg.WorkingDir

	log.WithField("at", "buildNTCP2Transport").Debug("creating NTCP2 transport instance")
	ntcp2Transport, err := ntcp.NewNTCP2Transport(*ri, ntcp2Config, r.keystore)
	if err != nil {
		log.WithError(err).Error("Failed to create NTCP2 transport")
		return nil, err
	}
	if r.netdb != nil && r.netdb.PeerTracker != nil {
		ntcp2Transport.SetPeerConnNotifier(r.netdb.PeerTracker)
	}
	if r.netdb != nil {
		ntcp2Transport.SetRouterInfoRefresher(r.netdb)
		ntcp2Transport.SetRouterInfoStorer(r.netdb)
	}
	log.WithFields(logger.Fields{"at": "buildNTCP2Transport"}).Debug("NTCP2 transport created successfully")
	return ntcp2Transport, nil
}

// publishNTCP2Address adds the NTCP2 address to RouterInfo, re-signs, and verifies consistency.
func publishNTCP2Address(r *Router, ri *router_info.RouterInfo, ntcp2Transport *ntcp.NTCP2Transport) error {
	ntcpaddr := ntcp2Transport.Addr()
	if err := validateAndAddTransportAddress(ri, ntcpaddr, "NTCP2", func() (*router_address.RouterAddress, error) {
		return ntcp.ConvertToRouterAddress(ntcp2Transport)
	}); err != nil {
		return err
	}

	if err := reSignAndVerifyRouterInfo(ri, r.keystore); err != nil {
		log.WithError(err).Error("Failed to re-sign RouterInfo after adding NTCP2 address")
		return err
	}
	ntcp2Transport.UpdateLocalRouterInfo(*ri)
	log.WithField("at", "buildNTCP2Transport").Debug("RouterInfo re-signed with NTCP2 address and pushed to transport")

	if err := ntcp.VerifyStaticKeyConsistency(ntcp2Transport, *ri); err != nil {
		return oops.Wrapf(err, "NTCP2 static key consistency check failed")
	}
	return nil
}

// hasNTCP2Address checks if RouterInfo contains at least one NTCP2 address
func hasNTCP2Address(routerInfo router_info.RouterInfo) bool {
	for _, addr := range routerInfo.RouterAddresses() {
		style := addr.TransportStyle()
		if styleStr, err := style.Data(); err == nil && strings.EqualFold(styleStr, "NTCP2") {
			return true
		}
	}
	return false
}
