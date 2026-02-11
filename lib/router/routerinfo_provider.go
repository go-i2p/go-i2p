package router

import (
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/go-i2p/common/router_address"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/keys"
	"github.com/go-i2p/go-i2p/lib/netdb"
	ntcp "github.com/go-i2p/go-i2p/lib/transport/ntcp2"
	"github.com/go-i2p/logger"
)

// routerInfoProvider implements netdb.RouterInfoProvider for the Router.
// It provides access to the local router's RouterInfo by constructing it
// from the RouterInfoKeystore. If a CongestionStateProvider is available,
// the congestion flag is included in the RouterInfo caps.
type routerInfoProvider struct {
	router            *Router
	monitorMu         sync.RWMutex
	congestionMonitor CongestionStateProvider
	// lastCongestionFlag tracks the previous congestion flag for change detection.
	// Uses atomic.Value for thread-safe read/write from concurrent GetRouterInfo() calls.
	lastCongestionFlag atomic.Value // stores string
}

// GetRouterInfo constructs and returns the current RouterInfo for this router.
// The RouterInfo is built from the router's keystore and includes:
//   - RouterIdentity (encryption/signing keys, certificate)
//   - Published timestamp
//   - Router addresses (e.g., NTCP2 transport addresses)
//   - Options (capabilities, network ID, congestion flag)
//   - Signature
//
// If a CongestionStateProvider is configured, the congestion flag (D/E/G)
// is included in the caps string per PROP_162.
//
// Returns an error if the RouterInfo cannot be constructed.
func (p *routerInfoProvider) GetRouterInfo() (*router_info.RouterInfo, error) {
	// Guard against nil keystore (can happen during shutdown)
	p.router.keystoreMux.RLock()
	ks := p.router.RouterInfoKeystore
	p.router.keystoreMux.RUnlock()

	if ks == nil {
		return nil, fmt.Errorf("router keystore not available (router may be shutting down)")
	}

	// Build options with congestion flag if available
	opts := p.buildRouterInfoOptions()

	// Collect transport addresses from the TransportMuxer so that published
	// RouterInfo includes our actual NTCP2 listening address(es). Without
	// this, peers looking us up in NetDB would see no addresses and be
	// unable to connect.
	addresses := p.collectTransportAddresses()

	ri, err := ks.ConstructRouterInfo(addresses, opts)
	if err != nil {
		return nil, err
	}

	return ri, nil
}

// collectTransportAddresses gathers RouterAddress entries from all active
// transports in the router's TransportMuxer. Returns nil if the muxer is not
// yet initialized (e.g. during early startup).
func (p *routerInfoProvider) collectTransportAddresses() []*router_address.RouterAddress {
	if p.router.TransportMuxer == nil {
		return nil
	}

	var addresses []*router_address.RouterAddress
	for _, t := range p.router.TransportMuxer.GetTransports() {
		if ntcp2Transport, ok := t.(*ntcp.NTCP2Transport); ok {
			addr, err := ntcp.ConvertToRouterAddress(ntcp2Transport)
			if err != nil {
				log.WithError(err).Warn("Failed to convert transport to RouterAddress")
				continue
			}
			addresses = append(addresses, addr)
		}
	}
	return addresses
}

// buildRouterInfoOptions constructs RouterInfoOptions with the current congestion flag.
// Returns empty options if no congestion monitor is configured.
func (p *routerInfoProvider) buildRouterInfoOptions() keys.RouterInfoOptions {
	p.monitorMu.RLock()
	monitor := p.congestionMonitor
	p.monitorMu.RUnlock()
	if monitor == nil {
		return keys.RouterInfoOptions{}
	}

	flag := monitor.GetCongestionFlag()
	flagStr := flag.String()

	// Log if congestion state changed (thread-safe via atomic.Value)
	oldFlag, _ := p.lastCongestionFlag.Load().(string)
	if flagStr != oldFlag {
		log.WithFields(logger.Fields{
			"at":       "routerInfoProvider.buildRouterInfoOptions",
			"old_flag": oldFlag,
			"new_flag": flagStr,
			"reason":   "congestion flag changed, will be reflected in next RouterInfo",
		}).Info("congestion flag updated")

		p.lastCongestionFlag.Store(flagStr)
	}

	return keys.RouterInfoOptions{
		CongestionFlag: flagStr,
	}
}

// SetCongestionMonitor sets the congestion state provider for the routerinfo_provider.
// This is called by the Router during initialization to wire up congestion monitoring.
func (p *routerInfoProvider) SetCongestionMonitor(monitor CongestionStateProvider) {
	p.monitorMu.Lock()
	p.congestionMonitor = monitor
	p.monitorMu.Unlock()

	log.WithFields(logger.Fields{
		"at":     "routerInfoProvider.SetCongestionMonitor",
		"reason": "congestion monitor configured for RouterInfo integration",
	}).Debug("congestion monitor set")
}

// GetCongestionFlag returns the current congestion flag or empty string if no monitor.
// This is useful for external components to check the current congestion state.
func (p *routerInfoProvider) GetCongestionFlag() string {
	p.monitorMu.RLock()
	monitor := p.congestionMonitor
	p.monitorMu.RUnlock()
	if monitor == nil {
		return ""
	}
	return monitor.GetCongestionFlag().String()
}

// newRouterInfoProvider creates a RouterInfoProvider for the given router.
// This is used internally by the Router to provide its RouterInfo to the
// NetDB Publisher for periodic publishing to floodfill routers.
// The CongestionStateProvider can be set later via SetCongestionMonitor.
func newRouterInfoProvider(r *Router) *routerInfoProvider {
	return &routerInfoProvider{
		router: r,
	}
}

// Compile-time interface check
var _ netdb.RouterInfoProvider = (*routerInfoProvider)(nil)
