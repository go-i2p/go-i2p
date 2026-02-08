package router

import (
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/keys"
	"github.com/go-i2p/go-i2p/lib/netdb"
	"github.com/go-i2p/logger"
)

// routerInfoProvider implements netdb.RouterInfoProvider for the Router.
// It provides access to the local router's RouterInfo by constructing it
// from the RouterInfoKeystore. If a CongestionStateProvider is available,
// the congestion flag is included in the RouterInfo caps.
type routerInfoProvider struct {
	router            *Router
	congestionMonitor CongestionStateProvider
	// lastCongestionFlag tracks the previous congestion flag for change detection
	lastCongestionFlag string
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
	// Build options with congestion flag if available
	opts := p.buildRouterInfoOptions()

	// Construct RouterInfo from the keystore
	// nil addresses means it will use default/empty addresses
	// In a full implementation, this would include actual NTCP2/SSU2 addresses
	ri, err := p.router.RouterInfoKeystore.ConstructRouterInfo(nil, opts)
	if err != nil {
		return nil, err
	}

	return ri, nil
}

// buildRouterInfoOptions constructs RouterInfoOptions with the current congestion flag.
// Returns empty options if no congestion monitor is configured.
func (p *routerInfoProvider) buildRouterInfoOptions() keys.RouterInfoOptions {
	if p.congestionMonitor == nil {
		return keys.RouterInfoOptions{}
	}

	flag := p.congestionMonitor.GetCongestionFlag()
	flagStr := flag.String()

	// Log if congestion state changed
	if flagStr != p.lastCongestionFlag {
		log.WithFields(logger.Fields{
			"at":       "routerInfoProvider.buildRouterInfoOptions",
			"old_flag": p.lastCongestionFlag,
			"new_flag": flagStr,
			"reason":   "congestion flag changed, will be reflected in next RouterInfo",
		}).Info("congestion flag updated")

		p.lastCongestionFlag = flagStr
	}

	return keys.RouterInfoOptions{
		CongestionFlag: flagStr,
	}
}

// SetCongestionMonitor sets the congestion state provider for the routerinfo_provider.
// This is called by the Router during initialization to wire up congestion monitoring.
func (p *routerInfoProvider) SetCongestionMonitor(monitor CongestionStateProvider) {
	p.congestionMonitor = monitor

	log.WithFields(logger.Fields{
		"at":     "routerInfoProvider.SetCongestionMonitor",
		"reason": "congestion monitor configured for RouterInfo integration",
	}).Debug("congestion monitor set")
}

// GetCongestionFlag returns the current congestion flag or empty string if no monitor.
// This is useful for external components to check the current congestion state.
func (p *routerInfoProvider) GetCongestionFlag() string {
	if p.congestionMonitor == nil {
		return ""
	}
	return p.congestionMonitor.GetCongestionFlag().String()
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
