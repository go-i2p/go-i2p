package router

import (
	"net"
	"sync"
	"sync/atomic"

	"github.com/go-i2p/common/router_address"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/keys"
	"github.com/go-i2p/go-i2p/lib/netdb"
	ntcp "github.com/go-i2p/go-i2p/lib/transport/ntcp2"
	"github.com/go-i2p/go-i2p/lib/transport/ssu2"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
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
	ks := p.router.keystore
	p.router.keystoreMux.RUnlock()

	if ks == nil {
		return nil, oops.Errorf("router keystore not available (router may be shutting down)")
	}

	// Build options with congestion flag if available
	opts := p.buildRouterInfoOptions()

	// Hidden mode (Java I2P semantics): publish caps with H + U, drop all
	// transport addresses. The router will not be advertised as reachable
	// and other peers will not select it for transit tunnels.
	hidden := p.router.cfg != nil && p.router.cfg.Hidden
	opts.Hidden = hidden

	// Collect transport addresses from the TransportMuxer so that published
	// RouterInfo includes our actual NTCP2 listening address(es). Without
	// this, peers looking us up in NetDB would see no addresses and be
	// unable to connect.
	var addresses []*router_address.RouterAddress
	if !hidden {
		addresses = p.collectTransportAddresses()
	}

	// Router is reachable only when not hidden AND at least one transport
	// address actually carries a publishable network endpoint (host:port).
	// Caps-only addresses (s + i + caps="4" / "6", no host) signify that
	// we are firewalled/unintroduced and should advertise 'U' (unreachable).
	opts.Reachable = !hidden && hasReachableAddress(addresses)

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
	if p.router.transports == nil {
		return nil
	}

	var addresses []*router_address.RouterAddress
	for _, t := range p.router.transports.GetTransports() {
		if addr := p.convertTransportToAddress(t); addr != nil {
			addresses = append(addresses, addr)
		}
	}
	return addresses
}

// convertTransportToAddress converts a transport to RouterAddress.
func (p *routerInfoProvider) convertTransportToAddress(t any) *router_address.RouterAddress {
	switch transport := t.(type) {
	case *ntcp.NTCP2Transport:
		addr, err := ntcp.ConvertToRouterAddress(transport)
		if err != nil {
			log.WithError(err).Warn("Failed to convert NTCP2 transport to RouterAddress")
			return nil
		}
		return addr
	case *ssu2.SSU2Transport:
		addr, err := ssu2.ConvertToRouterAddress(transport)
		if err != nil {
			log.WithError(err).Warn("Failed to convert SSU2 transport to RouterAddress")
			return nil
		}
		return addr
	default:
		return nil
	}
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

// hasReachableAddress reports whether at least one of the supplied
// RouterAddress entries advertises a publishable network endpoint
// (a "host" option). A caps-only address (no host) signals an
// unintroduced firewalled / hidden listener and must not contribute
// the 'R' (reachable) capability flag to the published RouterInfo.
func hasReachableAddress(addresses []*router_address.RouterAddress) bool {
	for _, addr := range addresses {
		if isPubliclyReachableRouterAddress(addr) {
			return true
		}
	}
	return false
}

// isPubliclyReachableRouterAddress reports whether addr has a host option that
// is a publicly routable IP address suitable for publishing reachability.
func isPubliclyReachableRouterAddress(addr *router_address.RouterAddress) bool {
	if addr == nil || !addr.CheckOption(router_address.HOST_OPTION_KEY) {
		return false
	}
	hostStr := addr.HostString()
	if hostStr == nil {
		return false
	}
	host, err := hostStr.Data()
	if err != nil {
		return false
	}
	return isPubliclyRoutableHost(host)
}

// isPubliclyRoutableHost reports whether host is a parseable IP literal that is
// globally routable and non-private.
func isPubliclyRoutableHost(host string) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	if !ip.IsGlobalUnicast() {
		return false
	}
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return false
	}
	if ip4 := ip.To4(); ip4 != nil && isSpecialUseIPv4(ip4) {
		return false
	}
	return true
}

// isSpecialUseIPv4 returns true for non-routable special-use IPv4 ranges that
// should not be treated as publicly reachable endpoints in RouterInfo caps.
func isSpecialUseIPv4(ip net.IP) bool {
	if ip == nil || ip.To4() == nil {
		return false
	}
	if ip[0] == 100 && ip[1]&0xC0 == 64 {
		return true // 100.64.0.0/10 carrier-grade NAT
	}
	if ip[0] == 192 && ip[1] == 0 && ip[2] == 0 {
		return true // 192.0.0.0/24 IETF protocol assignments
	}
	if ip[0] == 192 && ip[1] == 0 && ip[2] == 2 {
		return true // 192.0.2.0/24 TEST-NET-1
	}
	if ip[0] == 198 && ip[1] == 51 && ip[2] == 100 {
		return true // 198.51.100.0/24 TEST-NET-2
	}
	if ip[0] == 203 && ip[1] == 0 && ip[2] == 113 {
		return true // 203.0.113.0/24 TEST-NET-3
	}
	if ip[0] >= 224 {
		return true // multicast and reserved classes
	}
	return false
}
