package router

import (
	"fmt"
	"sync/atomic"
	"time"

	"github.com/go-i2p/common/router_address"
	"github.com/go-i2p/common/router_info"
	ntcp2 "github.com/go-i2p/go-i2p/lib/transport/ntcp2"
	"github.com/go-i2p/logger"
)

const (
	// reachabilityLoopInterval is how often the reachability loop checks for
	// external-address changes and conditionally republishes our RouterInfo.
	reachabilityLoopInterval = 5 * time.Minute

	// reachabilityInitialDelay is how long after startup to fire the first
	// reachability check.  Java I2P updates within ~90 seconds; we use 90s
	// here so stale 'U' caps are corrected quickly on the first tick
	// (GAP-4 fix — previously the first check was delayed 5 minutes).
	reachabilityInitialDelay = 90 * time.Second

	// reachabilityResignMinInterval rate-limits RouterInfo re-publication to
	// at most once every 30 seconds (prevents floodfill storming).
	reachabilityResignMinInterval = 30 * time.Second
)

// startReachabilityLoop starts the periodic reachability detection goroutine.
// It collects evidence from NAT-PMP/UPnP and PeerTest results, picks the most
// authoritative external host:port, and re-publishes our RouterInfo when it
// changes. The goroutine exits when r.ctx is cancelled (i.e. router Stop()).
func (r *Router) startReachabilityLoop() {
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		r.reachabilityLoop()
	}()
}

// reachabilityLoop is the body of the periodic reachability-detection goroutine.
func (r *Router) reachabilityLoop() {
	ticker := time.NewTicker(reachabilityLoopInterval)
	defer ticker.Stop()

	// initialTimer fires once at reachabilityInitialDelay to run the first
	// reachability check quickly after startup (GAP-4 fix).
	initialTimer := time.NewTimer(reachabilityInitialDelay)
	defer initialTimer.Stop()

	// lastPublishedExternal records what external address was last used for
	// re-publication so we only republish on changes.
	var lastPublishedExternal atomic.Value // stores string

	// lastResignAt is the wall-clock time of the most recent re-publication
	// triggered by this loop (zero value = never). It is read/written only
	// inside the goroutine body so no additional lock is required.
	var lastResignAt time.Time

	for {
		select {
		case <-r.ctx.Done():
			return
		case <-initialTimer.C:
			r.runReachabilityCheck(&lastPublishedExternal, &lastResignAt)
		case <-ticker.C:
			r.runReachabilityCheck(&lastPublishedExternal, &lastResignAt)
		}
	}
}

// runReachabilityCheck performs a single iteration of the reachability loop.
// It is a separate method to keep the goroutine body readable.
func (r *Router) runReachabilityCheck(lastPublished *atomic.Value, lastResignAt *time.Time) {
	ext := r.collectBestExternalAddr()
	prev, _ := lastPublished.Load().(string)

	if !r.hasAddressChanged(ext, prev) {
		return
	}

	if r.handleAddressLoss(ext, prev, lastPublished, lastResignAt) {
		return
	}

	if r.shouldRateLimitRepublication(*lastResignAt) {
		return
	}

	r.republishWithNewAddress(ext, prev, lastPublished, lastResignAt)
}

// hasAddressChanged checks if the external address has changed from the last published value.
func (r *Router) hasAddressChanged(ext, prev string) bool {
	if ext == prev {
		if ext == "" {
			log.WithField("at", "reachabilityLoop").Debug("no confirmed external address yet; skipping republication")
		}
		return false
	}
	return true
}

// handleAddressLoss manages the case where the external address has been lost.
// Returns true if the address was lost and has been handled.
func (r *Router) handleAddressLoss(ext, prev string, lastPublished *atomic.Value, lastResignAt *time.Time) bool {
	if ext != "" {
		return false
	}

	log.WithFields(logger.Fields{
		"at":       "reachabilityLoop",
		"prev_ext": prev,
	}).Info("external address lost — republishing RouterInfo with caps-only addresses")

	if r.publisher != nil {
		r.publisher.PublishOurRouterInfo()
	}
	r.refreshNTCP2LocalRouterInfo()
	lastPublished.Store(ext)
	*lastResignAt = time.Now()
	return true
}

// shouldRateLimitRepublication checks if republication should be rate-limited.
// Returns true if we should skip this republication due to rate limiting.
func (r *Router) shouldRateLimitRepublication(lastResignAt time.Time) bool {
	if lastResignAt.IsZero() {
		return false
	}

	now := time.Now()
	if now.Sub(lastResignAt) < reachabilityResignMinInterval {
		log.WithFields(logger.Fields{
			"at":        "reachabilityLoop",
			"wait_secs": reachabilityResignMinInterval.Seconds(),
		}).Debug("RouterInfo republication rate-limited; will retry next tick")
		return true
	}
	return false
}

// republishWithNewAddress publishes the RouterInfo with the new external address.
func (r *Router) republishWithNewAddress(ext, prev string, lastPublished *atomic.Value, lastResignAt *time.Time) {
	log.WithFields(logger.Fields{
		"at":       "reachabilityLoop",
		"prev_ext": prev,
		"new_ext":  ext,
	}).Info("external address changed — republishing RouterInfo")

	if r.publisher != nil {
		r.publisher.PublishOurRouterInfo()
	}

	// Push the freshly-rebuilt RI into NTCP2 so msg3 reflects the new caps
	// (e.g. 'U' → 'R' once SSU2 PeerTest confirms a public IPv4). Without
	// this, the NTCP2 transport keeps shipping the stale handshake-time
	// RouterInfo to peers and they will not learn we became reachable until
	// our floodfill publication propagates back to them.
	r.refreshNTCP2LocalRouterInfo()

	lastPublished.Store(ext)
	*lastResignAt = time.Now()
}

// refreshNTCP2LocalRouterInfo asks the routerInfoProvider for a fresh
// RouterInfo (with caps recomputed from current transport addresses) and
// pushes it into the NTCP2 transport for use as the msg3 payload.
// Best-effort: silently no-ops when any required component is unavailable.
func (r *Router) refreshNTCP2LocalRouterInfo() {
	if r.routerInfoProv == nil {
		return
	}
	ri, err := r.routerInfoProv.GetRouterInfo()
	if err != nil || ri == nil {
		log.WithError(err).Debug("could not refresh NTCP2 local RouterInfo")
		return
	}
	muxer := r.transports
	if muxer == nil {
		return
	}
	for _, t := range muxer.GetTransports() {
		if nt, ok := t.(*ntcp2.NTCP2Transport); ok {
			nt.UpdateLocalRouterInfo(*ri)
			log.WithFields(logger.Fields{
				"at":   "refreshNTCP2LocalRouterInfo",
				"caps": ri.RouterCapabilities(),
			}).Info("NTCP2 local RouterInfo refreshed for msg3")
			return
		}
	}
}

// collectBestExternalAddr returns the best confirmed external address from
// available evidence sources, in priority order:
//  1. SSU2 PeerTest / NAT-PMP confirmed address (cached in natStateCache)
//  2. NTCP2 published host:port from the current RouterInfo addresses
//     (BUG-2 fix: NTCP2-only routers were always returning "" here)
//  3. Locally-determined public IPv4 bind/host address. A publicly-routable
//     IPv4 host is directly reachable by definition, so this guarantees a
//     non-empty external address even before PeerTest completes (or when it
//     cannot run for lack of SSU2 peers), preventing a public node from being
//     misclassified as FIREWALLED.
//
// Returns "" when no evidence is available.
func (r *Router) collectBestExternalAddr() string {
	// 1. SSU2 PeerTest / NAT-PMP is the highest-quality source.
	if addr := r.getSSU2ExternalAddr(); addr != "" {
		return addr
	}

	// 2. Fall back to the NTCP2 address from the current RouterInfo.
	//    This covers NTCP2-only deployments on static or NAT-forwarded IPs.
	if addr := r.getNTCP2ExternalAddr(); addr != "" {
		return addr
	}

	// 3. Final fallback: locally-detected public IPv4 (directly reachable).
	return r.directPublicExternalAddr()
}

// directPublicExternalAddr returns the locally-determined public IPv4
// external address ("ip:port") from the SSU2 transport, or "" when the host is
// not bound to / does not own a publicly routable IPv4 address.
func (r *Router) directPublicExternalAddr() string {
	ssu2Transport := r.getSSU2Transport()
	if ssu2Transport == nil {
		return ""
	}
	return ssu2Transport.DirectPublicExternalAddr()
}

// getSSU2ExternalAddr retrieves the cached external address from SSU2 transport.
// Returns "" if SSU2 transport is not available or has no cached address.
func (r *Router) getSSU2ExternalAddr() string {
	ssu2Transport := r.getSSU2Transport()
	if ssu2Transport == nil {
		return ""
	}
	return ssu2Transport.GetCachedExternalAddr()
}

// getNTCP2ExternalAddr extracts the first publicly routable NTCP2 address from the current RouterInfo.
// Returns "" if no suitable address is found.
func (r *Router) getNTCP2ExternalAddr() string {
	ri, err := r.getRouterInfo()
	if err != nil || ri == nil {
		return ""
	}

	for _, addr := range ri.RouterAddresses() {
		if extAddr := r.extractPublicAddress(addr); extAddr != "" {
			return extAddr
		}
	}
	return ""
}

// getRouterInfo safely retrieves the current RouterInfo.
// Returns nil and error if routerInfoProv is unavailable.
func (r *Router) getRouterInfo() (*router_info.RouterInfo, error) {
	if r.routerInfoProv == nil {
		return nil, fmt.Errorf("routerInfoProv is nil")
	}
	return r.routerInfoProv.GetRouterInfo()
}

// extractPublicAddress extracts and validates a public host:port from a router address.
// Returns "" if the address is nil, missing host/port options, or not publicly routable.
func (r *Router) extractPublicAddress(addr *router_address.RouterAddress) string {
	if addr == nil || !addr.CheckOption(router_address.HOST_OPTION_KEY) {
		return ""
	}

	host, port, err := r.getHostAndPort(addr)
	if err != nil || !isPubliclyRoutableHost(host) {
		return ""
	}

	return host + ":" + port
}

// getHostAndPort extracts host and port strings from a router address.
// Returns error if either host or port is missing or invalid.
func (r *Router) getHostAndPort(addr *router_address.RouterAddress) (string, string, error) {
	hostStr := addr.HostString()
	portStr := addr.PortString()

	host, hErr := hostStr.Data()
	port, pErr := portStr.Data()

	if hErr != nil || pErr != nil || host == "" || port == "" {
		return "", "", fmt.Errorf("invalid host or port")
	}

	return host, port, nil
}
