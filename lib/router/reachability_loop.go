package router

import (
	"net"
	"sync/atomic"
	"time"

	"github.com/go-i2p/common/router_address"
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
	// Collect external address evidence from SSU2 transport.
	ext := r.collectBestExternalAddr()
	if ext == "" {
		log.WithField("at", "reachabilityLoop").Debug("no confirmed external address yet; skipping republication")
		return
	}

	// Compare with what we last published.
	prev, _ := lastPublished.Load().(string)
	if ext == prev {
		return // no change
	}

	// Rate-limit to avoid storming the floodfills.
	now := time.Now()
	if !lastResignAt.IsZero() && now.Sub(*lastResignAt) < reachabilityResignMinInterval {
		log.WithFields(logger.Fields{
			"at":        "reachabilityLoop",
			"wait_secs": reachabilityResignMinInterval.Seconds(),
		}).Debug("RouterInfo republication rate-limited; will retry next tick")
		return
	}

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
	*lastResignAt = now
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
	muxer := r.TransportMuxer
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
//
// Returns "" when no evidence is available.
func (r *Router) collectBestExternalAddr() string {
	// 1. SSU2 PeerTest / NAT-PMP is the highest-quality source.
	ssu2Transport := r.getSSU2Transport()
	if ssu2Transport != nil {
		if addr := ssu2Transport.GetCachedExternalAddr(); addr != "" {
			return addr
		}
	}

	// 2. Fall back to the NTCP2 address from the current RouterInfo.
	//    This covers NTCP2-only deployments on static or NAT-forwarded IPs.
	if r.routerInfoProv == nil {
		return ""
	}
	ri, err := r.routerInfoProv.GetRouterInfo()
	if err != nil || ri == nil {
		return ""
	}
	for _, addr := range ri.RouterAddresses() {
		if addr == nil {
			continue
		}
		if !addr.CheckOption(router_address.HOST_OPTION_KEY) {
			continue
		}
		hostStr := addr.HostString()
		portStr := addr.PortString()
		host, hErr := hostStr.Data()
		port, pErr := portStr.Data()
		if hErr != nil || pErr != nil || host == "" || port == "" {
			continue
		}
		// Only count globally-routable addresses; RFC1918/wireguard hosts
		// are not reachable by remote peers and must not suppress fallback.
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() {
			continue
		}
		return host + ":" + port
	}
	return ""
}
