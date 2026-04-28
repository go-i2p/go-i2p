package router

import (
	"sync/atomic"
	"time"

	ssu2 "github.com/go-i2p/go-i2p/lib/transport/ssu2"
	"github.com/go-i2p/logger"
)

const (
	// reachabilityLoopInterval is how often the reachability loop checks for
	// external-address changes and conditionally republishes our RouterInfo.
	reachabilityLoopInterval = 5 * time.Minute

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

	lastPublished.Store(ext)
	*lastResignAt = now
}

// collectBestExternalAddr returns the best confirmed external address from
// available evidence sources, in priority order:
//  1. SSU2 PeerTest / NAT-PMP confirmed address (cached in natStateCache)
//
// Returns "" when no evidence is available.
func (r *Router) collectBestExternalAddr() string {
	ssu2Transport := r.getSSU2Transport()
	if ssu2Transport == nil {
		return ""
	}
	return ssu2Transport.GetCachedExternalAddr()
}

// Ensure the ssu2 import is used even if getSSU2Transport is in another file.
var _ *ssu2.SSU2Transport
