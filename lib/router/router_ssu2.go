package router

import (
	"github.com/go-i2p/common/router_info"
	ssu2 "github.com/go-i2p/go-i2p/lib/transport/ssu2"

	"github.com/go-i2p/logger"
)

// ensureNetDBReady validates NetDB state and performs reseed if needed.
// Returns an error if the router's StdNetDB is nil (e.g. during shutdown).

// startSSU2NATDetection initiates peer testing on the SSU2 transport (if
// enabled) to determine our NAT type. If NAT requires introducers they are
// registered in the transport's IntroducerRegistry; a future RouterInfo
// republication via the publisher will then include them.
//
// This runs non-blocking: it hands off work to a goroutine managed by the
// SSU2 transport's WaitGroup, which exits when the transport is closed.
func (r *Router) startSSU2NATDetection() {
	ssu2Transport := r.getSSU2Transport()
	if ssu2Transport == nil {
		return // SSU2 not enabled or muxer not set
	}

	candidates := r.collectSSU2Candidates()
	if len(candidates) < 2 {
		log.WithField("count", len(candidates)).Debug("SSU2 NAT detection deferred: insufficient SSU2 peers")
		return
	}

	republish := r.createRepublishCallback()
	ssu2Transport.StartNATDetection(candidates, republish)
	log.WithFields(logger.Fields{"at": "startSSU2NATDetection"}).Debug("SSU2 NAT detection goroutine started")
}

// getSSU2Transport retrieves the SSU2 transport from the TransportMuxer.
// Returns nil if SSU2 is not enabled or muxer is not set.
func (r *Router) getSSU2Transport() *ssu2.SSU2Transport {
	muxer := r.transports
	if muxer == nil {
		return nil
	}
	for _, t := range muxer.GetTransports() {
		if s, ok := t.(*ssu2.SSU2Transport); ok {
			return s
		}
	}
	return nil
}

// collectSSU2Candidates gathers SSU2-capable RouterInfos for NAT detection.
// Skips our own RouterInfo and routers without dialable SSU2 addresses.
func (r *Router) collectSSU2Candidates() []router_info.RouterInfo {
	if r.netdb == nil {
		return nil
	}
	allRIs := r.netdb.GetAllRouterInfos()
	ourHash, ourHashErr := r.getOurRouterHash()

	var candidates []router_info.RouterInfo
	for _, ri := range allRIs {
		h, herr := ri.IdentHash()
		if herr != nil {
			continue
		}
		if ourHashErr == nil && h == ourHash {
			continue
		}
		if ssu2.HasDialableSSU2Address(&ri) {
			candidates = append(candidates, ri)
		}
	}
	return candidates
}

// createRepublishCallback creates a callback for triggering RouterInfo republication
// after NAT detection registers introducers.
func (r *Router) createRepublishCallback() func() {
	return func() {
		log.WithFields(logger.Fields{"at": "createRepublishCallback"}).Info("SSU2 NAT detection: introducers registered — triggering RouterInfo republication")
		if r.publisher != nil {
			r.publisher.PublishOurRouterInfo()
		}
	}
}
