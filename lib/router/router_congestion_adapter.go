package router

import (
	ntcp "github.com/go-i2p/go-i2p/lib/transport/ntcp2"

	"github.com/go-i2p/logger"

	"github.com/go-i2p/go-i2p/lib/config"
)

// logSubsystemStop logs a subsystem shutdown event with standard fields.
// This reduces duplication across the various stopXxx methods.

// startCongestionMonitor initializes and starts the congestion monitor (PROP_162).
// The monitor tracks local congestion and determines D/E/G flags for RouterInfo caps.
func (r *Router) startCongestionMonitor() {
	// Get congestion config from global defaults
	congestionCfg := config.Defaults().Congestion

	// Create metrics collector that gathers data from router subsystems
	collector := NewRouterMetricsCollector(
		WithParticipantCount(r.getParticipantCount),
		WithMaxParticipants(r.getMaxParticipants),
		WithBandwidthRates(r.getBandwidthRatesForCongestion),
		WithMaxBandwidth(r.getMaxBandwidth),
		WithConnectionCount(r.getConnectionCount),
		WithMaxConnections(r.getMaxConnections),
		WithAcceptingTunnels(r.isAcceptingTunnels),
	)

	// Create and start the congestion monitor
	r.congestionMonitor = NewCongestionMonitor(congestionCfg, collector)
	r.congestionMonitor.Start()

	log.WithFields(logger.Fields{
		"at":               "(Router) startCongestionMonitor",
		"phase":            "startup",
		"reason":           "congestion monitor initialized",
		"d_flag_threshold": congestionCfg.DFlagThreshold,
		"e_flag_threshold": congestionCfg.EFlagThreshold,
		"g_flag_threshold": congestionCfg.GFlagThreshold,
	}).Debug("congestion monitor started with PROP_162 thresholds")
}

// Metrics collector helper methods for CongestionMonitor integration

// getParticipantCount returns the current number of participating tunnels.
func (r *Router) getParticipantCount() int {
	if r.participantManager == nil {
		return 0
	}
	return r.participantManager.ParticipantCount()
}

// getMaxParticipants returns the maximum number of participating tunnels allowed.
func (r *Router) getMaxParticipants() int {
	if r.participantManager == nil {
		return 1000 // Default max if not configured
	}
	return r.participantManager.MaxParticipants()
}

// getBandwidthRatesForCongestion returns current bandwidth rates for congestion monitoring.
func (r *Router) getBandwidthRatesForCongestion() (inbound, outbound uint64) {
	return r.GetBandwidthRates()
}

// getMaxBandwidth returns the maximum bandwidth limit in bytes per second.
// Reads from RouterConfig.MaxBandwidth, defaulting to 1 MB/s if not configured.
func (r *Router) getMaxBandwidth() uint64 {
	if r.cfg != nil && r.cfg.MaxBandwidth > 0 {
		return r.cfg.MaxBandwidth
	}
	return 1024 * 1024 // Default 1 MB/s
}

// getConnectionCount returns the current number of active transport connections.
func (r *Router) getConnectionCount() int {
	muxer := r.transports
	if muxer == nil {
		return 0
	}
	// Count active sessions from all transports
	count := 0
	for _, t := range muxer.GetTransports() {
		if ntcp2Transport, ok := t.(*ntcp.NTCP2Transport); ok {
			count += int(ntcp2Transport.GetSessionCount())
		}
	}
	return count
}

// getMaxConnections returns the maximum number of transport connections allowed.
// Reads from RouterConfig.MaxConnections, defaulting to 200 if not configured.
func (r *Router) getMaxConnections() int {
	if r.cfg != nil && r.cfg.MaxConnections > 0 {
		return r.cfg.MaxConnections
	}
	return 200 // Default max connections
}

// isAcceptingTunnels returns true if the router is accepting tunnel participation.
// Reads from RouterConfig.AcceptTunnels. Hidden mode forces this to false so the
// PROP_162 congestion monitor advertises the "G" flag (rejecting all tunnels)
// in addition to the "H"/"U" caps published by the routerinfo provider.
func (r *Router) isAcceptingTunnels() bool {
	if r.cfg != nil {
		if r.cfg.Hidden {
			return false
		}
		return r.cfg.AcceptTunnels
	}
	return true // Default to accepting
}

// stopCongestionMonitor shuts down the congestion monitor if it is running.
func (r *Router) stopCongestionMonitor() {
	if r.congestionMonitor != nil {
		r.congestionMonitor.Stop()
		logSubsystemStop("(Router) stopCongestionMonitor", "congestion monitor")
	}
}
