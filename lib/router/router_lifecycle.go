package router

import (
	"context"
	"fmt"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/go-i2p/lib/transport"
	ntcp "github.com/go-i2p/go-i2p/lib/transport/ntcp2"
	"github.com/samber/oops"

	"github.com/go-i2p/logger"

	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/go-i2p/go-i2p/lib/netdb"
	"github.com/go-i2p/go-i2p/lib/tunnel"
)

// logSubsystemStop logs a subsystem shutdown event with standard fields.
// This reduces duplication across the various stopXxx methods.
func logSubsystemStop(method, subsystem string) {
	log.WithFields(logger.Fields{
		"at":     method,
		"phase":  "shutdown",
		"reason": subsystem + " stopped",
	}).Debug(subsystem + " stopped")
}

// logShutdownStep logs a shutdown step with standard fields.
func logShutdownStep(step int, reason, message string) {
	log.WithFields(logger.Fields{
		"at":     "(Router) Stop",
		"phase":  "shutdown",
		"step":   step,
		"reason": reason,
	}).Debug(message)
}

// stopAllSubsystems shuts down all router subsystems in the correct order.
func (r *Router) stopAllSubsystems() {
	r.stopTunnelManager()
	r.stopBandwidthTracker()
	r.stopCongestionMonitor()
	r.stopPublisher()
	r.stopExplorer()
	r.stopFloodfillServer()
	r.stopI2CPServer()
	r.stopI2PControlServer()
	r.stopParticipantManager()
	r.stopGarlicRouter()
	r.stopNetDB()
	r.sendCloseSignal()
}

// checkAlreadyStopped returns true if router is not running.
func (r *Router) checkAlreadyStopped() bool {
	if !r.running {
		r.runMux.Unlock()
		log.WithFields(logger.Fields{
			"at":     "(Router) Stop",
			"phase":  "shutdown",
			"reason": "router not running",
		}).Debug("router already stopped")
		return true
	}
	return false
}

// cancelRouterContext cancels the router context to signal shutdown.
func (r *Router) cancelRouterContext() {
	if r.cancel != nil {
		r.cancel()
		logShutdownStep(2, "context canceled to signal subsystems", "router context cancelled")
	}
}

// Stop initiates router shutdown and waits for all goroutines to complete.
// This method blocks until the router is fully stopped.
func (r *Router) Stop() {
	logShutdownStep(1, "shutdown requested", "stopping router")
	r.runMux.Lock()

	if r.checkAlreadyStopped() {
		return
	}

	r.running = false
	r.runMux.Unlock()

	r.cancelRouterContext()
	r.stopAllSubsystems()

	logShutdownStep(3, "waiting for goroutines to complete", "waiting for router goroutines to finish")
	r.wg.Wait()
	logShutdownStep(4, "all subsystems stopped", "router stopped successfully")
}

// StopWithContext initiates router shutdown like Stop, but respects the
// provided context for cancellation. If the context is cancelled before
// all goroutines finish, the method returns the context error. This allows
// HardStop to bound the time spent waiting for graceful shutdown.
func (r *Router) StopWithContext(ctx context.Context) error {
	logShutdownStep(1, "shutdown requested (with context)", "stopping router")
	r.runMux.Lock()

	if r.checkAlreadyStopped() {
		return nil
	}

	r.running = false
	r.runMux.Unlock()

	r.cancelRouterContext()
	r.stopAllSubsystems()

	logShutdownStep(3, "waiting for goroutines to complete", "waiting for router goroutines to finish")

	done := make(chan struct{})
	go func() {
		r.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		logShutdownStep(4, "all subsystems stopped", "router stopped successfully")
		return nil
	case <-ctx.Done():
		logShutdownStep(4, "context cancelled", "router stop interrupted by context")
		return ctx.Err()
	}
}

// stopNetDB shuts down the network database if it exists and logs the result.
func (r *Router) stopNetDB() {
	if r.StdNetDB != nil {
		r.StdNetDB.Stop()
		logSubsystemStop("(Router) stopNetDB", "netDB")
	}
}

// stopGarlicRouter shuts down the garlic router if it exists and logs the result.
// This cancels the background processPendingMessages goroutine to prevent goroutine leaks.
func (r *Router) stopGarlicRouter() {
	r.runMux.Lock()
	gr := r.garlicRouter
	r.runMux.Unlock()

	if gr != nil {
		gr.Stop()
		logSubsystemStop("(Router) stopGarlicRouter", "garlic router")
	}
}

// stopBandwidthTracker shuts down the bandwidth tracker if it is running and logs the result.
func (r *Router) stopBandwidthTracker() {
	if r.bandwidthTracker != nil {
		r.bandwidthTracker.Stop()
		log.WithFields(logger.Fields{"at": "stopBandwidthTracker"}).Debug("Bandwidth tracker stopped")
	}
}

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
	muxer := r.TransportMuxer
	if muxer == nil {
		return 0
	}
	// Count active sessions from all transports
	count := 0
	for _, t := range muxer.GetTransports() {
		if ntcp2Transport, ok := t.(*ntcp.NTCP2Transport); ok {
			count += ntcp2Transport.GetSessionCount()
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

// stopPublisher shuts down the NetDB publisher if it is running.
// The publisher periodically republishes our RouterInfo and LeaseSets to floodfill routers.
func (r *Router) stopPublisher() {
	if r.publisher != nil {
		r.publisher.Stop()
		r.publisher = nil
		logSubsystemStop("(Router) stopPublisher", "NetDB publisher")
	}
}

// stopExplorer shuts down the NetDB explorer if it is running.
func (r *Router) stopExplorer() {
	if r.explorer != nil {
		r.explorer.Stop()
		r.explorer = nil
		log.WithFields(logger.Fields{"at": "stopExplorer"}).Debug("NetDB explorer stopped")
	}
}

// stopFloodfillServer shuts down the floodfill server if it is running.
func (r *Router) stopFloodfillServer() {
	if r.floodfillServer != nil {
		r.floodfillServer.Stop()
		r.floodfillServer = nil
		log.WithFields(logger.Fields{"at": "stopFloodfillServer"}).Debug("Floodfill server stopped")
	}
}

// startFloodfillServer instantiates a FloodfillServer backed by the current NetDB
// and transport muxer. Floodfill serving is disabled by default; set
// netdb.floodfill_enabled in the config to enable it.
func (r *Router) startFloodfillServer() {
	if r.StdNetDB == nil || r.TransportMuxer == nil {
		log.WithFields(logger.Fields{"at": "startFloodfillServer"}).Debug("Floodfill server deferred: NetDB or transport muxer not ready")
		return
	}
	adapter := &floodfillTransportAdapter{muxer: r.TransportMuxer, db: r.StdNetDB}
	cfg := netdb.DefaultFloodfillConfig()
	if r.cfg != nil && r.cfg.NetDB != nil {
		cfg.Enabled = r.cfg.NetDB.FloodfillEnabled
	}
	ourHash, err := r.getOurRouterHash()
	if err == nil {
		cfg.OurHash = ourHash
	}
	r.floodfillServer = netdb.NewFloodfillServer(r.StdNetDB, adapter, cfg)
	log.WithField("enabled", cfg.Enabled).Debug("Floodfill server started")
}

// startExplorer instantiates and starts the NetDB explorer. The explorer
// actively discovers new peers by performing iterative lookups for random keys,
// improving peer diversity over time. It requires a running tunnel pool.
func (r *Router) startExplorer() {
	if r.StdNetDB == nil || r.tunnelManager == nil {
		log.WithFields(logger.Fields{"at": "startExplorer"}).Debug("NetDB explorer deferred: NetDB or tunnel manager not ready")
		return
	}
	tunnelPool := r.tunnelManager.GetOutboundPool()
	if tunnelPool == nil {
		log.WithFields(logger.Fields{"at": "startExplorer"}).Debug("NetDB explorer deferred: tunnel pool not available")
		return
	}

	cfg := netdb.DefaultExplorerConfig()

	ourHash, err := r.getOurRouterHash()
	if err == nil {
		cfg.OurHash = ourHash
	}

	r.explorer = netdb.NewExplorer(r.StdNetDB, tunnelPool, cfg)

	if r.messageRouter != nil {
		r.explorer.SetOurHash(ourHash)
	}

	if err := r.explorer.Start(); err != nil {
		log.WithError(err).Warn("Failed to start NetDB explorer")
		r.explorer = nil
		return
	}
	log.WithFields(logger.Fields{"at": "startExplorer"}).Debug("NetDB explorer started")
}

// startPublisher creates and starts the NetDB publisher for periodic RouterInfo and LeaseSet
// publishing to floodfill routers. The publisher requires NetDB, transport, and a tunnel pool.
// If prerequisites are not met, a warning is logged and publishing is skipped.
func (r *Router) startPublisher() {
	tunnelPool, err := r.resolvePublisherDependencies()
	if err != nil {
		log.WithFields(logger.Fields{"at": "startPublisher"}).Warn(err.Error())
		return
	}

	r.launchPublisher(tunnelPool)
}

// resolvePublisherDependencies verifies that NetDB, TransportMuxer, and a
// tunnel pool are available. Returns the tunnel pool or an error describing
// the missing prerequisite.
func (r *Router) resolvePublisherDependencies() (*tunnel.Pool, error) {
	if r.StdNetDB == nil {
		return nil, oops.Errorf("Cannot start publisher: NetDB not initialized")
	}
	if r.TransportMuxer == nil {
		return nil, oops.Errorf("Cannot start publisher: TransportMuxer not initialized")
	}
	var tunnelPool *tunnel.Pool
	if r.tunnelManager != nil {
		tunnelPool = r.tunnelManager.GetOutboundPool()
	}
	if tunnelPool == nil {
		return nil, oops.Errorf("Cannot start publisher: tunnel pool not available")
	}
	return tunnelPool, nil
}

// launchPublisher constructs the publisher from adapters and starts it.
// On failure the publisher field is left nil and a warning is logged.
func (r *Router) launchPublisher(tunnelPool *tunnel.Pool) {
	dbAdapter := &publisherNetDBAdapter{db: r.StdNetDB}
	transportAdapter := &publisherTransportAdapter{muxer: r.TransportMuxer}

	var riProvider netdb.RouterInfoProvider
	if r.routerInfoProv != nil {
		riProvider = r.routerInfoProv
	}

	publisherConfig := netdb.DefaultPublisherConfig()
	r.publisher = netdb.NewPublisher(dbAdapter, tunnelPool, transportAdapter, riProvider, publisherConfig)

	if err := r.publisher.Start(); err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"at":     "(Router) startPublisher",
			"phase":  "startup",
			"reason": "publisher start failed",
		}).Warn("Failed to start NetDB publisher, RouterInfo will not be republished")
		r.publisher = nil
		return
	}

	log.WithFields(logger.Fields{
		"at":                   "(Router) startPublisher",
		"phase":                "startup",
		"reason":               "publisher started successfully",
		"router_info_interval": publisherConfig.RouterInfoInterval,
		"lease_set_interval":   publisherConfig.LeaseSetInterval,
		"floodfill_count":      publisherConfig.FloodfillCount,
		"has_ri_provider":      riProvider != nil,
	}).Info("NetDB publisher started for periodic RouterInfo and LeaseSet publishing")
}

// stopTunnelManager shuts down the tunnel manager if it exists.
// This stops the tunnel pools and cleans up tunnel-related resources.
func (r *Router) stopTunnelManager() {
	if r.tunnelManager != nil {
		r.tunnelManager.Stop()
		logSubsystemStop("(Router) stopTunnelManager", "tunnel manager")
	}
}

// stopParticipantManager shuts down the participant manager if it exists.
func (r *Router) stopParticipantManager() {
	if r.participantManager != nil {
		r.participantManager.Stop()
		log.WithFields(logger.Fields{"at": "stopParticipantManager"}).Debug("Participant manager stopped")
	}
}

func (r *Router) stopI2CPServer() {
	// Wait for any in-flight LeaseSet distribution goroutines to complete
	// before stopping the I2CP server, as they may access transport sessions.
	// Use a 30-second timeout to prevent indefinite hangs during network partitions.
	if r.leaseSetPublisher != nil {
		if err := r.leaseSetPublisher.WaitWithTimeout(30 * time.Second); err != nil {
			log.WithError(err).Warn("LeaseSet publisher goroutines did not drain within timeout")
		} else {
			log.WithFields(logger.Fields{"at": "stopI2CPServer"}).Debug("LeaseSet publisher goroutines drained")
		}
	}
	if r.i2cpServer != nil {
		if err := r.i2cpServer.Stop(); err != nil {
			log.WithError(err).Error("Failed to stop I2CP server")
		} else {
			log.WithFields(logger.Fields{"at": "stopI2CPServer"}).Debug("I2CP server stopped")
		}
	}
}

// sendCloseSignal sends the close signal to the router channel without blocking.
// It uses a non-blocking send to prevent deadlocks if the channel is full or already signaled.
func (r *Router) sendCloseSignal() {
	select {
	case r.closeChnl <- true:
		log.WithFields(logger.Fields{"at": "sendCloseSignal"}).Debug("Router stop signal sent")
	default:
		log.WithFields(logger.Fields{"at": "sendCloseSignal"}).Debug("Router stop signal already sent or channel full")
	}
}

// Close closes any internal state and finalizes router resources so that nothing can start up again.
// This method performs final cleanup after Stop() to ensure all resources are released and the router
// cannot be restarted. Call Stop() before Close() for graceful shutdown; Close() will call Stop()
// if the router is still running.
//
// Resources released by Close():
//   - Transport layer connections (via TransportMuxer.Close())
//   - Active NTCP2 sessions
//   - Message router references
//   - Garlic router references
//   - Tunnel manager references
//   - Close channel
func (r *Router) Close() error {
	log.WithFields(logger.Fields{
		"at":     "(Router) Close",
		"phase":  "finalization",
		"step":   1,
		"reason": "finalizing router resources",
	}).Info("closing router and releasing all resources")

	r.ensureStopped()
	closeErr := r.closeTransports()
	r.clearActiveSessions()
	r.clearRoutingComponents()
	r.finalizeCloseChannel()

	log.WithFields(logger.Fields{
		"at":     "(Router) Close",
		"phase":  "finalization",
		"step":   9,
		"reason": "router finalization complete",
	}).Info("router closed successfully - all resources released")

	return closeErr
}

// ensureStopped stops the router if it is still running.
func (r *Router) ensureStopped() {
	r.runMux.RLock()
	isRunning := r.running
	r.runMux.RUnlock()

	if isRunning {
		log.WithFields(logger.Fields{
			"at":     "(Router) Close",
			"phase":  "finalization",
			"step":   2,
			"reason": "router still running, calling Stop() first",
		}).Debug("stopping router before close")
		r.Stop()
	}
}

// closeTransports closes the transport muxer and all underlying connections.
// Returns the first error encountered during transport shutdown.
func (r *Router) closeTransports() error {
	if r.TransportMuxer == nil {
		return nil
	}

	log.WithFields(logger.Fields{
		"at":     "(Router) Close",
		"phase":  "finalization",
		"step":   3,
		"reason": "closing transport layer",
	}).Debug("closing TransportMuxer")

	var closeErr error
	if err := r.TransportMuxer.Close(); err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"at":     "(Router) Close",
			"phase":  "finalization",
			"reason": "transport close failed",
		}).Warn("error closing transport muxer")
		closeErr = err
	}
	r.TransportMuxer = nil
	return closeErr
}

// clearActiveSessions closes and removes all active NTCP2 sessions from the router.
// The map is replaced with an empty map (not nil) so that async cleanup callbacks
// calling delete() on the map after shutdown do not panic.
func (r *Router) clearActiveSessions() {
	r.sessionMutex.Lock()
	sessions := r.activeSessions
	// Replace with empty map instead of nil to prevent panics from
	// async session cleanup callbacks that may call delete() after shutdown.
	r.activeSessions = make(map[common.Hash]transport.TransportSession)
	r.sessionMutex.Unlock()

	sessionCount := len(sessions)
	for hash, session := range sessions {
		if err := session.Close(); err != nil {
			log.WithFields(logger.Fields{
				"at":        "(Router) clearActiveSessions",
				"phase":     "finalization",
				"peer_hash": fmt.Sprintf("%x", hash[:8]),
				"error":     err.Error(),
			}).Warn("failed to close transport session during shutdown")
		}
	}

	if sessionCount > 0 {
		log.WithFields(logger.Fields{
			"at":            "(Router) Close",
			"phase":         "finalization",
			"step":          4,
			"reason":        "cleared active sessions",
			"session_count": sessionCount,
		}).Debug("active sessions cleared")
	}
}

// clearRoutingComponents releases all message routing, garlic routing,
// tunnel manager, keystore, and NetDB references.
// Acquires runMux to prevent concurrent reads of these fields during shutdown.
func (r *Router) clearRoutingComponents() {
	r.runMux.Lock()
	r.messageRouter = nil
	r.garlicRouter = nil
	r.tunnelManager = nil
	r.inboundHandler = nil
	r.publisher = nil
	r.explorer = nil
	r.floodfillServer = nil
	r.StdNetDB = nil
	r.runMux.Unlock()
	log.WithFields(logger.Fields{
		"at":     "(Router) Close",
		"phase":  "finalization",
		"step":   5,
		"reason": "message routing components cleared",
	}).Debug("message router, garlic router, tunnel manager, publisher, and NetDB references cleared")

	r.keystoreMux.Lock()
	r.RouterInfoKeystore = nil
	r.keystoreMux.Unlock()
	log.WithFields(logger.Fields{
		"at":     "(Router) Close",
		"phase":  "finalization",
		"step":   6,
		"reason": "keystore reference cleared",
	}).Debug("keystore reference cleared (keys preserved on disk)")
}

// finalizeCloseChannel closes the router's close channel to signal complete finalization.
func (r *Router) finalizeCloseChannel() {
	r.closeOnce.Do(func() {
		if r.closeChnl != nil {
			close(r.closeChnl)
			r.closeChnl = nil
			log.WithFields(logger.Fields{
				"at":     "(Router) Close",
				"phase":  "finalization",
				"step":   8,
				"reason": "close channel finalized",
			}).Debug("close channel closed")
		}
	})
}

// Start starts router mainloop and returns an error if startup-critical
// subsystems (NetDB, I2CP, I2PControl) fail to initialize.
// The router must be created via CreateRouter (not bare FromConfig) so that
// the keystore and transport are properly initialized before Start is called.
// Start initializes all subsystems and starts the router's main loop.
// It acquires runMux for the duration of pre-launch setup, then releases it
// before blocking on the mainloop's startup-error channel.
func (r *Router) Start() error {
	r.runMux.Lock()

	if err := r.validateSubsystems(); err != nil {
		r.runMux.Unlock()
		return err
	}

	if r.running {
		r.runMux.Unlock()
		log.WithFields(logger.Fields{
			"at":     "(Router) Start",
			"phase":  "startup",
			"reason": "router is already running",
			"state":  "running",
		}).Warn("attempted to start already running router")
		return nil
	}

	r.markRunning()
	log.WithField("at", "Start").Debug("step 2/6: initializing lifecycle context")
	r.initializeLifecycleContext()
	log.WithField("at", "Start").Debug("step 3/6: initializing bandwidth tracker")
	r.initializeBandwidthTracker()
	log.WithField("at", "Start").Debug("step 4/6: initializing congestion monitoring")
	r.initializeCongestionMonitoring()
	log.WithField("at", "Start").Debug("step 5/6: initializing router info provider")
	r.initializeRouterInfoProvider()
	log.WithField("at", "Start").Debug("step 6/6: launching mainloop")
	r.launchMainloop()

	// Release runMux BEFORE blocking on startupErr to prevent deadlocking
	// Stop() which also needs runMux. The running flag is already set, so
	// Stop() can proceed if called while we wait.
	r.runMux.Unlock()

	return r.awaitStartupResult()
}

// validateSubsystems checks that CreateRouter has fully initialized the router.
// Must be called while runMux is held.
func (r *Router) validateSubsystems() error {
	if r.RouterInfoKeystore == nil {
		return oops.Errorf("router not fully initialized: keystore is nil (use CreateRouter, not FromConfig directly)")
	}
	if r.TransportMuxer == nil {
		return oops.Errorf("router not fully initialized: transport muxer is nil (use CreateRouter, not FromConfig directly)")
	}
	return nil
}

// markRunning sets the running flag and logs the startup initiation.
// Must be called while runMux is held.
func (r *Router) markRunning() {
	log.WithFields(logger.Fields{
		"at":           "(Router) Start",
		"phase":        "startup",
		"step":         1,
		"reason":       "initiating router startup sequence",
		"i2cp_enabled": r.cfg.I2CP != nil && r.cfg.I2CP.Enabled,
	}).Info("starting router")
	r.running = true
}

// initializeLifecycleContext creates the router-level context for coordinated shutdown.
func (r *Router) initializeLifecycleContext() {
	r.ctx, r.cancel = context.WithCancel(context.Background())
	log.WithFields(logger.Fields{
		"at":     "(Router) Start",
		"phase":  "startup",
		"step":   2,
		"reason": "lifecycle context initialized",
	}).Debug("router context initialized")
}

// initializeBandwidthTracker creates and starts the bandwidth sampling tracker.
func (r *Router) initializeBandwidthTracker() {
	r.bandwidthTracker = NewBandwidthTracker()
	r.bandwidthTracker.Start(r.getTotalBandwidth)
	log.WithFields(logger.Fields{
		"at":     "(Router) Start",
		"phase":  "startup",
		"step":   3,
		"reason": "bandwidth tracker initialized",
	}).Debug("bandwidth tracker started")
}

// initializeCongestionMonitoring starts congestion monitoring per PROP_162.
func (r *Router) initializeCongestionMonitoring() {
	r.startCongestionMonitor()
	log.WithFields(logger.Fields{
		"at":     "(Router) Start",
		"phase":  "startup",
		"step":   4,
		"reason": "congestion monitor initialized",
	}).Debug("congestion monitor started")
}

// initializeRouterInfoProvider wires the routerInfoProvider so the NetDB publisher
// can access the local RouterInfo, optionally attaching the congestion monitor.
func (r *Router) initializeRouterInfoProvider() {
	r.routerInfoProv = newRouterInfoProvider(r)
	if r.congestionMonitor != nil {
		r.routerInfoProv.SetCongestionMonitor(r.congestionMonitor)
	}
	log.WithFields(logger.Fields{
		"at":     "(Router) Start",
		"phase":  "startup",
		"step":   5,
		"reason": "routerInfoProvider wired",
	}).Debug("router info provider initialized")
}

// launchMainloop starts the main event loop in a tracked goroutine.
func (r *Router) launchMainloop() {
	r.startupErr = make(chan error, 1)
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		r.mainloop()
	}()
}

// awaitStartupResult blocks until the mainloop reports startup success or failure.
func (r *Router) awaitStartupResult() error {
	if err := <-r.startupErr; err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"at":     "(Router) Start",
			"phase":  "startup",
			"reason": "startup-critical subsystem failed",
		}).Error("router startup failed")
		return err
	}
	log.WithFields(logger.Fields{
		"at":     "(Router) Start",
		"phase":  "running",
		"reason": "all startup-critical subsystems initialized",
	}).Info("router started successfully")
	if r.cfg != nil && r.cfg.Hidden {
		log.WithFields(logger.Fields{
			"at":     "(Router) Start",
			"phase":  "running",
			"reason": "hidden mode active",
			"caps":   "NUH (no transit, no inbound from network)",
		}).Info("router is in hidden mode: refusing transit, publishing no transport addresses")
	}
	return nil
}

// initializeNetDB creates and configures the network database.
// Idempotent: if r.StdNetDB has already been initialized (for example from
// CreateRouter, where it is created early so that transports can wire their
// PeerConnNotifier into r.StdNetDB.PeerTracker), this call is a no-op. This
// matters because r.StdNetDB MUST exist before initializeTransports runs;
// otherwise NTCP2/SSU2 transports silently skip SetPeerConnNotifier and
// successful connections are never recorded in PeerTracker, causing every
// known-good peer to be marked stale on its first tunnel-build failure.
func (r *Router) initializeNetDB() error {
	if r.StdNetDB != nil {
		log.WithFields(logger.Fields{"at": "initializeNetDB"}).Debug("NetDB already initialized; skipping")
		return nil
	}
	log.WithFields(logger.Fields{"at": "initializeNetDB"}).Debug("Initializing network database")
	r.StdNetDB = netdb.NewStdNetDB(r.cfg.NetDB.Path)
	r.StdNetDB.SetMaxRouterInfos(r.cfg.NetDB.MaxRouterInfos)
	log.WithField("netdb_path", r.cfg.NetDB.Path).Debug("Created StdNetDB")
	return nil
}

// initializeMessageRouter sets up message routing with NetDB integration
func (r *Router) initializeMessageRouter() {
	messageConfig := i2np.I2NPMessageDispatcherConfig{
		MaxRetries:     3,
		DefaultTimeout: 30 * time.Second,
		EnableLogging:  true,
	}
	r.messageRouter = i2np.NewI2NPMessageDispatcher(messageConfig)
	r.messageRouter.SetNetDB(r.StdNetDB)
	r.messageRouter.SetPeerSelector(r.StdNetDB)
	r.messageRouter.SetSessionProvider(r)

	r.initializeTunnelManager()
	r.wireDispatcherTunnelManager()
	r.wireParticipantManager()
	r.initializeGarlicRouter()
	r.wireGarlicSessionManager()
	r.wireTunnelDataHandler()
	r.wireTunnelGatewayHandler()
	r.wireBuildRecordIdentity()
	r.wireI2CPTunnelBuilder()

	log.WithFields(logger.Fields{"at": "initializeMessageRouter"}).Debug("Message router initialized with NetDB, peer selection, session provider, tunnel data handler, garlic sessions, and garlic forwarding")
}

// wireDispatcherTunnelManager unifies the dispatcher's tunnel manager with the router's.
func (r *Router) wireDispatcherTunnelManager() {
	r.messageRouter.SetTunnelManager(r.tunnelManager)
	r.messageRouter.GetProcessor().SetBuildReplyProcessor(r.tunnelManager)
	log.WithFields(logger.Fields{"at": "initializeMessageRouter"}).Debug("Dispatcher tunnel manager unified with router tunnel manager")
}

// wireParticipantManager initializes and wires the participant manager for transit tunnels.
func (r *Router) wireParticipantManager() {
	r.participantManager = tunnel.NewManager()
	r.messageRouter.GetProcessor().SetParticipantManager(r.participantManager)
	r.messageRouter.GetProcessor().SetBuildReplyForwarder(&transportBuildReplyForwarder{sessionProvider: r})
	// Apply the no-transit policy: hidden mode or AcceptTunnels=false both
	// require unconditional rejection of incoming tunnel build requests.
	if r.cfg != nil && (r.cfg.Hidden || !r.cfg.AcceptTunnels) {
		r.participantManager.SetRefuseAllTransit(true)
	}
	log.WithFields(logger.Fields{"at": "initializeMessageRouter"}).Debug("Participant manager and build reply forwarder wired into message processor")
}

// wireTunnelDataHandler wires the inbound message handler as the TunnelData handler.
func (r *Router) wireTunnelDataHandler() {
	if r.inboundHandler != nil {
		r.messageRouter.GetProcessor().SetTunnelDataHandler(r.inboundHandler)
		log.WithFields(logger.Fields{"at": "initializeMessageRouter"}).Debug("InboundMessageHandler wired as TunnelData handler on message processor")
	}
}

// wireTunnelGatewayHandler wires a TunnelGateway handler that re-parses the
// inner I2NP message from the gateway payload and dispatches it through the
// message processor. This is needed so that STBM build replies (type 26)
// wrapped inside a TunnelGateway (type 19) are properly processed.
func (r *Router) wireTunnelGatewayHandler() {
	r.messageRouter.GetProcessor().SetTunnelGatewayHandler(&tunnelGatewayDispatcher{
		processor: r.messageRouter.GetProcessor(),
	})
	log.WithFields(logger.Fields{"at": "initializeMessageRouter"}).Debug("TunnelGateway dispatcher wired into message processor")
}

// tunnelGatewayDispatcher implements i2np.TunnelGatewayHandler by parsing the
// inner I2NP message from a TunnelGateway payload and re-dispatching it.
type tunnelGatewayDispatcher struct {
	processor *i2np.MessageProcessor
}

// HandleGateway parses and dispatches an inner I2NP message carried in a
// TunnelGateway payload.
func (d *tunnelGatewayDispatcher) HandleGateway(tunnelID tunnel.TunnelID, payload []byte) error {
	// BUG-4 fix: use the short-format minimum (9 bytes) as the floor so that
	// valid 9–15 byte short I2NP messages are not rejected before the fallback
	// path is attempted. The previous guard of < 16 was too strict.
	if len(payload) < i2np.ShortI2NPHeaderSize {
		return oops.Errorf("TunnelGateway payload too short: %d bytes", len(payload))
	}
	inner := &i2np.BaseI2NPMessage{}
	if err := inner.UnmarshalBinary(payload); err != nil {
		// Fall back to short I2NP format (9-byte header) in case the payload
		// uses NTCP2 short format.
		inner2 := &i2np.BaseI2NPMessage{}
		if err2 := inner2.UnmarshalShortI2NP(payload); err2 != nil {
			return oops.Wrapf(err, "failed to parse inner I2NP message from TunnelGateway payload (standard: %v, short: %v)", err, err2)
		}
		inner = inner2
	}
	i2np.RecordExploratoryReplyStage(i2np.ExploratoryReplyStageTunnelGatewayParsed)
	log.WithFields(logger.Fields{
		"outer_tunnel_id": tunnelID,
		"inner_type":      inner.Type(),
		"inner_msg_id":    inner.MessageID(),
		"payload_size":    len(payload),
	}).Debug("TunnelGateway: dispatching inner I2NP message")
	return d.processor.ProcessMessage(inner)
}

// wireBuildRecordIdentity wires router identity and crypto keys for build record decryption.
func (r *Router) wireBuildRecordIdentity() {
	routerHash, err := r.getOurRouterHash()
	if err != nil {
		log.WithError(err).Error("Failed to get router hash for build record identity — transit tunnel building will be degraded")
		return
	}
	privKeyBytes := r.RouterInfoKeystore.GetEncryptionPrivateKey().Bytes()
	buildCrypto := i2np.NewBuildRecordCrypto()
	r.messageRouter.GetProcessor().SetOurRouterHash(routerHash)
	r.messageRouter.GetProcessor().SetBuildRequestDecryptor(buildCrypto)
	r.messageRouter.GetProcessor().SetOurPrivateKey(privKeyBytes)
	// Propagate our router hash to the tunnel manager so pools can set
	// ReplyGateway correctly. Without this, the last hop in every build
	// sends the reply to an all-zeros peer and builds always expire.
	if r.tunnelManager != nil {
		r.tunnelManager.SetOurRouterHash(routerHash)
	}
	log.WithFields(logger.Fields{"at": "initializeMessageRouter"}).Debug("MessageProcessor identity, decryptor, and private key wired for build record decryption")
}

// wireI2CPTunnelBuilder wires the tunnel manager into the I2CP server.
func (r *Router) wireI2CPTunnelBuilder() {
	if r.i2cpServer != nil && r.tunnelManager != nil {
		r.i2cpServer.SetTunnelBuilder(r.tunnelManager)
		log.WithFields(logger.Fields{"at": "initializeMessageRouter"}).Debug("I2CP server: tunnel builder wired after tunnel manager initialization")
	}
}

// configureRouterHashOnPools sets the router's hash on both tunnel pools.
// This must be done before starting maintenance to ensure build requests
// have valid identity information.
func (r *Router) configureRouterHashOnPools(inboundPool, outboundPool *tunnel.Pool) error {
	routerHash, err := r.getOurRouterHash()
	if err != nil {
		return err
	}
	if outboundPool != nil {
		outboundPool.SetRouterHash(routerHash)
	}
	if inboundPool != nil {
		inboundPool.SetRouterHash(routerHash)
	}
	return nil
}

// configureInboundPoolPolicy configures hop count and auto-fallback for the inbound pool.
// Returns true if zero-hop mode is enabled.
func (r *Router) configureInboundPoolPolicy(inboundPool *tunnel.Pool) bool {
	if inboundPool == nil {
		return false
	}

	zeroHopInbound := r.cfg != nil && (r.cfg.Hidden || r.cfg.AlwaysZeroHopInbound)
	if zeroHopInbound {
		if err := inboundPool.SetHopCount(0); err != nil {
			log.WithError(err).Error("Failed to enable zero-hop inbound tunnels")
		} else {
			log.WithFields(logger.Fields{
				"at":                      "configureInboundPoolPolicy",
				"hidden":                  r.cfg.Hidden,
				"always_zero_hop_inbound": r.cfg.AlwaysZeroHopInbound,
			}).Info("Inbound exploratory pool configured for zero-hop tunnels")
		}
	} else {
		// Wire auto-fallback: after autoFallbackThreshold consecutive build
		// timeouts, automatically switch to 0-hop inbound when no public
		// address is confirmed.
		inboundPool.SetAutoFallbackCheck(func() bool {
			return r.collectBestExternalAddr() == ""
		})
	}
	return zeroHopInbound
}

// configureOutboundPoolPolicy configures hop count and auto-fallback for the outbound pool.
// Returns true if one-hop mode is enabled.
func (r *Router) configureOutboundPoolPolicy(outboundPool *tunnel.Pool) bool {
	if outboundPool == nil {
		return false
	}

	oneHopOutbound := r.cfg != nil && (r.cfg.Hidden || r.cfg.AlwaysOneHopOutbound)
	if oneHopOutbound {
		if err := outboundPool.SetHopCount(1); err != nil {
			log.WithError(err).Error("Failed to enable one-hop outbound tunnels")
		} else {
			log.WithFields(logger.Fields{
				"at":                      "configureOutboundPoolPolicy",
				"hidden":                  r.cfg.Hidden,
				"always_one_hop_outbound": r.cfg.AlwaysOneHopOutbound,
			}).Info("Outbound exploratory pool configured for one-hop tunnels")
		}
	} else {
		// Wire auto-fallback: after autoFallbackThreshold consecutive outbound
		// build timeouts with no public address, switch to 1-hop outbound.
		outboundPool.SetAutoFallbackCheck(func() bool {
			return r.collectBestExternalAddr() == ""
		})
	}
	return oneHopOutbound
}

// wireReplyTunnelProviders configures reply tunnel providers for both pools.
// This enables TUNNEL delivery mode instead of ROUTER delivery mode,
// which works better behind NAT.
func (r *Router) wireReplyTunnelProviders(inboundPool, outboundPool *tunnel.Pool) {
	if inboundPool == nil {
		return
	}

	makeProvider := func(pool *tunnel.Pool) func() (tunnel.TunnelID, bool) {
		return func() (tunnel.TunnelID, bool) {
			active := pool.GetActiveTunnels()
			if len(active) == 0 {
				return 0, false
			}
			// Prefer the oldest active tunnel for stability.
			return active[0].ID, true
		}
	}

	inboundPool.SetReplyTunnelProvider(makeProvider(inboundPool))
	if outboundPool != nil {
		outboundPool.SetReplyTunnelProvider(makeProvider(inboundPool))
	}
}

// startPoolMaintenance starts maintenance goroutines for both tunnel pools.
func (r *Router) startPoolMaintenance(tm *i2np.TunnelManager, inboundPool, outboundPool *tunnel.Pool) {
	for _, pool := range []*tunnel.Pool{inboundPool, outboundPool} {
		if pool == nil {
			continue
		}
		pool.SetTunnelBuilder(tm)
		pool.SetPeerTracker(r.StdNetDB.PeerTracker)
		if err := pool.StartMaintenance(); err != nil {
			log.WithError(err).Error("Failed to start tunnel pool maintenance")
		}
	}
}

// launchInboundReadinessWatcher launches a goroutine that monitors inbound pool
// readiness and closes the gate channel when ready or on timeout.
func (r *Router) launchInboundReadinessWatcher(inboundPool, outboundPool *tunnel.Pool, inboundReady chan struct{}) {
	go func() {
		deadline := time.NewTimer(2 * tunnel.BuildTimeout)
		defer deadline.Stop()
		poll := time.NewTicker(500 * time.Millisecond)
		defer poll.Stop()

		r.runInboundReadinessLoop(inboundPool, outboundPool, inboundReady, deadline, poll)
	}()
}

// runInboundReadinessLoop polls for inbound pool readiness with timeout handling.
func (r *Router) runInboundReadinessLoop(inboundPool, outboundPool *tunnel.Pool, inboundReady chan struct{}, deadline *time.Timer, poll *time.Ticker) {
	for {
		select {
		case <-r.ctx.Done():
			close(inboundReady)
			return
		case <-deadline.C:
			r.handleInboundReadinessTimeout(inboundPool, outboundPool, inboundReady)
			return
		case <-poll.C:
			if r.checkInboundPoolReady(inboundPool, inboundReady) {
				return
			}
		}
	}
}

// checkInboundPoolReady checks if the inbound pool has active tunnels.
func (r *Router) checkInboundPoolReady(inboundPool *tunnel.Pool, inboundReady chan struct{}) bool {
	if inboundPool != nil && len(inboundPool.GetActiveTunnels()) > 0 {
		log.WithFields(logger.Fields{
			"at": "launchInboundReadinessWatcher",
		}).Debug("inbound pool ready; releasing outbound pool startup gate")
		close(inboundReady)
		return true
	}
	return false
}

// handleInboundReadinessTimeout handles the case when inbound pool doesn't
// become ready within the timeout period.
func (r *Router) handleInboundReadinessTimeout(inboundPool, outboundPool *tunnel.Pool, inboundReady chan struct{}) {
	log.WithFields(logger.Fields{
		"at":      "handleInboundReadinessTimeout",
		"timeout": 2 * tunnel.BuildTimeout,
	}).Warn("inbound pool readiness timeout; enforcing fallback before releasing outbound gate")

	// Force outbound to 1-hop first
	if outboundPool != nil {
		if err := outboundPool.SetHopCount(1); err != nil {
			log.WithFields(logger.Fields{
				"at":    "handleInboundReadinessTimeout",
				"error": err.Error(),
			}).Warn("failed to force outbound exploratory pool to one-hop")
		}
	}

	// Force inbound to 0-hop
	if inboundPool != nil {
		if err := inboundPool.SetHopCount(0); err != nil {
			log.WithFields(logger.Fields{
				"at":    "handleInboundReadinessTimeout",
				"error": err.Error(),
			}).Warn("failed to force inbound exploratory pool to zero-hop")
		}
		inboundPool.RunMaintenanceNow()
	}

	// Wait for 0-hop inbound to appear
	r.waitForFallbackInbound(inboundPool, inboundReady)
}

// waitForFallbackInbound waits up to 5s for 0-hop inbound tunnel after fallback.
func (r *Router) waitForFallbackInbound(inboundPool *tunnel.Pool, inboundReady chan struct{}) {
	fallbackPoll := time.NewTicker(300 * time.Millisecond)
	fallbackDeadline := time.NewTimer(5 * time.Second)
	defer fallbackPoll.Stop()
	defer fallbackDeadline.Stop()

	r.runFallbackInboundLoop(inboundPool, inboundReady, fallbackDeadline, fallbackPoll)
}

// runFallbackInboundLoop polls for fallback inbound pool readiness with timeout.
func (r *Router) runFallbackInboundLoop(inboundPool *tunnel.Pool, inboundReady chan struct{}, deadline *time.Timer, poll *time.Ticker) {
	for {
		select {
		case <-r.ctx.Done():
			close(inboundReady)
			return
		case <-deadline.C:
			r.handleFallbackTimeout(inboundReady)
			return
		case <-poll.C:
			if r.checkFallbackInboundReady(inboundPool, inboundReady) {
				return
			}
		}
	}
}

// handleFallbackTimeout handles the secondary fallback readiness timeout.
func (r *Router) handleFallbackTimeout(inboundReady chan struct{}) {
	log.WithFields(logger.Fields{
		"at": "waitForFallbackInbound",
	}).Warn("secondary fallback readiness timeout; releasing outbound gate")
	close(inboundReady)
}

// checkFallbackInboundReady checks if the fallback inbound pool has active tunnels.
func (r *Router) checkFallbackInboundReady(inboundPool *tunnel.Pool, inboundReady chan struct{}) bool {
	if inboundPool != nil && len(inboundPool.GetActiveTunnels()) > 0 {
		log.WithFields(logger.Fields{
			"at": "waitForFallbackInbound",
		}).Debug("0-hop inbound ready after fallback; releasing outbound gate")
		close(inboundReady)
		return true
	}
	return false
}

// launchProactiveFallbackChecks starts goroutines that trigger auto-fallback
// after one build timeout if no tunnels are established.
func (r *Router) launchProactiveFallbackChecks(inboundPool, outboundPool *tunnel.Pool, zeroHopInbound, oneHopOutbound bool) {
	if !zeroHopInbound && inboundPool != nil {
		r.launchInboundFallbackCheck(inboundPool)
	}

	if !oneHopOutbound && outboundPool != nil {
		r.launchOutboundFallbackCheck(outboundPool)
	}
}

// launchInboundFallbackCheck starts a goroutine to trigger inbound fallback after timeout.
func (r *Router) launchInboundFallbackCheck(pool *tunnel.Pool) {
	go func() {
		select {
		case <-r.ctx.Done():
			return
		case <-time.After(tunnel.BuildTimeout + 5*time.Second):
			if len(pool.GetActiveTunnels()) == 0 {
				pool.TriggerAutoFallbackCheck()
			}
		}
	}()
}

// launchOutboundFallbackCheck starts a goroutine to trigger outbound fallback after timeout.
func (r *Router) launchOutboundFallbackCheck(pool *tunnel.Pool) {
	go func() {
		select {
		case <-r.ctx.Done():
			return
		case <-time.After(tunnel.BuildTimeout + 5*time.Second):
			if len(pool.GetActiveTunnels()) == 0 {
				pool.TriggerAutoFallbackCheck()
			}
		}
	}()
}

// initializeTunnelManager creates and configures the tunnel manager for building and maintaining tunnels.
// The tunnel manager coordinates tunnel building, maintains tunnel pools, and handles tunnel lifecycle.
func (r *Router) initializeTunnelManager() {
	// Create tunnel manager with NetDB as peer selector
	tm := i2np.NewTunnelManager(r.StdNetDB)

	// Set router as session provider for sending tunnel build messages
	tm.SetSessionProvider(r)

	// Assign to router field with lock protection
	r.runMux.Lock()
	r.tunnelManager = tm
	r.runMux.Unlock()

	// Get tunnel pools
	outboundPool := tm.GetOutboundPool()
	inboundPool := tm.GetInboundPool()

	// Set router hash on pools before starting maintenance
	if err := r.configureRouterHashOnPools(inboundPool, outboundPool); err != nil {
		log.WithError(err).Error("Failed to get router hash for tunnel pools; skipping maintenance startup until identity is available")
		return
	}

	// Configure pool policies (hop count, auto-fallback) before starting maintenance
	zeroHopInbound := r.configureInboundPoolPolicy(inboundPool)
	oneHopOutbound := r.configureOutboundPoolPolicy(outboundPool)

	// Gate outbound pool's first build on inbound readiness
	inboundReady := make(chan struct{})
	if outboundPool != nil {
		outboundPool.SetStartupGate(inboundReady)
	}

	// Wire reply tunnel providers for both pools
	r.wireReplyTunnelProviders(inboundPool, outboundPool)

	// Start maintenance on both pools
	r.startPoolMaintenance(tm, inboundPool, outboundPool)

	// Launch watcher for inbound pool readiness
	r.launchInboundReadinessWatcher(inboundPool, outboundPool, inboundReady)

	// Launch proactive fallback checks after one build timeout
	r.launchProactiveFallbackChecks(inboundPool, outboundPool, zeroHopInbound, oneHopOutbound)

	log.WithFields(logger.Fields{
		"at":            "initializeTunnelManager",
		"inbound_pool":  inboundPool != nil,
		"outbound_pool": outboundPool != nil,
		"peer_tracker":  r.StdNetDB.PeerTracker != nil,
	}).Debug("Tunnel pools configured and maintenance started")

	log.WithFields(logger.Fields{
		"peer_selector": "netdb",
		"pools_created": true,
	}).Debug("Tunnel manager initialized with peer selection")
}

// initializeGarlicRouter sets up garlic message forwarding for non-LOCAL delivery types.
// This enables DESTINATION (0x01), ROUTER (0x02), and TUNNEL (0x03) garlic clove deliveries.
func (r *Router) initializeGarlicRouter() {
	// Get our router identity hash for reflexive delivery detection
	routerHash, err := r.getOurRouterHash()
	if err != nil {
		log.WithError(err).Error("Failed to get our router hash - garlic routing may not properly detect self-addressed messages")
		// Continue with zero hash; the router can still function but reflexive routing won't work
	}

	// Wrap StdNetDB with adapter to match GarlicNetDB interface
	garlicNetDB := newNetDBAdapter(r.StdNetDB)

	// Get tunnel pool from tunnel manager if available, otherwise nil
	var tunnelPool *tunnel.Pool
	if r.tunnelManager != nil {
		tunnelPool = r.tunnelManager.GetOutboundPool()
	}

	// Create garlic message router with router infrastructure
	gr := NewGarlicMessageRouter(
		garlicNetDB,      // NetDB for LeaseSet/RouterInfo lookups
		r.TransportMuxer, // Transport for sending to peer routers
		tunnelPool,       // Tunnel pool for DESTINATION and TUNNEL delivery
		routerHash,       // Our identity for reflexive routing
	)

	// Set bidirectional references for LOCAL delivery recursion
	gr.SetMessageProcessor(r.messageRouter.GetProcessor())
	r.messageRouter.GetProcessor().SetCloveForwarder(gr)

	// Protect write to garlicRouter field
	r.runMux.Lock()
	r.garlicRouter = gr
	r.runMux.Unlock()

	log.WithFields(logger.Fields{
		"our_hash":        fmt.Sprintf("%x", routerHash[:8]),
		"tunnel_support":  tunnelPool != nil,
		"transport_ready": r.TransportMuxer != nil,
		"netdb_ready":     r.StdNetDB != nil,
	}).Debug("Garlic message router initialized for non-LOCAL clove forwarding")
}

// wireGarlicSessionManager creates a GarlicSessionManager from the router's X25519
// encryption private key and injects it into the MessageProcessor for decrypting
// inbound garlic messages.
func (r *Router) wireGarlicSessionManager() {
	privKeyBytes := r.RouterInfoKeystore.GetEncryptionPrivateKey().Bytes()
	var privKey [32]byte
	copy(privKey[:], privKeyBytes)

	garlicMgr, err := i2np.NewGarlicSessionManager(privKey)
	if err != nil {
		log.WithError(err).Error("Failed to create garlic session manager — inbound garlic decryption will fail")
		return
	}
	r.messageRouter.GetProcessor().SetGarlicSessionManager(garlicMgr)
	if r.tunnelManager != nil {
		r.tunnelManager.SetGarlicKeyRegistrar(garlicMgr)
	}
	log.WithFields(logger.Fields{"at": "wireGarlicSessionManager"}).Debug("Garlic session manager wired into message processor")
}

// getOurRouterHash returns our router's identity hash.
// Returns an error if the hash cannot be computed.
func (r *Router) getOurRouterHash() (common.Hash, error) {
	log.WithField("at", "getOurRouterHash").Debug("constructing RouterInfo to derive identity hash")
	ri, err := r.RouterInfoKeystore.ConstructRouterInfo(nil)
	if err != nil {
		return common.Hash{}, oops.Wrapf(err, "failed to construct RouterInfo")
	}
	log.WithField("at", "getOurRouterHash").Debug("RouterInfo constructed, computing IdentHash")

	hash, err := ri.IdentHash()
	if err != nil {
		return common.Hash{}, oops.Wrapf(err, "failed to get IdentHash")
	}

	log.WithField("at", "getOurRouterHash").Debug("identity hash computed successfully")
	return hash, nil
}
