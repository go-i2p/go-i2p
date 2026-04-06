package router

import (
	"context"
	"fmt"
	"time"

	common "github.com/go-i2p/common/data"
	ntcp "github.com/go-i2p/go-i2p/lib/transport/ntcp2"

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
// Reads from RouterConfig.AcceptTunnels.
func (r *Router) isAcceptingTunnels() bool {
	if r.cfg != nil {
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
	if r.cfg != nil && r.cfg.NetDb != nil {
		cfg.Enabled = r.cfg.NetDb.FloodfillEnabled
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
	tunnelPool := r.tunnelManager.GetPool()
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
		return nil, fmt.Errorf("Cannot start publisher: NetDB not initialized")
	}
	if r.TransportMuxer == nil {
		return nil, fmt.Errorf("Cannot start publisher: TransportMuxer not initialized")
	}
	var tunnelPool *tunnel.Pool
	if r.tunnelManager != nil {
		tunnelPool = r.tunnelManager.GetPool()
	}
	if tunnelPool == nil {
		return nil, fmt.Errorf("Cannot start publisher: tunnel pool not available")
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
	r.activeSessions = make(map[common.Hash]*ntcp.NTCP2Session)
	r.sessionMutex.Unlock()

	sessionCount := len(sessions)
	for hash, session := range sessions {
		if err := session.Close(); err != nil {
			log.WithFields(logger.Fields{
				"at":        "(Router) clearActiveSessions",
				"phase":     "finalization",
				"peer_hash": fmt.Sprintf("%x", hash[:8]),
				"error":     err.Error(),
			}).Warn("failed to close NTCP2 session during shutdown")
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
		return fmt.Errorf("router not fully initialized: keystore is nil (use CreateRouter, not FromConfig directly)")
	}
	if r.TransportMuxer == nil {
		return fmt.Errorf("router not fully initialized: transport muxer is nil (use CreateRouter, not FromConfig directly)")
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
	return nil
}

// initializeNetDB creates and configures the network database
func (r *Router) initializeNetDB() error {
	log.WithFields(logger.Fields{"at": "initializeNetDB"}).Debug("Initializing network database")
	r.StdNetDB = netdb.NewStdNetDB(r.cfg.NetDb.Path)
	log.WithField("netdb_path", r.cfg.NetDb.Path).Debug("Created StdNetDB")
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

	// Set router as SessionProvider to enable message response routing
	r.messageRouter.SetSessionProvider(r)

	// Initialize tunnel manager for building and managing tunnels
	// Must be done before garlic router so it can access the tunnel pool
	r.initializeTunnelManager()

	// Initialize participant manager for tracking transit tunnels
	r.participantManager = tunnel.NewManager()
	log.WithFields(logger.Fields{"at": "initializeMessageRouter"}).Debug("Participant manager initialized for transit tunnel tracking")

	// Wire participant manager into the message processor so incoming tunnel
	// build requests from other routers are evaluated instead of silently dropped.
	r.messageRouter.GetProcessor().SetParticipantManager(r.participantManager)
	log.WithFields(logger.Fields{"at": "initializeMessageRouter"}).Debug("Participant manager wired into message processor")

	// Wire build reply forwarder so accepted tunnel build requests can send
	// replies back to the requester via the transport layer.
	r.messageRouter.GetProcessor().SetBuildReplyForwarder(&transportBuildReplyForwarder{sessionProvider: r})
	log.WithFields(logger.Fields{"at": "initializeMessageRouter"}).Debug("Build reply forwarder wired into message processor")

	// Initialize garlic message router for handling garlic clove forwarding
	r.initializeGarlicRouter()

	// Create and wire garlic session manager for decrypting inbound garlic messages.
	// Uses the router's X25519 encryption private key for ECIES decryption.
	r.wireGarlicSessionManager()

	// Wire InboundMessageHandler as the TunnelData handler on the message processor.
	// This enables inbound tunnel messages to be decrypted and delivered to I2CP sessions.
	if r.inboundHandler != nil {
		r.messageRouter.GetProcessor().SetTunnelDataHandler(r.inboundHandler)
		log.WithFields(logger.Fields{"at": "initializeMessageRouter"}).Debug("InboundMessageHandler wired as TunnelData handler on message processor")
	}

	// Wire our router identity, build-record decryptor, and X25519 private key so that
	// the MessageProcessor can recognise and decrypt inbound tunnel build records.
	// Without this, isRecordForUs always returns false and all decryption paths are dead.
	routerHash, err := r.getOurRouterHash()
	if err != nil {
		log.WithError(err).Error("Failed to get router hash for build record identity — transit tunnel building will be degraded")
	} else {
		privKeyBytes := r.RouterInfoKeystore.GetEncryptionPrivateKey().Bytes()
		buildCrypto := i2np.NewBuildRecordCrypto()
		r.messageRouter.GetProcessor().SetOurRouterHash(routerHash)
		r.messageRouter.GetProcessor().SetBuildRequestDecryptor(buildCrypto)
		r.messageRouter.GetProcessor().SetOurPrivateKey(privKeyBytes)
		log.WithFields(logger.Fields{"at": "initializeMessageRouter"}).Debug("MessageProcessor identity, decryptor, and private key wired for build record decryption")
	}

	// Wire tunnel manager into I2CP server now that it is available.
	// configureI2CPServerInfrastructure() was called before initializeTunnelManager()
	// during startup, so SetTunnelBuilder was skipped due to a nil tunnelManager.
	// We complete that wiring here.
	if r.i2cpServer != nil && r.tunnelManager != nil {
		r.i2cpServer.SetTunnelBuilder(r.tunnelManager)
		log.WithFields(logger.Fields{"at": "initializeMessageRouter"}).Debug("I2CP server: tunnel builder wired after tunnel manager initialization")
	}

	log.WithFields(logger.Fields{"at": "initializeMessageRouter"}).Debug("Message router initialized with NetDB, peer selection, session provider, tunnel data handler, garlic sessions, and garlic forwarding")
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

	// Configure automatic tunnel pool maintenance
	pool := tm.GetPool()
	pool.SetTunnelBuilder(tm) // TunnelManager implements BuilderInterface

	pool.SetPeerTracker(r.StdNetDB.PeerTracker)
	log.WithFields(logger.Fields{"at": "initializeTunnelManager"}).Debug("Tunnel pool configured with NetDB peer tracker for reputation tracking")

	if err := pool.StartMaintenance(); err != nil {
		log.WithError(err).Error("Failed to start tunnel pool maintenance")
	} else {
		log.WithFields(logger.Fields{"at": "initializeTunnelManager"}).Debug("Tunnel pool automatic maintenance started")
	}

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
		tunnelPool = r.tunnelManager.GetPool()
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
	log.WithFields(logger.Fields{"at": "wireGarlicSessionManager"}).Debug("Garlic session manager wired into message processor")
}

// getOurRouterHash returns our router's identity hash.
// Returns an error if the hash cannot be computed.
func (r *Router) getOurRouterHash() (common.Hash, error) {
	log.WithField("at", "getOurRouterHash").Debug("constructing RouterInfo to derive identity hash")
	ri, err := r.RouterInfoKeystore.ConstructRouterInfo(nil)
	if err != nil {
		return common.Hash{}, fmt.Errorf("failed to construct RouterInfo: %w", err)
	}
	log.WithField("at", "getOurRouterHash").Debug("RouterInfo constructed, computing IdentHash")

	hash, err := ri.IdentHash()
	if err != nil {
		return common.Hash{}, fmt.Errorf("failed to get IdentHash: %w", err)
	}

	log.WithField("at", "getOurRouterHash").Debug("identity hash computed successfully")
	return hash, nil
}
