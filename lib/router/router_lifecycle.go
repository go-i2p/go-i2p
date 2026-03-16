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

// Stop initiates router shutdown and waits for all goroutines to complete.
// This method blocks until the router is fully stopped.
func (r *Router) Stop() {
	log.WithFields(logger.Fields{
		"at":     "(Router) Stop",
		"phase":  "shutdown",
		"step":   1,
		"reason": "shutdown requested",
	}).Debug("stopping router")
	r.runMux.Lock()

	if !r.running {
		r.runMux.Unlock()
		log.WithFields(logger.Fields{
			"at":     "(Router) Stop",
			"phase":  "shutdown",
			"reason": "router not running",
		}).Debug("router already stopped")
		return
	}

	r.running = false
	r.runMux.Unlock()

	// Cancel router context to signal shutdown to all goroutines
	if r.cancel != nil {
		r.cancel()
		log.WithFields(logger.Fields{
			"at":     "(Router) Stop",
			"phase":  "shutdown",
			"step":   2,
			"reason": "context canceled to signal subsystems",
		}).Debug("router context cancelled")
	}

	r.stopTunnelManager()
	r.stopBandwidthTracker()
	r.stopCongestionMonitor()
	r.stopPublisher()
	r.stopI2CPServer()
	r.stopI2PControlServer()
	r.stopParticipantManager()
	r.stopGarlicRouter()
	r.stopNetDB()
	r.sendCloseSignal()

	// Wait for all goroutines to finish before returning
	log.WithFields(logger.Fields{
		"at":     "(Router) Stop",
		"phase":  "shutdown",
		"step":   3,
		"reason": "waiting for goroutines to complete",
	}).Debug("waiting for router goroutines to finish")
	r.wg.Wait()
	log.WithFields(logger.Fields{
		"at":     "(Router) Stop",
		"phase":  "shutdown",
		"step":   4,
		"reason": "all subsystems stopped",
	}).Debug("router stopped successfully")
}

// stopNetDB shuts down the network database if it exists and logs the result.
func (r *Router) stopNetDB() {
	if r.StdNetDB != nil {
		log.WithFields(logger.Fields{
			"at":     "(Router) stopNetDB",
			"phase":  "shutdown",
			"reason": "stopping network database",
		}).Debug("stopping NetDB")
		r.StdNetDB.Stop()
		log.WithFields(logger.Fields{
			"at":     "(Router) stopNetDB",
			"phase":  "shutdown",
			"reason": "network database stopped",
		}).Debug("netDB stopped")
	}
}

// stopGarlicRouter shuts down the garlic router if it exists and logs the result.
// This cancels the background processPendingMessages goroutine to prevent goroutine leaks.
func (r *Router) stopGarlicRouter() {
	r.runMux.Lock()
	gr := r.garlicRouter
	r.runMux.Unlock()

	if gr != nil {
		log.WithFields(logger.Fields{
			"at":     "(Router) stopGarlicRouter",
			"phase":  "shutdown",
			"reason": "stopping garlic router",
		}).Debug("stopping garlic router")
		gr.Stop()
		log.WithFields(logger.Fields{
			"at":     "(Router) stopGarlicRouter",
			"phase":  "shutdown",
			"reason": "garlic router stopped",
		}).Debug("garlic router stopped")
	}
}

// stopBandwidthTracker shuts down the bandwidth tracker if it is running and logs the result.
func (r *Router) stopBandwidthTracker() {
	if r.bandwidthTracker != nil {
		r.bandwidthTracker.Stop()
		log.Debug("Bandwidth tracker stopped")
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
		log.WithFields(logger.Fields{
			"at":     "(Router) stopCongestionMonitor",
			"phase":  "shutdown",
			"reason": "congestion monitor stopped",
		}).Debug("congestion monitor stopped")
	}
}

// stopPublisher shuts down the NetDB publisher if it is running.
// The publisher periodically republishes our RouterInfo and LeaseSets to floodfill routers.
func (r *Router) stopPublisher() {
	if r.publisher != nil {
		r.publisher.Stop()
		r.publisher = nil
		log.WithFields(logger.Fields{
			"at":     "(Router) stopPublisher",
			"phase":  "shutdown",
			"reason": "netdb publisher stopped",
		}).Debug("NetDB publisher stopped")
	}
}

// startPublisher creates and starts the NetDB publisher for periodic RouterInfo and LeaseSet
// publishing to floodfill routers. The publisher requires NetDB, transport, and a tunnel pool.
// If prerequisites are not met, a warning is logged and publishing is skipped.
func (r *Router) startPublisher() {
	tunnelPool, err := r.resolvePublisherDependencies()
	if err != nil {
		log.Warn(err.Error())
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
		log.WithFields(logger.Fields{
			"at":     "(Router) stopTunnelManager",
			"phase":  "shutdown",
			"reason": "tunnel manager stopped",
		}).Debug("tunnel manager stopped")
	}
}

// stopParticipantManager shuts down the participant manager if it exists.
func (r *Router) stopParticipantManager() {
	if r.participantManager != nil {
		r.participantManager.Stop()
		log.Debug("Participant manager stopped")
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
			log.Debug("LeaseSet publisher goroutines drained")
		}
	}
	if r.i2cpServer != nil {
		if err := r.i2cpServer.Stop(); err != nil {
			log.WithError(err).Error("Failed to stop I2CP server")
		} else {
			log.Debug("I2CP server stopped")
		}
	}
}

// sendCloseSignal sends the close signal to the router channel without blocking.
// It uses a non-blocking send to prevent deadlocks if the channel is full or already signaled.
func (r *Router) sendCloseSignal() {
	select {
	case r.closeChnl <- true:
		log.Debug("Router stop signal sent")
	default:
		log.Debug("Router stop signal already sent or channel full")
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
	r.initializeLifecycleContext()
	r.initializeBandwidthTracker()
	r.initializeCongestionMonitoring()
	r.initializeRouterInfoProvider()
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
	log.Debug("Initializing network database")
	r.StdNetDB = netdb.NewStdNetDB(r.cfg.NetDb.Path)
	log.WithField("netdb_path", r.cfg.NetDb.Path).Debug("Created StdNetDB")
	return nil
}

// initializeMessageRouter sets up message routing with NetDB integration
func (r *Router) initializeMessageRouter() {
	messageConfig := i2np.MessageRouterConfig{
		MaxRetries:     3,
		DefaultTimeout: 30 * time.Second,
		EnableLogging:  true,
	}
	r.messageRouter = i2np.NewMessageRouter(messageConfig)
	r.messageRouter.SetNetDB(r.StdNetDB)
	r.messageRouter.SetPeerSelector(r.StdNetDB)

	// Set router as SessionProvider to enable message response routing
	r.messageRouter.SetSessionProvider(r)

	// Initialize tunnel manager for building and managing tunnels
	// Must be done before garlic router so it can access the tunnel pool
	r.initializeTunnelManager()

	// Initialize participant manager for tracking transit tunnels
	r.participantManager = tunnel.NewManager()
	log.Debug("Participant manager initialized for transit tunnel tracking")

	// Initialize garlic message router for handling garlic clove forwarding
	r.initializeGarlicRouter()

	// Wire InboundMessageHandler as the TunnelData handler on the message processor.
	// This enables inbound tunnel messages to be decrypted and delivered to I2CP sessions.
	if r.inboundHandler != nil {
		r.messageRouter.GetProcessor().SetTunnelDataHandler(r.inboundHandler)
		log.Debug("InboundMessageHandler wired as TunnelData handler on message processor")
	}

	log.Debug("Message router initialized with NetDB, peer selection, session provider, tunnel data handler, and garlic forwarding")
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

	// HIGH PRIORITY FIX #3: Connect pool to NetDB peer tracker for reputation tracking
	// This enables peer connection success/failure tracking for improved peer selection
	pool.SetPeerTracker(r.StdNetDB.PeerTracker)
	log.Debug("Tunnel pool configured with NetDB peer tracker for reputation tracking")

	if err := pool.StartMaintenance(); err != nil {
		log.WithError(err).Error("Failed to start tunnel pool maintenance")
	} else {
		log.Debug("Tunnel pool automatic maintenance started")
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

// getOurRouterHash returns our router's identity hash.
// Returns an error if the hash cannot be computed.
func (r *Router) getOurRouterHash() (common.Hash, error) {
	// Try to construct a RouterInfo to get our hash
	ri, err := r.RouterInfoKeystore.ConstructRouterInfo(nil)
	if err != nil {
		return common.Hash{}, fmt.Errorf("failed to construct RouterInfo: %w", err)
	}

	hash, err := ri.IdentHash()
	if err != nil {
		return common.Hash{}, fmt.Errorf("failed to get IdentHash: %w", err)
	}

	return hash, nil
}
