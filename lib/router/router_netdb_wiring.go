package router

import (
	"time"

	"github.com/samber/oops"

	"github.com/go-i2p/logger"

	"github.com/go-i2p/go-i2p/lib/netdb"
	"github.com/go-i2p/go-i2p/lib/tunnel"
)

// logSubsystemStop logs a subsystem shutdown event with standard fields.
// This reduces duplication across the various stopXxx methods.

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
	if r.netdb == nil || r.transports == nil {
		log.WithFields(logger.Fields{"at": "startFloodfillServer"}).Debug("Floodfill server deferred: NetDB or transport muxer not ready")
		return
	}
	adapter := &floodfillTransportAdapter{muxer: r.transports, db: r.netdb}
	cfg := netdb.DefaultFloodfillConfig()
	if r.cfg != nil && r.cfg.NetDB != nil {
		cfg.Enabled = r.cfg.NetDB.FloodfillEnabled
	}
	ourHash, err := r.getOurRouterHash()
	if err == nil {
		cfg.OurHash = ourHash
	}
	r.floodfillServer = netdb.NewFloodfillServer(r.netdb, adapter, cfg)
	log.WithField("enabled", cfg.Enabled).Debug("Floodfill server started")
}

// startExplorer instantiates and starts the NetDB explorer. The explorer
// actively discovers new peers by performing iterative lookups for random keys,
// improving peer diversity over time. It requires a running tunnel pool.
func (r *Router) startExplorer() error {
	if r.netdb == nil || r.tunnelManager == nil {
		return oops.Errorf("NetDB explorer deferred: NetDB or tunnel manager not ready")
	}
	tunnelPool := r.tunnelManager.GetOutboundPool()
	if tunnelPool == nil {
		return oops.Errorf("NetDB explorer deferred: tunnel pool not available")
	}

	cfg := netdb.DefaultExplorerConfig()

	ourHash, err := r.getOurRouterHash()
	if err == nil {
		cfg.OurHash = ourHash
	}

	// Build the production lookup transport so the explorer can issue real
	// network DatabaseLookups. The client sends direct (non-tunnelled) lookups
	// over transport sessions and correlates replies by target key. The SAME
	// instance is registered as the processor's reply deliverer so inbound
	// DatabaseStore / DatabaseSearchReply messages wake the blocked lookups.
	if r.transports != nil && r.messageRouter != nil {
		if r.lookupClient == nil {
			r.lookupClient = netdb.NewDatabaseLookupClient(&publisherTransportAdapter{muxer: r.transports})
		}
		cfg.Transport = r.lookupClient
		r.messageRouter.GetProcessor().SetLookupReplyDeliverer(r.lookupClient)
	} else {
		log.WithFields(logger.Fields{"at": "startExplorer"}).Warn("NetDB explorer starting without transport: transport or message router not ready, lookups will be local-only")
	}

	r.explorer = netdb.NewExplorer(r.netdb, tunnelPool, cfg)

	if r.messageRouter != nil {
		r.explorer.SetOurHash(ourHash)
	}

	if err := r.explorer.Start(); err != nil {
		r.explorer = nil
		return oops.Wrapf(err, "failed to start NetDB explorer")
	}
	log.WithFields(logger.Fields{"at": "startExplorer"}).Debug("NetDB explorer started")
	return nil
}

// startPublisher creates and starts the NetDB publisher for periodic RouterInfo and LeaseSet
// publishing to floodfill routers. The publisher requires NetDB, transport, and a tunnel pool.
// If prerequisites are not met, a warning is logged and publishing is skipped.
func (r *Router) startPublisher() error {
	tunnelPool, err := r.resolvePublisherDependencies()
	if err != nil {
		return err
	}

	return r.launchPublisher(tunnelPool)
}

// resolvePublisherDependencies verifies that NetDB, TransportMuxer, and a
// tunnel pool are available. Returns the tunnel pool or an error describing
// the missing prerequisite.
func (r *Router) resolvePublisherDependencies() (*tunnel.Pool, error) {
	if r.netdb == nil {
		return nil, oops.Errorf("Cannot start publisher: NetDB not initialized")
	}
	if r.transports == nil {
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
func (r *Router) launchPublisher(tunnelPool *tunnel.Pool) error {
	dbAdapter := &publisherNetDBAdapter{db: r.netdb}
	transportAdapter := &publisherTransportAdapter{muxer: r.transports}

	var riProvider netdb.RouterInfoProvider
	if r.routerInfoProv != nil {
		riProvider = r.routerInfoProv
	}

	publisherConfig := netdb.DefaultPublisherConfig()
	r.publisher = netdb.NewPublisher(dbAdapter, tunnelPool, transportAdapter, riProvider, publisherConfig)
	if r.lookupClient != nil {
		r.publisher.SetLookupTransport(r.lookupClient)
	}
	if r.messageRouter != nil {
		r.messageRouter.GetProcessor().SetDeliveryStatusHandler(r.publisher)
	}
	if r.tunnelManager != nil {
		r.publisher.SetInboundPool(r.tunnelManager.GetInboundPool())
	}

	if err := r.publisher.Start(); err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"at":     "(Router) startPublisher",
			"phase":  "startup",
			"reason": "publisher start failed",
		}).Warn("Failed to start NetDB publisher, RouterInfo will not be republished")
		r.publisher = nil
		return oops.Wrapf(err, "failed to start NetDB publisher")
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

	// C1 FIX: Wire the publisher to the I2CP server if it's running.
	// This allows I2CP sessions to publish their LeaseSets after router startup.
	if r.i2cpServer != nil {
		r.i2cpServer.SetLeaseSetPublisher(r.publisher)
	}

	return nil
}

// startNetDBServiceWatchdog keeps critical NetDB services alive after startup.
// It retries startup for publisher/explorer when they are not running and retries
// deferred I2CP router-hash wiring if the first attempt failed during early startup.
func (r *Router) startNetDBServiceWatchdog() {
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-r.ctx.Done():
				return
			case <-ticker.C:
				r.retryI2CPRouterHashWiring()
				r.ensurePublisherRunning()
				r.ensureExplorerRunning()
			}
		}
	}()
}

func (r *Router) ensurePublisherRunning() {
	if r.publisher != nil {
		return
	}
	if err := r.startPublisher(); err != nil {
		log.WithError(err).WithField("at", "startNetDBServiceWatchdog").Warn("publisher recovery attempt failed")
		return
	}
	log.WithField("at", "startNetDBServiceWatchdog").Info("publisher recovered")
}

func (r *Router) ensureExplorerRunning() {
	if r.explorer != nil {
		return
	}
	if err := r.startExplorer(); err != nil {
		log.WithError(err).WithField("at", "startNetDBServiceWatchdog").Warn("explorer recovery attempt failed")
		return
	}
	log.WithField("at", "startNetDBServiceWatchdog").Info("explorer recovered")
}

// initializeNetDB creates and configures the network database.
// Idempotent: if r.netdb has already been initialized (for example from
// CreateRouter, where it is created early so that transports can wire their
// PeerConnNotifier into r.netdb.PeerTracker), this call is a no-op. This
// matters because r.netdb MUST exist before initializeTransports runs;
// otherwise NTCP2/SSU2 transports silently skip SetPeerConnNotifier and
// successful connections are never recorded in PeerTracker, causing every
// known-good peer to be marked stale on its first tunnel-build failure.
func (r *Router) initializeNetDB() error {
	if r.netdb != nil {
		log.WithFields(logger.Fields{"at": "initializeNetDB"}).Debug("NetDB already initialized; skipping")
		return nil
	}
	log.WithFields(logger.Fields{"at": "initializeNetDB"}).Debug("Initializing network database")
	r.netdb = netdb.NewStdNetDB(r.cfg.NetDB.Path)
	r.netdb.SetMaxRouterInfos(r.cfg.NetDB.MaxRouterInfos)
	log.WithField("netdb_path", r.cfg.NetDB.Path).Debug("Created StdNetDB")
	return nil
}
