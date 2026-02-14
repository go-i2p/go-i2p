package router

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/go-i2p/common/base32"
	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/bootstrap"
	"github.com/go-i2p/go-i2p/lib/i2cp"
	"github.com/go-i2p/go-i2p/lib/i2np"
	ntcp "github.com/go-i2p/go-i2p/lib/transport/ntcp2"
	ntcp2 "github.com/go-i2p/go-noise/ntcp2"

	"github.com/go-i2p/logger"

	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/go-i2p/go-i2p/lib/keys"
	"github.com/go-i2p/go-i2p/lib/netdb"
	"github.com/go-i2p/go-i2p/lib/transport"
	"github.com/go-i2p/go-i2p/lib/tunnel"
)

// i2p router type
type Router struct {
	// keystore for router info
	*keys.RouterInfoKeystore
	// multi-transport manager
	*transport.TransportMuxer
	// netdb
	*netdb.StdNetDB
	// message router for processing I2NP messages
	messageRouter *i2np.MessageRouter
	// garlic message router for handling non-LOCAL garlic clove forwarding
	garlicRouter *GarlicMessageRouter
	// router configuration
	cfg *config.RouterConfig
	// close channel
	closeChnl chan bool
	// wg tracks goroutine completion for clean shutdown
	wg sync.WaitGroup
	// running flag and mutex for thread-safe access
	running bool
	runMux  sync.RWMutex

	// ctx is the router's lifecycle context, cancelled when Stop() is called
	ctx context.Context
	// cancel cancels the router's context, triggering graceful shutdown
	cancel context.CancelFunc

	// Session tracking for NTCP2 message routing
	activeSessions map[common.Hash]*ntcp.NTCP2Session
	// sessionMutex protects concurrent access to activeSessions map
	sessionMutex sync.RWMutex

	// I2CP server for client applications
	i2cpServer *i2cp.Server

	// tunnelManager manages tunnel building and pool maintenance
	tunnelManager *i2np.TunnelManager

	// participantManager tracks tunnels where this router acts as a transit hop
	participantManager *tunnel.Manager

	// i2pcontrolServer provides RPC monitoring interface
	i2pcontrolServer interface {
		Start() error
		Stop()
	}

	// bandwidthTracker tracks bandwidth usage and calculates rolling averages
	bandwidthTracker *BandwidthTracker

	// closeOnce ensures finalizeCloseChannel is safe to call concurrently
	closeOnce sync.Once

	// congestionMonitor tracks local congestion state and determines D/E/G flags
	// for RouterInfo advertisement per PROP_162
	congestionMonitor *CongestionMonitor

	// inboundHandler processes inbound tunnel messages and delivers to I2CP sessions
	inboundHandler *InboundMessageHandler

	// routerInfoProv provides the local RouterInfo to the NetDB publisher
	routerInfoProv *routerInfoProvider

	// publisher publishes our RouterInfo and LeaseSets to floodfill routers
	publisher *netdb.Publisher

	// leaseSetPublisher handles LeaseSet publication to local NetDB and network
	leaseSetPublisher *LeaseSetPublisher

	// isReseeding tracks whether the router is currently performing a reseed operation
	isReseeding bool
	// reseedMutex protects concurrent access to isReseeding flag
	reseedMutex sync.RWMutex

	// keystoreMux protects concurrent access to RouterInfoKeystore
	keystoreMux sync.RWMutex

	// startupErr receives any error from the mainloop goroutine during
	// startup-critical initialization (NetDB, I2CP, I2PControl).  Start()
	// blocks on this channel so callers get a synchronous error report.
	startupErr chan error
}

// CreateRouter creates a router with the provided configuration
func CreateRouter(cfg *config.RouterConfig) (*Router, error) {
	log.WithFields(logger.Fields{
		"at":          "(Router) CreateRouter",
		"phase":       "startup",
		"step":        1,
		"reason":      "creating router instance",
		"base_dir":    cfg.BaseDir,
		"working_dir": cfg.WorkingDir,
	}).Debug("creating router with provided configuration")

	r, err := FromConfig(cfg)
	if err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"at":     "(Router) CreateRouter",
			"phase":  "startup",
			"reason": "router configuration failed",
		}).Error("failed to create router from configuration")
		return nil, err
	}
	log.WithFields(logger.Fields{
		"at":     "(Router) CreateRouter",
		"phase":  "startup",
		"step":   2,
		"reason": "router instance created successfully",
	}).Debug("router created successfully")

	if err := initializeRouterKeystore(r, cfg); err != nil {
		return nil, err
	}

	if err := validateRouterKeys(r); err != nil {
		return nil, err
	}

	ri, err := constructRouterInfo(r)
	if err != nil {
		return nil, err
	}

	if err := setupNTCP2Transport(r, ri); err != nil {
		return nil, err
	}

	return r, nil
}

// initializeRouterKeystore creates and stores the router keystore
func initializeRouterKeystore(r *Router, cfg *config.RouterConfig) error {
	log.WithFields(logger.Fields{
		"at":          "(Router) initializeRouterKeystore",
		"phase":       "startup",
		"step":        3,
		"reason":      "initializing router keystore",
		"working_dir": cfg.WorkingDir,
	}).Debug("working directory is:", cfg.WorkingDir)

	keystore, err := keys.NewRouterInfoKeystore(cfg.WorkingDir, "localRouter")
	if err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"at":          "(Router) initializeRouterKeystore",
			"phase":       "startup",
			"reason":      "keystore creation failed",
			"working_dir": cfg.WorkingDir,
		}).Error("failed to create RouterInfoKeystore")
		return err
	}
	log.WithFields(logger.Fields{
		"at":     "(Router) initializeRouterKeystore",
		"phase":  "startup",
		"step":   3,
		"reason": "keystore created successfully",
	}).Debug("routerInfoKeystore created successfully")

	if err = keystore.StoreKeys(); err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"at":     "(Router) initializeRouterKeystore",
			"phase":  "startup",
			"reason": "keystore persistence failed",
		}).Error("failed to store RouterInfoKeystore")
		return err
	}
	log.Debug("RouterInfoKeystore stored successfully")

	r.RouterInfoKeystore = keystore
	return nil
}

// validateRouterKeys extracts and validates the router's public key
func validateRouterKeys(r *Router) error {
	pub, _, err := r.RouterInfoKeystore.GetKeys()
	if err != nil {
		log.WithError(err).Error("Failed to get keys from RouterInfoKeystore")
		return err
	}

	// sha256 hash of public key
	pubHash := sha256.Sum256(pub.Bytes())
	b32PubHash := base32.EncodeToString(pubHash[:])
	log.Debug("Router public key hash:", b32PubHash)

	return nil
}

// constructRouterInfo builds the router info from the keystore
func constructRouterInfo(r *Router) (*router_info.RouterInfo, error) {
	ri, err := r.RouterInfoKeystore.ConstructRouterInfo(nil)
	if err != nil {
		log.WithError(err).Error("Failed to construct RouterInfo")
		return nil, err
	}

	log.Debug("RouterInfo constructed successfully")
	log.Debug("RouterInfo:", ri)
	return ri, nil
}

// setupNTCP2Transport configures and initializes the NTCP2 transport layer
func setupNTCP2Transport(r *Router, ri *router_info.RouterInfo) error {
	// add NTCP2 transport
	ntcp2Config, err := ntcp.NewConfig(":0") // Use port 0 for automatic assignment
	if err != nil {
		log.WithError(err).Error("Failed to create NTCP2 config")
		return err
	}

	// Set working directory for persistent key storage
	ntcp2Config.WorkingDir = r.cfg.WorkingDir

	ntcp2Transport, err := ntcp.NewNTCP2Transport(*ri, ntcp2Config, r.RouterInfoKeystore)
	if err != nil {
		log.WithError(err).Error("Failed to create NTCP2 transport")
		return err
	}
	log.Debug("NTCP2 transport created successfully")

	r.TransportMuxer = transport.Mux(ntcp2Transport)
	ntcpaddr := ntcp2Transport.Addr()
	if ntcpaddr == nil {
		log.Error("Failed to get NTCP2 address")
		return errors.New("failed to get NTCP2 address")
	}
	log.Debug("NTCP2 address:", ntcpaddr)

	// Convert NTCP2 transport address to RouterAddress and add to RouterInfo
	routerAddress, err := ntcp.ConvertToRouterAddress(ntcp2Transport)
	if err != nil {
		log.WithError(err).Error("Failed to convert NTCP2 address to RouterAddress")
		return fmt.Errorf("failed to convert NTCP2 address: %w", err)
	}
	ri.AddAddress(routerAddress)
	log.WithFields(logger.Fields{
		"host": ntcpaddr.String(),
		"cost": routerAddress.Cost(),
	}).Info("NTCP2 address added to RouterInfo")

	return nil
}

// getTotalBandwidth returns the total bytes sent and received from all transports.
// This method is used by the bandwidth tracker to sample bandwidth usage.
func (r *Router) getTotalBandwidth() (sent, received uint64) {
	// Capture TransportMuxer locally to avoid TOCTOU race:
	// the field could be set to nil by concurrent shutdown between
	// the nil check and the method call.
	muxer := r.TransportMuxer
	if muxer == nil {
		return 0, 0
	}

	// Get all transports from the muxer
	for _, t := range muxer.GetTransports() {
		// Check if this is an NTCP2 transport
		if ntcp2Transport, ok := t.(*ntcp.NTCP2Transport); ok {
			s, rcv := ntcp2Transport.GetTotalBandwidth()
			sent += s
			received += rcv
		}
	}
	return sent, received
}

// GetBandwidthRates returns the current 15-second inbound and outbound bandwidth rates.
// Returns rates in bytes per second.
func (r *Router) GetBandwidthRates() (inbound, outbound uint64) {
	if r.bandwidthTracker == nil {
		return 0, 0
	}
	return r.bandwidthTracker.GetRates()
}

// GetTransportAddr returns the listening address of the first available transport.
// This is used by I2PControl to expose NTCP2 port and address information.
// Returns nil if no transports are available.
func (r *Router) GetTransportAddr() interface{} {
	// Capture locally to avoid TOCTOU race with concurrent shutdown.
	muxer := r.TransportMuxer
	if muxer == nil {
		return nil
	}

	transports := muxer.GetTransports()
	if len(transports) == 0 {
		return nil
	}

	// Return the address of the first transport (typically NTCP2)
	return transports[0].Addr()
}

// FromConfig creates a minimal Router stub from config. This is a low-level
// internal function used by CreateRouter. It only initializes cfg and closeChnl.
//
// WARNING: Do not use FromConfig directly unless you intend to manually
// initialize the keystore, transport, and other subsystems afterward.
// Use CreateRouter instead, which fully initializes the router.
// Calling Start() on a router created solely via FromConfig will return
// an error because required subsystems (keystore, transport) are nil.
func FromConfig(c *config.RouterConfig) (r *Router, err error) {
	if c == nil {
		return nil, fmt.Errorf("router config cannot be nil")
	}
	log.WithFields(logger.Fields{
		"at":          "(Router) FromConfig",
		"phase":       "startup",
		"step":        1,
		"reason":      "constructing router from config",
		"base_dir":    c.BaseDir,
		"working_dir": c.WorkingDir,
	}).Debug("creating router from configuration")
	r = new(Router)
	r.cfg = c
	r.closeChnl = make(chan bool)
	log.WithFields(logger.Fields{
		"at":     "(Router) FromConfig",
		"phase":  "startup",
		"reason": "router struct initialized",
	}).Debug("router created successfully from configuration")
	return r, err
}

// Wait blocks until router is fully stopped
func (r *Router) Wait() {
	log.WithFields(logger.Fields{
		"at":     "(Router) Wait",
		"phase":  "running",
		"reason": "waiting for router shutdown",
	}).Debug("waiting for router to stop")
	r.wg.Wait()
	log.WithFields(logger.Fields{
		"at":     "(Router) Wait",
		"phase":  "shutdown",
		"reason": "all router goroutines completed",
	}).Debug("router has stopped")
}

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

// GetTunnelManager returns the tunnel manager in a thread-safe manner.
// Returns nil if the tunnel manager has not been initialized yet.
func (r *Router) GetTunnelManager() *i2np.TunnelManager {
	r.runMux.RLock()
	defer r.runMux.RUnlock()
	return r.tunnelManager
}

// GetParticipantManager returns the participant manager for transit tunnel tracking.
// Returns nil if not initialized.
func (r *Router) GetParticipantManager() *tunnel.Manager {
	r.runMux.RLock()
	defer r.runMux.RUnlock()
	return r.participantManager
}

// GetGarlicRouter returns the garlic router in a thread-safe manner.
// Returns nil if the garlic router has not been initialized yet.
func (r *Router) GetGarlicRouter() *GarlicMessageRouter {
	r.runMux.RLock()
	defer r.runMux.RUnlock()
	return r.garlicRouter
}

// GetCongestionMonitor returns the congestion monitor for PROP_162 congestion cap tracking.
// Returns nil if the congestion monitor has not been initialized yet.
func (r *Router) GetCongestionMonitor() CongestionStateProvider {
	r.runMux.RLock()
	defer r.runMux.RUnlock()
	return r.congestionMonitor
}

// ensureNetDBReady validates NetDB state and performs reseed if needed.
// Returns an error if the router's StdNetDB is nil (e.g. during shutdown).
func (r *Router) ensureNetDBReady() error {
	if r.StdNetDB == nil {
		return fmt.Errorf("StdNetDB is nil (router may be shutting down)")
	}
	if err := r.StdNetDB.Ensure(); err != nil {
		log.WithError(err).Error("Failed to ensure NetDB")
		return err
	}

	if sz := r.StdNetDB.Size(); sz >= 0 {
		log.WithField("size", sz).Debug("NetDB Size: " + strconv.Itoa(sz))
	} else {
		log.Warn("Unable to determine NetDB size")
	}

	if r.StdNetDB.Size() < r.cfg.Bootstrap.LowPeerThreshold {
		return r.performReseed()
	}
	return nil
}

// performReseed executes network database reseeding process.
// It selects the appropriate bootstrapper based on configuration and executes the reseed operation.
func (r *Router) performReseed() error {
	r.setReseedingFlag(true)
	defer r.setReseedingFlag(false)

	r.logReseedStart()

	bootstrapper, err := r.createBootstrapper()
	if err != nil {
		return err
	}

	return r.executeReseed(bootstrapper)
}

// setReseedingFlag safely sets the isReseeding flag with proper mutex protection.
func (r *Router) setReseedingFlag(value bool) {
	r.reseedMutex.Lock()
	r.isReseeding = value
	r.reseedMutex.Unlock()
}

// logReseedStart logs the beginning of the reseed operation with relevant metrics.
func (r *Router) logReseedStart() {
	log.WithFields(logger.Fields{
		"at":             "(Router) performReseed",
		"phase":          "bootstrap",
		"reason":         "netdb below threshold, initiating bootstrap",
		"current_size":   r.StdNetDB.Size(),
		"threshold":      r.cfg.Bootstrap.LowPeerThreshold,
		"shortfall":      r.cfg.Bootstrap.LowPeerThreshold - r.StdNetDB.Size(),
		"bootstrap_type": r.cfg.Bootstrap.BootstrapType,
	}).Warn("netDb below threshold, initiating bootstrap")
}

// createBootstrapper creates the appropriate bootstrapper based on user configuration.
// Returns the bootstrapper instance and any configuration error encountered.
func (r *Router) createBootstrapper() (bootstrap.Bootstrap, error) {
	switch r.cfg.Bootstrap.BootstrapType {
	case "file":
		return r.createFileBootstrapper()
	case "reseed":
		return r.createReseedBootstrapper(), nil
	case "local":
		return r.createLocalBootstrapper(), nil
	case "auto", "":
		return r.createCompositeBootstrapper(), nil
	default:
		return r.createFallbackBootstrapper(), nil
	}
}

// createFileBootstrapper creates a file-based bootstrapper from a local reseed file.
// Returns an error if the reseed file path is not configured.
func (r *Router) createFileBootstrapper() (bootstrap.Bootstrap, error) {
	if r.cfg.Bootstrap.ReseedFilePath == "" {
		log.WithFields(logger.Fields{
			"at":             "(Router) createFileBootstrapper",
			"phase":          "bootstrap",
			"reason":         "bootstrap_type is file but path not configured",
			"bootstrap_type": "file",
		}).Error("bootstrap configuration error")
		return nil, fmt.Errorf("bootstrap_type is 'file' but no reseed_file_path is configured")
	}
	log.WithFields(logger.Fields{
		"at":        "(Router) createFileBootstrapper",
		"phase":     "bootstrap",
		"reason":    "using file bootstrap as configured",
		"file_path": r.cfg.Bootstrap.ReseedFilePath,
		"strategy":  "file_only",
	}).Info("using file bootstrap only (as specified by bootstrap_type)")
	return bootstrap.NewFileBootstrap(r.cfg.Bootstrap.ReseedFilePath), nil
}

// createReseedBootstrapper creates a bootstrapper that fetches peers from reseed servers.
func (r *Router) createReseedBootstrapper() bootstrap.Bootstrap {
	log.Info("Using reseed bootstrap only (as specified by bootstrap_type)")
	return bootstrap.NewReseedBootstrap(r.cfg.Bootstrap)
}

// createLocalBootstrapper creates a bootstrapper that reads from local netDb directories.
func (r *Router) createLocalBootstrapper() bootstrap.Bootstrap {
	log.Info("Using local netDb bootstrap only (as specified by bootstrap_type)")
	return bootstrap.NewLocalNetDbBootstrap(r.cfg.Bootstrap)
}

// createCompositeBootstrapper creates a bootstrapper that tries all methods sequentially.
func (r *Router) createCompositeBootstrapper() bootstrap.Bootstrap {
	log.WithFields(logger.Fields{
		"at":             "(Router) createCompositeBootstrapper",
		"phase":          "bootstrap",
		"reason":         "using composite bootstrap strategy",
		"bootstrap_type": r.cfg.Bootstrap.BootstrapType,
		"strategy":       "file -> reseed -> local_netdb",
		"reseed_servers": len(r.cfg.Bootstrap.ReseedServers),
	}).Info("using composite bootstrap (tries all methods)")
	return bootstrap.NewCompositeBootstrap(r.cfg.Bootstrap)
}

// createFallbackBootstrapper creates a composite bootstrapper as fallback for unknown types.
func (r *Router) createFallbackBootstrapper() bootstrap.Bootstrap {
	log.WithFields(logger.Fields{
		"at":             "(Router) createFallbackBootstrapper",
		"phase":          "bootstrap",
		"reason":         "unknown bootstrap_type, using fallback",
		"bootstrap_type": r.cfg.Bootstrap.BootstrapType,
		"fallback":       "composite",
		"valid_types":    "file, reseed, local, auto",
	}).Warn("unknown bootstrap_type, falling back to composite bootstrap")
	return bootstrap.NewCompositeBootstrap(r.cfg.Bootstrap)
}

// executeReseed performs the actual reseed operation using the provided bootstrapper.
// It logs success or failure and returns any error encountered.
func (r *Router) executeReseed(bootstrapper bootstrap.Bootstrap) error {
	if err := r.StdNetDB.Reseed(bootstrapper, r.cfg.Bootstrap.LowPeerThreshold); err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"at":           "(Router) executeReseed",
			"phase":        "bootstrap",
			"reason":       "bootstrap failed but continuing",
			"current_size": r.StdNetDB.Size(),
			"target":       r.cfg.Bootstrap.LowPeerThreshold,
			"impact":       "router will operate with limited peer connectivity",
		}).Warn("bootstrap failed, continuing with limited NetDB")
		return err
	}
	log.WithFields(logger.Fields{
		"at":           "(Router) executeReseed",
		"phase":        "bootstrap",
		"reason":       "bootstrap completed successfully",
		"netdb_size":   r.StdNetDB.Size(),
		"threshold":    r.cfg.Bootstrap.LowPeerThreshold,
		"peers_gained": r.StdNetDB.Size() - (r.cfg.Bootstrap.LowPeerThreshold - 1),
	}).Info("bootstrap completed successfully")
	return nil
}

// runMainLoop executes the primary router event loop
func (r *Router) runMainLoop() {
	log.WithFields(logger.Fields{
		"at": "(Router) mainloop",
	}).Debug("Router ready with database message processing enabled")

	// Block until shutdown signal — no need for a 1-second ticker poll.
	// Both closeChnl and ctx.Done() are signaled during Stop().
	select {
	case <-r.closeChnl:
		log.Debug("Router received close signal in mainloop")
	case <-r.ctx.Done():
		log.Debug("Router context cancelled in mainloop")
	}
}

// run i2p router mainloop
func (r *Router) mainloop() {
	// Initialize active sessions map for tracking NTCP2 connections
	r.activeSessions = make(map[common.Hash]*ntcp.NTCP2Session)
	log.Debug("Initialized active sessions map")

	if err := r.initializeCoreComponents(); err != nil {
		r.startupErr <- err
		r.Stop()
		return
	}

	r.wireInboundHandler()
	r.initializeMessageRouter()
	r.startPublisher()

	// Signal Start() that all startup-critical initialization succeeded
	r.startupErr <- nil

	// Start session monitors for inbound message processing
	r.startSessionMonitors()

	r.runMainLoop()
	log.Debug("Exiting router mainloop")
}

// initializeCoreComponents initializes NetDB, I2CP, and I2PControl servers in order.
// Returns an error if any critical component fails to start.
func (r *Router) initializeCoreComponents() error {
	if err := r.initializeNetDB(); err != nil {
		log.WithError(err).Error("Failed to initialize NetDB")
		return fmt.Errorf("NetDB initialization failed: %w", err)
	}

	if err := r.ensureNetDBReady(); err != nil {
		log.WithFields(logger.Fields{
			"at":     "(Router) mainloop",
			"reason": err.Error(),
		}).Error("NetDB startup failed")
		return fmt.Errorf("NetDB readiness check failed: %w", err)
	}

	if r.cfg.I2CP != nil && r.cfg.I2CP.Enabled {
		if err := r.startI2CPServer(); err != nil {
			return fmt.Errorf("I2CP server startup failed: %w", err)
		}
	}

	if err := r.startI2PControlServer(); err != nil {
		return fmt.Errorf("I2PControl server startup failed: %w", err)
	}

	return nil
}

// wireInboundHandler sets up the InboundMessageHandler for tunnel-to-I2CP delivery
// if an I2CP server is running.
func (r *Router) wireInboundHandler() {
	if r.i2cpServer != nil {
		r.inboundHandler = NewInboundMessageHandler(r.i2cpServer.GetSessionManager())
		log.WithFields(logger.Fields{
			"at":     "(Router) mainloop",
			"reason": "InboundMessageHandler wired to I2CP session manager",
		}).Debug("inbound message handler initialized")
	}
}

// Session Monitoring and Message Processing

// startSessionMonitors launches goroutines to monitor and process inbound sessions.
// This is the entry point for the session monitoring subsystem.
func (r *Router) startSessionMonitors() {
	log.Debug("Starting session monitors")
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		r.monitorInboundSessions()
	}()
}

// monitorInboundSessions continuously accepts new inbound NTCP2 connections
// and spawns a message processor goroutine for each new session.
// This loop runs until the router is stopped.
func (r *Router) monitorInboundSessions() {
	log.Debug("Starting inbound session monitor")

	for r.shouldContinueMonitoring() {
		if conn := r.acceptInboundConnection(); conn != nil {
			r.handleNewConnection(conn)
		}
	}

	log.Debug("Stopping inbound session monitor")
}

// shouldContinueMonitoring checks if the router is still running.
func (r *Router) shouldContinueMonitoring() bool {
	r.runMux.RLock()
	defer r.runMux.RUnlock()
	return r.running
}

// acceptInboundConnection attempts to accept a new connection with timeout.
// Returns nil if timeout occurs, connection fails, or TransportMuxer is nil (during shutdown).
func (r *Router) acceptInboundConnection() net.Conn {
	muxer := r.TransportMuxer
	if muxer == nil {
		return nil
	}
	conn, err := muxer.AcceptWithTimeout(5 * time.Second)
	if err != nil {
		if !errors.Is(err, context.DeadlineExceeded) {
			log.WithError(err).Warn("Failed to accept inbound connection")
		}
		return nil
	}
	return conn
}

// handleNewConnection processes a new inbound connection by creating and starting a session.
func (r *Router) handleNewConnection(conn net.Conn) {
	session, peerHash, err := r.createSessionFromConn(conn)
	if err != nil {
		log.WithError(err).Error("Failed to create session from connection")
		conn.Close()
		return
	}

	r.addSession(peerHash, session)
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		r.processSessionMessages(session, peerHash)
	}()

	log.WithField("peer_hash", fmt.Sprintf("%x", peerHash[:8])).Info("Started monitoring new inbound session")
}

// createSessionFromConn creates an NTCP2Session from a net.Conn.
// This method extracts the peer's router hash from the connection address
// and configures a cleanup callback for session lifecycle management.
// Returns the session, peer hash, and any error encountered.
func (r *Router) createSessionFromConn(conn net.Conn) (*ntcp.NTCP2Session, common.Hash, error) {
	// Type assert to NTCP2Addr to extract peer router hash
	ntcpAddr, ok := conn.RemoteAddr().(*ntcp2.NTCP2Addr)
	if !ok {
		return nil, common.Hash{}, fmt.Errorf("invalid connection type: expected NTCP2Addr, got %T", conn.RemoteAddr())
	}

	// Extract router hash from NTCP2 address
	peerHashBytes := ntcpAddr.RouterHash()
	if len(peerHashBytes) != 32 {
		return nil, common.Hash{}, fmt.Errorf("invalid router hash length: expected 32, got %d", len(peerHashBytes))
	}

	var peerHash common.Hash
	copy(peerHash[:], peerHashBytes)

	// Create session with router's lifecycle context
	// When the router stops, this context is cancelled, closing all sessions
	sessionLogger := logger.WithField("peer_hash", fmt.Sprintf("%x", peerHash[:8]))
	session := ntcp.NewNTCP2Session(conn, r.ctx, sessionLogger)

	// Configure cleanup callback to remove session when it closes
	session.SetCleanupCallback(func() {
		r.removeSession(peerHash)
	})

	return session, peerHash, nil
}

// processSessionMessages reads and processes I2NP messages from a single session.
// This method runs in a dedicated goroutine for each active session,
// continuously reading messages until the session closes or the router stops.
// Message processing errors are logged but don't terminate the session.
func (r *Router) processSessionMessages(session *ntcp.NTCP2Session, peerHash common.Hash) {
	defer log.WithField("peer_hash", fmt.Sprintf("%x", peerHash[:8])).Debug("Session message processor stopped")

	for r.shouldContinueMonitoring() {
		if msg := r.readNextMessage(session, peerHash); msg != nil {
			r.handleIncomingMessage(msg, peerHash)
		} else {
			return
		}
	}
}

// readNextMessage reads the next I2NP message from the session.
// Returns nil if an error occurs or the session is closed.
func (r *Router) readNextMessage(session *ntcp.NTCP2Session, peerHash common.Hash) i2np.I2NPMessage {
	msg, err := session.ReadNextI2NP()
	if err != nil {
		r.logReadError(err, peerHash)
		return nil
	}
	return msg
}

// logReadError logs the appropriate error message based on error type.
func (r *Router) logReadError(err error, peerHash common.Hash) {
	peerHashStr := fmt.Sprintf("%x", peerHash[:8])

	if errors.Is(err, ntcp.ErrSessionClosed) {
		log.WithField("peer_hash", peerHashStr).Debug("Session closed normally")
	} else {
		log.WithError(err).WithField("peer_hash", peerHashStr).Warn("Error reading I2NP message from session")
	}
}

// handleIncomingMessage routes the message and logs any routing errors.
func (r *Router) handleIncomingMessage(msg i2np.I2NPMessage, peerHash common.Hash) {
	if err := r.routeMessage(msg, peerHash); err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"message_type": msg.Type(),
			"message_id":   msg.MessageID(),
			"peer_hash":    fmt.Sprintf("%x", peerHash[:8]),
		}).Error("Failed to route I2NP message")
	}
}

// routeMessage routes an I2NP message to the appropriate handler based on its type.
// This method serves as the main dispatch point for all incoming I2NP messages,
// directing them to the correct processing subsystem (database, tunnel, or general).
// Returns an error if the message type is unsupported or routing fails.
func (r *Router) routeMessage(msg i2np.I2NPMessage, fromPeer common.Hash) error {
	log.WithFields(logger.Fields{
		"message_type": msg.Type(),
		"message_id":   msg.MessageID(),
		"from_peer":    fmt.Sprintf("%x", fromPeer[:8]),
	}).Debug("Routing I2NP message")

	// Grab a local reference under lock to prevent race with clearRoutingComponents()
	r.runMux.RLock()
	mr := r.messageRouter
	r.runMux.RUnlock()

	if mr == nil {
		return fmt.Errorf("message router not available (router may be shutting down)")
	}

	// Route based on message type to appropriate handler
	switch msg.Type() {
	case i2np.I2NP_MESSAGE_TYPE_DATABASE_STORE:
		// Parse DatabaseStore message from BaseI2NPMessage data
		dbStore, err := r.parseDatabaseStoreMessage(msg)
		if err != nil {
			return fmt.Errorf("failed to parse DatabaseStore message: %w", err)
		}
		return mr.RouteDatabaseMessage(dbStore)

	case i2np.I2NP_MESSAGE_TYPE_DATABASE_LOOKUP:
		return mr.RouteDatabaseMessage(msg)

	case i2np.I2NP_MESSAGE_TYPE_DATABASE_SEARCH_REPLY:
		return mr.RouteDatabaseMessage(msg)

	case i2np.I2NP_MESSAGE_TYPE_DATA:
		return mr.RouteMessage(msg)

	case i2np.I2NP_MESSAGE_TYPE_DELIVERY_STATUS:
		return mr.RouteMessage(msg)

	case i2np.I2NP_MESSAGE_TYPE_GARLIC:
		// Route garlic messages to the MessageProcessor for decryption and clove processing.
		// The processor handles ECIES-X25519-AEAD-Ratchet decryption and clove routing.
		return mr.RouteMessage(msg)

	case i2np.I2NP_MESSAGE_TYPE_TUNNEL_DATA:
		return mr.RouteMessage(msg)

	case i2np.I2NP_MESSAGE_TYPE_TUNNEL_GATEWAY:
		// Route TunnelGateway messages to the MessageProcessor for tunnel injection.
		// The processor delegates to the configured tunnelGatewayHandler for
		// layered encryption and forwarding to the next hop.
		return mr.RouteMessage(msg)

	case i2np.I2NP_MESSAGE_TYPE_TUNNEL_BUILD:
		return mr.RouteTunnelMessage(msg)

	case i2np.I2NP_MESSAGE_TYPE_TUNNEL_BUILD_REPLY:
		return mr.RouteTunnelMessage(msg)

	case i2np.I2NP_MESSAGE_TYPE_VARIABLE_TUNNEL_BUILD:
		return mr.RouteTunnelMessage(msg)

	case i2np.I2NP_MESSAGE_TYPE_VARIABLE_TUNNEL_BUILD_REPLY:
		return mr.RouteTunnelMessage(msg)

	default:
		return fmt.Errorf("unsupported message type: %d", msg.Type())
	}
}

// parseDatabaseStoreMessage extracts and parses DatabaseStore data from a BaseI2NPMessage.
// This converts the raw I2NP message into a structured DatabaseStore that implements
// the DatabaseWriter interface for NetDB storage.
func (r *Router) parseDatabaseStoreMessage(msg i2np.I2NPMessage) (*i2np.DatabaseStore, error) {
	// Extract payload from BaseI2NPMessage
	payload, ok := msg.(i2np.PayloadCarrier)
	if !ok {
		return nil, fmt.Errorf("message does not implement PayloadCarrier interface")
	}

	// Create DatabaseStore and unmarshal the payload
	dbStore := &i2np.DatabaseStore{}
	if err := dbStore.UnmarshalBinary(payload.GetPayload()); err != nil {
		return nil, fmt.Errorf("failed to unmarshal DatabaseStore: %w", err)
	}

	log.WithFields(logger.Fields{
		"message_id": msg.MessageID(),
		"store_type": dbStore.GetStoreType(),
		"key":        dbStore.GetStoreKey().String(),
	}).Info("Parsed DatabaseStore message from peer")

	return dbStore, nil
}

// Session Management Methods

// addSession registers a new active session by peer hash.
// This method is called when a new NTCP2 connection is established,
// allowing the router to track active sessions for message routing.
// Thread-safe for concurrent access. No-ops if the session map is nil (after shutdown).
func (r *Router) addSession(peerHash common.Hash, session *ntcp.NTCP2Session) {
	r.sessionMutex.Lock()
	defer r.sessionMutex.Unlock()

	if r.activeSessions == nil {
		log.WithField("peer_hash", fmt.Sprintf("%x", peerHash[:8])).Warn("Cannot add session: router is shutting down")
		return
	}

	r.activeSessions[peerHash] = session
	log.WithField("peer_hash", fmt.Sprintf("%x", peerHash[:8])).Debug("Added active session")
}

// startI2CPServer initializes and starts the I2CP server
func (r *Router) startI2CPServer() error {
	r.leaseSetPublisher = NewLeaseSetPublisher(r)
	serverConfig := &i2cp.ServerConfig{
		ListenAddr:        r.cfg.I2CP.Address,
		Network:           r.cfg.I2CP.Network,
		MaxSessions:       r.cfg.I2CP.MaxSessions,
		LeaseSetPublisher: r.leaseSetPublisher,
	}

	server, err := i2cp.NewServer(serverConfig)
	if err != nil {
		return fmt.Errorf("failed to create I2CP server: %w", err)
	}

	// Set NetDB for HostLookup functionality
	server.SetNetDB(r.StdNetDB)

	// Provide real bandwidth limits from router config
	server.SetBandwidthProvider(&routerBandwidthProvider{cfg: r.cfg})

	// Configure tunnel infrastructure for session tunnel pool initialization
	if r.tunnelManager != nil {
		server.SetTunnelBuilder(r.tunnelManager)
		log.Debug("I2CP server: tunnel builder configured")
	} else {
		log.Warn("I2CP server: tunnel manager not available for session pools")
	}

	// Create peer selector for tunnel building
	peerSelector, err := tunnel.NewDefaultPeerSelector(r.StdNetDB)
	if err != nil {
		log.WithError(err).Warn("Failed to create peer selector for I2CP sessions")
	} else {
		server.SetPeerSelector(peerSelector)
		log.Debug("I2CP server: peer selector configured")
	}

	if err := server.Start(); err != nil {
		return fmt.Errorf("failed to start I2CP server: %w", err)
	}

	r.i2cpServer = server

	log.WithFields(logger.Fields{
		"address":      r.cfg.I2CP.Address,
		"network":      r.cfg.I2CP.Network,
		"max_sessions": r.cfg.I2CP.MaxSessions,
	}).Info("I2CP server started")

	return nil
}

// removeSession removes a session when it closes.
// This method is typically called from a session's cleanup callback
// to ensure the router doesn't attempt to send messages to closed sessions.
// Thread-safe for concurrent access.
func (r *Router) removeSession(peerHash common.Hash) {
	r.sessionMutex.Lock()
	defer r.sessionMutex.Unlock()

	delete(r.activeSessions, peerHash)
	log.WithField("peer_hash", fmt.Sprintf("%x", peerHash[:8])).Debug("Removed session")
}

// getSessionByHash retrieves a session for a specific peer.
// Returns an error if no active session exists for the given peer hash.
// Thread-safe for concurrent read access using RWMutex.
func (r *Router) getSessionByHash(peerHash common.Hash) (*ntcp.NTCP2Session, error) {
	r.sessionMutex.RLock()
	defer r.sessionMutex.RUnlock()

	if session, ok := r.activeSessions[peerHash]; ok {
		return session, nil
	}
	return nil, fmt.Errorf("no session found for peer %x", peerHash[:8])
}

// GetSessionByHash implements SessionProvider interface for DatabaseManager.
// This enables the I2NP message processing layer to send responses back through
// the router's active transport sessions.
// NTCP2Session already implements the i2np.TransportSession interface.
// If no active session exists, it attempts to establish an outbound connection.
func (r *Router) GetSessionByHash(hash common.Hash) (i2np.TransportSession, error) {
	// Check if router is still running before proceeding
	r.runMux.RLock()
	running := r.running
	r.runMux.RUnlock()

	if !running {
		return nil, errors.New("router is not running")
	}

	// First check for existing session
	session, err := r.getSessionByHash(hash)
	if err == nil {
		// NTCP2Session implements i2np.TransportSession (QueueSendI2NP, SendQueueSize)
		return session, nil
	}

	// No existing session - try to establish outbound connection
	log.WithField("peer_hash", fmt.Sprintf("%x", hash[:8])).Debug("No active session, attempting outbound connection")

	routerInfo, err := r.retrieveRouterInfoWithTimeout(hash)
	if err != nil {
		return nil, err
	}

	transportSession, err := r.establishOutboundSession(hash, routerInfo)
	if err != nil {
		return nil, err
	}

	r.registerNewSession(hash, transportSession)
	return transportSession, nil
}

// retrieveRouterInfoWithTimeout looks up RouterInfo from NetDB with a timeout.
func (r *Router) retrieveRouterInfoWithTimeout(hash common.Hash) (*router_info.RouterInfo, error) {
	// Check if NetDB is available
	if r.StdNetDB == nil {
		return nil, errors.New("router NetDB not available")
	}

	routerInfoChan := r.StdNetDB.GetRouterInfo(hash)
	if routerInfoChan == nil {
		return nil, fmt.Errorf("no RouterInfo found for peer %x", hash[:8])
	}

	timer := time.NewTimer(30 * time.Second)
	defer timer.Stop()

	select {
	case routerInfo, ok := <-routerInfoChan:
		if !ok {
			return nil, fmt.Errorf("failed to receive RouterInfo for peer %x", hash[:8])
		}
		return &routerInfo, nil

	case <-timer.C:
		r.logRouterInfoTimeout(hash)
		return nil, fmt.Errorf("timeout waiting for RouterInfo for peer %x", hash[:8])
	}
}

// establishOutboundSession creates a new transport session to a peer.
func (r *Router) establishOutboundSession(hash common.Hash, routerInfo *router_info.RouterInfo) (i2np.TransportSession, error) {
	if err := r.validateTransportMuxer(hash); err != nil {
		return nil, err
	}

	transportSession, err := r.TransportMuxer.GetSession(*routerInfo)
	if err != nil {
		r.logSessionEstablishmentFailure(hash, routerInfo, err)
		return nil, fmt.Errorf("failed to establish outbound session: %w", err)
	}

	return transportSession, nil
}

// validateTransportMuxer checks if the transport muxer is initialized.
func (r *Router) validateTransportMuxer(hash common.Hash) error {
	if r.TransportMuxer == nil {
		log.WithFields(logger.Fields{
			"at":        "Router.GetSessionByHash",
			"phase":     "session_establishment",
			"operation": "outbound_connection",
			"peer_hash": fmt.Sprintf("%x", hash[:8]),
			"reason":    "transport_not_initialized",
		}).Error("TransportMuxer not initialized")
		return fmt.Errorf("transport not initialized for peer %x", hash[:8])
	}
	return nil
}

// registerNewSession stores a newly established session if it's an NTCP2 session.
func (r *Router) registerNewSession(hash common.Hash, transportSession i2np.TransportSession) {
	if ntcp2Session, ok := transportSession.(*ntcp.NTCP2Session); ok {
		r.addSession(hash, ntcp2Session)
		log.WithField("peer_hash", fmt.Sprintf("%x", hash[:8])).Info("Established and registered new outbound session")
	}
}

// logSessionEstablishmentFailure logs detailed context about session establishment failures.
func (r *Router) logSessionEstablishmentFailure(hash common.Hash, routerInfo *router_info.RouterInfo, err error) {
	log.WithFields(logger.Fields{
		"at":            "Router.GetSessionByHash",
		"phase":         "session_establishment",
		"operation":     "outbound_connection",
		"peer_hash":     fmt.Sprintf("%x", hash[:8]),
		"error":         err.Error(),
		"address_count": len(routerInfo.RouterAddresses()),
		"has_ntcp2":     hasNTCP2Address(*routerInfo),
	}).Error("failed to get session")
	log.WithError(err).WithField("peer_hash", fmt.Sprintf("%x", hash[:8])).Error("Failed to establish outbound session")
}

// logRouterInfoTimeout logs timeout events when waiting for RouterInfo from NetDB.
func (r *Router) logRouterInfoTimeout(hash common.Hash) {
	log.WithFields(logger.Fields{
		"at":        "Router.GetSessionByHash",
		"phase":     "session_establishment",
		"operation": "netdb_lookup",
		"peer_hash": fmt.Sprintf("%x", hash[:8]),
		"timeout":   "30s",
	}).Error("Timeout waiting for RouterInfo from NetDB")
}

// GetNetDB returns the network database for I2PControl statistics collection.
// Returns nil if NetDB has not been initialized.
func (r *Router) GetNetDB() *netdb.StdNetDB {
	return r.StdNetDB
}

// GetConfig returns the router configuration for I2PControl.
func (r *Router) GetConfig() *config.RouterConfig {
	return r.cfg
}

// IsRunning returns whether the router is currently operational.
// Thread-safe access to running state.
func (r *Router) IsRunning() bool {
	r.runMux.RLock()
	defer r.runMux.RUnlock()
	return r.running
}

// IsReseeding returns whether the router is currently performing a NetDB reseed operation.
// Thread-safe access to reseeding state.
func (r *Router) IsReseeding() bool {
	r.reseedMutex.RLock()
	defer r.reseedMutex.RUnlock()
	return r.isReseeding
}

// Reseed triggers an explicit NetDB reseed operation.
// This can be called via I2PControl to manually repopulate the network database.
// It runs in the current goroutine and returns any error encountered.
func (r *Router) Reseed() error {
	log.WithFields(logger.Fields{
		"at":     "(Router) Reseed",
		"reason": "explicit reseed requested",
	}).Info("Manual reseed triggered")
	return r.performReseed()
}

// hasNTCP2Address checks if RouterInfo contains at least one NTCP2 address
func hasNTCP2Address(routerInfo router_info.RouterInfo) bool {
	for _, addr := range routerInfo.RouterAddresses() {
		style := addr.TransportStyle()
		if styleStr, err := style.Data(); err == nil && styleStr == "ntcp2" {
			return true
		}
	}
	return false
}

// routerBandwidthProvider adapts the router config to the I2CP bandwidth
// limits interface so the I2CP server returns the real configured limit
// instead of a hardcoded value.
type routerBandwidthProvider struct {
	cfg *config.RouterConfig
}

// GetBandwidthLimits returns the router's configured MaxBandwidth for both
// inbound and outbound directions. If MaxBandwidth is 0 (unlimited) or
// exceeds uint32 range, it clamps to math.MaxUint32.
func (bp *routerBandwidthProvider) GetBandwidthLimits() (inbound, outbound uint32) {
	bw := bp.cfg.MaxBandwidth
	if bw == 0 || bw > uint64(^uint32(0)) {
		return ^uint32(0), ^uint32(0) // unlimited
	}
	limit := uint32(bw)
	return limit, limit
}
