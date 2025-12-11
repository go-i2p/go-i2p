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

	// i2pcontrolServer provides RPC monitoring interface
	i2pcontrolServer interface {
		Start() error
		Stop()
	}
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

// create router from configuration
func FromConfig(c *config.RouterConfig) (r *Router, err error) {
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
	return
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

	r.stopI2CPServer()
	r.stopI2PControlServer()
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

// stopI2CPServer shuts down the I2CP server if it is running and logs the result.
func (r *Router) stopI2CPServer() {
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

// Close closes any internal state and finalizes router resources so that nothing can start up again
func (r *Router) Close() error {
	log.Warn("Closing router not implemented(?)")
	return nil
}

// Start starts router mainloop
func (r *Router) Start() {
	r.runMux.Lock()
	defer r.runMux.Unlock()

	if r.running {
		log.WithFields(logger.Fields{
			"at":     "(Router) Start",
			"phase":  "startup",
			"reason": "router is already running",
			"state":  "running",
		}).Warn("attempted to start already running router")
		return
	}
	log.WithFields(logger.Fields{
		"at":           "(Router) Start",
		"phase":        "startup",
		"step":         1,
		"reason":       "initiating router startup sequence",
		"i2cp_enabled": r.cfg.I2CP != nil && r.cfg.I2CP.Enabled,
	}).Info("starting router")
	r.running = true

	// Create router-level context for lifecycle management
	// This context is cancelled in Stop() for coordinated shutdown
	r.ctx, r.cancel = context.WithCancel(context.Background())
	log.WithFields(logger.Fields{
		"at":     "(Router) Start",
		"phase":  "startup",
		"step":   2,
		"reason": "lifecycle context initialized",
	}).Debug("router context initialized")

	// Start I2CP server if enabled
	if r.cfg.I2CP != nil && r.cfg.I2CP.Enabled {
		if err := r.startI2CPServer(); err != nil {
			log.WithError(err).Error("Failed to start I2CP server")
		}
	}

	// Start I2PControl server if enabled
	if err := r.startI2PControlServer(); err != nil {
		log.WithError(err).Error("Failed to start I2PControl server")
	}

	// Track mainloop goroutine for clean shutdown
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		r.mainloop()
	}()
}

// initializeNetDB creates and configures the network database
func (r *Router) initializeNetDB() error {
	log.Debug("Entering router mainloop")
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

	// Initialize garlic message router for handling garlic clove forwarding
	r.initializeGarlicRouter()

	log.Debug("Message router initialized with NetDB, peer selection, session provider, and garlic forwarding")
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
	routerHash := r.getOurRouterHash()

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
// Returns zero hash on error (garlic router will still function but won't detect reflexive routing).
func (r *Router) getOurRouterHash() common.Hash {
	// Try to construct a RouterInfo to get our hash
	ri, err := r.RouterInfoKeystore.ConstructRouterInfo(nil)
	if err != nil {
		log.WithError(err).Warn("Failed to construct RouterInfo for hash extraction, reflexive routing may not work")
		return common.Hash{} // Return zero hash as fallback
	}

	hash, err := ri.IdentHash()
	if err != nil {
		log.WithError(err).Warn("Failed to get IdentHash from RouterInfo, reflexive routing may not work")
		return common.Hash{} // Return zero hash as fallback
	}

	return hash
}

// GetTunnelManager returns the tunnel manager in a thread-safe manner.
// Returns nil if the tunnel manager has not been initialized yet.
func (r *Router) GetTunnelManager() *i2np.TunnelManager {
	r.runMux.RLock()
	defer r.runMux.RUnlock()
	return r.tunnelManager
}

// GetGarlicRouter returns the garlic router in a thread-safe manner.
// Returns nil if the garlic router has not been initialized yet.
func (r *Router) GetGarlicRouter() *GarlicMessageRouter {
	r.runMux.RLock()
	defer r.runMux.RUnlock()
	return r.garlicRouter
}

// ensureNetDBReady validates NetDB state and performs reseed if needed
func (r *Router) ensureNetDBReady() error {
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

// performReseed executes network database reseeding process
func (r *Router) performReseed() error {
	log.WithFields(logger.Fields{
		"at":             "(Router) performReseed",
		"phase":          "bootstrap",
		"reason":         "netdb below threshold, initiating bootstrap",
		"current_size":   r.StdNetDB.Size(),
		"threshold":      r.cfg.Bootstrap.LowPeerThreshold,
		"shortfall":      r.cfg.Bootstrap.LowPeerThreshold - r.StdNetDB.Size(),
		"bootstrap_type": r.cfg.Bootstrap.BootstrapType,
	}).Warn("netDb below threshold, initiating bootstrap")

	// Create the appropriate bootstrapper based on user configuration
	var bootstrapper bootstrap.Bootstrap

	switch r.cfg.Bootstrap.BootstrapType {
	case "file":
		// Use file bootstrap only
		if r.cfg.Bootstrap.ReseedFilePath == "" {
			log.WithFields(logger.Fields{
				"at":             "(Router) performReseed",
				"phase":          "bootstrap",
				"reason":         "bootstrap_type is file but path not configured",
				"bootstrap_type": "file",
			}).Error("bootstrap configuration error")
			return fmt.Errorf("bootstrap_type is 'file' but no reseed_file_path is configured")
		}
		log.WithFields(logger.Fields{
			"at":        "(Router) performReseed",
			"phase":     "bootstrap",
			"reason":    "using file bootstrap as configured",
			"file_path": r.cfg.Bootstrap.ReseedFilePath,
			"strategy":  "file_only",
		}).Info("using file bootstrap only (as specified by bootstrap_type)")
		bootstrapper = bootstrap.NewFileBootstrap(r.cfg.Bootstrap.ReseedFilePath)

	case "reseed":
		// Use reseed bootstrap only
		log.Info("Using reseed bootstrap only (as specified by bootstrap_type)")
		bootstrapper = bootstrap.NewReseedBootstrap(r.cfg.Bootstrap)

	case "local":
		// Use local netDb bootstrap only
		log.Info("Using local netDb bootstrap only (as specified by bootstrap_type)")
		bootstrapper = bootstrap.NewLocalNetDbBootstrap(r.cfg.Bootstrap)

	case "auto", "":
		// Use composite bootstrap which tries all methods
		log.WithFields(logger.Fields{
			"at":             "(Router) performReseed",
			"phase":          "bootstrap",
			"reason":         "using composite bootstrap strategy",
			"bootstrap_type": r.cfg.Bootstrap.BootstrapType,
			"strategy":       "file -> reseed -> local_netdb",
			"reseed_servers": len(r.cfg.Bootstrap.ReseedServers),
		}).Info("using composite bootstrap (tries all methods)")
		bootstrapper = bootstrap.NewCompositeBootstrap(r.cfg.Bootstrap)

	default:
		log.WithFields(logger.Fields{
			"at":             "(Router) performReseed",
			"phase":          "bootstrap",
			"reason":         "unknown bootstrap_type, using fallback",
			"bootstrap_type": r.cfg.Bootstrap.BootstrapType,
			"fallback":       "composite",
			"valid_types":    "file, reseed, local, auto",
		}).Warn("unknown bootstrap_type, falling back to composite bootstrap")
		bootstrapper = bootstrap.NewCompositeBootstrap(r.cfg.Bootstrap)
	}

	if err := r.StdNetDB.Reseed(bootstrapper, r.cfg.Bootstrap.LowPeerThreshold); err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"at":           "(Router) performReseed",
			"phase":        "bootstrap",
			"reason":       "bootstrap failed but continuing",
			"current_size": r.StdNetDB.Size(),
			"target":       r.cfg.Bootstrap.LowPeerThreshold,
			"impact":       "router will operate with limited peer connectivity",
		}).Warn("bootstrap failed, continuing with limited NetDB")
		return err
	}
	log.WithFields(logger.Fields{
		"at":           "(Router) performReseed",
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

	for {
		r.runMux.RLock()
		shouldRun := r.running
		r.runMux.RUnlock()

		if !shouldRun {
			break
		}

		select {
		case <-r.closeChnl:
			log.Debug("Router received close signal in mainloop")
			return
		case <-time.After(time.Second):
			// Continue loop after 1 second timeout
		}
	}
}

// run i2p router mainloop
func (r *Router) mainloop() {
	// Initialize active sessions map for tracking NTCP2 connections
	r.activeSessions = make(map[common.Hash]*ntcp.NTCP2Session)
	log.Debug("Initialized active sessions map")

	if err := r.initializeNetDB(); err != nil {
		log.WithError(err).Error("Failed to initialize NetDB")
		r.Stop()
		return
	}

	// Ensure NetDB is ready before initializing components that depend on it
	if err := r.ensureNetDBReady(); err != nil {
		log.WithFields(logger.Fields{
			"at":     "(Router) mainloop",
			"reason": err.Error(),
		}).Error("NetDB startup failed")
		r.Stop()
		return
	}

	r.initializeMessageRouter()

	// Start session monitors for inbound message processing
	r.startSessionMonitors()

	r.runMainLoop()
	log.Debug("Exiting router mainloop")
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
// Returns nil if timeout occurs or connection fails.
func (r *Router) acceptInboundConnection() net.Conn {
	conn, err := r.TransportMuxer.AcceptWithTimeout(5 * time.Second)
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
	go r.processSessionMessages(session, peerHash)

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

	// Route based on message type to appropriate handler
	switch msg.Type() {
	case i2np.I2NP_MESSAGE_TYPE_DATABASE_STORE:
		// Parse DatabaseStore message from BaseI2NPMessage data
		dbStore, err := r.parseDatabaseStoreMessage(msg)
		if err != nil {
			return fmt.Errorf("failed to parse DatabaseStore message: %w", err)
		}
		return r.messageRouter.RouteDatabaseMessage(dbStore)

	case i2np.I2NP_MESSAGE_TYPE_DATABASE_LOOKUP:
		return r.messageRouter.RouteDatabaseMessage(msg)

	case i2np.I2NP_MESSAGE_TYPE_DATABASE_SEARCH_REPLY:
		return r.messageRouter.RouteDatabaseMessage(msg)

	case i2np.I2NP_MESSAGE_TYPE_DATA:
		return r.messageRouter.RouteMessage(msg)

	case i2np.I2NP_MESSAGE_TYPE_DELIVERY_STATUS:
		return r.messageRouter.RouteMessage(msg)

	case i2np.I2NP_MESSAGE_TYPE_TUNNEL_DATA:
		return r.messageRouter.RouteMessage(msg)

	case i2np.I2NP_MESSAGE_TYPE_TUNNEL_BUILD:
		return r.messageRouter.RouteTunnelMessage(msg)

	case i2np.I2NP_MESSAGE_TYPE_TUNNEL_BUILD_REPLY:
		return r.messageRouter.RouteTunnelMessage(msg)

	case i2np.I2NP_MESSAGE_TYPE_VARIABLE_TUNNEL_BUILD:
		return r.messageRouter.RouteTunnelMessage(msg)

	case i2np.I2NP_MESSAGE_TYPE_VARIABLE_TUNNEL_BUILD_REPLY:
		return r.messageRouter.RouteTunnelMessage(msg)

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
// Thread-safe for concurrent access.
func (r *Router) addSession(peerHash common.Hash, session *ntcp.NTCP2Session) {
	r.sessionMutex.Lock()
	defer r.sessionMutex.Unlock()

	r.activeSessions[peerHash] = session
	log.WithField("peer_hash", fmt.Sprintf("%x", peerHash[:8])).Debug("Added active session")
}

// startI2CPServer initializes and starts the I2CP server
func (r *Router) startI2CPServer() error {
	serverConfig := &i2cp.ServerConfig{
		ListenAddr:        r.cfg.I2CP.Address,
		Network:           r.cfg.I2CP.Network,
		MaxSessions:       r.cfg.I2CP.MaxSessions,
		LeaseSetPublisher: NewLeaseSetPublisher(r),
	}

	server, err := i2cp.NewServer(serverConfig)
	if err != nil {
		return fmt.Errorf("failed to create I2CP server: %w", err)
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
	// First check for existing session
	session, err := r.getSessionByHash(hash)
	if err == nil {
		// NTCP2Session implements i2np.TransportSession (QueueSendI2NP, SendQueueSize)
		return session, nil
	}

	// No existing session - try to establish outbound connection
	log.WithField("peer_hash", fmt.Sprintf("%x", hash[:8])).Debug("No active session, attempting outbound connection")

	// Look up RouterInfo from NetDB with timeout
	routerInfoChan := r.StdNetDB.GetRouterInfo(hash)
	if routerInfoChan == nil {
		return nil, fmt.Errorf("no RouterInfo found for peer %x", hash[:8])
	}

	// Receive RouterInfo from channel with timeout
	select {
	case routerInfo, ok := <-routerInfoChan:
		if !ok {
			return nil, fmt.Errorf("failed to receive RouterInfo for peer %x", hash[:8])
		}

		// Check if TransportMuxer is initialized before using it
		if r.TransportMuxer == nil {
			log.WithFields(logger.Fields{
				"at":        "Router.GetSessionByHash",
				"phase":     "session_establishment",
				"operation": "outbound_connection",
				"peer_hash": fmt.Sprintf("%x", hash[:8]),
				"reason":    "transport_not_initialized",
			}).Error("TransportMuxer not initialized")
			return nil, fmt.Errorf("transport not initialized for peer %x", hash[:8])
		}

		// Use TransportMuxer to establish outbound session
		transportSession, err := r.TransportMuxer.GetSession(routerInfo)
		if err != nil {
			// Enhanced logging for session establishment failures - Issue #2 from AUDIT.md
			// Include context about peer and transport compatibility
			log.WithFields(logger.Fields{
				"at":            "Router.GetSessionByHash",
				"phase":         "session_establishment",
				"operation":     "outbound_connection",
				"peer_hash":     fmt.Sprintf("%x", hash[:8]),
				"error":         err.Error(),
				"address_count": len(routerInfo.RouterAddresses()),
				"has_ntcp2":     hasNTCP2Address(routerInfo),
			}).Error("failed to get session")
			log.WithError(err).WithField("peer_hash", fmt.Sprintf("%x", hash[:8])).Error("Failed to establish outbound session")
			return nil, fmt.Errorf("failed to establish outbound session: %w", err)
		}

		// Convert TransportSession to NTCP2Session and store it
		if ntcp2Session, ok := transportSession.(*ntcp.NTCP2Session); ok {
			r.addSession(hash, ntcp2Session)
			log.WithField("peer_hash", fmt.Sprintf("%x", hash[:8])).Info("Established and registered new outbound session")
		}

		return transportSession, nil

	case <-time.After(30 * time.Second):
		// Enhanced logging for RouterInfo lookup timeout
		log.WithFields(logger.Fields{
			"at":        "Router.GetSessionByHash",
			"phase":     "session_establishment",
			"operation": "netdb_lookup",
			"peer_hash": fmt.Sprintf("%x", hash[:8]),
			"timeout":   "30s",
		}).Error("Timeout waiting for RouterInfo from NetDB")
		return nil, fmt.Errorf("timeout waiting for RouterInfo for peer %x", hash[:8])
	}
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
