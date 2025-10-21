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
	"github.com/go-i2p/go-i2p/lib/i2np"
	ntcp "github.com/go-i2p/go-i2p/lib/transport/ntcp2"
	ntcp2 "github.com/go-i2p/go-noise/ntcp2"

	"github.com/go-i2p/logger"

	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/go-i2p/go-i2p/lib/keys"
	"github.com/go-i2p/go-i2p/lib/netdb"
	"github.com/go-i2p/go-i2p/lib/transport"
)

var log = logger.GetGoI2PLogger()

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
	// router configuration
	cfg *config.RouterConfig
	// close channel
	closeChnl chan bool
	// running flag and mutex for thread-safe access
	running bool
	runMux  sync.RWMutex

	// Session tracking for NTCP2 message routing
	activeSessions map[common.Hash]*ntcp.NTCP2Session
	// sessionMutex protects concurrent access to activeSessions map
	sessionMutex sync.RWMutex
}

// CreateRouter creates a router with the provided configuration
func CreateRouter(cfg *config.RouterConfig) (*Router, error) {
	log.Debug("Creating router with provided configuration")

	r, err := FromConfig(cfg)
	if err != nil {
		log.WithError(err).Error("Failed to create router from configuration")
		return nil, err
	}
	log.Debug("Router created successfully with provided configuration")

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
	log.Debug("Working directory is:", cfg.WorkingDir)

	keystore, err := keys.NewRouterInfoKeystore(cfg.WorkingDir, "localRouter")
	if err != nil {
		log.WithError(err).Error("Failed to create RouterInfoKeystore")
		return err
	}
	log.Debug("RouterInfoKeystore created successfully")

	if err = keystore.StoreKeys(); err != nil {
		log.WithError(err).Error("Failed to store RouterInfoKeystore")
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

	ntcp2Transport, err := ntcp.NewNTCP2Transport(*ri, ntcp2Config)
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
	log.WithField("config", c).Debug("Creating router from configuration")
	r = new(Router)
	r.cfg = c
	r.closeChnl = make(chan bool)
	log.Debug("Router created successfully from configuration")
	return
}

// Wait blocks until router is fully stopped
func (r *Router) Wait() {
	log.Debug("Waiting for router to stop")
	<-r.closeChnl
	log.Debug("Router has stopped")
}

// Stop starts stopping internal state of router
func (r *Router) Stop() {
	log.Debug("Stopping router")
	r.runMux.Lock()
	defer r.runMux.Unlock()

	if !r.running {
		log.Debug("Router already stopped")
		return
	}

	r.running = false

	// Send close signal without blocking - use select with default case
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
			"reason": "router is already running",
		}).Error("Error Starting router")
		return
	}
	log.Debug("Starting router")
	r.running = true
	go r.mainloop()
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

	log.Debug("Message router initialized with NetDB, peer selection, and session provider")
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
	log.Info("NetDB below threshold, initiating reseed")

	bootstrapper := bootstrap.NewReseedBootstrap(r.cfg.Bootstrap)

	if err := r.StdNetDB.Reseed(bootstrapper, r.cfg.Bootstrap.LowPeerThreshold); err != nil {
		log.WithError(err).Warn("Initial reseed failed, continuing with limited NetDB")
		return err
	}
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

	r.initializeMessageRouter()

	if err := r.ensureNetDBReady(); err != nil {
		log.WithFields(logger.Fields{
			"at":     "(Router) mainloop",
			"reason": err.Error(),
		}).Error("Netdb Startup failed")
		r.Stop()
		return
	}

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
	go r.monitorInboundSessions()
}

// monitorInboundSessions continuously accepts new inbound NTCP2 connections
// and spawns a message processor goroutine for each new session.
// This loop runs until the router is stopped.
func (r *Router) monitorInboundSessions() {
	log.Debug("Starting inbound session monitor")

	for {
		// Check if router is still running
		r.runMux.RLock()
		shouldRun := r.running
		r.runMux.RUnlock()

		if !shouldRun {
			log.Debug("Stopping inbound session monitor")
			return
		}

		// Accept incoming NTCP2 connection with timeout to allow shutdown checks
		conn, err := r.TransportMuxer.AcceptWithTimeout(5 * time.Second)
		if err != nil {
			// Timeout is expected behavior, continue monitoring
			if errors.Is(err, context.DeadlineExceeded) {
				continue
			}
			log.WithError(err).Warn("Failed to accept inbound connection")
			continue
		}

		// Extract peer information and create session
		session, peerHash, err := r.createSessionFromConn(conn)
		if err != nil {
			log.WithError(err).Error("Failed to create session from connection")
			conn.Close()
			continue
		}

		// Track session and start message processor
		r.addSession(peerHash, session)
		go r.processSessionMessages(session, peerHash)

		log.WithField("peer_hash", fmt.Sprintf("%x", peerHash[:8])).Info("Started monitoring new inbound session")
	}
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

	// Create session with router's context
	// TODO: Use router-level context for better lifecycle management
	ctx := context.Background()
	sessionLogger := logger.WithField("peer_hash", fmt.Sprintf("%x", peerHash[:8]))
	session := ntcp.NewNTCP2Session(conn, ctx, sessionLogger)

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

	for {
		// Check if router is still running
		r.runMux.RLock()
		shouldRun := r.running
		r.runMux.RUnlock()

		if !shouldRun {
			return
		}

		// Read next I2NP message from session (blocking call)
		msg, err := session.ReadNextI2NP()
		if err != nil {
			// Check if session closed normally
			if errors.Is(err, ntcp.ErrSessionClosed) {
				log.WithField("peer_hash", fmt.Sprintf("%x", peerHash[:8])).Debug("Session closed normally")
			} else {
				log.WithError(err).WithField("peer_hash", fmt.Sprintf("%x", peerHash[:8])).Warn("Error reading I2NP message from session")
			}
			return
		}

		// Route message through MessageRouter - errors are logged but don't close session
		if err := r.routeMessage(msg, peerHash); err != nil {
			log.WithError(err).WithFields(logger.Fields{
				"message_type": msg.Type(),
				"message_id":   msg.MessageID(),
				"peer_hash":    fmt.Sprintf("%x", peerHash[:8]),
			}).Error("Failed to route I2NP message")
		}
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
		return r.messageRouter.RouteDatabaseMessage(msg)

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
func (r *Router) GetSessionByHash(hash common.Hash) (i2np.TransportSession, error) {
	session, err := r.getSessionByHash(hash)
	if err != nil {
		return nil, err
	}
	// NTCP2Session implements i2np.TransportSession (QueueSendI2NP, SendQueueSize)
	return session, nil
}
