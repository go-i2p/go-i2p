package router

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/bootstrap"
	"github.com/go-i2p/go-i2p/lib/i2cp"
	"github.com/go-i2p/go-i2p/lib/i2np"
	ntcp "github.com/go-i2p/go-i2p/lib/transport/ntcp2"
	ntcp2 "github.com/go-i2p/go-noise/ntcp2"

	"github.com/go-i2p/logger"

	"github.com/go-i2p/go-i2p/lib/tunnel"
)

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
		ReadTimeout:       r.cfg.I2CP.ReadTimeout,
		WriteTimeout:      r.cfg.I2CP.WriteTimeout,
		SessionTimeout:    r.cfg.I2CP.SessionTimeout,
		LeaseSetPublisher: r.leaseSetPublisher,
	}

	server, err := i2cp.NewServer(serverConfig)
	if err != nil {
		return fmt.Errorf("failed to create I2CP server: %w", err)
	}

	// Set NetDB for HostLookup functionality
	server.SetNetDB(r.StdNetDB)

	// Configure optional I2CP authentication from config
	if r.cfg.I2CP.Username != "" && r.cfg.I2CP.Password != "" {
		auth, authErr := i2cp.NewPasswordAuthenticator(r.cfg.I2CP.Username, r.cfg.I2CP.Password)
		if authErr != nil {
			return fmt.Errorf("failed to create I2CP authenticator: %w", authErr)
		}
		server.SetAuthenticator(auth)
		log.Info("I2CP server: authentication enabled")
	}

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
