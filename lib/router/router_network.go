package router

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/bootstrap"
	"github.com/go-i2p/go-i2p/lib/i2cp"
	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/go-i2p/go-i2p/lib/naming"
	"github.com/go-i2p/go-i2p/lib/netdb"
	"github.com/go-i2p/go-i2p/lib/transport"
	ntcp "github.com/go-i2p/go-i2p/lib/transport/ntcp2"
	ssu2 "github.com/go-i2p/go-i2p/lib/transport/ssu2"
	ntcp2 "github.com/go-i2p/go-noise/ntcp2"
	ssu2noise "github.com/go-i2p/go-noise/ssu2"
	"github.com/samber/oops"

	"github.com/go-i2p/logger"

	"github.com/go-i2p/go-i2p/lib/tunnel"
)

// ensureNetDBReady validates NetDB state and performs reseed if needed.
// Returns an error if the router's StdNetDB is nil (e.g. during shutdown).
func (r *Router) ensureNetDBReady() error {
	if r.StdNetDB == nil {
		return oops.Errorf("StdNetDB is nil (router may be shutting down)")
	}
	if err := r.StdNetDB.Ensure(); err != nil {
		log.WithError(err).Error("Failed to ensure NetDB")
		return err
	}

	if sz := r.StdNetDB.Size(); sz >= 0 {
		log.WithField("size", sz).Debug("NetDB Size: " + strconv.Itoa(sz))
	} else {
		log.WithFields(logger.Fields{"at": "ensureNetDBReady"}).Warn("Unable to determine NetDB size")
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
		return nil, oops.Errorf("bootstrap_type is 'file' but no reseed_file_path is configured")
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
	log.WithFields(logger.Fields{"at": "createReseedBootstrapper"}).Info("Using reseed bootstrap only (as specified by bootstrap_type)")
	return bootstrap.NewReseedBootstrap(r.cfg.Bootstrap)
}

// createLocalBootstrapper creates a bootstrapper that reads from local netDb directories.
func (r *Router) createLocalBootstrapper() bootstrap.Bootstrap {
	log.WithFields(logger.Fields{"at": "createLocalBootstrapper"}).Info("Using local netDb bootstrap only (as specified by bootstrap_type)")
	return bootstrap.NewLocalNetDBBootstrap(r.cfg.Bootstrap)
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

// natRecheckInterval is how often the router re-runs SSU2 NAT detection
// to account for network changes (e.g., IP address change, NAT mapping expiry).
const natRecheckInterval = 15 * time.Minute

// runMainLoop executes the primary router event loop
func (r *Router) runMainLoop() {
	log.WithFields(logger.Fields{
		"at": "(Router) mainloop",
	}).Debug("Router ready with database message processing enabled")

	natTicker := time.NewTicker(natRecheckInterval)
	defer natTicker.Stop()

	for {
		select {
		case <-r.closeChnl:
			log.WithFields(logger.Fields{"at": "runMainLoop"}).Debug("Router received close signal in mainloop")
			return
		case <-r.ctx.Done():
			log.WithFields(logger.Fields{"at": "runMainLoop"}).Debug("Router context cancelled in mainloop")
			return
		case <-natTicker.C:
			r.startSSU2NATDetection()
		}
	}
}

// run i2p router mainloop
func (r *Router) mainloop() {
	// Initialize active sessions map for tracking NTCP2 connections
	r.activeSessions = make(map[common.Hash]transport.TransportSession)
	log.WithField("at", "mainloop").Debug("initialized active sessions map")

	log.WithField("at", "mainloop").Debug("step 1: initializing core components (NetDB, I2CP, I2PControl)")
	if err := r.initializeCoreComponents(); err != nil {
		r.startupErr <- err
		r.Stop()
		return
	}
	log.WithField("at", "mainloop").Debug("step 2: wiring inbound handler")
	r.wireInboundHandler()
	log.WithField("at", "mainloop").Debug("step 3: initializing message router (includes ConstructRouterInfo for identity hash)")
	r.initializeMessageRouter()
	log.WithField("at", "mainloop").Debug("step 4: starting publisher")
	r.startPublisher()
	log.WithField("at", "mainloop").Debug("step 5: starting explorer")
	r.startExplorer()
	log.WithField("at", "mainloop").Debug("step 6: starting floodfill server")
	r.startFloodfillServer()
	log.WithField("at", "mainloop").Debug("step 7: starting SSU2 NAT detection")
	r.startSSU2NATDetection()

	// Signal Start() that all startup-critical initialization succeeded
	log.WithField("at", "mainloop").Debug("signaling startup success")
	r.startupErr <- nil

	// Start health monitor for resource leak detection
	log.WithField("at", "mainloop").Debug("starting health monitor")
	r.startHealthMonitor()

	// Start session monitors for inbound message processing
	log.WithField("at", "mainloop").Debug("starting session monitors")
	r.startSessionMonitors()

	r.runMainLoop()
	log.WithFields(logger.Fields{"at": "mainloop"}).Debug("Exiting router mainloop")
}

// initializeCoreComponents initializes NetDB, I2CP, and I2PControl servers in order.
// Returns an error if any critical component fails to start.
func (r *Router) initializeCoreComponents() error {
	if err := r.initializeNetDB(); err != nil {
		log.WithError(err).Error("Failed to initialize NetDB")
		return oops.Wrapf(err, "NetDB initialization failed")
	}

	if err := r.ensureNetDBReady(); err != nil {
		log.WithFields(logger.Fields{
			"at":     "(Router) mainloop",
			"reason": err.Error(),
		}).Error("NetDB startup failed")
		return oops.Wrapf(err, "NetDB readiness check failed")
	}

	if r.cfg.I2CP != nil && r.cfg.I2CP.Enabled {
		if err := r.startI2CPServer(); err != nil {
			return oops.Wrapf(err, "I2CP server startup failed")
		}
	}

	if err := r.startI2PControlServer(); err != nil {
		return oops.Wrapf(err, "I2PControl server startup failed")
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
	log.WithFields(logger.Fields{"at": "startSessionMonitors"}).Debug("Starting session monitors")
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
	log.WithFields(logger.Fields{"at": "monitorInboundSessions"}).Debug("Starting inbound session monitor")

	for r.shouldContinueMonitoring() {
		if conn := r.acceptInboundConnection(); conn != nil {
			r.handleNewConnection(conn)
		}
	}

	log.WithFields(logger.Fields{"at": "monitorInboundSessions"}).Debug("Stopping inbound session monitor")
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
// It supports both NTCP2 (remote address is *ntcp2.NTCP2Addr) and SSU2 (remote address is
// *ssu2noise.SSU2Addr) inbound connections via a type switch on the connection's remote address.
func (r *Router) handleNewConnection(conn net.Conn) {
	sessionLogger := logger.WithField("remote_addr", conn.RemoteAddr().String())

	switch addr := conn.RemoteAddr().(type) {
	case *ntcp2.NTCP2Addr:
		peerHash := common.Hash(addr.RouterHash())
		sessionLog := logger.WithField("peer_hash", fmt.Sprintf("%x", peerHash[:8]))
		session := ntcp.NewNTCP2Session(conn, r.ctx, sessionLog)
		session.SetCleanupCallback(func() { r.removeSession(peerHash) })
		r.addSession(peerHash, session)
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			r.processSessionMessages(session, staticAuthenticatedPeer{hash: peerHash, handshakeComplete: true})
		}()
		sessionLog.Info("Started monitoring new inbound NTCP2 session")

	case *ssu2noise.SSU2Addr:
		peerHash := common.Hash(addr.RouterHash())
		sessionLog := logger.WithField("peer_hash", fmt.Sprintf("%x", peerHash[:8]))
		ssu2Conn, ok := conn.(*ssu2noise.SSU2Conn)
		if !ok {
			sessionLog.WithField("conn_type", fmt.Sprintf("%T", conn)).Error("Inbound SSU2 connection is not *ssu2noise.SSU2Conn, dropping")
			conn.Close()
			return
		}
		session := ssu2.NewSSU2Session(ssu2Conn, r.ctx, sessionLog)
		session.SetCleanupCallback(func() { r.removeSession(peerHash) })
		r.addSession(peerHash, session)
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			r.processSessionMessages(session, staticAuthenticatedPeer{hash: peerHash, handshakeComplete: true})
		}()
		sessionLog.Info("Started monitoring new inbound SSU2 session")

	default:
		sessionLogger.WithField("addr_type", fmt.Sprintf("%T", conn.RemoteAddr())).Error("Unrecognised inbound connection address type, dropping")
		conn.Close()
	}
}

// i2npReader is a transport session that supports reading inbound I2NP messages.
// Both NTCP2Session and SSU2Session implement this interface.
type i2npReader interface {
	ReadNextI2NP() (i2np.I2NPMessage, error)
}

// AuthenticatedPeer defines the minimum identity guarantees required before
// starting a session message processor.
type AuthenticatedPeer interface {
	PeerHash() common.Hash
	HandshakeComplete() bool
}

type staticAuthenticatedPeer struct {
	hash              common.Hash
	handshakeComplete bool
}

func (p staticAuthenticatedPeer) PeerHash() common.Hash {
	return p.hash
}

func (p staticAuthenticatedPeer) HandshakeComplete() bool {
	return p.handshakeComplete
}

// processSessionMessages reads and processes I2NP messages from a single session.
// This method runs in a dedicated goroutine for each active session,
// continuously reading messages until the session closes or the router stops.
// Message processing errors are logged but don't terminate the session.
func (r *Router) processSessionMessages(session i2npReader, peer AuthenticatedPeer) {
	if peer == nil || !peer.HandshakeComplete() {
		log.WithField("at", "processSessionMessages").Warn("Refusing to start session message processor for unauthenticated peer")
		return
	}

	peerHash := peer.PeerHash()
	defer log.WithField("peer_hash", fmt.Sprintf("%x", peerHash[:8])).Debug("Session message processor stopped")

	for r.shouldContinueMonitoring() {
		if !r.processSessionMessageSafely(session, peerHash) {
			return
		}
	}
}

// processSessionMessageSafely processes a single inbound message and recovers
// from parser/dispatcher panics so one malicious payload cannot crash the router.
func (r *Router) processSessionMessageSafely(session i2npReader, peerHash common.Hash) (keepProcessing bool) {
	keepProcessing = true
	defer func() {
		if rec := recover(); rec != nil {
			log.WithFields(logger.Fields{
				"peer_hash": fmt.Sprintf("%x", peerHash[:8]),
				"panic":     fmt.Sprintf("%v", rec),
			}).Error("Recovered from panic in I2NP dispatch; dropping session")
			keepProcessing = false
		}
	}()

	msg := r.readNextMessage(session, peerHash)
	if msg == nil {
		return false
	}
	r.handleIncomingMessage(msg, peerHash)
	return true
}

// readNextMessage reads the next I2NP message from the session.
// Returns nil if an error occurs or the session is closed.
func (r *Router) readNextMessage(session i2npReader, peerHash common.Hash) i2np.I2NPMessage {
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

	if isBenignReadError(err) {
		log.WithField("peer_hash", peerHashStr).Debug("Session closed normally")
		return
	}

	if isFramingOrLengthViolation(err) {
		if shouldLogReadWarn(peerHashStr) {
			log.WithError(err).WithField("peer_hash", peerHashStr).Warn("Error reading I2NP message from session")
		} else {
			log.WithError(err).WithField("peer_hash", peerHashStr).Debug("Suppressed repeated read warning for noisy peer")
		}
	} else {
		log.WithError(err).WithField("peer_hash", peerHashStr).Debug("Session read ended with non-framing error")
	}
}

func isBenignReadError(err error) bool {
	return errors.Is(err, ntcp.ErrSessionClosed) ||
		errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, net.ErrClosed) ||
		errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded)
}

func isFramingOrLengthViolation(err error) bool {
	errText := strings.ToLower(err.Error())
	return strings.Contains(errText, "frame") ||
		strings.Contains(errText, "framing") ||
		strings.Contains(errText, "length") ||
		strings.Contains(errText, "payload")
}

var (
	readWarnLimiterMu   sync.Mutex
	readWarnLastByPeer  = make(map[string]time.Time)
	readWarnMinInterval = 5 * time.Second
)

func shouldLogReadWarn(peerHash string) bool {
	readWarnLimiterMu.Lock()
	defer readWarnLimiterMu.Unlock()

	now := time.Now()
	last, ok := readWarnLastByPeer[peerHash]
	if ok && now.Sub(last) < readWarnMinInterval {
		return false
	}
	readWarnLastByPeer[peerHash] = now
	return true
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
func (r *Router) routeMessage(msg i2np.I2NPMessage, fromPeer common.Hash) (err error) {
	messageType, messageID := safeMessageMetadata(msg)
	defer func() {
		if rec := recover(); rec != nil {
			err = oops.Errorf("panic while routing I2NP message type %d: %v", messageType, rec)
			log.WithError(err).WithFields(logger.Fields{
				"message_type": messageType,
				"message_id":   messageID,
				"from_peer":    fmt.Sprintf("%x", fromPeer[:8]),
				"panic":        fmt.Sprintf("%v", rec),
			}).Error("Recovered from panic in routeMessage")
		}
	}()

	log.WithFields(logger.Fields{
		"message_type": messageType,
		"message_id":   messageID,
		"from_peer":    fmt.Sprintf("%x", fromPeer[:8]),
	}).Debug("Routing I2NP message")

	mr, fs := r.getRoutingComponents()
	if mr == nil {
		return oops.Errorf("message router not available (router may be shutting down)")
	}

	return r.dispatchByMessageType(msg, mr, fs, fromPeer)
}

func safeMessageMetadata(msg i2np.I2NPMessage) (messageType, messageID int) {
	return safeMessageType(msg), safeMessageID(msg)
}

func safeMessageType(msg i2np.I2NPMessage) (messageType int) {
	defer func() {
		if rec := recover(); rec != nil {
			messageType = -1
		}
	}()
	return msg.Type()
}

func safeMessageID(msg i2np.I2NPMessage) (messageID int) {
	defer func() {
		if rec := recover(); rec != nil {
			messageID = -1
		}
	}()
	return msg.MessageID()
}

// getRoutingComponents returns the message router and floodfill server under lock.
func (r *Router) getRoutingComponents() (*i2np.I2NPMessageDispatcher, *netdb.FloodfillServer) {
	r.runMux.RLock()
	defer r.runMux.RUnlock()
	return r.messageRouter, r.floodfillServer
}

// dispatchByMessageType routes a message to the appropriate handler based on type.
func (r *Router) dispatchByMessageType(msg i2np.I2NPMessage, mr *i2np.I2NPMessageDispatcher, fs *netdb.FloodfillServer, fromPeer common.Hash) error {
	switch msg.Type() {
	case i2np.I2NPMessageTypeDatabaseStore:
		return r.routeDatabaseStore(msg, mr, fromPeer)
	case i2np.I2NPMessageTypeDatabaseLookup:
		return r.routeDatabaseLookup(msg, mr, fs)
	case i2np.I2NPMessageTypeDatabaseSearchReply:
		return mr.RouteDatabaseMessage(msg)
	case i2np.I2NPMessageTypeData, i2np.I2NPMessageTypeDeliveryStatus,
		i2np.I2NPMessageTypeGarlic, i2np.I2NPMessageTypeTunnelData,
		i2np.I2NPMessageTypeTunnelGateway:
		return mr.RouteMessage(msg)
	case i2np.I2NPMessageTypeTunnelBuild, i2np.I2NPMessageTypeTunnelBuildReply,
		i2np.I2NPMessageTypeVariableTunnelBuild, i2np.I2NPMessageTypeVariableTunnelBuildReply,
		i2np.I2NPMessageTypeShortTunnelBuild, i2np.I2NPMessageTypeShortTunnelBuildReply:
		return mr.GetProcessor().ProcessMessage(msg)
	default:
		return oops.Errorf("unsupported message type: %d", msg.Type())
	}
}

// routeDatabaseStore handles DatabaseStore message routing.
func (r *Router) routeDatabaseStore(msg i2np.I2NPMessage, mr *i2np.I2NPMessageDispatcher, fromPeer common.Hash) error {
	dbStore, err := r.parseDatabaseStoreMessage(msg)
	if err != nil {
		return oops.Wrapf(err, "failed to parse DatabaseStore message")
	}
	return mr.RouteDatabaseMessageFromPeer(dbStore, &fromPeer)
}

// routeDatabaseLookup handles DatabaseLookup message routing with optional floodfill handling.
func (r *Router) routeDatabaseLookup(msg i2np.I2NPMessage, mr *i2np.I2NPMessageDispatcher, fs *netdb.FloodfillServer) error {
	if fs != nil {
		if lookup, err := r.parseDatabaseLookupMessage(msg); err == nil {
			if err := fs.HandleDatabaseLookup(lookup); err != nil {
				log.WithError(err).Debug("Floodfill server lookup handling failed (non-fatal)")
			}
		}
	}
	return mr.RouteDatabaseMessage(msg)
}

// parseDatabaseStoreMessage extracts and parses DatabaseStore data from a BaseI2NPMessage.
// This converts the raw I2NP message into a structured DatabaseStore that implements
// the DatabaseWriter interface for NetDB storage.
func (r *Router) parseDatabaseStoreMessage(msg i2np.I2NPMessage) (*i2np.DatabaseStore, error) {
	// Extract raw message data from BaseI2NPMessage
	dataCarrier, ok := msg.(i2np.DataCarrier)
	if !ok {
		return nil, oops.Errorf("message does not implement DataCarrier interface")
	}

	// Create DatabaseStore and unmarshal the payload
	dbStore := &i2np.DatabaseStore{}
	if err := dbStore.UnmarshalBinary(dataCarrier.GetData()); err != nil {
		return nil, oops.Wrapf(err, "failed to unmarshal DatabaseStore")
	}

	log.WithFields(logger.Fields{
		"message_id": msg.MessageID(),
		"store_type": dbStore.GetStoreType(),
		"key":        dbStore.GetStoreKey().String(),
	}).Info("Parsed DatabaseStore message from peer")

	return dbStore, nil
}

// parseDatabaseLookupMessage extracts and parses a DatabaseLookup from a BaseI2NPMessage.
func (r *Router) parseDatabaseLookupMessage(msg i2np.I2NPMessage) (*i2np.DatabaseLookup, error) {
	dataCarrier, ok := msg.(i2np.DataCarrier)
	if !ok {
		return nil, oops.Errorf("message does not implement DataCarrier interface")
	}
	dl, err := i2np.ReadDatabaseLookup(dataCarrier.GetData())
	if err != nil {
		return nil, oops.Wrapf(err, "failed to parse DatabaseLookup")
	}
	return &dl, nil
}

// Session Management Methods

// addSession registers a new active session by peer hash.
// This method is called when a new NTCP2 connection is established,
// allowing the router to track active sessions for message routing.
// Thread-safe for concurrent access. No-ops if the session map is nil (after shutdown).
func (r *Router) addSession(peerHash common.Hash, session transport.TransportSession) {
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

	server, err := r.createI2CPServer()
	if err != nil {
		return err
	}

	r.configureI2CPServerInfrastructure(server)

	if err := server.Start(); err != nil {
		return oops.Wrapf(err, "failed to start I2CP server")
	}

	r.i2cpServer = server

	log.WithFields(logger.Fields{
		"address":      r.cfg.I2CP.Address,
		"network":      r.cfg.I2CP.Network,
		"max_sessions": r.cfg.I2CP.MaxSessions,
	}).Info("I2CP server started")

	return nil
}

// createI2CPServer creates a new I2CP server with the router's configuration.
func (r *Router) createI2CPServer() (*i2cp.Server, error) {
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
		return nil, oops.Wrapf(err, "failed to create I2CP server")
	}
	return server, nil
}

// configureI2CPServerInfrastructure sets up NetDB, auth, bandwidth, tunnels, and peer selection.
func (r *Router) configureI2CPServerInfrastructure(server *i2cp.Server) {
	server.SetNetDB(r.StdNetDB)

	if r.cfg.I2CP.Username != "" && r.cfg.I2CP.Password != "" {
		auth, authErr := i2cp.NewPasswordAuthenticator(r.cfg.I2CP.Username, r.cfg.I2CP.Password)
		if authErr == nil {
			server.SetAuthenticator(auth)
			log.WithFields(logger.Fields{"at": "configureI2CPServerInfrastructure"}).Info("I2CP server: authentication enabled")
		}
	}

	server.SetBandwidthProvider(&routerBandwidthProvider{cfg: r.cfg})

	if r.tunnelManager != nil {
		server.SetTunnelBuilder(r.tunnelManager)
		log.WithFields(logger.Fields{"at": "configureI2CPServerInfrastructure"}).Debug("I2CP server: tunnel builder configured")
	} else {
		log.WithFields(logger.Fields{"at": "configureI2CPServerInfrastructure"}).Debug("I2CP server: tunnel manager not available for session pools")
	}

	peerSelector, err := tunnel.NewDefaultPeerSelector(r.StdNetDB)
	if err != nil {
		log.WithError(err).Warn("Failed to create peer selector for I2CP sessions")
	} else {
		server.SetPeerSelector(peerSelector)
		log.WithFields(logger.Fields{"at": "configureI2CPServerInfrastructure"}).Debug("I2CP server: peer selector configured")
	}

	hostResolver, err := naming.NewHostsTxtResolver()
	if err != nil {
		log.WithError(err).Warn("Failed to create hostname resolver for I2CP")
	} else {
		server.SetHostnameResolver(hostResolver)
		log.WithFields(logger.Fields{"at": "configureI2CPServerInfrastructure"}).Debug("I2CP server: hostname resolver configured")
	}

	// Wire destination resolver backed by the NetDB so outbound SendMessage
	// calls can look up the recipient's X25519 public key for garlic encryption.
	destResolver := netdb.NewDestinationResolver(r.StdNetDB)
	server.SetDestinationResolver(destResolver)
	log.WithFields(logger.Fields{"at": "configureI2CPServerInfrastructure"}).Debug("I2CP server: destination resolver configured")

	// Wire message router for outbound I2CP message routing through garlic encryption
	// and into the tunnel subsystem. The garlic session manager is created from the
	// router's X25519 key and the transport send function routes via established sessions.
	r.wireI2CPMessageRouter(server)
}

// wireI2CPMessageRouter creates and injects a MessageRouter into the I2CP server.
// The MessageRouter handles outbound message encryption via garlic sessions and
// sends encrypted messages through the transport layer to tunnel gateways.
func (r *Router) wireI2CPMessageRouter(server *i2cp.Server) {
	privKeyBytes := r.RouterInfoKeystore.GetEncryptionPrivateKey().Bytes()
	var privKey [32]byte
	copy(privKey[:], privKeyBytes)

	garlicMgr, err := i2np.NewGarlicSessionManager(privKey)
	if err != nil {
		log.WithError(err).Error("I2CP server: failed to create garlic session manager — outbound routing disabled")
		return
	}

	transportSend := func(peerHash common.Hash, msg i2np.I2NPMessage) error {
		session, sErr := r.GetSessionByHash(peerHash)
		if sErr != nil {
			return oops.Wrapf(sErr, "no session for peer %x", peerHash[:8])
		}
		return session.QueueSendI2NP(msg)
	}

	msgRouter := i2cp.NewMessageRouter(garlicMgr, transportSend)
	server.SetMessageRouter(msgRouter)
	log.WithFields(logger.Fields{"at": "wireI2CPMessageRouter"}).Debug("I2CP server: message router configured for outbound routing")
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
func (r *Router) getSessionByHash(peerHash common.Hash) (transport.TransportSession, error) {
	r.sessionMutex.RLock()
	defer r.sessionMutex.RUnlock()

	if session, ok := r.activeSessions[peerHash]; ok {
		return session, nil
	}
	return nil, oops.Errorf("no session found for peer %x", peerHash[:8])
}

// GetSessionByHash implements SessionProvider interface for DatabaseManager.
// This enables the I2NP message processing layer to send responses back through
// the router's active transport sessions.
// NTCP2Session already implements the i2np.TransportSession interface.
// If no active session exists, it attempts to establish an outbound connection.
func (r *Router) GetSessionByHash(hash common.Hash) (i2np.I2NPTransportSession, error) {
	// Check if router is still running before proceeding
	r.runMux.RLock()
	running := r.running
	r.runMux.RUnlock()

	if !running {
		return nil, oops.Errorf("router is not running")
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
	routerInfoChan, err := r.getRouterInfoChannel(hash)
	if err != nil {
		return nil, err
	}
	return r.waitForRouterInfo(routerInfoChan, hash)
}

// getRouterInfoChannel initiates a RouterInfo lookup and returns the result channel.
func (r *Router) getRouterInfoChannel(hash common.Hash) (<-chan router_info.RouterInfo, error) {
	if r.StdNetDB == nil {
		return nil, oops.Errorf("router NetDB not available")
	}
	routerInfoChan := r.StdNetDB.GetRouterInfo(hash)
	if routerInfoChan == nil {
		return nil, oops.Errorf("no RouterInfo found for peer %x", hash[:8])
	}
	return routerInfoChan, nil
}

// waitForRouterInfo waits for a RouterInfo to arrive on the channel with timeout.
func (r *Router) waitForRouterInfo(ch <-chan router_info.RouterInfo, hash common.Hash) (*router_info.RouterInfo, error) {
	timer := time.NewTimer(30 * time.Second)
	defer timer.Stop()

	select {
	case routerInfo, ok := <-ch:
		if !ok {
			return nil, oops.Errorf("failed to receive RouterInfo for peer %x", hash[:8])
		}
		return &routerInfo, nil
	case <-timer.C:
		r.logRouterInfoTimeout(hash)
		return nil, oops.Errorf("timeout waiting for RouterInfo for peer %x", hash[:8])
	}
}

// establishOutboundSession creates a new transport session to a peer.
func (r *Router) establishOutboundSession(hash common.Hash, routerInfo *router_info.RouterInfo) (i2np.I2NPTransportSession, error) {
	if err := r.validateTransportMuxer(hash); err != nil {
		return nil, err
	}

	transportSession, err := r.TransportMuxer.GetSession(*routerInfo)
	if err != nil {
		r.logSessionEstablishmentFailure(hash, routerInfo, err)
		return nil, oops.Wrapf(err, "failed to establish outbound session")
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
		return oops.Errorf("transport not initialized for peer %x", hash[:8])
	}
	return nil
}

// registerNewSession stores a newly established session and starts a reader
// goroutine so that inbound I2NP messages on outbound sessions are processed.
// Without the reader goroutine, messages (e.g. tunnel build replies) pile up in
// the session's recvChan and are never consumed, which was the root cause of
// zero operational tunnels (RCA-1 / AUDIT.md).
func (r *Router) registerNewSession(hash common.Hash, transportSession i2np.I2NPTransportSession) {
	// Unwrap the trackedSession wrapper from TransportMuxer so the type switch
	// can match the concrete session type (NTCP2Session, SSU2Session).
	// Without this, the *trackedSession wrapper causes every case to miss,
	// falling through to the default branch and preventing reader goroutines
	// from starting on outbound sessions (see AUDIT-2026-04-09.md RCA-1).
	type unwrapper interface {
		Unwrap() transport.TransportSession
	}
	if uw, ok := transportSession.(unwrapper); ok {
		if inner, ok := uw.Unwrap().(i2np.I2NPTransportSession); ok {
			transportSession = inner
		}
	}

	switch s := transportSession.(type) {
	case *ntcp.NTCP2Session:
		r.addSession(hash, s)
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			r.processSessionMessages(s, staticAuthenticatedPeer{hash: hash, handshakeComplete: true})
		}()
		log.WithField("peer_hash", fmt.Sprintf("%x", hash[:8])).Info("Established and registered new outbound NTCP2 session")
	case *ssu2.SSU2Session:
		r.addSession(hash, s)
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			r.processSessionMessages(s, staticAuthenticatedPeer{hash: hash, handshakeComplete: true})
		}()
		log.WithField("peer_hash", fmt.Sprintf("%x", hash[:8])).Info("Established and registered new outbound SSU2 session")
	default:
		log.WithField("peer_hash", fmt.Sprintf("%x", hash[:8])).Warn("Unknown transport session type, cannot start reader goroutine")
	}
}

// logSessionEstablishmentFailure logs detailed context about session establishment failures.
// Downgraded from Error to Warn because the error is already returned to
// the caller; logging it again at Error inflated the apparent error count (E4/E5
// in the AUDIT report were the same event logged twice).
func (r *Router) logSessionEstablishmentFailure(hash common.Hash, routerInfo *router_info.RouterInfo, err error) {
	log.WithFields(logger.Fields{
		"at":            "Router.GetSessionByHash",
		"phase":         "session_establishment",
		"operation":     "outbound_connection",
		"peer_hash":     fmt.Sprintf("%x", hash[:8]),
		"error":         err.Error(),
		"address_count": len(routerInfo.RouterAddresses()),
		"has_ntcp2":     hasNTCP2Address(*routerInfo),
	}).Warn("failed to get session")
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
	muxer := r.TransportMuxer
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
	if r.StdNetDB == nil {
		return nil
	}
	allRIs := r.StdNetDB.GetAllRouterInfos()
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

// GetNetDB returns the network database for I2PControl statistics collection.
// Returns nil if NetDB has not been initialized.
