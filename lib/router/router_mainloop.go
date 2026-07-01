package router

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/go-i2p/lib/i2cp"
	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/go-i2p/go-i2p/lib/netdb"
	"github.com/go-i2p/go-i2p/lib/transport"
	ntcp "github.com/go-i2p/go-i2p/lib/transport/ntcp2"
	ssu2 "github.com/go-i2p/go-i2p/lib/transport/ssu2"
	"github.com/go-i2p/go-i2p/lib/util/logutil"
	ntcp2 "github.com/go-i2p/go-noise/ntcp2"
	ssu2noise "github.com/go-i2p/go-noise/ssu2"
	"github.com/samber/oops"

	"github.com/go-i2p/logger"
)

// ensureNetDBReady validates NetDB state and performs reseed if needed.
// Returns an error if the router's StdNetDB is nil (e.g. during shutdown).

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
	if err := r.initializeMessageRouter(); err != nil {
		r.startupErr <- oops.Wrapf(err, "message router initialization failed")
		r.Stop()
		return
	}
	if r.lookupClient == nil && r.transports != nil && r.messageRouter != nil {
		r.lookupClient = netdb.NewDatabaseLookupClient(&publisherTransportAdapter{muxer: r.transports})
		r.messageRouter.GetProcessor().SetLookupReplyDeliverer(r.lookupClient)
	}
	log.WithField("at", "mainloop").Debug("step 4: starting publisher")
	if err := r.startPublisher(); err != nil {
		r.startupErr <- oops.Wrapf(err, "publisher startup failed")
		r.Stop()
		return
	}
	if r.messageRouter != nil && r.publisher != nil {
		r.messageRouter.GetProcessor().SetDeliveryStatusHandler(r.publisher)
	}
	log.WithField("at", "mainloop").Debug("step 5: starting explorer")
	if err := r.startExplorer(); err != nil {
		r.startupErr <- oops.Wrapf(err, "explorer startup failed")
		r.Stop()
		return
	}
	log.WithField("at", "mainloop").Debug("step 6: starting floodfill server")
	r.startFloodfillServer()
	log.WithField("at", "mainloop").Debug("step 7: starting SSU2 NAT detection")
	r.startSSU2NATDetection()
	log.WithField("at", "mainloop").Debug("step 7b: starting hidden-mode introducer selector")
	r.startIntroducerSelector()
	log.WithField("at", "mainloop").Debug("step 7c: starting reachability loop")
	r.startReachabilityLoop()

	// Signal Start() that all startup-critical initialization succeeded
	log.WithField("at", "mainloop").Debug("signaling startup success")
	r.startupErr <- nil

	// Start health monitor for resource leak detection
	log.WithField("at", "mainloop").Debug("starting health monitor")
	r.startHealthMonitor()

	// Start read warn limiter cleanup for unbounded map prevention
	log.WithField("at", "mainloop").Debug("starting read warn limiter cleanup")
	r.startReadWarnLimiterCleanup()

	// Start session monitors for inbound message processing
	log.WithField("at", "mainloop").Debug("starting session monitors")
	r.startSessionMonitors()

	// Keep critical NetDB services alive and retry I2CP hash wiring after startup.
	log.WithField("at", "mainloop").Debug("starting NetDB service watchdog")
	r.startNetDBServiceWatchdog()

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

// wireInboundHandler sets up the InboundMessageHandler for tunnel-data processing.
// The handler is always created so exploratory/transit tunnel data remains functional
// even when I2CP is disabled.
func (r *Router) wireInboundHandler() {
	var sessionManager *i2cp.SessionManager
	if r.i2cpServer != nil {
		sessionManager = r.i2cpServer.GetSessionManager()
	}

	r.inboundHandler = NewInboundMessageHandler(sessionManager)
	log.WithFields(logger.Fields{
		"at":              "(Router) mainloop",
		"has_i2cp":        r.i2cpServer != nil,
		"has_session_mgr": sessionManager != nil,
		"reason":          "InboundMessageHandler initialized for tunnel-data processing",
	}).Debug("inbound message handler initialized")
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
	muxer := r.transports
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
	case *ntcp2.Addr:
		peerHash := common.Hash(addr.RouterHash())
		sessionLog := logger.WithField("peer_hash", logutil.HashPrefix(peerHash))
		session := ntcp.NewNTCP2Session(conn, r.ctx, sessionLog)
		session.AppendCleanupCallback(func() { r.removeSession(peerHash) })
		r.addSession(peerHash, session)
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			r.processSessionMessages(session, staticAuthenticatedPeer{hash: peerHash, handshakeComplete: true})
		}()
		sessionLog.Info("Started monitoring new inbound NTCP2 session")

	case *ssu2noise.SSU2Addr:
		peerHash := common.Hash(addr.RouterHash())
		sessionLog := logger.WithField("peer_hash", logutil.HashPrefix(peerHash))
		ssu2Conn, ok := conn.(*ssu2noise.SSU2Conn)
		if !ok {
			sessionLog.WithField("conn_type", fmt.Sprintf("%T", conn)).Error("Inbound SSU2 connection is not *ssu2noise.SSU2Conn, dropping")
			conn.Close()
			return
		}
		session := ssu2.NewSSU2Session(ssu2Conn, r.ctx, sessionLog)
		r.attachInboundSSU2TransportCallbacks(session)
		session.AppendCleanupCallback(func() { r.removeSession(peerHash) })
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

// attachInboundSSU2TransportCallbacks wires transport-level callbacks into an
// inbound SSU2 session when an SSU2 transport is active in the muxer.
func (r *Router) attachInboundSSU2TransportCallbacks(session *ssu2.SSU2Session) {
	if r == nil || r.transports == nil || session == nil {
		return
	}
	for _, tr := range r.transports.GetTransports() {
		if ssu2Tr, ok := tr.(*ssu2.SSU2Transport); ok {
			ssu2Tr.AttachTransportCallbacks(session)
			return
		}
	}
}

// i2npReader is a transport session that supports reading inbound I2NP messages.
// Both NTCP2Session and SSU2Session implement this interface.
type i2npReader interface {
	ReadNextI2NP() (i2np.Message, error)
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

// PeerHash returns the authenticated peer hash.
func (p staticAuthenticatedPeer) PeerHash() common.Hash {
	return p.hash
}

// HandshakeComplete reports whether the peer handshake completed.
func (p staticAuthenticatedPeer) HandshakeComplete() bool {
	return p.handshakeComplete
}
