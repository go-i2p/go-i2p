package i2cp

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/destination"
	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/go-i2p/logger"
)

// ServerConfig holds configuration for the I2CP server
type ServerConfig struct {
	// Address to listen on (e.g., "localhost:7654" or "/tmp/i2cp.sock" for Unix socket)
	ListenAddr string

	// Network type: "tcp" or "unix"
	Network string

	// Maximum number of concurrent sessions
	MaxSessions int

	// ReadTimeout is the maximum duration for reading requests from clients
	// Zero means no timeout. Default: 60 seconds
	ReadTimeout time.Duration

	// WriteTimeout is the maximum duration for writing responses to clients
	// Zero means no timeout. Default: 30 seconds
	WriteTimeout time.Duration

	// SessionTimeout is how long idle sessions stay alive before being closed
	// Zero means no timeout (sessions persist until explicit disconnect). Default: 30 minutes
	SessionTimeout time.Duration

	// LeaseSet publisher for distributing LeaseSets to the network (optional)
	// If nil, sessions will function but won't publish to the network
	LeaseSetPublisher LeaseSetPublisher
}

// DefaultServerConfig returns a ServerConfig with sensible defaults.
// This function delegates to config.DefaultI2CPConfig for consistency,
// ensuring a single source of truth for I2CP defaults.
func DefaultServerConfig() *ServerConfig {
	return &ServerConfig{
		ListenAddr:     config.DefaultI2CPConfig.Address,
		Network:        config.DefaultI2CPConfig.Network,
		MaxSessions:    config.DefaultI2CPConfig.MaxSessions,
		ReadTimeout:    60 * time.Second,
		WriteTimeout:   30 * time.Second,
		SessionTimeout: 30 * time.Minute,
	}
}

// connectionState tracks per-connection rate limiting state
type connectionState struct {
	lastMessageTime time.Time
	messageCount    int
	bytesRead       uint64
}

// Server is an I2CP protocol server that accepts client connections
type Server struct {
	config  *ServerConfig
	manager *SessionManager

	listener net.Listener

	// Message routing
	messageRouter *MessageRouter

	// Destination resolution
	destinationResolver interface {
		ResolveDestination(destHash common.Hash) ([32]byte, error)
	}

	// NetDB access for HostLookup queries
	netdb interface {
		GetLeaseSetBytes(hash common.Hash) ([]byte, error)
	}

	// Tunnel infrastructure for session tunnel pool initialization
	tunnelBuilder tunnel.BuilderInterface
	peerSelector  tunnel.PeerSelector

	// Connection tracking for message delivery
	mu           sync.RWMutex
	running      bool
	sessionConns map[uint16]net.Conn // Session ID -> active connection

	// Per-connection write serialization to prevent concurrent writes
	// from corrupting the I2CP wire stream
	connWriteMu map[uint16]*sync.Mutex // Session ID -> write mutex

	// Connection-level rate limiting to prevent abuse before session creation
	connMutex  sync.RWMutex
	connStates map[net.Conn]*connectionState

	// LeaseSet publishing
	leaseSetPublisher LeaseSetPublisher

	// Message ID generation for status tracking
	nextMessageID atomic.Uint32

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// GetSessionManager returns the underlying SessionManager.
// This is used by the Router to wire InboundMessageHandler for tunnel-to-session delivery.
func (s *Server) GetSessionManager() *SessionManager {
	return s.manager
}

// NewServer creates a new I2CP server
func NewServer(config *ServerConfig) (*Server, error) {
	if config == nil {
		config = DefaultServerConfig()
	}

	log.WithFields(logger.Fields{
		"at":          "i2cp.NewServer",
		"network":     config.Network,
		"listenAddr":  config.ListenAddr,
		"maxSessions": config.MaxSessions,
	}).Info("creating_i2cp_server")

	ctx, cancel := context.WithCancel(context.Background())

	return &Server{
		config:            config,
		manager:           NewSessionManager(),
		sessionConns:      make(map[uint16]net.Conn),
		connWriteMu:       make(map[uint16]*sync.Mutex),
		connStates:        make(map[net.Conn]*connectionState),
		leaseSetPublisher: config.LeaseSetPublisher,
		ctx:               ctx,
		cancel:            cancel,
	}, nil
}

// Start begins listening for I2CP connections
func (s *Server) Start() error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return fmt.Errorf("server already running")
	}
	s.running = true
	s.mu.Unlock()

	// Create listener
	listener, err := net.Listen(s.config.Network, s.config.ListenAddr)
	if err != nil {
		s.mu.Lock()
		s.running = false
		s.mu.Unlock()
		return fmt.Errorf("failed to listen on %s: %w", s.config.ListenAddr, err)
	}

	s.listener = listener

	log.WithFields(logger.Fields{
		"at":      "i2cp.Server.Start",
		"network": s.config.Network,
		"address": s.config.ListenAddr,
	}).Info("i2cp_server_started")

	// Start accept loop
	s.wg.Add(1)
	go s.acceptLoop()

	// Start session timeout cleanup goroutine if timeout is configured
	if s.config.SessionTimeout > 0 {
		s.wg.Add(1)
		go s.sessionTimeoutCleanup()
	}

	return nil
}

// Stop gracefully stops the server
func (s *Server) Stop() error {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return nil
	}
	s.running = false
	s.mu.Unlock()

	// Cancel context to signal all goroutines
	s.cancel()

	// Close listener
	if s.listener != nil {
		if err := s.listener.Close(); err != nil {
			log.WithError(err).Warn("error_closing_listener")
		}
	}

	// Stop all sessions
	s.manager.StopAll()

	// Wait for all goroutines
	s.wg.Wait()

	log.WithField("at", "i2cp.Server.Stop").Info("i2cp_server_stopped")

	return nil
}

// SetTunnelBuilder sets the tunnel builder for session tunnel pool initialization.
// Must be called before sessions are created. Thread-safe.
func (s *Server) SetTunnelBuilder(builder tunnel.BuilderInterface) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tunnelBuilder = builder
	log.WithFields(logger.Fields{
		"at":     "i2cp.Server.SetTunnelBuilder",
		"reason": "tunnel builder configured",
	}).Debug("tunnel builder set for I2CP server")
}

// SetPeerSelector sets the peer selector for session tunnel pool initialization.
// Must be called before sessions are created. Thread-safe.
func (s *Server) SetPeerSelector(selector tunnel.PeerSelector) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.peerSelector = selector
	log.WithFields(logger.Fields{
		"at":     "i2cp.Server.SetPeerSelector",
		"reason": "peer selector configured",
	}).Debug("peer selector set for I2CP server")
}

// recoverFromAcceptPanic recovers from any panic in the accept loop to prevent server crash.
func recoverFromAcceptPanic() {
	if r := recover(); r != nil {
		log.WithFields(logger.Fields{
			"at":    "i2cp.Server.acceptLoop",
			"panic": r,
		}).Error("panic_in_accept_loop")
	}
}

// acceptAndLogConnection accepts a new connection and logs the connection attempt.
// Returns the accepted connection and a boolean indicating if the loop should terminate.
func (s *Server) acceptAndLogConnection() (net.Conn, bool) {
	conn, err := s.listener.Accept()
	if err != nil {
		return nil, s.handleAcceptError(err)
	}

	log.WithFields(logger.Fields{
		"at":         "i2cp.Server.acceptLoop",
		"remoteAddr": conn.RemoteAddr().String(),
		"localAddr":  conn.LocalAddr().String(),
	}).Info("new_i2cp_connection")

	return conn, false
}

// acceptLoop accepts incoming connections
func (s *Server) acceptLoop() {
	defer s.wg.Done()
	defer recoverFromAcceptPanic()

	for {
		conn, shouldStop := s.acceptAndLogConnection()
		if shouldStop {
			return
		}
		if conn == nil {
			continue
		}

		if s.shouldRejectConnection(conn) {
			continue
		}

		s.wg.Add(1)
		go s.handleConnection(conn)
	}
}

// sessionTimeoutCleanup periodically checks for idle sessions and closes them
func (s *Server) sessionTimeoutCleanup() {
	defer s.wg.Done()

	// Check for idle sessions every minute
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	log.WithFields(logger.Fields{
		"at":             "i2cp.Server.sessionTimeoutCleanup",
		"sessionTimeout": s.config.SessionTimeout,
	}).Info("session_timeout_cleanup_started")

	for {
		select {
		case <-ticker.C:
			s.cleanupIdleSessions()
		case <-s.ctx.Done():
			return
		}
	}
}

// cleanupIdleSessions checks all sessions and closes those that have been idle beyond SessionTimeout
func (s *Server) cleanupIdleSessions() {
	sessions := s.manager.GetAllSessions()
	now := time.Now()

	for _, session := range sessions {
		if !session.IsActive() {
			continue
		}

		idleTime := now.Sub(session.LastActivity())
		if idleTime > s.config.SessionTimeout {
			log.WithFields(logger.Fields{
				"at":        "i2cp.Server.cleanupIdleSessions",
				"sessionID": session.ID(),
				"idleTime":  idleTime,
				"timeout":   s.config.SessionTimeout,
			}).Info("closing_idle_session")

			// Stop the session
			session.Stop()

			// Remove from server's session tracking
			s.mu.Lock()
			delete(s.sessionConns, session.ID())
			delete(s.connWriteMu, session.ID())
			s.mu.Unlock()

			// Remove from manager
			s.manager.RemoveSession(session.ID())
		}
	}
}

// handleAcceptError processes errors from listener.Accept().
// Returns true if the accept loop should terminate, false to continue.
func (s *Server) handleAcceptError(err error) bool {
	select {
	case <-s.ctx.Done():
		// Server is shutting down
		return true
	default:
		log.WithError(err).Error("failed_to_accept_connection")
		return false
	}
}

// shouldRejectConnection checks if a connection should be rejected due to session limits.
// Closes the connection if rejected.
func (s *Server) shouldRejectConnection(conn net.Conn) bool {
	if s.manager.SessionCount() >= s.config.MaxSessions {
		log.WithFields(logger.Fields{
			"at":           "i2cp.Server.shouldRejectConnection",
			"sessionCount": s.manager.SessionCount(),
			"maxSessions":  s.config.MaxSessions,
			"remoteAddr":   conn.RemoteAddr().String(),
		}).Warn("max_sessions_reached_rejecting_connection")
		conn.Close()
		return true
	}
	return false
}

// handleConnection processes a single client connection
func (s *Server) handleConnection(conn net.Conn) {
	defer s.wg.Done()
	defer conn.Close()
	defer s.cleanupConnectionState(conn)

	s.logClientConnected(conn)

	// Read and validate protocol version byte (0x2a) per I2CP specification.
	// This must be the first byte sent by the client before any I2CP messages.
	if !s.readProtocolByte(conn) {
		return
	}

	var session *Session
	defer s.cleanupSessionConnection(&session)

	s.runConnectionLoop(conn, &session)
}

// logClientConnected logs when a client connects to the server.
func (s *Server) logClientConnected(conn net.Conn) {
	// i2psnark compatibility: Track client connection details for debugging
	log.WithFields(logger.Fields{
		"at":             "i2cp.Server.handleConnection",
		"remoteAddr":     conn.RemoteAddr().String(),
		"localAddr":      conn.LocalAddr().String(),
		"network":        conn.RemoteAddr().Network(),
		"activeSessions": s.manager.SessionCount(),
	}).Info("client_connected")
}

// cleanupSessionConnection removes the session connection mapping on disconnect.
func (s *Server) cleanupSessionConnection(sessionPtr **Session) {
	if *sessionPtr != nil {
		sessionID := (*sessionPtr).ID()
		s.mu.Lock()
		delete(s.sessionConns, sessionID)
		delete(s.connWriteMu, sessionID)
		s.mu.Unlock()
		log.WithFields(logger.Fields{
			"at":        "i2cp.Server.cleanupSessionConnection",
			"sessionID": sessionID,
		}).Debug("client_disconnected")
	}
}

// getConnWriteMutex returns the per-connection write mutex for the given session.
// Returns nil if the session is not tracked. The caller must hold s.mu.RLock
// to call this safely.
func (s *Server) getConnWriteMutex(sessionID uint16) *sync.Mutex {
	return s.connWriteMu[sessionID]
}

// cleanupConnectionState removes connection state tracking on disconnect.
func (s *Server) cleanupConnectionState(conn net.Conn) {
	s.connMutex.Lock()
	delete(s.connStates, conn)
	s.connMutex.Unlock()
}

// readProtocolByte reads and validates the I2CP protocol version byte (0x2a).
// Per I2CP specification, this must be the first byte sent by the client.
// Returns true if the protocol byte is valid, false otherwise.
func (s *Server) readProtocolByte(conn net.Conn) bool {
	protocolByte := make([]byte, 1)
	if _, err := io.ReadFull(conn, protocolByte); err != nil {
		log.WithFields(logger.Fields{
			"at":         "i2cp.Server.readProtocolByte",
			"remoteAddr": conn.RemoteAddr().String(),
			"error":      err.Error(),
		}).Error("failed_to_read_protocol_byte")
		return false
	}

	const expectedProtocolByte = 0x2a
	if protocolByte[0] != expectedProtocolByte {
		log.WithFields(logger.Fields{
			"at":         "i2cp.Server.readProtocolByte",
			"remoteAddr": conn.RemoteAddr().String(),
			"expected":   fmt.Sprintf("0x%02x", expectedProtocolByte),
			"received":   fmt.Sprintf("0x%02x", protocolByte[0]),
		}).Error("invalid_protocol_byte")
		return false
	}

	log.WithFields(logger.Fields{
		"at":           "i2cp.Server.readProtocolByte",
		"remoteAddr":   conn.RemoteAddr().String(),
		"protocolByte": fmt.Sprintf("0x%02x", protocolByte[0]),
	}).Info("protocol_handshake_successful")

	return true
}

// runConnectionLoop processes messages from the client connection.
func (s *Server) runConnectionLoop(conn net.Conn, sessionPtr **Session) {
	for {
		if s.shouldStopConnectionLoop() {
			return
		}

		if !s.processOneMessage(conn, sessionPtr) {
			return
		}
	}
}

// shouldStopConnectionLoop checks if the connection loop should terminate.
func (s *Server) shouldStopConnectionLoop() bool {
	select {
	case <-s.ctx.Done():
		return true
	default:
		return false
	}
}

// processOneMessage handles a single message from the client connection.
// Returns false if the connection should be closed, true to continue.
func (s *Server) processOneMessage(conn net.Conn, sessionPtr **Session) bool {
	msg, err := s.readClientMessage(conn)
	if err != nil {
		return false
	}

	s.logReceivedMessage(msg)

	response, err := s.processClientMessage(msg, sessionPtr)
	if err != nil {
		return true // Continue despite processing error
	}

	s.handleNewSessionTracking(msg, sessionPtr, conn)

	if err := s.sendResponse(conn, response, sessionPtr); err != nil {
		return false
	}

	return true
}

// readClientMessage reads an I2CP message from the connection with rate limiting.
func (s *Server) readClientMessage(conn net.Conn) (*Message, error) {
	// Set read deadline if timeout is configured
	if s.config.ReadTimeout > 0 {
		if err := conn.SetReadDeadline(time.Now().Add(s.config.ReadTimeout)); err != nil {
			log.WithFields(logger.Fields{
				"at":    "i2cp.Server.readClientMessage",
				"error": err.Error(),
			}).Warn("failed_to_set_read_deadline")
		}
	}

	// Check connection-level rate limits before reading
	if !s.checkConnectionRateLimit(conn) {
		state := s.getOrCreateConnectionState(conn)
		log.WithFields(logger.Fields{
			"at":           "i2cp.Server.readClientMessage",
			"remoteAddr":   conn.RemoteAddr().String(),
			"messageCount": state.messageCount,
			"bytesRead":    state.bytesRead,
		}).Warn("connection_rate_limit_exceeded")
		return nil, fmt.Errorf("connection rate limit exceeded")
	}

	msg, err := ReadMessage(conn)
	if err != nil {
		// i2psnark compatibility: Log connection state on read failures
		state := s.getOrCreateConnectionState(conn)
		log.WithFields(logger.Fields{
			"at":           "i2cp.Server.readClientMessage",
			"remoteAddr":   conn.RemoteAddr().String(),
			"error":        err.Error(),
			"messageCount": state.messageCount,
			"bytesRead":    state.bytesRead,
		}).Warn("failed_to_read_message")
		return nil, err
	}

	// Update connection state after successful read
	s.updateConnectionState(conn, msg)

	return msg, nil
}

// checkConnectionRateLimit enforces per-connection rate limits.
// Returns true if the connection is within limits, false if rate limited.
// Conservative limits prevent resource exhaustion from malicious clients,
// especially during pre-session phase before authentication is complete.
// Legitimate I2CP clients rarely exceed these limits.
func (s *Server) checkConnectionRateLimit(conn net.Conn) bool {
	const (
		maxMessagesPerSecond = 100                   // Maximum 100 messages/second per connection (conservative for security)
		maxBytesPerSecond    = 10 * 1024 * 1024      // Maximum 10 MB/second per connection
		minMessageInterval   = 10 * time.Millisecond // Minimum 10ms between messages (prevents rapid-fire attacks)
	)

	state := s.getOrCreateConnectionState(conn)
	now := time.Now()
	elapsed := now.Sub(state.lastMessageTime)

	// Reset counters every second
	s.resetCountersIfNeeded(state, elapsed)

	// Check all rate limits
	return s.isWithinRateLimits(state, elapsed, maxMessagesPerSecond, maxBytesPerSecond, minMessageInterval)
}

// getOrCreateConnectionState retrieves or creates connection state.
func (s *Server) getOrCreateConnectionState(conn net.Conn) *connectionState {
	s.connMutex.Lock()
	defer s.connMutex.Unlock()

	state, exists := s.connStates[conn]
	if !exists {
		state = &connectionState{
			lastMessageTime: time.Time{}, // Zero value allows first message immediately
			messageCount:    0,
			bytesRead:       0,
		}
		s.connStates[conn] = state
	}
	return state
}

// resetCountersIfNeeded resets rate limit counters after one second.
func (s *Server) resetCountersIfNeeded(state *connectionState, elapsed time.Duration) {
	if elapsed >= time.Second {
		state.messageCount = 0
		state.bytesRead = 0
	}
}

// isWithinRateLimits checks if connection is within all rate limits.
func (s *Server) isWithinRateLimits(state *connectionState, elapsed time.Duration, maxMessages, maxBytes int, minInterval time.Duration) bool {
	// Check message rate limit
	if state.messageCount >= maxMessages {
		return false
	}

	// Check bandwidth limit
	if state.bytesRead >= uint64(maxBytes) {
		return false
	}

	// Only enforce minimum interval if we're approaching the rate limit
	// This allows legitimate bursts while preventing extreme abuse
	if state.messageCount > maxMessages/10 && elapsed < minInterval {
		return false
	}

	return true
}

// updateConnectionState updates connection statistics after reading a message.
func (s *Server) updateConnectionState(conn net.Conn, msg *Message) {
	s.connMutex.Lock()
	defer s.connMutex.Unlock()

	if state, exists := s.connStates[conn]; exists {
		state.lastMessageTime = time.Now()
		state.messageCount++
		state.bytesRead += uint64(7 + len(msg.Payload)) // Header + payload
	}
}

// logReceivedMessage logs details about a received message.
func (s *Server) logReceivedMessage(msg *Message) {
	log.WithFields(logger.Fields{
		"at":          "i2cp.Server.handleConnection",
		"type":        MessageTypeName(msg.Type),
		"typeID":      msg.Type,
		"sessionID":   msg.SessionID,
		"payloadSize": len(msg.Payload),
	}).Debug("received_message")
}

// processClientMessage handles a client message and returns a response.
func (s *Server) processClientMessage(msg *Message, sessionPtr **Session) (*Message, error) {
	response, err := s.handleMessage(msg, sessionPtr)
	if err != nil {
		log.WithError(err).Error("failed_to_handle_message")
		return nil, err
	}
	return response, nil
}

// handleNewSessionTracking tracks new session connections and starts message delivery.
func (s *Server) handleNewSessionTracking(msg *Message, sessionPtr **Session, conn net.Conn) {
	if *sessionPtr != nil && msg.Type == MessageTypeCreateSession {
		s.mu.Lock()
		s.sessionConns[(*sessionPtr).ID()] = conn
		s.connWriteMu[(*sessionPtr).ID()] = &sync.Mutex{}
		s.mu.Unlock()

		s.wg.Add(1)
		go s.deliverMessagesToClient(*sessionPtr, conn)

		// Start tunnel monitoring to send RequestVariableLeaseSet when ready
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.monitorTunnelsAndRequestLeaseSet(*sessionPtr, conn)
		}()
	}
}

// sendResponse writes a response message to the connection if present.
// Uses per-connection write mutex to prevent concurrent write corruption.
func (s *Server) sendResponse(conn net.Conn, response *Message, sessionPtr **Session) error {
	if response != nil {
		// Set write deadline if timeout is configured
		if s.config.WriteTimeout > 0 {
			if err := conn.SetWriteDeadline(time.Now().Add(s.config.WriteTimeout)); err != nil {
				log.WithFields(logger.Fields{
					"at":    "i2cp.Server.sendResponse",
					"error": err.Error(),
				}).Warn("failed_to_set_write_deadline")
			}
		}

		log.WithFields(logger.Fields{
			"at":          "i2cp.Server.sendResponse",
			"type":        MessageTypeName(response.Type),
			"sessionID":   response.SessionID,
			"payloadSize": len(response.Payload),
		}).Debug("sending_response")

		// Acquire per-connection write mutex if session exists
		var writeMu *sync.Mutex
		if *sessionPtr != nil {
			s.mu.RLock()
			writeMu = s.connWriteMu[(*sessionPtr).ID()]
			s.mu.RUnlock()
		}

		if writeMu != nil {
			writeMu.Lock()
		}
		err := WriteMessage(conn, response)
		if writeMu != nil {
			writeMu.Unlock()
		}

		if err != nil {
			log.WithFields(logger.Fields{
				"at":    "i2cp.Server.sendResponse",
				"type":  MessageTypeName(response.Type),
				"error": err.Error(),
			}).Error("failed_to_write_response")
			return err
		}
	}
	return nil
}

// handleMessage processes a single I2CP message and returns an optional response
func (s *Server) handleMessage(msg *Message, sessionPtr **Session) (*Message, error) {
	// i2psnark compatibility: Log all incoming messages for debugging
	var currentSessionID uint16
	if *sessionPtr != nil {
		currentSessionID = (*sessionPtr).ID()
	}

	log.WithFields(logger.Fields{
		"at":               "i2cp.Server.handleMessage",
		"msgType":          MessageTypeName(msg.Type),
		"msgTypeID":        msg.Type,
		"msgSessionID":     msg.SessionID,
		"currentSessionID": currentSessionID,
		"payloadSize":      len(msg.Payload),
	}).Debug("processing_i2cp_message")

	switch msg.Type {
	case MessageTypeCreateSession:
		return s.handleCreateSession(msg, sessionPtr)

	case MessageTypeDestroySession:
		return s.handleDestroySession(msg, sessionPtr)

	case MessageTypeReconfigureSession:
		return s.handleReconfigureSession(msg, sessionPtr)

	case MessageTypeCreateLeaseSet:
		return s.handleCreateLeaseSet(msg, sessionPtr)

	case MessageTypeCreateLeaseSet2:
		return s.handleCreateLeaseSet2(msg, sessionPtr)

	case MessageTypeGetDate:
		return s.handleGetDate(msg)

	case MessageTypeGetBandwidthLimits:
		return s.handleGetBandwidthLimits(msg)

	case MessageTypeSendMessage:
		return s.handleSendMessage(msg, sessionPtr)

	case MessageTypeSendMessageExpires:
		return s.handleSendMessageExpires(msg, sessionPtr)

	case MessageTypeDisconnect:
		return s.handleDisconnect(msg, sessionPtr)

	case MessageTypeHostLookup:
		return s.handleHostLookup(msg)

	case MessageTypeBlindingInfo:
		return s.handleBlindingInfo(msg, sessionPtr)

	default:
		// i2psnark compatibility: Log unsupported message types with full context
		log.WithFields(logger.Fields{
			"at":          "i2cp.Server.handleMessage",
			"msgType":     MessageTypeName(msg.Type),
			"msgTypeID":   msg.Type,
			"sessionID":   msg.SessionID,
			"payloadSize": len(msg.Payload),
			"payloadHex":  fmt.Sprintf("%x", msg.Payload[:min(32, len(msg.Payload))]),
		}).Warn("unsupported_message_type")
		return nil, fmt.Errorf("unsupported message type: %d", msg.Type)
	}
}

// handleCreateSession creates a new session
func (s *Server) handleCreateSession(msg *Message, sessionPtr **Session) (*Message, error) {
	// Parse and validate session configuration
	dest, config := parseSessionConfiguration(msg.Payload)

	// Create session with parsed or default configuration
	// If dest is nil, NewSession will generate a new destination
	session, err := s.manager.CreateSession(dest, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	// Configure LeaseSet publisher if available
	if s.leaseSetPublisher != nil {
		session.SetLeaseSetPublisher(s.leaseSetPublisher)
	}

	// Initialize tunnel pools with builders if available
	if err := s.initializeSessionTunnelPools(session, config); err != nil {
		// Log warning but don't fail session creation - pools can be set up later
		log.WithFields(logger.Fields{
			"at":        "i2cp.Server.handleCreateSession",
			"sessionID": session.ID(),
			"error":     err.Error(),
		}).Warn("failed to initialize tunnel pools")
	}

	*sessionPtr = session

	// i2psnark compatibility: Log detailed session creation info
	log.WithFields(logger.Fields{
		"at":                     "i2cp.Server.handleCreateSession",
		"sessionID":              session.ID(),
		"inbound_tunnel_length":  config.InboundTunnelLength,
		"outbound_tunnel_length": config.OutboundTunnelLength,
		"inbound_tunnel_count":   config.InboundTunnelCount,
		"outbound_tunnel_count":  config.OutboundTunnelCount,
		"payloadSize":            len(msg.Payload),
		"hasDestination":         dest != nil,
	}).Info("session_created")

	// Build success response
	return buildSessionStatusResponse(session.ID()), nil
}

// parseSessionConfiguration extracts and validates session configuration from payload.
// Returns destination and configuration, using defaults when payload is empty or invalid.
func parseSessionConfiguration(payload []byte) (*destination.Destination, *SessionConfig) {
	// Empty payload - use defaults (backward compatibility with tests)
	if len(payload) == 0 {
		log.WithFields(logger.Fields{
			"at":           "parseSessionConfiguration",
			"reason":       "empty_payload_backward_compat",
			"payload_size": 0,
		}).Debug("using default session config")
		return nil, DefaultSessionConfig()
	}

	// Parse destination and session configuration from payload
	dest, config, err := ParseCreateSessionPayload(payload)
	if err != nil {
		log.WithFields(logger.Fields{
			"at":           "parseSessionConfiguration",
			"reason":       "parse_failure",
			"payload_size": len(payload),
			"error":        err.Error(),
		}).Warn("failed to parse create session payload, using defaults")
		return nil, DefaultSessionConfig()
	}

	// Validate the parsed configuration
	if err := ValidateSessionConfig(config); err != nil {
		log.WithFields(logger.Fields{
			"at":           "parseSessionConfiguration",
			"reason":       "validation_failure",
			"payload_size": len(payload),
			"error":        err.Error(),
		}).Warn("invalid session config, using defaults")
		return dest, DefaultSessionConfig()
	}

	return dest, config
}

// initializeSessionTunnelPools creates and configures tunnel pools for a session.
// This requires both tunnelBuilder and peerSelector to be set via SetTunnelBuilder
// and SetPeerSelector. If either is missing, pools are not initialized and an error
// is returned (but session creation can still proceed).
func (s *Server) initializeSessionTunnelPools(session *Session, config *SessionConfig) error {
	s.mu.RLock()
	builder := s.tunnelBuilder
	selector := s.peerSelector
	s.mu.RUnlock()

	// Check if tunnel infrastructure is available
	if builder == nil || selector == nil {
		return fmt.Errorf("tunnel infrastructure not configured (builder=%v, selector=%v)",
			builder != nil, selector != nil)
	}

	// Create inbound tunnel pool
	inboundConfig := tunnel.PoolConfig{
		MinTunnels:       config.InboundTunnelCount,
		MaxTunnels:       config.InboundTunnelCount + 2, // Allow some extra capacity
		TunnelLifetime:   10 * time.Minute,
		RebuildThreshold: 2 * time.Minute,
		BuildRetryDelay:  2 * time.Second,
		MaxBuildRetries:  3,
		HopCount:         config.InboundTunnelLength,
		IsInbound:        true,
	}
	inboundPool := tunnel.NewTunnelPoolWithConfig(selector, inboundConfig)
	inboundPool.SetTunnelBuilder(builder)
	session.SetInboundPool(inboundPool)

	// Create outbound tunnel pool
	outboundConfig := tunnel.PoolConfig{
		MinTunnels:       config.OutboundTunnelCount,
		MaxTunnels:       config.OutboundTunnelCount + 2, // Allow some extra capacity
		TunnelLifetime:   10 * time.Minute,
		RebuildThreshold: 2 * time.Minute,
		BuildRetryDelay:  2 * time.Second,
		MaxBuildRetries:  3,
		HopCount:         config.OutboundTunnelLength,
		IsInbound:        false,
	}
	outboundPool := tunnel.NewTunnelPoolWithConfig(selector, outboundConfig)
	outboundPool.SetTunnelBuilder(builder)
	session.SetOutboundPool(outboundPool)

	log.WithFields(logger.Fields{
		"at":                    "i2cp.Server.initializeSessionTunnelPools",
		"sessionID":             session.ID(),
		"inbound_hop_count":     config.InboundTunnelLength,
		"outbound_hop_count":    config.OutboundTunnelLength,
		"inbound_tunnel_count":  config.InboundTunnelCount,
		"outbound_tunnel_count": config.OutboundTunnelCount,
	}).Info("tunnel_pools_initialized")

	return nil
}

// buildSessionStatusResponse creates a successful SessionStatus message.
// Per I2CP spec: SessionStatus payload is SessionID(2 bytes) + Status(1 byte)
func buildSessionStatusResponse(sessionID uint16) *Message {
	payload := make([]byte, 3)
	binary.BigEndian.PutUint16(payload[0:2], sessionID) // SessionID
	payload[2] = 0x00                                   // Success status byte

	return &Message{
		Type:      MessageTypeSessionStatus,
		SessionID: sessionID, // Keep for application logic
		Payload:   payload,
	}
}

// buildMessageStatusResponse creates a MessageStatus message.
// Per I2CP spec, MessageStatus payload format (15 bytes):
// - 2 bytes: Session ID (uint16, big endian)
// - 4 bytes: Message ID (uint32, big endian)
// - 1 byte:  Status code
// - 4 bytes: Message size (uint32, big endian)
// - 4 bytes: Nonce (uint32, big endian)
func buildMessageStatusResponse(sessionID uint16, messageID uint32, statusCode uint8, messageSize, nonce uint32) *Message {
	payload := make([]byte, 15)
	binary.BigEndian.PutUint16(payload[0:2], sessionID)    // SessionID
	binary.BigEndian.PutUint32(payload[2:6], messageID)    // MessageID
	payload[6] = statusCode                                // Status
	binary.BigEndian.PutUint32(payload[7:11], messageSize) // Message size
	binary.BigEndian.PutUint32(payload[11:15], nonce)      // Nonce

	return &Message{
		Type:      MessageTypeMessageStatus,
		SessionID: sessionID, // Keep for application logic
		Payload:   payload,
	}
}

// handleDestroySession destroys a session
func (s *Server) handleDestroySession(msg *Message, sessionPtr **Session) (*Message, error) {
	if *sessionPtr == nil {
		return nil, fmt.Errorf("session not active")
	}

	sessionID := (*sessionPtr).ID()

	if err := s.manager.DestroySession(sessionID); err != nil {
		return nil, fmt.Errorf("failed to destroy session: %w", err)
	}

	*sessionPtr = nil

	log.WithFields(logger.Fields{
		"at":        "i2cp.Server.handleDestroySession",
		"reason":    "client_requested",
		"sessionID": sessionID,
	}).Info("session_destroyed")

	// Per I2CP spec, return SessionStatus(Destroyed) to confirm session termination
	// Status code 0 = Destroyed
	return &Message{
		Type:      MessageTypeSessionStatus,
		SessionID: sessionID,
		Payload:   []byte{0}, // Status 0 = Destroyed
	}, nil
}

// monitorTunnelsAndRequestLeaseSet monitors a session's tunnel pools and sends
// RequestVariableLeaseSet (type 37) when tunnels are ready. This is required by
// I2CP protocol - the router must tell the client when to publish its LeaseSet.
//
// Per I2CP spec: After session creation, router waits for inbound+outbound tunnels,
// then sends type 37 with lease data. Client responds with CreateLeaseSet (type 5).
//
// TODO: Full tunnel pool integration required. The router must:
// 1. Attach tunnel pools with proper TunnelBuilder during session creation
// 2. Provide peer selector for tunnel hop selection
// 3. Integrate with transport layer for tunnel establishment
// 4. Set up tunnel lifecycle management (expiry, rotation)
// Currently pools may not build tunnels automatically without this integration.
func (s *Server) monitorTunnelsAndRequestLeaseSet(session *Session, conn net.Conn) {
	sessionID := session.ID()
	logMonitoringStart(sessionID)

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	timeout := time.After(2 * time.Minute)
	s.waitForTunnelReadiness(session, conn, sessionID, ticker, timeout)
}

// waitForTunnelReadiness polls tunnel pools until tunnels are ready, context is cancelled, or timeout occurs.
func (s *Server) waitForTunnelReadiness(session *Session, conn net.Conn, sessionID uint16, ticker *time.Ticker, timeout <-chan time.Time) {
	for {
		if s.checkMonitoringEvent(session, conn, sessionID, ticker, timeout) {
			return
		}
	}
}

// checkMonitoringEvent processes a single monitoring event and returns true if monitoring should stop.
func (s *Server) checkMonitoringEvent(session *Session, conn net.Conn, sessionID uint16, ticker *time.Ticker, timeout <-chan time.Time) bool {
	select {
	case <-s.ctx.Done():
		log.WithFields(logger.Fields{
			"at":        "i2cp.Server.monitorTunnelsAndRequestLeaseSet",
			"sessionID": sessionID,
		}).Debug("context_cancelled_stopping_tunnel_monitoring")
		return true

	case <-timeout:
		logTimeoutWaitingForTunnels(sessionID)
		return true

	case <-ticker.C:
		if tunnels, ready := checkTunnelReadiness(session); ready {
			s.handleTunnelsReady(session, conn, sessionID, tunnels)
			return true
		}
		return false
	}
}

// logMonitoringStart logs the start of tunnel monitoring.
func logMonitoringStart(sessionID uint16) {
	log.WithFields(logger.Fields{
		"at":        "i2cp.Server.monitorTunnelsAndRequestLeaseSet",
		"sessionID": sessionID,
	}).Debug("starting_tunnel_monitoring")
}

// logTimeoutWaitingForTunnels logs when tunnel monitoring times out.
func logTimeoutWaitingForTunnels(sessionID uint16) {
	log.WithFields(logger.Fields{
		"at":        "i2cp.Server.monitorTunnelsAndRequestLeaseSet",
		"sessionID": sessionID,
	}).Warn("timeout_waiting_for_tunnels")
}

// tunnelReadinessResult holds tunnel readiness check results.
type tunnelReadinessResult struct {
	inboundTunnels  []*tunnel.TunnelState
	outboundTunnels []*tunnel.TunnelState
}

// checkTunnelReadiness verifies if both inbound and outbound tunnels are available and active.
func checkTunnelReadiness(session *Session) (tunnelReadinessResult, bool) {
	result := tunnelReadinessResult{}

	inboundPool := session.InboundPool()
	outboundPool := session.OutboundPool()

	if inboundPool == nil || outboundPool == nil {
		return result, false
	}

	result.inboundTunnels = inboundPool.GetActiveTunnels()
	result.outboundTunnels = outboundPool.GetActiveTunnels()

	if len(result.inboundTunnels) == 0 || len(result.outboundTunnels) == 0 {
		return result, false
	}

	return result, true
}

// handleTunnelsReady processes tunnel readiness by sending LeaseSet request and starting maintenance.
func (s *Server) handleTunnelsReady(session *Session, conn net.Conn, sessionID uint16, tunnels tunnelReadinessResult) {
	logTunnelsReady(sessionID, len(tunnels.inboundTunnels), len(tunnels.outboundTunnels))

	if err := s.sendLeaseSetRequest(session, conn, sessionID, tunnels.inboundTunnels); err != nil {
		return
	}

	startLeaseSetMaintenance(session, sessionID)
}

// logTunnelsReady logs when tunnels become ready.
func logTunnelsReady(sessionID uint16, inboundCount, outboundCount int) {
	log.WithFields(logger.Fields{
		"at":              "i2cp.Server.monitorTunnelsAndRequestLeaseSet",
		"sessionID":       sessionID,
		"inboundTunnels":  inboundCount,
		"outboundTunnels": outboundCount,
	}).Info("tunnels_ready_sending_leaseset_request")
}

// sendLeaseSetRequest builds and sends the RequestVariableLeaseSet message to the client.
func (s *Server) sendLeaseSetRequest(session *Session, conn net.Conn, sessionID uint16, inTunnels []*tunnel.TunnelState) error {
	payload, err := s.buildRequestVariableLeaseSetPayload(inTunnels)
	if err != nil {
		log.WithFields(logger.Fields{
			"at":        "i2cp.Server.monitorTunnelsAndRequestLeaseSet",
			"sessionID": sessionID,
			"error":     err.Error(),
		}).Error("failed_to_build_leaseset_request")
		return err
	}

	msg := &Message{
		Type:      MessageTypeRequestVariableLeaseSet,
		SessionID: sessionID,
		Payload:   payload,
	}

	s.mu.RLock()
	writeMu := s.connWriteMu[sessionID]
	s.mu.RUnlock()

	if writeMu != nil {
		writeMu.Lock()
	}
	err = WriteMessage(conn, msg)
	if writeMu != nil {
		writeMu.Unlock()
	}

	if err != nil {
		log.WithFields(logger.Fields{
			"at":        "i2cp.Server.monitorTunnelsAndRequestLeaseSet",
			"sessionID": sessionID,
			"error":     err.Error(),
		}).Error("failed_to_send_leaseset_request")
		return err
	}

	log.WithFields(logger.Fields{
		"at":          "i2cp.Server.monitorTunnelsAndRequestLeaseSet",
		"sessionID":   sessionID,
		"payloadSize": len(payload),
	}).Info("sent_request_variable_leaseset")

	return nil
}

// startLeaseSetMaintenance initiates automatic LeaseSet maintenance for the session.
func startLeaseSetMaintenance(session *Session, sessionID uint16) {
	if err := session.StartLeaseSetMaintenance(); err != nil {
		log.WithFields(logger.Fields{
			"at":        "i2cp.Server.monitorTunnelsAndRequestLeaseSet",
			"sessionID": sessionID,
			"error":     err.Error(),
		}).Error("failed_to_start_leaseset_maintenance")
	} else {
		log.WithFields(logger.Fields{
			"at":        "i2cp.Server.monitorTunnelsAndRequestLeaseSet",
			"sessionID": sessionID,
		}).Info("leaseset_maintenance_started")
	}
}

// buildRequestVariableLeaseSetPayload constructs the payload for RequestVariableLeaseSet (type 37).
// Payload format per I2CP spec:
//
//	1 byte: number of leases (N)
//	For each lease (N times):
//	  32 bytes: tunnel gateway router hash
//	  4 bytes:  tunnel ID (big endian uint32)
//	  8 bytes:  end date (milliseconds since epoch, big endian uint64)
func (s *Server) buildRequestVariableLeaseSetPayload(tunnels []*tunnel.TunnelState) ([]byte, error) {
	if len(tunnels) == 0 {
		return nil, fmt.Errorf("no tunnels provided")
	}

	if len(tunnels) > 16 {
		// Limit to 16 leases to keep LeaseSet size reasonable
		tunnels = tunnels[:16]
	}

	// Calculate payload size: 1 byte count + N * (32 + 4 + 8) bytes
	payloadSize := 1 + len(tunnels)*44
	payload := make([]byte, payloadSize)

	payload[0] = byte(len(tunnels))

	offset := 1
	now := time.Now()

	for _, tun := range tunnels {
		if tun == nil || len(tun.Hops) == 0 {
			continue
		}

		// Gateway router hash (32 bytes)
		copy(payload[offset:offset+32], tun.Hops[0][:])
		offset += 32

		// Tunnel ID (4 bytes, big endian)
		binary.BigEndian.PutUint32(payload[offset:offset+4], uint32(tun.ID))
		offset += 4

		// End date (8 bytes, big endian, milliseconds since epoch)
		endDate := tun.CreatedAt.Add(10 * time.Minute) // Standard 10-minute lease
		if endDate.Before(now) {
			endDate = now.Add(5 * time.Minute) // Use 5 minutes if tunnel is old
		}
		endDateMillis := uint64(endDate.UnixMilli())
		binary.BigEndian.PutUint64(payload[offset:offset+8], endDateMillis)
		offset += 8
	}

	return payload, nil
}

// handleReconfigureSession updates session configuration
func (s *Server) handleReconfigureSession(msg *Message, sessionPtr **Session) (*Message, error) {
	if *sessionPtr == nil {
		return nil, fmt.Errorf("session not active")
	}

	// Parse new configuration from payload
	newConfig, err := ParseReconfigureSessionPayload(msg.Payload)
	if err != nil {
		log.WithError(err).Error("failed to parse reconfigure session payload")
		return nil, fmt.Errorf("failed to parse reconfigure payload: %w", err)
	}

	// Validate the new configuration
	if err := ValidateSessionConfig(newConfig); err != nil {
		log.WithError(err).Warn("invalid session config in reconfigure request")
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	if err := (*sessionPtr).Reconfigure(newConfig); err != nil {
		return nil, fmt.Errorf("failed to reconfigure session: %w", err)
	}

	log.WithFields(logger.Fields{
		"at":                     "i2cp.Server.handleReconfigureSession",
		"sessionID":              (*sessionPtr).ID(),
		"inbound_tunnel_length":  newConfig.InboundTunnelLength,
		"outbound_tunnel_length": newConfig.OutboundTunnelLength,
		"inbound_tunnel_count":   newConfig.InboundTunnelCount,
		"outbound_tunnel_count":  newConfig.OutboundTunnelCount,
	}).Info("session_reconfigured")

	// No response for ReconfigureSession
	return nil, nil
}

// handleCreateLeaseSet creates and publishes a LeaseSet for the session.
// This handler generates a LeaseSet from the session's inbound tunnel pool
// and returns it to the client. In a full implementation, this would also
// publish the LeaseSet to the network database.
func (s *Server) handleCreateLeaseSet(msg *Message, sessionPtr **Session) (*Message, error) {
	if *sessionPtr == nil {
		return nil, fmt.Errorf("no active session")
	}

	session := *sessionPtr

	// i2psnark compatibility: Log LeaseSet creation request
	log.WithFields(logger.Fields{
		"at":          "i2cp.Server.handleCreateLeaseSet",
		"sessionID":   session.ID(),
		"payloadSize": len(msg.Payload),
	}).Debug("creating_leaseset")

	// Create LeaseSet from session's inbound tunnels
	leaseSetBytes, err := session.CreateLeaseSet()
	if err != nil {
		log.WithFields(logger.Fields{
			"at":        "i2cp.Server.handleCreateLeaseSet",
			"sessionID": session.ID(),
			"error":     err,
		}).Error("failed_to_create_leaseset")
		return nil, fmt.Errorf("failed to create LeaseSet: %w", err)
	}

	log.WithFields(logger.Fields{
		"at":        "i2cp.Server.handleCreateLeaseSet",
		"sessionID": session.ID(),
		"size":      len(leaseSetBytes),
	}).Info("leaseset_created")

	// Publish LeaseSet to network database (NetDB) if publisher is configured.
	// The session's publishLeaseSetToNetwork method:
	// - Calculates the destination hash (SHA256 of destination)
	// - Calls the LeaseSetPublisher.PublishLeaseSet() interface
	// - Returns nil if no publisher configured (allows testing without network)
	// - Logs errors but doesn't fail the operation (LeaseSet is cached locally)
	if err := session.publishLeaseSetToNetwork(leaseSetBytes); err != nil {
		// Log warning but don't fail - LeaseSet creation succeeded
		log.WithFields(logger.Fields{
			"at":        "i2cp.Server.handleCreateLeaseSet",
			"sessionID": session.ID(),
			"error":     err,
		}).Warn("failed_to_publish_leaseset_to_network")
	}

	// For I2CP protocol, we don't send a response to CreateLeaseSet
	// The client just needs to know the operation succeeded (no error)
	return nil, nil
}

// handleCreateLeaseSet2 handles CreateLeaseSet2Message (type 41) - modern LeaseSet format.
// This is the modern replacement for CreateLeaseSet (type 5), supporting:
// - LeaseSet2 format (type 3) with modern crypto (X25519/Ed25519)
// - EncryptedLeaseSet (type 5) for destination privacy
// - MetaLeaseSet (type 7) for multiple destinations
// - Multiple encryption keys per destination
//
// Per I2CP v0.9.67 spec:
// "CreateLeaseSet2Message: Create a LeaseSet2. Sent from client to router.
//
//	Supports LeaseSet2, EncryptedLeaseSet, and MetaLeaseSet formats.
//	Use this instead of CreateLeaseSetMessage for all routers 0.9.39+."
//
// Payload format:
//
//	2 bytes: Session ID
//	N bytes: Complete serialized LeaseSet2 (format depends on type byte)
//
// Unlike CreateLeaseSet (type 5), the client provides the complete serialized
// LeaseSet2 structure. The router validates and publishes it to the network.
func (s *Server) handleCreateLeaseSet2(msg *Message, sessionPtr **Session) (*Message, error) {
	if *sessionPtr == nil {
		return nil, fmt.Errorf("no active session")
	}

	session := *sessionPtr

	// i2psnark compatibility: Log LeaseSet2 creation request
	log.WithFields(logger.Fields{
		"at":          "i2cp.Server.handleCreateLeaseSet2",
		"sessionID":   session.ID(),
		"payloadSize": len(msg.Payload),
	}).Debug("handling_create_leaseset2")

	// Validate payload size - need at least session ID (2 bytes) + minimal LeaseSet2
	// Minimum LeaseSet2: destination (387+ bytes) + published (8) + expires (2) + flags (2) + leases (1+) ≈ 400 bytes
	if len(msg.Payload) < 400 {
		log.WithFields(logger.Fields{
			"at":          "i2cp.Server.handleCreateLeaseSet2",
			"sessionID":   session.ID(),
			"payloadSize": len(msg.Payload),
		}).Warn("create_leaseset2_payload_too_short")
		return nil, fmt.Errorf("CreateLeaseSet2 payload too short: %d bytes", len(msg.Payload))
	}

	// Extract serialized LeaseSet2 from payload
	// The payload should contain the complete LeaseSet2 structure as generated by the client
	leaseSetBytes := msg.Payload

	// Log LeaseSet2 type for debugging
	// The type is not at a fixed position in CreateLeaseSet2Message payload,
	// as the client sends the complete serialized structure.
	// For LeaseSet2 (type 3), the structure starts with the Destination (387+ bytes),
	// followed by published timestamp, expires field, flags, and then leases.
	// We accept it as-is and rely on the client to provide valid LeaseSet2 data.

	log.WithFields(logger.Fields{
		"at":        "i2cp.Server.handleCreateLeaseSet2",
		"sessionID": session.ID(),
		"size":      len(leaseSetBytes),
	}).Info("leaseset2_received")

	// Note: For CreateLeaseSet2, the client provides the complete serialized LeaseSet2.
	// Unlike CreateLeaseSet (type 5) where we generate it from tunnels, here we accept
	// the client's LeaseSet2 as-is. The session's publishLeaseSetToNetwork will cache it.

	// Publish LeaseSet2 to network database if publisher is configured
	if err := session.publishLeaseSetToNetwork(leaseSetBytes); err != nil {
		// Log warning but don't fail - LeaseSet2 storage succeeded
		log.WithFields(logger.Fields{
			"at":        "i2cp.Server.handleCreateLeaseSet2",
			"sessionID": session.ID(),
			"error":     err,
		}).Warn("failed_to_publish_leaseset2_to_network")
	}

	log.WithFields(logger.Fields{
		"at":        "i2cp.Server.handleCreateLeaseSet2",
		"sessionID": session.ID(),
		"size":      len(leaseSetBytes),
	}).Info("leaseset2_processed")

	// Per I2CP protocol, no response is sent for CreateLeaseSet2Message
	// Success is indicated by not returning an error
	return nil, nil
}

// handleGetDate returns the current router time and protocol version.
// Per I2CP v0.9.67 spec (as of router 0.8.7):
// "The two parties' protocol version strings are exchanged in the Get/Set Date Messages.
//
//	Going forward, clients may use this information to communicate correctly with old routers."
//
// SetDate payload format:
//
//	Bytes 0-7:  Current time (milliseconds since epoch, big endian)
//	Bytes 8-9:  Version string length (big endian uint16)
//	Bytes 10+:  Protocol version string (UTF-8)
func (s *Server) handleGetDate(msg *Message) (*Message, error) {
	// Parse client version if provided in GetDate payload
	clientVersion := ""
	if len(msg.Payload) >= 2 {
		strLen := binary.BigEndian.Uint16(msg.Payload[0:2])
		if len(msg.Payload) >= 2+int(strLen) {
			clientVersion = string(msg.Payload[2 : 2+strLen])
		}
	}

	log.WithFields(logger.Fields{
		"at":            "i2cp.Server.handleGetDate",
		"sessionID":     msg.SessionID,
		"clientVersion": clientVersion,
	}).Debug("handling_get_date_request")

	// Store client version in session if we have one
	// GetDate can be called before CreateSession in some clients,
	// so we need to handle session lookup gracefully.
	if msg.SessionID != 0 && clientVersion != "" {
		if session, exists := s.manager.GetSession(msg.SessionID); exists {
			session.SetProtocolVersion(clientVersion)
			log.WithFields(logger.Fields{
				"at":            "i2cp.Server.handleGetDate",
				"sessionID":     msg.SessionID,
				"clientVersion": clientVersion,
			}).Debug("stored_client_protocol_version")
		}
	}

	// Current router time (milliseconds since Unix epoch)
	currentTimeMillis := time.Now().UnixMilli()

	// Protocol version string: "0.9.67"
	versionStr := fmt.Sprintf("%d.%d.%d",
		ProtocolVersionMajor, ProtocolVersionMinor, ProtocolVersionPatch)
	versionBytes := []byte(versionStr)

	// Build payload: 8 bytes (time) + 2 bytes (string length) + version string
	payload := make([]byte, 8+2+len(versionBytes))

	// Time (8 bytes, big endian)
	binary.BigEndian.PutUint64(payload[0:8], uint64(currentTimeMillis))

	// Version string length (2 bytes, big endian)
	binary.BigEndian.PutUint16(payload[8:10], uint16(len(versionBytes)))

	// Version string
	copy(payload[10:], versionBytes)

	response := &Message{
		Type:      MessageTypeSetDate,
		SessionID: msg.SessionID,
		Payload:   payload,
	}

	log.WithFields(logger.Fields{
		"at":              "i2cp.Server.handleGetDate",
		"reason":          "client_requested",
		"time_millis":     currentTimeMillis,
		"protocolVersion": versionStr,
		"clientVersion":   clientVersion,
	}).Debug("returning router time and version")
	return response, nil
}

// handleGetBandwidthLimits returns bandwidth limits
func (s *Server) handleGetBandwidthLimits(msg *Message) (*Message, error) {
	// I2CP BandwidthLimits format: two 4-byte integers (big endian)
	// [inbound_limit:4][outbound_limit:4]
	// Values are in bytes per second (0 = unlimited)

	// Default bandwidth limits (in bytes per second)
	var (
		inboundLimit  uint32 = 100 * 1024 * 1024 // 100 MB/s inbound
		outboundLimit uint32 = 100 * 1024 * 1024 // 100 MB/s outbound
	)

	payload := make([]byte, 8)

	// Inbound limit (4 bytes, big endian)
	payload[0] = byte(inboundLimit >> 24)
	payload[1] = byte(inboundLimit >> 16)
	payload[2] = byte(inboundLimit >> 8)
	payload[3] = byte(inboundLimit)

	// Outbound limit (4 bytes, big endian)
	payload[4] = byte(outboundLimit >> 24)
	payload[5] = byte(outboundLimit >> 16)
	payload[6] = byte(outboundLimit >> 8)
	payload[7] = byte(outboundLimit)

	response := &Message{
		Type:      MessageTypeBandwidthLimits,
		SessionID: msg.SessionID,
		Payload:   payload,
	}

	log.WithFields(logger.Fields{
		"at":           "i2cp.Server.handleGetBandwidthLimits",
		"reason":       "client_requested",
		"inbound_bps":  inboundLimit,
		"outbound_bps": outboundLimit,
	}).Debug("returning bandwidth limits")

	return response, nil
}

// handleDisconnect handles a graceful client disconnect request.
// This allows clients to terminate the connection with a reason string.
// The server will:
// 1. Parse the disconnect reason from the payload
// 2. Log the disconnect with the reason
// 3. Clean up the session if one exists
// 4. Return nil to signal connection should be closed (no response sent)
//
// Note: Returning nil from a handler signals the connection should be closed.
func (s *Server) handleDisconnect(msg *Message, sessionPtr **Session) (*Message, error) {
	// Parse disconnect payload
	disconnectMsg, err := ParseDisconnectPayload(msg.Payload)
	if err != nil {
		log.WithFields(logger.Fields{
			"at":          "i2cp.Server.handleDisconnect",
			"sessionID":   msg.SessionID,
			"payloadSize": len(msg.Payload),
			"error":       err.Error(),
		}).Error("failed_to_parse_disconnect_payload")
		// Even if parse fails, proceed with disconnect
		disconnectMsg = &DisconnectPayload{Reason: "unknown (parse error)"}
	}

	log.WithFields(logger.Fields{
		"at":        "i2cp.Server.handleDisconnect",
		"sessionID": msg.SessionID,
		"reason":    disconnectMsg.Reason,
	}).Info("client_disconnect_requested")

	// Clean up session if it exists
	if *sessionPtr != nil {
		session := *sessionPtr
		log.WithFields(logger.Fields{
			"at":        "i2cp.Server.handleDisconnect",
			"sessionID": session.ID(),
			"reason":    disconnectMsg.Reason,
		}).Info("destroying_session_on_disconnect")

		// Destroy the session (this cleans up resources)
		if err := s.manager.DestroySession(session.ID()); err != nil {
			log.WithFields(logger.Fields{
				"at":        "i2cp.Server.handleDisconnect",
				"sessionID": session.ID(),
				"error":     err.Error(),
			}).Warn("failed_to_destroy_session_on_disconnect")
		}

		// Clear session pointer
		*sessionPtr = nil
	}

	// Returning nil signals the connection should be closed gracefully
	// No response message is sent - client expects connection to close
	return nil, nil
}

// logHostLookupParseError logs an error when parsing host lookup payload fails.
func logHostLookupParseError(sessionID uint16, payloadSize int, err error) {
	log.WithFields(logger.Fields{
		"at":          "i2cp.Server.handleHostLookup",
		"sessionID":   sessionID,
		"payloadSize": payloadSize,
		"error":       err.Error(),
	}).Error("failed_to_parse_host_lookup_payload")
}

// logHostLookupRequest logs a host lookup request.
func logHostLookupRequest(sessionID uint16, lookupMsg *HostLookupPayload) {
	log.WithFields(logger.Fields{
		"at":         "i2cp.Server.handleHostLookup",
		"sessionID":  sessionID,
		"requestID":  lookupMsg.RequestID,
		"lookupType": lookupMsg.LookupType,
		"query":      lookupMsg.Query,
	}).Info("host_lookup_requested")
}

// handleHostnameLookup handles hostname lookup type (not yet implemented).
func handleHostnameLookup(lookupMsg *HostLookupPayload) *HostReplyPayload {
	log.WithFields(logger.Fields{
		"at":        "i2cp.Server.handleHostLookup",
		"requestID": lookupMsg.RequestID,
		"query":     lookupMsg.Query,
	}).Debug("hostname_lookup_not_implemented")
	return &HostReplyPayload{
		RequestID:   lookupMsg.RequestID,
		ResultCode:  HostReplyError,
		Destination: nil,
	}
}

// handleUnknownLookupType handles unknown lookup types.
func handleUnknownLookupType(lookupMsg *HostLookupPayload) *HostReplyPayload {
	log.WithFields(logger.Fields{
		"at":         "i2cp.Server.handleHostLookup",
		"requestID":  lookupMsg.RequestID,
		"lookupType": lookupMsg.LookupType,
	}).Warn("unknown_lookup_type")
	return &HostReplyPayload{
		RequestID:   lookupMsg.RequestID,
		ResultCode:  HostReplyError,
		Destination: nil,
	}
}

// buildHostReplyMessage constructs the host reply message from payload.
func buildHostReplyMessage(sessionID uint16, replyPayload *HostReplyPayload) (*Message, error) {
	replyData, err := replyPayload.MarshalBinary()
	if err != nil {
		log.WithFields(logger.Fields{
			"at":        "i2cp.Server.handleHostLookup",
			"requestID": replyPayload.RequestID,
			"error":     err.Error(),
		}).Error("failed_to_marshal_host_reply")
		return nil, fmt.Errorf("failed to marshal HostReply: %w", err)
	}

	log.WithFields(logger.Fields{
		"at":         "i2cp.Server.handleHostLookup",
		"requestID":  replyPayload.RequestID,
		"resultCode": replyPayload.ResultCode,
	}).Debug("returning_host_reply")

	return &Message{
		Type:      MessageTypeHostReply,
		SessionID: sessionID,
		Payload:   replyData,
	}, nil
}

// handleHostLookup handles a destination lookup request by hash or hostname.
// This allows clients to query for destination information.
//
// Lookup types:
// - Type 0 (hash): Query NetDB for destination by hash
// - Type 1 (hostname): Requires naming service integration (not yet implemented)
//
// For hash lookups, the destination is retrieved from the LeaseSet stored in NetDB.
func (s *Server) handleHostLookup(msg *Message) (*Message, error) {
	lookupMsg, err := ParseHostLookupPayload(msg.Payload)
	if err != nil {
		logHostLookupParseError(msg.SessionID, len(msg.Payload), err)
		return nil, fmt.Errorf("failed to parse HostLookup payload: %w", err)
	}

	logHostLookupRequest(msg.SessionID, lookupMsg)

	var replyPayload *HostReplyPayload
	switch lookupMsg.LookupType {
	case HostLookupTypeHash:
		replyPayload = s.lookupDestinationByHash(lookupMsg)
	case HostLookupTypeHostname:
		replyPayload = handleHostnameLookup(lookupMsg)
	default:
		replyPayload = handleUnknownLookupType(lookupMsg)
	}

	return buildHostReplyMessage(msg.SessionID, replyPayload)
}

// lookupDestinationByHash queries NetDB for a LeaseSet by hash and extracts the destination.
// Returns HostReplyPayload with the destination bytes if found, or an error code if not found.
// parseDestinationHash parses a destination hash from the query string.
// Returns the parsed hash and nil if successful, or a zero hash and an error reply if parsing fails.
func parseDestinationHash(lookupMsg *HostLookupPayload) (common.Hash, *HostReplyPayload) {
	var destHash common.Hash

	if len(lookupMsg.Query) < 64 {
		log.WithFields(logger.Fields{
			"at":        "i2cp.Server.lookupDestinationByHash",
			"requestID": lookupMsg.RequestID,
			"queryLen":  len(lookupMsg.Query),
		}).Warn("query_too_short_for_hash")
		return destHash, &HostReplyPayload{
			RequestID:   lookupMsg.RequestID,
			ResultCode:  HostReplyError,
			Destination: nil,
		}
	}

	_, err := fmt.Sscanf(lookupMsg.Query[:64], "%x", &destHash)
	if err != nil {
		log.WithFields(logger.Fields{
			"at":        "i2cp.Server.lookupDestinationByHash",
			"requestID": lookupMsg.RequestID,
			"query":     lookupMsg.Query,
			"error":     err.Error(),
		}).Warn("invalid_hash_format")
		return destHash, &HostReplyPayload{
			RequestID:   lookupMsg.RequestID,
			ResultCode:  HostReplyError,
			Destination: nil,
		}
	}

	return destHash, nil
}

// queryLeaseSetFromNetDB queries the NetDB for a LeaseSet and extracts the destination.
// Returns the destination bytes and nil if successful, or nil and an error reply if the query fails.
func (s *Server) queryLeaseSetFromNetDB(destHash common.Hash, requestID uint32) ([]byte, *HostReplyPayload) {
	leaseSetBytes, err := s.netdb.GetLeaseSetBytes(destHash)
	if err != nil {
		log.WithFields(logger.Fields{
			"at":        "i2cp.Server.lookupDestinationByHash",
			"requestID": requestID,
			"destHash":  fmt.Sprintf("%x", destHash[:8]),
			"error":     err.Error(),
		}).Debug("leaseset_not_found_in_netdb")
		return nil, &HostReplyPayload{
			RequestID:   requestID,
			ResultCode:  HostReplyNotFound,
			Destination: nil,
		}
	}

	destination, err := s.extractDestinationFromLeaseSet(leaseSetBytes)
	if err != nil {
		log.WithFields(logger.Fields{
			"at":        "i2cp.Server.lookupDestinationByHash",
			"requestID": requestID,
			"destHash":  fmt.Sprintf("%x", destHash[:8]),
			"error":     err.Error(),
		}).Error("failed_to_extract_destination")
		return nil, &HostReplyPayload{
			RequestID:   requestID,
			ResultCode:  HostReplyError,
			Destination: nil,
		}
	}

	return destination, nil
}

func (s *Server) lookupDestinationByHash(lookupMsg *HostLookupPayload) *HostReplyPayload {
	if s.netdb == nil {
		log.WithFields(logger.Fields{
			"at":        "i2cp.Server.lookupDestinationByHash",
			"requestID": lookupMsg.RequestID,
		}).Warn("no_netdb_configured")
		return &HostReplyPayload{
			RequestID:   lookupMsg.RequestID,
			ResultCode:  HostReplyError,
			Destination: nil,
		}
	}

	destHash, errReply := parseDestinationHash(lookupMsg)
	if errReply != nil {
		return errReply
	}

	destination, errReply := s.queryLeaseSetFromNetDB(destHash, lookupMsg.RequestID)
	if errReply != nil {
		return errReply
	}

	log.WithFields(logger.Fields{
		"at":           "i2cp.Server.lookupDestinationByHash",
		"requestID":    lookupMsg.RequestID,
		"destHash":     fmt.Sprintf("%x", destHash[:8]),
		"destByteSize": len(destination),
	}).Info("destination_found")

	return &HostReplyPayload{
		RequestID:   lookupMsg.RequestID,
		ResultCode:  HostReplySuccess,
		Destination: destination,
	}
}

// extractDestinationFromLeaseSet extracts the destination bytes from a LeaseSet.
// The destination is at the beginning of the LeaseSet structure.
// Returns the destination bytes suitable for HostReply, or an error if parsing fails.
func (s *Server) extractDestinationFromLeaseSet(leaseSetBytes []byte) ([]byte, error) {
	// LeaseSet format starts with Destination
	// Destination minimum size is 387 bytes (for standard ElGamal/DSA)
	// But can be larger with key certificates
	if len(leaseSetBytes) < 387 {
		return nil, fmt.Errorf("leaseset too small: %d bytes", len(leaseSetBytes))
	}

	// Parse the destination to determine its actual size
	_, remainder, err := destination.ReadDestination(leaseSetBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse destination: %w", err)
	}

	// Calculate how many bytes the destination occupies
	destSize := len(leaseSetBytes) - len(remainder)

	// Return the destination bytes
	return leaseSetBytes[:destSize], nil
}

// handleBlindingInfo handles blinded destination parameters.
// This allows clients to configure destination blinding for privacy enhancement.
// Blinded destinations rotate daily at UTC midnight to prevent long-term correlation.
//
// Workflow:
// 1. Parse BlindingInfo payload (enabled flag + optional secret)
// 2. Update session configuration with blinding parameters
// 3. If enabled, trigger blinded destination derivation
// 4. Session will automatically use blinded destinations in EncryptedLeaseSets
//
// The session's updateBlindedDestination() handles daily rotation automatically.
func (s *Server) handleBlindingInfo(msg *Message, sessionPtr **Session) (*Message, error) {
	if *sessionPtr == nil {
		return nil, fmt.Errorf("session not active")
	}

	session := *sessionPtr

	blindingInfo, err := parseAndLogBlindingInfo(msg, session)
	if err != nil {
		return nil, err
	}

	updateSessionBlindingConfig(session, blindingInfo)

	if err := applyBlindedDestinationUpdate(session, blindingInfo); err != nil {
		return nil, err
	}

	return nil, nil
}

// parseAndLogBlindingInfo parses the BlindingInfo payload and logs the received configuration.
func parseAndLogBlindingInfo(msg *Message, session *Session) (*BlindingInfoPayload, error) {
	blindingInfo, err := ParseBlindingInfoPayload(msg.Payload)
	if err != nil {
		log.WithFields(logger.Fields{
			"at":          "i2cp.Server.handleBlindingInfo",
			"sessionID":   session.ID(),
			"payloadSize": len(msg.Payload),
			"error":       err.Error(),
		}).Error("failed_to_parse_blinding_info")
		return nil, fmt.Errorf("failed to parse BlindingInfo payload: %w", err)
	}

	log.WithFields(logger.Fields{
		"at":        "i2cp.Server.handleBlindingInfo",
		"sessionID": session.ID(),
		"enabled":   blindingInfo.Enabled,
		"hasSecret": len(blindingInfo.Secret) > 0,
	}).Info("received_blinding_info")

	return blindingInfo, nil
}

// updateSessionBlindingConfig updates the session's blinding configuration based on the received info.
func updateSessionBlindingConfig(session *Session, blindingInfo *BlindingInfoPayload) {
	session.mu.Lock()
	defer session.mu.Unlock()

	session.config.UseEncryptedLeaseSet = blindingInfo.Enabled
	if blindingInfo.Enabled && len(blindingInfo.Secret) > 0 {
		session.config.BlindingSecret = blindingInfo.Secret
		session.blindingSecret = nil
	} else if blindingInfo.Enabled {
		session.config.BlindingSecret = nil
		session.blindingSecret = nil
	} else {
		session.config.BlindingSecret = nil
		session.blindingSecret = nil
		session.blindedDestination = nil
	}
}

// applyBlindedDestinationUpdate triggers blinded destination update if blinding is enabled.
func applyBlindedDestinationUpdate(session *Session, blindingInfo *BlindingInfoPayload) error {
	if !blindingInfo.Enabled {
		return nil
	}

	if err := session.updateBlindedDestination(); err != nil {
		log.WithFields(logger.Fields{
			"at":        "i2cp.Server.handleBlindingInfo",
			"sessionID": session.ID(),
			"error":     err.Error(),
		}).Error("failed_to_update_blinded_destination")
		return fmt.Errorf("failed to update blinded destination: %w", err)
	}

	log.WithFields(logger.Fields{
		"at":        "i2cp.Server.handleBlindingInfo",
		"sessionID": session.ID(),
	}).Debug("blinded_destination_updated")

	return nil
}

// handleSendMessage handles a client sending a message to a destination.
// This implements the full message delivery flow with status tracking:
// 1. Parse and validate the SendMessage payload
// 2. Generate unique message ID for tracking
// 3. Send immediate MessageStatus (accepted) to client
// 4. Route message asynchronously with delivery status callbacks
//
// Message routing:
// - Wraps payload in garlic encryption using destination's public key
// - Selects outbound tunnel from session's tunnel pool
// - Sends encrypted garlic through tunnel gateway
// - Reports final status (success/failure) via MessageStatus message
func (s *Server) handleSendMessage(msg *Message, sessionPtr **Session) (*Message, error) {
	session, err := s.validateSessionForSending(sessionPtr)
	if err != nil {
		return nil, err
	}

	sendMsg, err := s.parseSendMessagePayload(msg, session)
	if err != nil {
		return nil, err
	}

	if err := s.validateOutboundPool(session); err != nil {
		return nil, err
	}

	// Generate unique message ID for tracking
	messageID := s.nextMessageID.Add(1)

	log.WithFields(logger.Fields{
		"at":          "i2cp.Server.handleSendMessage",
		"sessionID":   session.ID(),
		"messageID":   messageID,
		"destination": fmt.Sprintf("%x", sendMsg.Destination[:8]),
		"payloadSize": len(sendMsg.Payload),
	}).Debug("sending_message_accepted")

	// Send immediate acceptance status to client
	acceptMsg := buildMessageStatusResponse(
		session.ID(),
		messageID,
		MessageStatusAccepted,
		uint32(len(sendMsg.Payload)),
		0, // nonce
	)

	// Route message asynchronously with status tracking
	go s.routeMessageWithStatus(session, messageID, sendMsg)

	// Return immediate acceptance response
	return acceptMsg, nil
}

// validateSessionForSending validates that a session exists for sending.
func (s *Server) validateSessionForSending(sessionPtr **Session) (*Session, error) {
	if *sessionPtr == nil {
		return nil, fmt.Errorf("session not active")
	}
	return *sessionPtr, nil
}

// parseSendMessagePayload parses the SendMessage payload from the message.
func (s *Server) parseSendMessagePayload(msg *Message, session *Session) (*SendMessagePayload, error) {
	// i2psnark compatibility: Log SendMessage details before parsing
	log.WithFields(logger.Fields{
		"at":          "i2cp.Server.parseSendMessagePayload",
		"sessionID":   session.ID(),
		"payloadSize": len(msg.Payload),
	}).Debug("parsing_send_message_payload")

	sendMsg, err := ParseSendMessagePayload(msg.Payload)
	if err != nil {
		// i2psnark compatibility: Show payload excerpt on parse failure
		excerptLen := min(64, len(msg.Payload))
		log.WithFields(logger.Fields{
			"at":             "i2cp.Server.parseSendMessagePayload",
			"sessionID":      session.ID(),
			"payloadSize":    len(msg.Payload),
			"error":          err,
			"payloadExcerpt": fmt.Sprintf("%x", msg.Payload[:excerptLen]),
		}).Error("failed_to_parse_send_message")
		return nil, fmt.Errorf("failed to parse SendMessage payload: %w", err)
	}

	// Validate payload size to prevent exceeding I2CP limits after garlic encryption
	// i2psnark compatibility: Account for overhead from garlic encryption
	// Data message (4 bytes) + garlic encryption (~200 bytes typical)
	// Conservative limit: MaxPayloadSize - 2048 bytes for all overhead
	// Increased overhead budget to accommodate larger i2psnark messages
	const maxSafePayloadSize = MaxPayloadSize - 2048
	if len(sendMsg.Payload) > maxSafePayloadSize {
		// i2psnark compatibility: Log detailed size information for debugging
		log.WithFields(logger.Fields{
			"at":              "i2cp.Server.parseSendMessagePayload",
			"sessionID":       session.ID(),
			"payloadSize":     len(sendMsg.Payload),
			"maxAllowed":      maxSafePayloadSize,
			"maxPayloadSize":  MaxPayloadSize,
			"overhead":        512,
			"destinationHash": fmt.Sprintf("%x", sendMsg.Destination[:8]),
		}).Error("send_message_payload_too_large")
		return nil, fmt.Errorf("message payload too large: %d bytes (max %d bytes to allow for encryption overhead)",
			len(sendMsg.Payload), maxSafePayloadSize)
	}

	return sendMsg, nil
}

// validateOutboundPool validates that the session has an outbound tunnel pool.
func (s *Server) validateOutboundPool(session *Session) error {
	outboundPool := session.OutboundPool()
	if outboundPool == nil {
		log.WithFields(logger.Fields{
			"at":        "i2cp.Server.validateOutboundPool",
			"sessionID": session.ID(),
		}).Warn("no_outbound_tunnel_pool")
		return fmt.Errorf("session %d has no outbound tunnel pool", session.ID())
	}
	return nil
}

// handleSendMessageExpires handles SendMessageExpires (type 36) messages.
// This is an enhanced version of SendMessage that includes expiration time and delivery flags.
// The message will not be sent if it has already expired when processing begins.
func (s *Server) handleSendMessageExpires(msg *Message, sessionPtr **Session) (*Message, error) {
	session, err := s.validateSessionForSending(sessionPtr)
	if err != nil {
		return nil, err
	}

	// Parse SendMessageExpires payload
	sendMsgExpires, err := s.parseSendMessageExpiresPayload(msg, session)
	if err != nil {
		return nil, err
	}

	if err := s.validateOutboundPool(session); err != nil {
		return nil, err
	}

	// Generate unique message ID for tracking
	messageID := s.nextMessageID.Add(1)

	log.WithFields(logger.Fields{
		"at":          "i2cp.Server.handleSendMessageExpires",
		"sessionID":   session.ID(),
		"messageID":   messageID,
		"destination": fmt.Sprintf("%x", sendMsgExpires.Destination[:8]),
		"payloadSize": len(sendMsgExpires.Payload),
		"nonce":       sendMsgExpires.Nonce,
		"flags":       sendMsgExpires.Flags,
		"expiration":  sendMsgExpires.Expiration,
	}).Debug("sending_message_expires_accepted")

	// Send immediate acceptance status to client
	acceptMsg := buildMessageStatusResponse(
		session.ID(),
		messageID,
		MessageStatusAccepted,
		uint32(len(sendMsgExpires.Payload)),
		sendMsgExpires.Nonce,
	)

	// Route message asynchronously with status tracking and expiration
	go s.routeMessageExpiresWithStatus(session, messageID, sendMsgExpires)

	// Return immediate acceptance response
	return acceptMsg, nil
}

// parseSendMessageExpiresPayload parses the SendMessageExpires payload from the message.
func (s *Server) parseSendMessageExpiresPayload(msg *Message, session *Session) (*SendMessageExpiresPayload, error) {
	log.WithFields(logger.Fields{
		"at":          "i2cp.Server.parseSendMessageExpiresPayload",
		"sessionID":   session.ID(),
		"payloadSize": len(msg.Payload),
	}).Debug("parsing_send_message_expires_payload")

	sendMsg, err := ParseSendMessageExpiresPayload(msg.Payload)
	if err != nil {
		excerptLen := min(64, len(msg.Payload))
		log.WithFields(logger.Fields{
			"at":             "i2cp.Server.parseSendMessageExpiresPayload",
			"sessionID":      session.ID(),
			"payloadSize":    len(msg.Payload),
			"error":          err,
			"payloadExcerpt": fmt.Sprintf("%x", msg.Payload[:excerptLen]),
		}).Error("failed_to_parse_send_message_expires")
		return nil, fmt.Errorf("failed to parse SendMessageExpires payload: %w", err)
	}

	// Validate payload size (same limits as SendMessage)
	const maxSafePayloadSize = MaxPayloadSize - 2048
	if len(sendMsg.Payload) > maxSafePayloadSize {
		log.WithFields(logger.Fields{
			"at":              "i2cp.Server.parseSendMessageExpiresPayload",
			"sessionID":       session.ID(),
			"payloadSize":     len(sendMsg.Payload),
			"maxAllowed":      maxSafePayloadSize,
			"maxPayloadSize":  MaxPayloadSize,
			"destinationHash": fmt.Sprintf("%x", sendMsg.Destination[:8]),
		}).Error("send_message_expires_payload_too_large")
		return nil, fmt.Errorf("message payload too large: %d bytes (max %d bytes to allow for encryption overhead)",
			len(sendMsg.Payload), maxSafePayloadSize)
	}

	return sendMsg, nil
}

// routeMessageExpiresWithStatus routes a SendMessageExpires message asynchronously with
// delivery status tracking and expiration checking.
func (s *Server) routeMessageExpiresWithStatus(session *Session, messageID uint32, sendMsg *SendMessageExpiresPayload) {
	log.WithFields(logger.Fields{
		"at":          "i2cp.Server.routeMessageExpiresWithStatus",
		"sessionID":   session.ID(),
		"messageID":   messageID,
		"destination": fmt.Sprintf("%x", sendMsg.Destination[:8]),
		"payloadSize": len(sendMsg.Payload),
		"expiration":  sendMsg.Expiration,
		"nonce":       sendMsg.Nonce,
	}).Info("routing_message_expires")

	// Create status callback
	statusCallback := func(msgID uint32, statusCode uint8, messageSize, nonce uint32) {
		statusMsg := buildMessageStatusResponse(session.ID(), msgID, statusCode, messageSize, sendMsg.Nonce)
		s.sendStatusToClient(session, statusMsg)
	}

	// Resolve destination public key
	destPubKey, err := s.resolveDestinationKey(sendMsg.Destination)
	if err != nil {
		log.WithFields(logger.Fields{
			"at":          "i2cp.Server.routeMessageExpiresWithStatus",
			"sessionID":   session.ID(),
			"messageID":   messageID,
			"destination": fmt.Sprintf("%x", sendMsg.Destination[:8]),
			"error":       err.Error(),
		}).Error("failed_to_resolve_destination_key")
		// Send failure status
		statusCallback(messageID, MessageStatusNoLeaseSet, uint32(len(sendMsg.Payload)), sendMsg.Nonce)
		return
	}

	// Route through message router with expiration
	if s.messageRouter != nil {
		err := s.messageRouter.RouteOutboundMessage(
			session,
			messageID,
			sendMsg.Destination,
			destPubKey,
			sendMsg.Payload,
			sendMsg.Expiration, // Pass expiration time
			statusCallback,
		)
		if err != nil {
			log.WithFields(logger.Fields{
				"at":          "i2cp.Server.routeMessageExpiresWithStatus",
				"sessionID":   session.ID(),
				"messageID":   messageID,
				"destination": fmt.Sprintf("%x", sendMsg.Destination[:8]),
				"error":       err.Error(),
			}).Error("failed_to_route_message_expires")
			// Status callback already invoked by RouteOutboundMessage
		}
	} else {
		log.WithFields(logger.Fields{
			"at":          "i2cp.Server.routeMessageExpiresWithStatus",
			"sessionID":   session.ID(),
			"messageID":   messageID,
			"destination": fmt.Sprintf("%x", sendMsg.Destination[:8]),
		}).Warn("no_message_router_configured")
	}
}

// routeMessageWithStatus routes a message asynchronously with delivery status tracking.
// This method is called from a goroutine and handles the complete routing flow including
// status callbacks to notify the client of delivery success/failure.
func (s *Server) routeMessageWithStatus(session *Session, messageID uint32, sendMsg *SendMessagePayload) {
	log.WithFields(logger.Fields{
		"at":          "i2cp.Server.routeMessageWithStatus",
		"sessionID":   session.ID(),
		"messageID":   messageID,
		"destination": fmt.Sprintf("%x", sendMsg.Destination[:8]),
		"payloadSize": len(sendMsg.Payload),
	}).Debug("routing_message_async")

	// Create status callback to send MessageStatus to client
	statusCallback := func(msgID uint32, statusCode uint8, messageSize, nonce uint32) {
		statusMsg := buildMessageStatusResponse(session.ID(), msgID, statusCode, messageSize, nonce)
		s.sendStatusToClient(session, statusMsg)
	}

	// Look up destination's encryption public key from NetDB
	destPubKey, err := s.resolveDestinationKey(sendMsg.Destination)
	if err != nil {
		log.WithFields(logger.Fields{
			"at":          "i2cp.Server.routeMessageWithStatus",
			"sessionID":   session.ID(),
			"messageID":   messageID,
			"destination": fmt.Sprintf("%x", sendMsg.Destination[:8]),
			"error":       err.Error(),
		}).Error("failed_to_resolve_destination_key")
		// Send failure status
		statusCallback(messageID, MessageStatusNoLeaseSet, uint32(len(sendMsg.Payload)), 0)
		return
	}

	// Route through message router
	if s.messageRouter != nil {
		err := s.messageRouter.RouteOutboundMessage(
			session,
			messageID,
			sendMsg.Destination,
			destPubKey,
			sendMsg.Payload,
			0, // no expiration for SendMessage (type 7)
			statusCallback,
		)
		if err != nil {
			log.WithFields(logger.Fields{
				"at":          "i2cp.Server.routeMessageWithStatus",
				"sessionID":   session.ID(),
				"messageID":   messageID,
				"destination": fmt.Sprintf("%x", sendMsg.Destination[:8]),
				"error":       err.Error(),
			}).Error("failed_to_route_message")
			// Status callback already invoked by RouteOutboundMessage
		}
	} else {
		log.WithFields(logger.Fields{
			"at":          "i2cp.Server.routeMessageWithStatus",
			"sessionID":   session.ID(),
			"messageID":   messageID,
			"destination": fmt.Sprintf("%x", sendMsg.Destination[:8]),
		}).Warn("no_message_router_message_queued")
		// Send failure status when no router available
		statusCallback(messageID, MessageStatusFailure, uint32(len(sendMsg.Payload)), 0)
	}
}

// sendStatusToClient sends a MessageStatus message to the client connection.
func (s *Server) sendStatusToClient(session *Session, statusMsg *Message) {
	s.mu.RLock()
	conn, exists := s.sessionConns[session.ID()]
	writeMu := s.connWriteMu[session.ID()]
	s.mu.RUnlock()

	if !exists || writeMu == nil {
		log.WithFields(logger.Fields{
			"at":        "i2cp.Server.sendStatusToClient",
			"sessionID": session.ID(),
		}).Warn("no_connection_for_status_message")
		return
	}

	data, err := statusMsg.MarshalBinary()
	if err != nil {
		log.WithFields(logger.Fields{
			"at":        "i2cp.Server.sendStatusToClient",
			"sessionID": session.ID(),
			"error":     err.Error(),
		}).Error("failed_to_marshal_status_message")
		return
	}

	writeMu.Lock()
	_, err = conn.Write(data)
	writeMu.Unlock()
	if err != nil {
		log.WithFields(logger.Fields{
			"at":        "i2cp.Server.sendStatusToClient",
			"sessionID": session.ID(),
			"error":     err.Error(),
		}).Error("failed_to_send_status_message")
	}
}

// routeMessageToDestination routes the message through the I2P network.
// Deprecated: Use routeMessageWithStatus for new code that supports delivery tracking.
func (s *Server) routeMessageToDestination(session *Session, sendMsg *SendMessagePayload) {
	log.WithFields(logger.Fields{
		"at":          "i2cp.Server.routeMessageToDestination",
		"sessionID":   session.ID(),
		"destination": fmt.Sprintf("%x", sendMsg.Destination[:8]),
		"payloadSize": len(sendMsg.Payload),
	}).Debug("routing_outbound_message")

	// Look up destination's encryption public key from NetDB
	destPubKey, err := s.resolveDestinationKey(sendMsg.Destination)
	if err != nil {
		log.WithFields(logger.Fields{
			"at":          "i2cp.Server.routeMessageToDestination",
			"sessionID":   session.ID(),
			"destination": fmt.Sprintf("%x", sendMsg.Destination[:8]),
			"error":       err.Error(),
		}).Error("failed_to_resolve_destination_key")
		return
	}

	if s.messageRouter != nil {
		// Call with messageID=0 and no callback for backward compatibility
		err := s.messageRouter.RouteOutboundMessage(
			session,
			0, // messageID
			sendMsg.Destination,
			destPubKey,
			sendMsg.Payload,
			0,   // no expiration
			nil, // no status callback
		)
		if err != nil {
			log.WithFields(logger.Fields{
				"at":          "i2cp.Server.routeMessageToDestination",
				"sessionID":   session.ID(),
				"destination": fmt.Sprintf("%x", sendMsg.Destination[:8]),
				"error":       err.Error(),
			}).Error("failed_to_route_message")
		}
	} else {
		s.logMessageQueuedWithoutRouter(session, sendMsg)
	}
}

// resolveDestinationKey looks up the destination's encryption public key from NetDB.
// Returns the X25519 public key needed for ECIES-X25519-AEAD garlic encryption.
// Falls back to zero key if no resolver is configured (for testing/development).
func (s *Server) resolveDestinationKey(destHash common.Hash) ([32]byte, error) {
	if s.destinationResolver == nil {
		log.WithField("destination", fmt.Sprintf("%x", destHash[:8])).
			Warn("no_destination_resolver_configured_using_zero_key")
		return [32]byte{}, nil
	}

	pubKey, err := s.destinationResolver.ResolveDestination(destHash)
	if err != nil {
		return [32]byte{}, fmt.Errorf("failed to resolve destination: %w", err)
	}

	log.WithField("destination", fmt.Sprintf("%x", destHash[:8])).
		Debug("resolved_destination_public_key")
	return pubKey, nil
}

// routeWithMessageRouter attempts to route the message using the message router.
// Deprecated: Use routeMessageWithStatus for new code with delivery tracking.
func (s *Server) routeWithMessageRouter(session *Session, messageID uint32, sendMsg *SendMessagePayload, destPubKey [32]byte, statusCallback MessageStatusCallback) {
	err := s.messageRouter.RouteOutboundMessage(
		session,
		messageID,
		sendMsg.Destination,
		destPubKey,
		sendMsg.Payload,
		0, // no expiration
		statusCallback,
	)
	if err != nil {
		log.WithFields(logger.Fields{
			"at":          "i2cp.Server.routeWithMessageRouter",
			"sessionID":   session.ID(),
			"messageID":   messageID,
			"destination": fmt.Sprintf("%x", sendMsg.Destination[:8]),
			"error":       err,
		}).Error("failed_to_route_message")
	} else {
		log.WithFields(logger.Fields{
			"at":          "i2cp.Server.routeWithMessageRouter",
			"sessionID":   session.ID(),
			"messageID":   messageID,
			"destination": fmt.Sprintf("%x", sendMsg.Destination[:8]),
			"payloadSize": len(sendMsg.Payload),
		}).Info("message_routed_successfully")
	}
}

// logMessageQueuedWithoutRouter logs that a message was queued without a router.
func (s *Server) logMessageQueuedWithoutRouter(session *Session, sendMsg *SendMessagePayload) {
	log.WithFields(logger.Fields{
		"at":          "i2cp.Server.logMessageQueuedWithoutRouter",
		"sessionID":   session.ID(),
		"destination": fmt.Sprintf("%x", sendMsg.Destination[:8]),
		"payloadSize": len(sendMsg.Payload),
	}).Info("message_queued_for_sending_no_router")
}

// SessionManager returns the server's session manager
func (s *Server) SessionManager() *SessionManager {
	return s.manager
}

// SetMessageRouter sets the message router for outbound message handling.
// This should be called after creating the server and before starting it.
func (s *Server) SetMessageRouter(router *MessageRouter) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.messageRouter = router
}

// SetDestinationResolver sets the destination resolver for looking up encryption keys.
// This enables the server to resolve destination hashes to X25519 public keys
// from the NetDB for garlic encryption.
func (s *Server) SetDestinationResolver(resolver interface {
	ResolveDestination(destHash common.Hash) ([32]byte, error)
},
) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.destinationResolver = resolver
}

// SetNetDB sets the NetDB accessor for looking up LeaseSet data.
// This enables HostLookup queries to retrieve full destination information.
func (s *Server) SetNetDB(netdb interface {
	GetLeaseSetBytes(hash common.Hash) ([]byte, error)
},
) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.netdb = netdb
}

// IsRunning returns whether the server is currently running
func (s *Server) IsRunning() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.running
}

// deliverMessagesToClient runs in a goroutine to deliver incoming messages to a client.
// This monitors the session's incoming message queue and sends MessagePayload messages
// to the client connection when messages arrive from the I2P network.
//
// The goroutine exits when:
// - The session is stopped
// - The server is shutting down
// - An error occurs writing to the connection
func (s *Server) deliverMessagesToClient(session *Session, conn net.Conn) {
	defer s.wg.Done()
	defer s.recoverFromDeliveryPanic(session)

	sessionID := session.ID()
	messageCounter := uint32(1)

	s.logDeliveryStarted(sessionID)
	s.runDeliveryLoop(session, sessionID, conn, &messageCounter)
}

// recoverFromDeliveryPanic recovers from panics during message delivery to prevent goroutine leaks.
// Logs panic information for debugging purposes.
func (s *Server) recoverFromDeliveryPanic(session *Session) {
	if r := recover(); r != nil {
		log.WithFields(logger.Fields{
			"at":        "i2cp.Server.deliverMessagesToClient",
			"sessionID": session.ID(),
			"panic":     r,
		}).Error("panic_in_message_delivery_goroutine")
	}
}

// runDeliveryLoop executes the main message delivery loop for a session.
// Message ID counter uses uint32 and will wrap to 1 after reaching max value.
// This allows ~4.2 billion messages before wrap-around. I2CP spec doesn't mandate
// specific overflow behavior, so we use natural uint32 wrapping.
// Clients should handle message IDs as opaque identifiers, not sequence numbers.
func (s *Server) runDeliveryLoop(session *Session, sessionID uint16, conn net.Conn, messageCounter *uint32) {
	for {
		if shouldStopDelivery := s.checkServerShutdown(); shouldStopDelivery {
			return
		}

		incomingMsg, shouldStop := s.receiveIncomingMessage(session, sessionID)
		if shouldStop {
			return
		}

		i2cpMsg, err := s.prepareMessagePayload(sessionID, incomingMsg, messageCounter)
		if err != nil {
			continue
		}

		if shouldStop := s.sendMessageToClient(conn, sessionID, i2cpMsg); shouldStop {
			return
		}

		s.logMessageDelivered(sessionID, *messageCounter-1, len(incomingMsg.Payload))
	}
}

// logDeliveryStarted logs when the message delivery goroutine starts.
func (s *Server) logDeliveryStarted(sessionID uint16) {
	log.WithFields(logger.Fields{
		"at":        "i2cp.Server.deliverMessagesToClient",
		"sessionID": sessionID,
	}).Info("started_message_delivery_goroutine")
}

// checkServerShutdown checks if the server is shutting down.
func (s *Server) checkServerShutdown() bool {
	select {
	case <-s.ctx.Done():
		return true
	default:
		return false
	}
}

// receiveIncomingMessage receives a message from the session queue.
func (s *Server) receiveIncomingMessage(session *Session, sessionID uint16) (*IncomingMessage, bool) {
	incomingMsg, err := session.ReceiveMessage()
	if err != nil {
		log.WithFields(logger.Fields{
			"at":        "i2cp.Server.receiveIncomingMessage",
			"sessionID": sessionID,
			"error":     err,
		}).Error("failed_to_receive_message")
		return nil, true
	}

	if incomingMsg == nil {
		log.WithFields(logger.Fields{
			"at":        "i2cp.Server.receiveIncomingMessage",
			"sessionID": sessionID,
		}).Debug("session_stopped_stopping_delivery")
		return nil, true
	}

	return incomingMsg, false
}

// prepareMessagePayload creates and serializes a MessagePayload message.
func (s *Server) prepareMessagePayload(
	sessionID uint16,
	incomingMsg *IncomingMessage,
	messageCounter *uint32,
) (*Message, error) {
	// Validate payload size: MessagePayloadPayload has 2-byte SessionID + 4-byte MessageID + payload
	// Total must not exceed I2CP MaxPayloadSize constant
	const headerSize = 6 // SessionID(2) + MessageID(4)
	if len(incomingMsg.Payload)+headerSize > MaxPayloadSize {
		log.WithFields(logger.Fields{
			"at":          "i2cp.Server.prepareMessagePayload",
			"sessionID":   sessionID,
			"payloadSize": len(incomingMsg.Payload),
			"maxAllowed":  MaxPayloadSize - headerSize,
		}).Error("incoming_message_payload_too_large")
		return nil, fmt.Errorf("message payload too large: %d bytes (max %d bytes)",
			len(incomingMsg.Payload), MaxPayloadSize-headerSize)
	}

	msgPayload := &MessagePayloadPayload{
		SessionID: sessionID,
		MessageID: *messageCounter,
		Payload:   incomingMsg.Payload,
	}

	// Increment counter with explicit wrap-around handling
	// When counter reaches max uint32, wrap to 1 (skip 0 to avoid potential issues)
	*messageCounter++
	if *messageCounter == 0 {
		*messageCounter = 1
	}

	payloadBytes, err := msgPayload.MarshalBinary()
	if err != nil {
		log.WithFields(logger.Fields{
			"at":        "i2cp.Server.prepareMessagePayload",
			"sessionID": sessionID,
			"error":     err,
		}).Error("failed_to_marshal_message_payload")
		return nil, err
	}

	i2cpMsg := &Message{
		Type:      MessageTypeMessagePayload,
		SessionID: sessionID,
		Payload:   payloadBytes,
	}

	return i2cpMsg, nil
}

// sendMessageToClient sends a message to the client connection.
// Uses per-connection write mutex to prevent concurrent write corruption.
func (s *Server) sendMessageToClient(conn net.Conn, sessionID uint16, msg *Message) bool {
	s.mu.RLock()
	writeMu := s.connWriteMu[sessionID]
	s.mu.RUnlock()

	if writeMu != nil {
		writeMu.Lock()
	}
	err := WriteMessage(conn, msg)
	if writeMu != nil {
		writeMu.Unlock()
	}

	if err != nil {
		log.WithFields(logger.Fields{
			"at":        "i2cp.Server.sendMessageToClient",
			"sessionID": sessionID,
			"error":     err,
		}).Error("failed_to_write_message_payload")
		return true
	}
	return false
}

// logMessageDelivered logs successful message delivery to client.
func (s *Server) logMessageDelivered(sessionID uint16, messageID uint32, size int) {
	log.WithFields(logger.Fields{
		"at":          "i2cp.Server.deliverMessagesToClient",
		"sessionID":   sessionID,
		"messageID":   messageID,
		"payloadSize": size,
	}).Info("delivered_message_to_client")
}

// min returns the minimum of two integers (helper for i2psnark compatibility logging)
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
