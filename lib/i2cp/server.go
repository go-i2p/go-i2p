package i2cp

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
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

	// LeaseSet publisher for distributing LeaseSets to the network (optional)
	// If nil, sessions will function but won't publish to the network
	LeaseSetPublisher LeaseSetPublisher
}

// DefaultServerConfig returns a ServerConfig with sensible defaults
func DefaultServerConfig() *ServerConfig {
	return &ServerConfig{
		ListenAddr:  fmt.Sprintf("localhost:%d", config.DefaultI2CPPort),
		Network:     "tcp",
		MaxSessions: 100,
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

	// Connection tracking for message delivery
	mu           sync.RWMutex
	running      bool
	sessionConns map[uint16]net.Conn // Session ID -> active connection

	// Connection-level rate limiting to prevent abuse before session creation
	connMutex  sync.RWMutex
	connStates map[net.Conn]*connectionState

	// LeaseSet publishing
	leaseSetPublisher LeaseSetPublisher

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
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

// acceptLoop accepts incoming connections
func (s *Server) acceptLoop() {
	defer s.wg.Done()
	defer func() {
		// Defensive: recover from any panic during shutdown to prevent server crash
		if r := recover(); r != nil {
			log.WithFields(logger.Fields{
				"at":    "i2cp.Server.acceptLoop",
				"panic": r,
			}).Error("panic_in_accept_loop")
		}
	}()

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if s.handleAcceptError(err) {
				return
			}
			continue
		}

		// i2psnark compatibility: Log all connection attempts
		log.WithFields(logger.Fields{
			"at":         "i2cp.Server.acceptLoop",
			"remoteAddr": conn.RemoteAddr().String(),
			"localAddr":  conn.LocalAddr().String(),
		}).Info("new_i2cp_connection")

		if s.shouldRejectConnection(conn) {
			continue
		}

		s.wg.Add(1)
		go s.handleConnection(conn)
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
		s.mu.Unlock()
		log.WithFields(logger.Fields{
			"at":        "i2cp.Server.cleanupSessionConnection",
			"sessionID": sessionID,
		}).Debug("client_disconnected")
	}
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

	if err := s.sendResponse(conn, response); err != nil {
		return false
	}

	return true
}

// readClientMessage reads an I2CP message from the connection with rate limiting.
func (s *Server) readClientMessage(conn net.Conn) (*Message, error) {
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
// Limits are set high to accommodate legitimate local client applications
// while still preventing extreme resource exhaustion attacks.
func (s *Server) checkConnectionRateLimit(conn net.Conn) bool {
	const (
		maxMessagesPerSecond = 10000                 // Maximum 10,000 messages/second per connection
		maxBytesPerSecond    = 100 * 1024 * 1024     // Maximum 100 MB/second per connection
		minMessageInterval   = 10 * time.Microsecond // Minimum 10μs between messages (prevents extreme spam)
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
func (s *Server) sendResponse(conn net.Conn, response *Message) error {
	if response != nil {
		log.WithFields(logger.Fields{
			"at":          "i2cp.Server.sendResponse",
			"type":        MessageTypeName(response.Type),
			"sessionID":   response.SessionID,
			"payloadSize": len(response.Payload),
		}).Debug("sending_response")
		if err := WriteMessage(conn, response); err != nil {
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

	case MessageTypeGetDate:
		return s.handleGetDate(msg)

	case MessageTypeGetBandwidthLimits:
		return s.handleGetBandwidthLimits(msg)

	case MessageTypeSendMessage:
		return s.handleSendMessage(msg, sessionPtr)

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

// buildSessionStatusResponse creates a successful SessionStatus message.
func buildSessionStatusResponse(sessionID uint16) *Message {
	return &Message{
		Type:      MessageTypeSessionStatus,
		SessionID: sessionID,
		Payload:   []byte{0x00}, // Success status byte
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

	// No response for DestroySession
	return nil, nil
}

// monitorTunnelsAndRequestLeaseSet monitors a session's tunnel pools and sends
// RequestVariableLeaseSet (type 37) when tunnels are ready. This is required by
// I2CP protocol - the router must tell the client when to publish its LeaseSet.
//
// Per I2CP spec: After session creation, router waits for inbound+outbound tunnels,
// then sends type 37 with lease data. Client responds with CreateLeaseSet (type 5).
//
// NOTE: This requires tunnel pools to be attached to the session by the router layer.
// Currently pools are not attached during handleCreateSession, so this will wait
// indefinitely. This is Bug #2's partial fix - pools need router integration.
func (s *Server) monitorTunnelsAndRequestLeaseSet(session *Session, conn net.Conn) {
	sessionID := session.ID()

	log.WithFields(logger.Fields{
		"at":        "i2cp.Server.monitorTunnelsAndRequestLeaseSet",
		"sessionID": sessionID,
	}).Debug("starting_tunnel_monitoring")

	// Wait for both inbound and outbound tunnels to be ready
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	timeout := time.After(2 * time.Minute) // Give up after 2 minutes

	for {
		select {
		case <-timeout:
			log.WithFields(logger.Fields{
				"at":        "i2cp.Server.monitorTunnelsAndRequestLeaseSet",
				"sessionID": sessionID,
			}).Warn("timeout_waiting_for_tunnels")
			return

		case <-ticker.C:
			inboundPool := session.InboundPool()
			outboundPool := session.OutboundPool()

			// Check if pools are attached and have active tunnels
			if inboundPool == nil || outboundPool == nil {
				continue
			}

			inTunnels := inboundPool.GetActiveTunnels()
			outTunnels := outboundPool.GetActiveTunnels()

			if len(inTunnels) == 0 || len(outTunnels) == 0 {
				continue
			}

			// Tunnels ready - build and send RequestVariableLeaseSet
			log.WithFields(logger.Fields{
				"at":              "i2cp.Server.monitorTunnelsAndRequestLeaseSet",
				"sessionID":       sessionID,
				"inboundTunnels":  len(inTunnels),
				"outboundTunnels": len(outTunnels),
			}).Info("tunnels_ready_sending_leaseset_request")

			payload, err := s.buildRequestVariableLeaseSetPayload(inTunnels)
			if err != nil {
				log.WithFields(logger.Fields{
					"at":        "i2cp.Server.monitorTunnelsAndRequestLeaseSet",
					"sessionID": sessionID,
					"error":     err.Error(),
				}).Error("failed_to_build_leaseset_request")
				return
			}

			msg := &Message{
				Type:      MessageTypeRequestVariableLeaseSet,
				SessionID: sessionID,
				Payload:   payload,
			}

			if err := WriteMessage(conn, msg); err != nil {
				log.WithFields(logger.Fields{
					"at":        "i2cp.Server.monitorTunnelsAndRequestLeaseSet",
					"sessionID": sessionID,
					"error":     err.Error(),
				}).Error("failed_to_send_leaseset_request")
				return
			}

			log.WithFields(logger.Fields{
				"at":          "i2cp.Server.monitorTunnelsAndRequestLeaseSet",
				"sessionID":   sessionID,
				"payloadSize": len(payload),
			}).Info("sent_request_variable_leaseset")

			return
		}
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

// handleGetDate returns the current router time
func (s *Server) handleGetDate(msg *Message) (*Message, error) {
	// i2psnark compatibility: Log time query
	log.WithFields(logger.Fields{
		"at":        "i2cp.Server.handleGetDate",
		"sessionID": msg.SessionID,
	}).Debug("handling_get_date_request")

	// I2P time format: 8 bytes representing milliseconds since Unix epoch (big endian)
	currentTimeMillis := time.Now().UnixMilli()

	// Encode as 8-byte big endian integer
	payload := make([]byte, 8)
	payload[0] = byte(currentTimeMillis >> 56)
	payload[1] = byte(currentTimeMillis >> 48)
	payload[2] = byte(currentTimeMillis >> 40)
	payload[3] = byte(currentTimeMillis >> 32)
	payload[4] = byte(currentTimeMillis >> 24)
	payload[5] = byte(currentTimeMillis >> 16)
	payload[6] = byte(currentTimeMillis >> 8)
	payload[7] = byte(currentTimeMillis)

	response := &Message{
		Type:      MessageTypeSetDate,
		SessionID: msg.SessionID,
		Payload:   payload,
	}

	log.WithFields(logger.Fields{
		"at":          "i2cp.Server.handleGetDate",
		"reason":      "client_requested",
		"time_millis": currentTimeMillis,
	}).Debug("returning router time")
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

// handleSendMessage handles a client sending a message to a destination.
// This parses the SendMessage payload (destination hash + message data),
// validates the session state, and initiates message routing.
//
// In a full implementation, this would:
// 1. Wrap the payload in garlic encryption using the destination's public key
// 2. Select an outbound tunnel from the session's tunnel pool
// 3. Send the garlic message through the tunnel to the destination
//
// Current implementation provides payload parsing and validation.
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

	s.routeMessageToDestination(session, sendMsg)

	return nil, nil
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

// routeMessageToDestination routes the message through the I2P network.
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
		s.routeWithMessageRouter(session, sendMsg, destPubKey)
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
func (s *Server) routeWithMessageRouter(session *Session, sendMsg *SendMessagePayload, destPubKey [32]byte) {
	err := s.messageRouter.RouteOutboundMessage(
		session,
		sendMsg.Destination,
		destPubKey,
		sendMsg.Payload,
	)
	if err != nil {
		log.WithFields(logger.Fields{
			"at":          "i2cp.Server.routeWithMessageRouter",
			"sessionID":   session.ID(),
			"destination": fmt.Sprintf("%x", sendMsg.Destination[:8]),
			"error":       err,
		}).Error("failed_to_route_message")
	} else {
		log.WithFields(logger.Fields{
			"at":          "i2cp.Server.routeWithMessageRouter",
			"sessionID":   session.ID(),
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
	defer func() {
		// Defensive: recover from any panic during shutdown to prevent goroutine leak
		if r := recover(); r != nil {
			log.WithFields(logger.Fields{
				"at":        "i2cp.Server.deliverMessagesToClient",
				"sessionID": session.ID(),
				"panic":     r,
			}).Error("panic_in_message_delivery_goroutine")
		}
	}()

	sessionID := session.ID()
	// Message ID counter uses uint32 and will wrap to 1 after reaching max value.
	// This allows ~4.2 billion messages before wrap-around. I2CP spec doesn't mandate
	// specific overflow behavior, so we use natural uint32 wrapping.
	// Clients should handle message IDs as opaque identifiers, not sequence numbers.
	messageCounter := uint32(1)

	s.logDeliveryStarted(sessionID)

	for {
		if shouldStopDelivery := s.checkServerShutdown(); shouldStopDelivery {
			return
		}

		incomingMsg, shouldStop := s.receiveIncomingMessage(session, sessionID)
		if shouldStop {
			return
		}

		i2cpMsg, err := s.prepareMessagePayload(sessionID, incomingMsg, &messageCounter)
		if err != nil {
			continue
		}

		if shouldStop := s.sendMessageToClient(conn, sessionID, i2cpMsg); shouldStop {
			return
		}

		s.logMessageDelivered(sessionID, messageCounter-1, len(incomingMsg.Payload))
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
	// Validate payload size: MessagePayloadPayload has 4-byte MessageID + payload
	// Total must not exceed I2CP MaxPayloadSize (65535 bytes)
	const messageIDSize = 4
	if len(incomingMsg.Payload)+messageIDSize > MaxPayloadSize {
		log.WithFields(logger.Fields{
			"at":          "i2cp.Server.prepareMessagePayload",
			"sessionID":   sessionID,
			"payloadSize": len(incomingMsg.Payload),
			"maxAllowed":  MaxPayloadSize - messageIDSize,
		}).Error("incoming_message_payload_too_large")
		return nil, fmt.Errorf("message payload too large: %d bytes (max %d bytes)",
			len(incomingMsg.Payload), MaxPayloadSize-messageIDSize)
	}

	msgPayload := &MessagePayloadPayload{
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
func (s *Server) sendMessageToClient(conn net.Conn, sessionID uint16, msg *Message) bool {
	if err := WriteMessage(conn, msg); err != nil {
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
