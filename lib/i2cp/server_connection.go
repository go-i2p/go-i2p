package i2cp

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"
	"golang.org/x/time/rate"
)

const (
	hostLookupLimit = rate.Limit(10)
	hostLookupBurst = 60
)

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
	}).Debug("new_i2cp_connection")

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

// cleanupIdleSessions checks all sessions and closes those that have been idle beyond SessionTimeout.
// Uses DestroySession for coordinated cleanup to prevent races with cleanupSessionConnection.
func (s *Server) cleanupIdleSessions() {
	sessions := s.manager.GetAllSessions()
	now := time.Now()

	for _, session := range sessions {
		s.cleanupSessionIfIdle(session, now)
	}
}

// cleanupSessionIfIdle checks if a session is idle and cleans it up if necessary.
func (s *Server) cleanupSessionIfIdle(session *Session, now time.Time) {
	if !session.IsActive() {
		return
	}

	idleTime := now.Sub(session.LastActivity())
	if idleTime <= s.config.SessionTimeout {
		return
	}

	sessionID := session.ID()
	log.WithFields(logger.Fields{
		"at":        "i2cp.Server.cleanupIdleSessions",
		"sessionID": sessionID,
		"idleTime":  idleTime,
		"timeout":   s.config.SessionTimeout,
	}).Info("closing_idle_session")

	if !s.claimSessionCleanup(sessionID) {
		return
	}

	if err := s.manager.DestroySession(sessionID); err != nil {
		log.WithFields(logger.Fields{
			"at":        "i2cp.Server.cleanupIdleSessions",
			"sessionID": sessionID,
		}).Debug("session already destroyed by connection cleanup")
	}
}

// claimSessionCleanup attempts to claim ownership of session cleanup.
// Returns true if cleanup ownership was claimed, false if already handled.
func (s *Server) claimSessionCleanup(sessionID uint16) bool {
	s.mu.Lock()
	_, owned := s.sessionConns[sessionID]
	delete(s.sessionConns, sessionID)
	delete(s.connWriteMu, sessionID)
	s.mu.Unlock()
	return owned
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

// shouldRejectConnection checks if a connection should be rejected due to
// connection or session limits. Tracks active TCP connections separately from
// sessions to prevent resource exhaustion from unauthenticated connections.
// Closes the connection if rejected.
func (s *Server) shouldRejectConnection(conn net.Conn) bool {
	connCount := s.activeConnCount.Load()
	sessionCount := s.manager.SessionCount()
	maxSessions := s.config.MaxSessions

	// Reject if either active connections OR sessions exceed the limit.
	// Use 2x MaxSessions as the connection limit to allow some headroom
	// for connections that haven't created sessions yet.
	maxConns := maxSessions * 2
	if int(connCount) >= maxConns {
		log.WithFields(logger.Fields{
			"at":           "i2cp.Server.shouldRejectConnection",
			"activeConns":  connCount,
			"maxConns":     maxConns,
			"sessionCount": sessionCount,
			"remoteAddr":   conn.RemoteAddr().String(),
		}).Warn("max_connections_reached_rejecting")
		conn.Close()
		return true
	}
	if sessionCount >= maxSessions {
		log.WithFields(logger.Fields{
			"at":           "i2cp.Server.shouldRejectConnection",
			"sessionCount": sessionCount,
			"maxSessions":  maxSessions,
			"remoteAddr":   conn.RemoteAddr().String(),
		}).Warn("max_sessions_reached_rejecting_connection")
		conn.Close()
		return true
	}
	s.activeConnCount.Add(1)
	return false
}

// handleConnection processes a single client connection
func (s *Server) handleConnection(conn net.Conn) {
	defer s.wg.Done()
	defer s.recoverFromConnectionPanic(conn)
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

func (s *Server) recoverFromConnectionPanic(conn net.Conn) {
	if r := recover(); r != nil {
		log.WithFields(logger.Fields{
			"at":         "i2cp.Server.handleConnection",
			"remoteAddr": conn.RemoteAddr().String(),
			"localAddr":  conn.LocalAddr().String(),
			"panic":      r,
		}).Error("panic_in_connection_handler")
	}
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
	}).Debug("client_connected")
}

// cleanupSessionConnection removes the session connection mapping on disconnect
// and properly destroys the session to release all associated resources.
// Uses delete-from-map as a coordination mechanism with cleanupIdleSessions:
// only the path that successfully removes the session from the map proceeds
// with DestroySession, preventing double-cleanup races.
func (s *Server) cleanupSessionConnection(sessionPtr **Session) {
	if *sessionPtr != nil {
		session := *sessionPtr
		sessionID := session.ID()

		// Attempt to claim ownership of cleanup by removing from map.
		// If the key is already gone, cleanupIdleSessions already handled it.
		s.mu.Lock()
		_, owned := s.sessionConns[sessionID]
		delete(s.sessionConns, sessionID)
		delete(s.connWriteMu, sessionID)
		s.mu.Unlock()

		if !owned {
			log.WithFields(logger.Fields{
				"at":        "i2cp.Server.cleanupSessionConnection",
				"sessionID": sessionID,
			}).Debug("session already cleaned up by idle cleanup, skipping")
			return
		}

		// We own the cleanup — destroy the session.
		if err := s.manager.DestroySession(sessionID); err != nil {
			log.WithFields(logger.Fields{
				"at":        "i2cp.Server.cleanupSessionConnection",
				"sessionID": sessionID,
			}).Debug("session already destroyed")
		}

		log.WithFields(logger.Fields{
			"at":        "i2cp.Server.cleanupSessionConnection",
			"sessionID": sessionID,
		}).Debug("client_disconnected")
	}
}

// cleanupConnectionState removes connection state tracking on disconnect
// and decrements the active connection counter.
func (s *Server) cleanupConnectionState(conn net.Conn) {
	s.connMutex.Lock()
	delete(s.connStates, conn)
	s.connMutex.Unlock()
	s.activeConnCount.Add(-1)
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
	}).Debug("protocol_handshake_successful")

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

	if msg.Type == MessageTypeGetDate {
		s.attemptAuthFromGetDate(conn, msg)
	}

	if !s.checkMessageAuthentication(conn, msg) {
		return false
	}

	if rateLimitedResponse, allowed := s.allowHostLookup(conn, msg); !allowed {
		if err := s.sendResponse(conn, rateLimitedResponse, sessionPtr); err != nil {
			return false
		}
		return true
	}

	return s.processAndRespond(conn, msg, sessionPtr)
}

// checkMessageAuthentication verifies the client is authenticated for protected
// operations. GetDate, GetBandwidthLimits, and Disconnect remain available
// without authentication to preserve the I2CP handshake flow.
func (s *Server) checkMessageAuthentication(conn net.Conn, msg *Message) bool {
	if !s.requiresAuthentication(msg.Type) {
		return true
	}
	state := s.getOrCreateConnectionState(conn)
	if s.isConnectionAuthenticated(state) {
		return true
	}
	log.WithFields(logger.Fields{
		"at":         "i2cp.Server.processOneMessage",
		"msgType":    MessageTypeName(msg.Type),
		"remoteAddr": conn.RemoteAddr().String(),
	}).Warn("unauthenticated_client_rejected")
	return false
}

// processAndRespond processes the client message and sends the response.
// Returns false if the connection should be closed, true to continue.
func (s *Server) processAndRespond(conn net.Conn, msg *Message, sessionPtr **Session) bool {
	response, err := s.processClientMessage(conn, msg, sessionPtr)
	if err != nil {
		return !errors.Is(err, errClientDisconnected)
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
		return nil, oops.Errorf("connection rate limit exceeded")
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

	// Hold connMutex for the entire check-reset-verify sequence to prevent
	// a race between resetCountersIfNeeded (which writes) and
	// updateConnectionState (which also writes under the same lock).
	s.connMutex.Lock()
	defer s.connMutex.Unlock()

	state, exists := s.connStates[conn]
	if !exists {
		state = &connectionState{
			conn:              conn,
			lastMessageTime:   time.Time{}, // Zero value allows first message immediately
			messageCount:      0,
			bytesRead:         0,
			hostLookupLimiter: rate.NewLimiter(hostLookupLimit, hostLookupBurst),
		}
		s.connStates[conn] = state
	}

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
			conn:              conn,
			lastMessageTime:   time.Time{}, // Zero value allows first message immediately
			messageCount:      0,
			bytesRead:         0,
			hostLookupLimiter: rate.NewLimiter(hostLookupLimit, hostLookupBurst),
		}
		s.connStates[conn] = state
	}
	if state.conn == nil {
		state.conn = conn
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
func (s *Server) processClientMessage(conn net.Conn, msg *Message, sessionPtr **Session) (response *Message, err error) {
	defer func() {
		if r := recover(); r != nil {
			log.WithFields(logger.Fields{
				"at":         "i2cp.Server.processClientMessage",
				"msgType":    MessageTypeName(msg.Type),
				"remoteAddr": conn.RemoteAddr().String(),
				"panic":      r,
			}).Error("panic_in_message_handler")
			response = nil
			err = oops.Errorf("panic handling %s: %v", MessageTypeName(msg.Type), r)
		}
	}()

	response, err = s.handleMessage(conn, msg, sessionPtr)
	if err != nil {
		log.WithError(err).Error("failed_to_handle_message")
		return nil, err
	}
	return response, nil
}

func (s *Server) allowHostLookup(conn net.Conn, msg *Message) (*Message, bool) {
	if msg.Type != MessageTypeHostLookup {
		return nil, true
	}

	state := s.getOrCreateConnectionState(conn)
	if state.hostLookupLimiter.Allow() {
		return nil, true
	}

	log.WithFields(logger.Fields{
		"at":         "i2cp.Server.allowHostLookup",
		"remoteAddr": conn.RemoteAddr().String(),
		"burst":      hostLookupBurst,
		"rate":       float64(hostLookupLimit),
	}).Warn("host_lookup_rate_limited")

	response, err := buildHostReplyMessage(msg.SessionID, &HostReplyPayload{
		RequestID:  extractHostLookupRequestID(msg.Payload),
		ResultCode: HostReplyTimeout,
	})
	if err != nil {
		log.WithFields(logger.Fields{
			"at":    "i2cp.Server.allowHostLookup",
			"error": err.Error(),
		}).Warn("failed_to_build_host_lookup_rate_limit_reply")
		return nil, false
	}

	return response, false
}

func extractHostLookupRequestID(payload []byte) uint32 {
	lookupMsg, err := ParseHostLookupPayload(payload)
	if err != nil {
		return 0
	}
	return lookupMsg.RequestID
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
	if response == nil {
		return nil
	}

	s.applyWriteDeadline(conn)

	log.WithFields(logger.Fields{
		"at":          "i2cp.Server.sendResponse",
		"type":        MessageTypeName(response.Type),
		"sessionID":   response.SessionID,
		"payloadSize": len(response.Payload),
	}).Debug("sending_response")

	writeMu, holdingRLock := s.acquireWriteMutex(sessionPtr)

	err := WriteMessage(conn, response)

	s.releaseWriteMutex(writeMu, holdingRLock)

	if err != nil {
		log.WithFields(logger.Fields{
			"at":    "i2cp.Server.sendResponse",
			"type":  MessageTypeName(response.Type),
			"error": err.Error(),
		}).Error("failed_to_write_response")
		return err
	}
	return nil
}

// applyWriteDeadline sets the connection write deadline if a timeout is configured.
func (s *Server) applyWriteDeadline(conn net.Conn) {
	if s.config.WriteTimeout > 0 {
		if err := conn.SetWriteDeadline(time.Now().Add(s.config.WriteTimeout)); err != nil {
			log.WithFields(logger.Fields{
				"at":    "i2cp.Server.sendResponse",
				"error": err.Error(),
			}).Warn("failed_to_set_write_deadline")
		}
	}
}

// acquireWriteMutex acquires the per-connection write mutex for the session
// if available. Returns the mutex. The RLock is held only briefly to look up
// the mutex, then released before acquiring the write mutex, so it does not
// block session management operations during slow network I/O.
func (s *Server) acquireWriteMutex(sessionPtr **Session) (*sync.Mutex, bool) {
	if *sessionPtr == nil {
		return nil, false
	}
	s.mu.RLock()
	writeMu := s.connWriteMu[(*sessionPtr).ID()]
	s.mu.RUnlock() // Release RLock immediately after map lookup
	if writeMu == nil {
		return nil, false
	}
	writeMu.Lock()
	return writeMu, false // RLock is no longer held
}

// releaseWriteMutex releases the write mutex and the server RLock if held.
func (s *Server) releaseWriteMutex(writeMu *sync.Mutex, holdingRLock bool) {
	if writeMu != nil {
		writeMu.Unlock()
	}
	if holdingRLock {
		s.mu.RUnlock()
	}
}
