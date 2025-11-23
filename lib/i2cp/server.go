package i2cp

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/go-i2p/logger"
)

// log is the package logger
var log = logger.GetGoI2PLogger()

// DefaultI2CPPort is the standard I2CP port
const DefaultI2CPPort = 7654

// ServerConfig holds configuration for the I2CP server
type ServerConfig struct {
	// Address to listen on (e.g., "localhost:7654" or "/tmp/i2cp.sock" for Unix socket)
	ListenAddr string

	// Network type: "tcp" or "unix"
	Network string

	// Maximum number of concurrent sessions
	MaxSessions int
}

// DefaultServerConfig returns a ServerConfig with sensible defaults
func DefaultServerConfig() *ServerConfig {
	return &ServerConfig{
		ListenAddr:  fmt.Sprintf("localhost:%d", DefaultI2CPPort),
		Network:     "tcp",
		MaxSessions: 100,
	}
}

// Server is an I2CP protocol server that accepts client connections
type Server struct {
	config  *ServerConfig
	manager *SessionManager

	listener net.Listener

	// Message routing
	messageRouter *MessageRouter

	// Connection tracking for message delivery
	mu           sync.RWMutex
	running      bool
	sessionConns map[uint16]net.Conn // Session ID -> active connection

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewServer creates a new I2CP server
func NewServer(config *ServerConfig) (*Server, error) {
	if config == nil {
		config = DefaultServerConfig()
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &Server{
		config:       config,
		manager:      NewSessionManager(),
		sessionConns: make(map[uint16]net.Conn),
		ctx:          ctx,
		cancel:       cancel,
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

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.ctx.Done():
				// Server is shutting down
				return
			default:
				log.WithError(err).Error("failed_to_accept_connection")
				continue
			}
		}

		// Check session limit
		if s.manager.SessionCount() >= s.config.MaxSessions {
			log.WithFields(logger.Fields{
				"at":           "i2cp.Server.acceptLoop",
				"sessionCount": s.manager.SessionCount(),
				"maxSessions":  s.config.MaxSessions,
			}).Warn("max_sessions_reached")
			conn.Close()
			continue
		}

		// Handle connection
		s.wg.Add(1)
		go s.handleConnection(conn)
	}
}

// handleConnection processes a single client connection
func (s *Server) handleConnection(conn net.Conn) {
	defer s.wg.Done()
	defer conn.Close()

	s.logClientConnected(conn)

	var session *Session
	defer s.cleanupSessionConnection(&session)

	s.runConnectionLoop(conn, &session)
}

// logClientConnected logs when a client connects to the server.
func (s *Server) logClientConnected(conn net.Conn) {
	log.WithFields(logger.Fields{
		"at":         "i2cp.Server.handleConnection",
		"remoteAddr": conn.RemoteAddr(),
	}).Info("client_connected")
}

// cleanupSessionConnection removes the session connection mapping on disconnect.
func (s *Server) cleanupSessionConnection(sessionPtr **Session) {
	if *sessionPtr != nil {
		s.mu.Lock()
		delete(s.sessionConns, (*sessionPtr).ID())
		s.mu.Unlock()
	}
}

// runConnectionLoop processes messages from the client connection.
func (s *Server) runConnectionLoop(conn net.Conn, sessionPtr **Session) {
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		msg, err := s.readClientMessage(conn)
		if err != nil {
			return
		}

		s.logReceivedMessage(msg)

		response, err := s.processClientMessage(msg, sessionPtr)
		if err != nil {
			continue
		}

		s.handleNewSessionTracking(msg, sessionPtr, conn)

		if err := s.sendResponse(conn, response); err != nil {
			return
		}
	}
}

// readClientMessage reads an I2CP message from the connection.
func (s *Server) readClientMessage(conn net.Conn) (*Message, error) {
	msg, err := ReadMessage(conn)
	if err != nil {
		log.WithError(err).Debug("failed_to_read_message")
		return nil, err
	}
	return msg, nil
}

// logReceivedMessage logs details about a received message.
func (s *Server) logReceivedMessage(msg *Message) {
	log.WithFields(logger.Fields{
		"at":        "i2cp.Server.handleConnection",
		"type":      MessageTypeName(msg.Type),
		"sessionID": msg.SessionID,
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
	}
}

// sendResponse writes a response message to the connection if present.
func (s *Server) sendResponse(conn net.Conn, response *Message) error {
	if response != nil {
		if err := WriteMessage(conn, response); err != nil {
			log.WithError(err).Error("failed_to_write_response")
			return err
		}
	}
	return nil
}

// handleMessage processes a single I2CP message and returns an optional response
func (s *Server) handleMessage(msg *Message, sessionPtr **Session) (*Message, error) {
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
		log.WithFields(logger.Fields{
			"at":   "i2cp.Server.handleMessage",
			"type": msg.Type,
		}).Warn("unsupported_message_type")
		return nil, fmt.Errorf("unsupported message type: %d", msg.Type)
	}
}

// handleCreateSession creates a new session
func (s *Server) handleCreateSession(msg *Message, sessionPtr **Session) (*Message, error) {
	// TODO: Parse session configuration from payload
	config := DefaultSessionConfig()

	// Create session
	session, err := s.manager.CreateSession(nil, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	*sessionPtr = session

	log.WithFields(logger.Fields{
		"at":        "i2cp.Server.handleCreateSession",
		"sessionID": session.ID(),
	}).Info("session_created")

	// Send SessionStatus response (status byte: 0 = success)
	response := &Message{
		Type:      MessageTypeSessionStatus,
		SessionID: session.ID(),
		Payload:   []byte{0x00}, // Success
	}

	return response, nil
}

// handleDestroySession destroys a session
func (s *Server) handleDestroySession(msg *Message, sessionPtr **Session) (*Message, error) {
	if *sessionPtr == nil {
		return nil, fmt.Errorf("no active session")
	}

	sessionID := (*sessionPtr).ID()

	if err := s.manager.DestroySession(sessionID); err != nil {
		return nil, fmt.Errorf("failed to destroy session: %w", err)
	}

	*sessionPtr = nil

	log.WithFields(logger.Fields{
		"at":        "i2cp.Server.handleDestroySession",
		"sessionID": sessionID,
	}).Info("session_destroyed")

	// No response for DestroySession
	return nil, nil
}

// handleReconfigureSession updates session configuration
func (s *Server) handleReconfigureSession(msg *Message, sessionPtr **Session) (*Message, error) {
	if *sessionPtr == nil {
		return nil, fmt.Errorf("no active session")
	}

	// TODO: Parse new configuration from payload
	newConfig := DefaultSessionConfig()

	if err := (*sessionPtr).Reconfigure(newConfig); err != nil {
		return nil, fmt.Errorf("failed to reconfigure session: %w", err)
	}

	log.WithFields(logger.Fields{
		"at":        "i2cp.Server.handleReconfigureSession",
		"sessionID": (*sessionPtr).ID(),
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

	// TODO: Publish LeaseSet to network database (NetDB)
	// This would involve sending a DatabaseStore message with the LeaseSet

	// For I2CP protocol, we don't send a response to CreateLeaseSet
	// The client just needs to know the operation succeeded (no error)
	return nil, nil
}

// handleGetDate returns the current router time
func (s *Server) handleGetDate(msg *Message) (*Message, error) {
	// TODO: Implement proper I2P time format
	// For now, return empty payload
	response := &Message{
		Type:      MessageTypeSetDate,
		SessionID: msg.SessionID,
		Payload:   []byte{}, // TODO: Encode current time
	}

	return response, nil
}

// handleGetBandwidthLimits returns bandwidth limits
func (s *Server) handleGetBandwidthLimits(msg *Message) (*Message, error) {
	// TODO: Implement actual bandwidth limits
	// For now, return empty payload
	response := &Message{
		Type:      MessageTypeBandwidthLimits,
		SessionID: msg.SessionID,
		Payload:   []byte{}, // TODO: Encode bandwidth limits
	}

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
	if *sessionPtr == nil {
		return nil, fmt.Errorf("no active session")
	}

	session := *sessionPtr

	// Parse SendMessage payload
	sendMsg, err := ParseSendMessagePayload(msg.Payload)
	if err != nil {
		log.WithFields(logger.Fields{
			"at":        "i2cp.Server.handleSendMessage",
			"sessionID": session.ID(),
			"error":     err,
		}).Error("failed_to_parse_send_message")
		return nil, fmt.Errorf("failed to parse SendMessage payload: %w", err)
	}

	// Validate session has outbound tunnels
	outboundPool := session.OutboundPool()
	if outboundPool == nil {
		log.WithFields(logger.Fields{
			"at":        "i2cp.Server.handleSendMessage",
			"sessionID": session.ID(),
		}).Warn("no_outbound_tunnel_pool")
		return nil, fmt.Errorf("session %d has no outbound tunnel pool", session.ID())
	}

	// Route the message through the I2P network
	// This requires the destination's public key for garlic encryption
	// For now, we'll need to look up the destination in NetDB to get the public key
	// TODO: Add NetDB lookup integration to get destination's RouterInfo/LeaseSet

	// Placeholder: Use zero key for testing - in production this must be looked up
	var destPubKey [32]byte

	// If message router is configured, route the message
	if s.messageRouter != nil {
		err = s.messageRouter.RouteOutboundMessage(
			session,
			sendMsg.Destination,
			destPubKey,
			sendMsg.Payload,
		)
		if err != nil {
			log.WithFields(logger.Fields{
				"at":          "i2cp.Server.handleSendMessage",
				"sessionID":   session.ID(),
				"destination": fmt.Sprintf("%x", sendMsg.Destination[:8]),
				"error":       err,
			}).Error("failed_to_route_message")
			// Don't return error - message routing is best-effort
		} else {
			log.WithFields(logger.Fields{
				"at":          "i2cp.Server.handleSendMessage",
				"sessionID":   session.ID(),
				"destination": fmt.Sprintf("%x", sendMsg.Destination[:8]),
				"payloadSize": len(sendMsg.Payload),
			}).Info("message_routed_successfully")
		}
	} else {
		log.WithFields(logger.Fields{
			"at":          "i2cp.Server.handleSendMessage",
			"sessionID":   session.ID(),
			"destination": fmt.Sprintf("%x", sendMsg.Destination[:8]),
			"payloadSize": len(sendMsg.Payload),
		}).Info("message_queued_for_sending_no_router")
	}

	// No immediate response for SendMessage (fire-and-forget)
	// In the future, we may send DeliveryStatus responses for reliability
	return nil, nil
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

	sessionID := session.ID()
	messageCounter := uint32(1) // Start message IDs at 1

	log.WithFields(logger.Fields{
		"at":        "i2cp.Server.deliverMessagesToClient",
		"sessionID": sessionID,
	}).Debug("started_message_delivery_goroutine")

	for {
		select {
		case <-s.ctx.Done():
			// Server is shutting down
			return

		default:
			// Try to receive a message from the session queue
			incomingMsg, err := session.ReceiveMessage()
			if err != nil {
				log.WithFields(logger.Fields{
					"at":        "i2cp.Server.deliverMessagesToClient",
					"sessionID": sessionID,
					"error":     err,
				}).Error("failed_to_receive_message")
				return
			}

			// nil message means session was stopped
			if incomingMsg == nil {
				log.WithFields(logger.Fields{
					"at":        "i2cp.Server.deliverMessagesToClient",
					"sessionID": sessionID,
				}).Debug("session_stopped_stopping_delivery")
				return
			}

			// Create MessagePayload message
			msgPayload := &MessagePayloadPayload{
				MessageID: messageCounter,
				Payload:   incomingMsg.Payload,
			}

			messageCounter++ // Increment for next message

			// Serialize MessagePayload payload
			payloadBytes, err := msgPayload.MarshalBinary()
			if err != nil {
				log.WithFields(logger.Fields{
					"at":        "i2cp.Server.deliverMessagesToClient",
					"sessionID": sessionID,
					"error":     err,
				}).Error("failed_to_marshal_message_payload")
				continue
			}

			// Create I2CP MessagePayload message
			i2cpMsg := &Message{
				Type:      MessageTypeMessagePayload,
				SessionID: sessionID,
				Payload:   payloadBytes,
			}

			// Send to client
			if err := WriteMessage(conn, i2cpMsg); err != nil {
				log.WithFields(logger.Fields{
					"at":        "i2cp.Server.deliverMessagesToClient",
					"sessionID": sessionID,
					"error":     err,
				}).Error("failed_to_write_message_payload")
				return
			}

			log.WithFields(logger.Fields{
				"at":        "i2cp.Server.deliverMessagesToClient",
				"sessionID": sessionID,
				"messageID": msgPayload.MessageID,
				"size":      len(incomingMsg.Payload),
			}).Debug("delivered_message_to_client")
		}
	}
}
