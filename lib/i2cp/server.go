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

	mu      sync.RWMutex
	running bool

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
		config:  config,
		manager: NewSessionManager(),
		ctx:     ctx,
		cancel:  cancel,
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

	log.WithFields(logger.Fields{
		"at":         "i2cp.Server.handleConnection",
		"remoteAddr": conn.RemoteAddr(),
	}).Info("client_connected")

	var session *Session

	// Connection loop
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		// Read message
		msg, err := ReadMessage(conn)
		if err != nil {
			log.WithError(err).Debug("failed_to_read_message")
			return
		}

		log.WithFields(logger.Fields{
			"at":        "i2cp.Server.handleConnection",
			"type":      MessageTypeName(msg.Type),
			"sessionID": msg.SessionID,
		}).Debug("received_message")

		// Process message
		response, err := s.handleMessage(msg, &session)
		if err != nil {
			log.WithError(err).Error("failed_to_handle_message")
			// Send error response (simplified - in real impl would send proper error message)
			continue
		}

		// Send response if any
		if response != nil {
			if err := WriteMessage(conn, response); err != nil {
				log.WithError(err).Error("failed_to_write_response")
				return
			}
		}
	}
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

// handleSendMessage handles a client sending a message
func (s *Server) handleSendMessage(msg *Message, sessionPtr **Session) (*Message, error) {
	if *sessionPtr == nil {
		return nil, fmt.Errorf("no active session")
	}

	// TODO: Parse destination and payload from msg.Payload
	// TODO: Route message through tunnels

	log.WithFields(logger.Fields{
		"at":        "i2cp.Server.handleSendMessage",
		"sessionID": (*sessionPtr).ID(),
		"size":      len(msg.Payload),
	}).Debug("message_queued_for_sending")

	// No immediate response for SendMessage
	return nil, nil
}

// SessionManager returns the server's session manager
func (s *Server) SessionManager() *SessionManager {
	return s.manager
}

// IsRunning returns whether the server is currently running
func (s *Server) IsRunning() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.running
}
