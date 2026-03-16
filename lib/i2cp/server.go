package i2cp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/go-i2p/logger"
)

// errClientDisconnected is a sentinel error returned by handleDisconnect to
// signal that the client has gracefully disconnected and the connection loop
// should terminate without logging a spurious read-error.
var errClientDisconnected = errors.New("client disconnected")

// HostnameResolver resolves .i2p hostnames to their binary Destination representation.
// Implementations may use an address book file, naming service, or subscription list.
type HostnameResolver interface {
	// ResolveHostname resolves an I2P hostname (e.g., "forum.i2p") to the raw
	// Destination bytes. Returns the destination bytes and nil on success,
	// or nil and an error if the hostname cannot be resolved.
	ResolveHostname(hostname string) ([]byte, error)
}

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

// connectionState tracks per-connection rate limiting and authentication state
type connectionState struct {
	lastMessageTime time.Time
	messageCount    int
	bytesRead       uint64
	authenticated   atomic.Bool // true if this connection has been authenticated (or auth not required)
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

	// HostnameResolver resolves .i2p hostnames to Destination bytes.
	// If nil, hostname lookups return HostReplyError (not implemented).
	// Implementations may use an address book, naming service, or subscription list.
	hostnameResolver HostnameResolver

	// BandwidthLimitsProvider supplies configured bandwidth limits (bytes/sec).
	// If nil, the server falls back to a conservative default.
	bandwidthProvider interface {
		GetBandwidthLimits() (inbound, outbound uint32)
	}

	// Optional authentication for I2CP connections.
	// When set, clients must provide valid credentials via GetDate options
	// before session-mutating operations (CreateSession, etc.) are allowed.
	authenticator Authenticator

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

	// Active TCP connection counter (separate from session count).
	// Prevents resource exhaustion from unauthenticated TCP connections
	// that haven't created sessions yet.
	activeConnCount atomic.Int32

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
// ErrNoDestinationResolver is returned when a message cannot be routed because
// no destination resolver has been configured on the I2CP server. Without a
// resolver, the server cannot look up the recipient's public key, so encryption
// (and therefore routing) is impossible.
var ErrNoDestinationResolver = errors.New("no destination resolver configured: cannot resolve encryption key")

// resolveDestinationKey looks up the destination's encryption public key from NetDB.
// Returns the X25519 public key needed for ECIES-X25519-AEAD garlic encryption.
// Returns ErrNoDestinationResolver if no resolver has been set via SetDestinationResolver.
func (s *Server) resolveDestinationKey(destHash common.Hash) ([32]byte, error) {
	if s.destinationResolver == nil {
		log.WithField("destination", fmt.Sprintf("%x", destHash[:8])).
			Error("no_destination_resolver_configured")
		return [32]byte{}, ErrNoDestinationResolver
	}

	pubKey, err := s.destinationResolver.ResolveDestination(destHash)
	if err != nil {
		return [32]byte{}, fmt.Errorf("failed to resolve destination: %w", err)
	}

	log.WithField("destination", fmt.Sprintf("%x", destHash[:8])).
		Debug("resolved_destination_public_key")
	return pubKey, nil
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

// SetHostnameResolver sets the resolver used for hostname-based HostLookup queries.
// When set, hostname lookups (type 1) will delegate to this resolver instead of
// returning an error. If nil, hostname lookups return HostReplyError.
func (s *Server) SetHostnameResolver(resolver HostnameResolver) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hostnameResolver = resolver
}

// SetBandwidthProvider sets the provider used by handleGetBandwidthLimits
// to return real configured bandwidth limits instead of hardcoded defaults.
func (s *Server) SetBandwidthProvider(bp interface {
	GetBandwidthLimits() (inbound, outbound uint32)
},
) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bandwidthProvider = bp
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
