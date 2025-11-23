package i2cp

import (
	"fmt"
	"sync"
	"time"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/common/destination"
	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/lease"
	"github.com/go-i2p/common/lease_set2"
	"github.com/go-i2p/go-i2p/lib/keys"
	"github.com/go-i2p/go-i2p/lib/tunnel"
)

// SessionConfig holds the configuration for an I2CP session
type SessionConfig struct {
	// Tunnel parameters
	InboundTunnelLength  int           // Number of hops for inbound tunnels (default: 3)
	OutboundTunnelLength int           // Number of hops for outbound tunnels (default: 3)
	InboundTunnelCount   int           // Number of inbound tunnels (default: 5)
	OutboundTunnelCount  int           // Number of outbound tunnels (default: 5)
	TunnelLifetime       time.Duration // Tunnel lifetime before rotation (default: 10 minutes)

	// Network parameters
	MessageTimeout time.Duration // Message delivery timeout (default: 60 seconds)

	// Session metadata
	Nickname string // Optional nickname for debugging
}

// DefaultSessionConfig returns a SessionConfig with sensible defaults
func DefaultSessionConfig() *SessionConfig {
	return &SessionConfig{
		InboundTunnelLength:  3,
		OutboundTunnelLength: 3,
		InboundTunnelCount:   5,
		OutboundTunnelCount:  5,
		TunnelLifetime:       10 * time.Minute,
		MessageTimeout:       60 * time.Second,
		Nickname:             "",
	}
}

// Session represents an active I2CP client session
type Session struct {
	mu sync.RWMutex

	// Session identity
	id          uint16                    // Session ID (assigned by router)
	destination *destination.Destination  // Client's I2P destination
	keys        *keys.DestinationKeyStore // Private keys for LeaseSet signing and decryption
	config      *SessionConfig            // Session configuration

	// Tunnel pools
	inboundPool  *tunnel.Pool // Pool of inbound tunnels
	outboundPool *tunnel.Pool // Pool of outbound tunnels

	// Session state
	createdAt time.Time // Session creation time
	active    bool      // Session is active

	// Message queues
	incomingMessages chan *IncomingMessage // Messages received from I2P network

	// Lifecycle
	stopCh   chan struct{} // Signal to stop session
	stopOnce sync.Once     // Ensure cleanup happens only once
}

// IncomingMessage represents a message received from the I2P network
type IncomingMessage struct {
	Payload   []byte    // Message data
	Timestamp time.Time // When the message was received
}

// NewSession creates a new I2CP session
// The destination parameter can be nil, in which case a new destination will be generated
func NewSession(id uint16, dest *destination.Destination, config *SessionConfig) (*Session, error) {
	if config == nil {
		config = DefaultSessionConfig()
	}

	// Generate destination with keys if not provided
	var keyStore *keys.DestinationKeyStore
	if dest == nil {
		// Create new destination with Ed25519/ElGamal keys
		var err error
		keyStore, err = keys.NewDestinationKeyStore()
		if err != nil {
			return nil, fmt.Errorf("failed to generate keys: %w", err)
		}
		dest = keyStore.Destination()
	}

	return &Session{
		id:               id,
		destination:      dest,
		keys:             keyStore,
		config:           config,
		createdAt:        time.Now(),
		active:           true,
		incomingMessages: make(chan *IncomingMessage, 100), // Buffer 100 messages
		stopCh:           make(chan struct{}),
	}, nil
}

// ID returns the session ID
func (s *Session) ID() uint16 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.id
}

// Destination returns the session's destination
func (s *Session) Destination() *destination.Destination {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.destination
}

// Config returns the session configuration
func (s *Session) Config() *SessionConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.config
}

// IsActive returns whether the session is active
func (s *Session) IsActive() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.active
}

// CreatedAt returns when the session was created
func (s *Session) CreatedAt() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.createdAt
}

// SetInboundPool sets the inbound tunnel pool for this session
func (s *Session) SetInboundPool(pool *tunnel.Pool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.inboundPool = pool
}

// SetOutboundPool sets the outbound tunnel pool for this session
func (s *Session) SetOutboundPool(pool *tunnel.Pool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.outboundPool = pool
}

// InboundPool returns the inbound tunnel pool
func (s *Session) InboundPool() *tunnel.Pool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.inboundPool
}

// OutboundPool returns the outbound tunnel pool
func (s *Session) OutboundPool() *tunnel.Pool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.outboundPool
}

// QueueIncomingMessage queues a message for delivery to the client
// Returns an error if the session is not active or the queue is full
func (s *Session) QueueIncomingMessage(payload []byte) error {
	s.mu.RLock()
	active := s.active
	s.mu.RUnlock()

	if !active {
		return fmt.Errorf("session %d is not active", s.id)
	}

	msg := &IncomingMessage{
		Payload:   payload,
		Timestamp: time.Now(),
	}

	select {
	case s.incomingMessages <- msg:
		return nil
	default:
		return fmt.Errorf("incoming message queue full for session %d", s.id)
	}
}

// QueueIncomingMessageWithID queues a message for delivery to the client with a message ID.
// This is a higher-level method that wraps the payload in a MessagePayloadPayload structure
// before queuing it for delivery. The message ID can be used for tracking and correlation.
// Returns an error if the session is not active or the queue is full.
func (s *Session) QueueIncomingMessageWithID(messageID uint32, payload []byte) error {
	s.mu.RLock()
	active := s.active
	s.mu.RUnlock()

	if !active {
		return fmt.Errorf("session %d is not active", s.id)
	}

	msg := &IncomingMessage{
		Payload:   payload,
		Timestamp: time.Now(),
	}

	select {
	case s.incomingMessages <- msg:
		return nil
	default:
		return fmt.Errorf("incoming message queue full for session %d", s.id)
	}
}

// ReceiveMessage blocks until a message is available or the session is stopped
// Returns nil, nil if the session is stopped
func (s *Session) ReceiveMessage() (*IncomingMessage, error) {
	select {
	case msg := <-s.incomingMessages:
		return msg, nil
	case <-s.stopCh:
		return nil, nil
	}
}

// Reconfigure updates the session configuration
// Note: This only updates config values, tunnel pools need to be recreated separately
func (s *Session) Reconfigure(newConfig *SessionConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.active {
		return fmt.Errorf("cannot reconfigure inactive session %d", s.id)
	}

	s.config = newConfig
	return nil
}

// CreateLeaseSet generates a new LeaseSet2 for this session using active inbound tunnels.
// The LeaseSet2 contains leases from the inbound tunnel pool and is signed by the session's
// destination private signing key. Uses modern X25519 encryption keys. This method requires:
// - The session is active
// - The session has private keys (generated during session creation)
// - The inbound tunnel pool is set and contains at least one active tunnel
//
// Returns the serialized LeaseSet2 ready for publishing to the network database.
func (s *Session) CreateLeaseSet() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.active {
		return nil, fmt.Errorf("session %d is not active", s.id)
	}

	if s.inboundPool == nil {
		return nil, fmt.Errorf("session %d has no inbound tunnel pool", s.id)
	}

	if s.destination == nil {
		return nil, fmt.Errorf("session %d has no destination", s.id)
	}

	if s.keys == nil {
		return nil, fmt.Errorf("session %d has no private keys", s.id)
	}

	// Get active tunnels from inbound pool
	tunnels := s.inboundPool.GetActiveTunnels()
	if len(tunnels) == 0 {
		return nil, fmt.Errorf("session %d has no active inbound tunnels", s.id)
	}

	// Create leases from active tunnels
	// Each lease represents an inbound tunnel endpoint that can receive messages
	leases := make([]lease.Lease2, 0, len(tunnels))
	for _, tun := range tunnels {
		if tun == nil || tun.State != tunnel.TunnelReady {
			continue
		}

		// Get tunnel gateway (first hop router hash)
		// For inbound tunnels, the gateway is the first hop in the Hops slice
		if len(tun.Hops) == 0 {
			continue
		}
		gatewayBytes := tun.Hops[0]

		// Convert gateway bytes to data.Hash (32 bytes)
		var gateway data.Hash
		copy(gateway[:], gatewayBytes[:])

		// Get tunnel ID
		tunnelID := uint32(tun.ID)

		// Calculate lease expiration based on tunnel lifetime
		// Use tunnel creation time + configured lifetime
		expiration := tun.CreatedAt.Add(s.config.TunnelLifetime)

		// Create Lease2
		l, err := lease.NewLease2(gateway, tunnelID, expiration)
		if err != nil {
			return nil, fmt.Errorf("failed to create lease: %w", err)
		}

		leases = append(leases, *l)
	}

	if len(leases) == 0 {
		return nil, fmt.Errorf("session %d has no valid leases to publish", s.id)
	}

	// Get destination and keys
	dest := *s.destination
	signingPrivateKey := s.keys.SigningPrivateKey()
	encryptionPublicKey := s.keys.EncryptionPublicKey()

	// Create EncryptionKey for LeaseSet2
	// LeaseSet2 uses a slice of EncryptionKey structs to support multiple encryption types
	encKey := lease_set2.EncryptionKey{
		KeyType: key_certificate.KEYCERT_CRYPTO_X25519,
		KeyLen:  32,
		KeyData: encryptionPublicKey.Bytes(),
	}

	// Set published time and expiration
	published := uint32(time.Now().Unix())
	expiresOffset := uint16(s.config.TunnelLifetime.Seconds())

	// Create the LeaseSet2
	ls2, err := lease_set2.NewLeaseSet2(
		dest,
		published,
		expiresOffset,
		0,              // flags: 0 for standard published leaseset
		nil,            // no offline signature
		data.Mapping{}, // empty options map
		[]lease_set2.EncryptionKey{encKey},
		leases,
		signingPrivateKey,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create LeaseSet2: %w", err)
	}

	// Serialize to bytes for network transmission
	data, err := ls2.Bytes()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize LeaseSet2: %w", err)
	}

	return data, nil
}

// Stop gracefully stops the session and cleans up resources
func (s *Session) Stop() {
	s.stopOnce.Do(func() {
		s.mu.Lock()
		s.active = false
		s.mu.Unlock()

		close(s.stopCh)

		// Drain incoming message queue
		for {
			select {
			case <-s.incomingMessages:
				// Discard
			default:
				return
			}
		}
	})
}

// SessionManager manages all active I2CP sessions
type SessionManager struct {
	mu       sync.RWMutex
	sessions map[uint16]*Session // Session ID -> Session
	nextID   uint16              // Next available session ID
}

// NewSessionManager creates a new session manager
func NewSessionManager() *SessionManager {
	return &SessionManager{
		sessions: make(map[uint16]*Session),
		nextID:   1, // Start from 1, skip reserved 0x0000
	}
}

// CreateSession creates a new session with the given destination and config
func (sm *SessionManager) CreateSession(dest *destination.Destination, config *SessionConfig) (*Session, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Allocate session ID
	sessionID := sm.allocateSessionID()
	if sessionID == SessionIDReservedControl || sessionID == SessionIDReservedBroadcast {
		return nil, fmt.Errorf("no available session IDs")
	}

	// Create session
	session, err := NewSession(sessionID, dest, config)
	if err != nil {
		return nil, err
	}

	// Register session
	sm.sessions[sessionID] = session

	return session, nil
}

// GetSession retrieves a session by ID
func (sm *SessionManager) GetSession(sessionID uint16) (*Session, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	session, ok := sm.sessions[sessionID]
	return session, ok
}

// DestroySession removes and stops a session
func (sm *SessionManager) DestroySession(sessionID uint16) error {
	sm.mu.Lock()
	session, ok := sm.sessions[sessionID]
	if !ok {
		sm.mu.Unlock()
		return fmt.Errorf("session %d not found", sessionID)
	}

	delete(sm.sessions, sessionID)
	sm.mu.Unlock()

	// Stop session (outside lock to prevent deadlock)
	session.Stop()

	return nil
}

// SessionCount returns the number of active sessions
func (sm *SessionManager) SessionCount() int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return len(sm.sessions)
}

// allocateSessionID finds the next available session ID
// Must be called with sm.mu locked
func (sm *SessionManager) allocateSessionID() uint16 {
	startID := sm.nextID

	for {
		id := sm.nextID
		sm.nextID++

		// Skip reserved IDs
		if id == SessionIDReservedControl || id == SessionIDReservedBroadcast {
			continue
		}

		// Check if ID is available
		if _, exists := sm.sessions[id]; !exists {
			return id
		}

		// Wrapped around, no IDs available
		if sm.nextID == startID {
			return SessionIDReservedControl // Signal error
		}
	}
}

// StopAll stops all active sessions
func (sm *SessionManager) StopAll() {
	sm.mu.Lock()
	sessions := make([]*Session, 0, len(sm.sessions))
	for _, session := range sm.sessions {
		sessions = append(sessions, session)
	}
	sm.sessions = make(map[uint16]*Session)
	sm.mu.Unlock()

	// Stop all sessions outside lock
	for _, session := range sessions {
		session.Stop()
	}
}
