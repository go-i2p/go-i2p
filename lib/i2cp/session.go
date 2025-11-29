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
	"github.com/go-i2p/go-i2p/lib/netdb"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/go-i2p/logger"
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

	// NetDB isolation - each client gets its own LeaseSet-only database
	clientNetDB *netdb.ClientNetDB // Isolated NetDB for this client (LeaseSets only)

	// Session state
	createdAt time.Time // Session creation time
	active    bool      // Session is active

	// Message queues
	incomingMessages chan *IncomingMessage // Messages received from I2P network

	// LeaseSet state
	currentLeaseSet     []byte            // Currently published LeaseSet
	leaseSetPublishedAt time.Time         // When LeaseSet was last published
	publisher           LeaseSetPublisher // Publisher for distributing LeaseSets to network

	// Lifecycle
	stopCh      chan struct{}  // Signal to stop session
	stopOnce    sync.Once      // Ensure cleanup happens only once
	maintWg     sync.WaitGroup // Track maintenance goroutine
	maintTicker *time.Ticker   // Ticker for LeaseSet maintenance
}

// IncomingMessage represents a message received from the I2P network
type IncomingMessage struct {
	Payload   []byte    // Message data
	Timestamp time.Time // When the message was received
}

// NewSession creates a new I2CP session with its own isolated in-memory NetDB.
// The destination parameter can be nil, in which case a new destination will be generated.
// Each session gets a completely separate in-memory StdNetDB instance to prevent client linkability.
// Client NetDBs are ephemeral and not persisted to disk.
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

	// Create isolated in-memory StdNetDB for this client (ephemeral, not persisted)
	// Pass empty string to create in-memory only database
	stdDB := netdb.NewStdNetDB("")
	clientNetDB := netdb.NewClientNetDB(stdDB)
	log.Debug("Created ephemeral in-memory NetDB for client session")

	return &Session{
		id:               id,
		destination:      dest,
		keys:             keyStore,
		config:           config,
		clientNetDB:      clientNetDB,
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

// SetLeaseSetPublisher configures the publisher for distributing LeaseSets to the network.
// This should be called during session initialization before starting LeaseSet maintenance.
// The publisher is responsible for storing LeaseSets in the local NetDB and distributing
// them to floodfill routers on the I2P network.
func (s *Session) SetLeaseSetPublisher(publisher LeaseSetPublisher) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.publisher = publisher
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
// The LeaseSet is also cached in the session for maintenance purposes.
func (s *Session) CreateLeaseSet() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.validateSessionState(); err != nil {
		return nil, err
	}

	tunnels, err := s.collectActiveTunnels()
	if err != nil {
		return nil, err
	}

	leases, err := s.buildLeasesFromTunnels(tunnels)
	if err != nil {
		return nil, err
	}

	encKey, err := s.prepareEncryptionKey()
	if err != nil {
		return nil, err
	}

	leaseSetBytes, err := s.assembleLeaseSet(leases, encKey)
	if err != nil {
		return nil, err
	}

	s.currentLeaseSet = leaseSetBytes
	s.leaseSetPublishedAt = time.Now()

	return leaseSetBytes, nil
}

// validateSessionState checks if the session is in a valid state for LeaseSet creation.
// Returns an error if the session is inactive or missing required components.
func (s *Session) validateSessionState() error {
	if !s.active {
		return fmt.Errorf("session %d is not active", s.id)
	}

	if s.inboundPool == nil {
		return fmt.Errorf("session %d has no inbound tunnel pool", s.id)
	}

	if s.destination == nil {
		return fmt.Errorf("session %d has no destination", s.id)
	}

	if s.keys == nil {
		return fmt.Errorf("session %d has no private keys", s.id)
	}

	return nil
}

// collectActiveTunnels retrieves active tunnels from the inbound pool.
// Returns an error if no active tunnels are available.
func (s *Session) collectActiveTunnels() ([]*tunnel.TunnelState, error) {
	tunnels := s.inboundPool.GetActiveTunnels()
	if len(tunnels) == 0 {
		return nil, fmt.Errorf("session %d has no active inbound tunnels", s.id)
	}
	return tunnels, nil
}

// buildLeasesFromTunnels creates Lease2 structures from active tunnel data.
// Each lease represents an inbound tunnel endpoint that can receive messages.
// Returns an error if no valid leases can be created from the provided tunnels.
func (s *Session) buildLeasesFromTunnels(tunnels []*tunnel.TunnelState) ([]lease.Lease2, error) {
	leases := make([]lease.Lease2, 0, len(tunnels))

	for _, tun := range tunnels {
		if tun == nil || tun.State != tunnel.TunnelReady {
			continue
		}

		if len(tun.Hops) == 0 {
			continue
		}

		l, err := s.createLeaseFromTunnel(tun)
		if err != nil {
			return nil, fmt.Errorf("failed to create lease: %w", err)
		}

		leases = append(leases, *l)
	}

	if len(leases) == 0 {
		return nil, fmt.Errorf("session %d has no valid leases to publish", s.id)
	}

	return leases, nil
}

// createLeaseFromTunnel constructs a single Lease2 from tunnel metadata.
// Extracts the gateway router hash, tunnel ID, and calculates expiration time.
func (s *Session) createLeaseFromTunnel(tun *tunnel.TunnelState) (*lease.Lease2, error) {
	gatewayBytes := tun.Hops[0]

	var gateway data.Hash
	copy(gateway[:], gatewayBytes[:])

	tunnelID := uint32(tun.ID)
	expiration := tun.CreatedAt.Add(s.config.TunnelLifetime)

	return lease.NewLease2(gateway, tunnelID, expiration)
}

// prepareEncryptionKey creates the EncryptionKey structure for LeaseSet2.
// Uses X25519 public key from the session's key store.
func (s *Session) prepareEncryptionKey() (lease_set2.EncryptionKey, error) {
	encryptionPublicKey, err := s.keys.EncryptionPublicKey()
	if err != nil {
		return lease_set2.EncryptionKey{}, fmt.Errorf("failed to get encryption public key: %w", err)
	}

	return lease_set2.EncryptionKey{
		KeyType: key_certificate.KEYCERT_CRYPTO_X25519,
		KeyLen:  32,
		KeyData: encryptionPublicKey.Bytes(),
	}, nil
}

// assembleLeaseSet constructs and serializes the final LeaseSet2 structure.
// Combines destination, leases, and encryption key into a signed LeaseSet2.
func (s *Session) assembleLeaseSet(leases []lease.Lease2, encKey lease_set2.EncryptionKey) ([]byte, error) {
	dest := *s.destination
	signingPrivateKey := s.keys.SigningPrivateKey()

	published := uint32(time.Now().Unix())
	expiresOffset := uint16(s.config.TunnelLifetime.Seconds())

	ls2, err := lease_set2.NewLeaseSet2(
		dest,
		published,
		expiresOffset,
		0,
		nil,
		data.Mapping{},
		[]lease_set2.EncryptionKey{encKey},
		leases,
		signingPrivateKey,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create LeaseSet2: %w", err)
	}

	leaseSetBytes, err := ls2.Bytes()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize LeaseSet2: %w", err)
	}

	return leaseSetBytes, nil
}

// StartLeaseSetMaintenance begins automatic LeaseSet maintenance.
// This runs a background goroutine that:
// - Regenerates the LeaseSet before it expires
// - Publishes updated LeaseSets when tunnels change
// - Ensures the session remains reachable on the network
//
// The maintenance interval is calculated based on TunnelLifetime:
// - Check every TunnelLifetime/4 (e.g., every 2.5 minutes for 10-minute tunnels)
// - Regenerate when remaining lifetime < TunnelLifetime/2
//
// Must be called after tunnel pools are started.
func (s *Session) StartLeaseSetMaintenance() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.active {
		return fmt.Errorf("session %d is not active", s.id)
	}

	if s.inboundPool == nil {
		return fmt.Errorf("session %d has no inbound tunnel pool", s.id)
	}

	// Calculate maintenance interval: check every 1/4 of tunnel lifetime
	// For default 10-minute tunnels, this means checking every 2.5 minutes
	maintenanceInterval := s.config.TunnelLifetime / 4

	s.maintTicker = time.NewTicker(maintenanceInterval)

	s.maintWg.Add(1)
	go s.leaseSetMaintenanceLoop()

	log.WithFields(logger.Fields{
		"at":                  "i2cp.Session.StartLeaseSetMaintenance",
		"sessionID":           s.id,
		"maintenanceInterval": maintenanceInterval,
	}).Info("started_leaseset_maintenance")

	return nil
}

// leaseSetMaintenanceLoop runs in a background goroutine to maintain the LeaseSet.
// It periodically checks if the LeaseSet needs regeneration and publishes updates.
func (s *Session) leaseSetMaintenanceLoop() {
	defer s.maintWg.Done()
	defer s.cleanupMaintenanceTicker()

	s.generateInitialLeaseSet()
	s.runMaintenanceTickerLoop()
}

// cleanupMaintenanceTicker stops and clears the maintenance ticker during shutdown.
func (s *Session) cleanupMaintenanceTicker() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.maintTicker != nil {
		s.maintTicker.Stop()
		s.maintTicker = nil
	}
}

// generateInitialLeaseSet creates the first LeaseSet immediately upon maintenance start.
func (s *Session) generateInitialLeaseSet() {
	if err := s.maintainLeaseSet(); err != nil {
		log.WithFields(logger.Fields{
			"at":        "i2cp.Session.generateInitialLeaseSet",
			"sessionID": s.ID(),
			"error":     err,
		}).Error("failed_initial_leaseset_generation")
	}
}

// runMaintenanceTickerLoop executes the main maintenance event loop until stopped.
func (s *Session) runMaintenanceTickerLoop() {
	for {
		select {
		case <-s.stopCh:
			s.logMaintenanceStopped()
			return

		case <-s.maintTicker.C:
			s.handleMaintenanceTick()
		}
	}
}

// logMaintenanceStopped records debug information when maintenance is stopped.
func (s *Session) logMaintenanceStopped() {
	log.WithFields(logger.Fields{
		"at":        "i2cp.Session.logMaintenanceStopped",
		"sessionID": s.ID(),
	}).Debug("leaseset_maintenance_stopped")
}

// handleMaintenanceTick processes periodic LeaseSet maintenance tasks.
func (s *Session) handleMaintenanceTick() {
	if err := s.maintainLeaseSet(); err != nil {
		log.WithFields(logger.Fields{
			"at":        "i2cp.Session.handleMaintenanceTick",
			"sessionID": s.ID(),
			"error":     err,
		}).Warn("failed_to_maintain_leaseset")
	}
}

// maintainLeaseSet checks if LeaseSet needs regeneration and publishes if needed.
// Regeneration is triggered when:
// - No LeaseSet exists yet
// - Current LeaseSet is more than half its lifetime old
// - Tunnel pool has changed significantly
func (s *Session) maintainLeaseSet() error {
	needsRegeneration := s.checkLeaseSetRegeneration()

	if !needsRegeneration {
		return nil
	}

	return s.regenerateAndPublishLeaseSet()
}

// checkLeaseSetRegeneration evaluates whether the LeaseSet requires regeneration.
// Returns true if no LeaseSet exists or if the current LeaseSet exceeds half its lifetime.
func (s *Session) checkLeaseSetRegeneration() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.currentLeaseSet == nil {
		s.logLeaseSetMissing()
		return true
	}

	return s.evaluateLeaseSetAge()
}

// logLeaseSetMissing logs debug information when no LeaseSet exists.
func (s *Session) logLeaseSetMissing() {
	log.WithFields(logger.Fields{
		"at":        "i2cp.Session.maintainLeaseSet",
		"sessionID": s.id,
	}).Debug("no_leaseset_exists_generating_new")
}

// evaluateLeaseSetAge determines if the current LeaseSet is too old and needs regeneration.
// Regeneration occurs when more than half the tunnel lifetime has elapsed.
func (s *Session) evaluateLeaseSetAge() bool {
	now := time.Now()
	age := now.Sub(s.leaseSetPublishedAt)
	regenerationThreshold := s.config.TunnelLifetime / 2

	if age > regenerationThreshold {
		s.logLeaseSetExpiration(age, regenerationThreshold)
		return true
	}

	return false
}

// logLeaseSetExpiration logs debug information when LeaseSet exceeds regeneration threshold.
func (s *Session) logLeaseSetExpiration(age, threshold time.Duration) {
	log.WithFields(logger.Fields{
		"at":                    "i2cp.Session.maintainLeaseSet",
		"sessionID":             s.id,
		"age":                   age,
		"regenerationThreshold": threshold,
	}).Debug("leaseset_exceeds_regeneration_threshold")
}

// regenerateAndPublishLeaseSet creates a new LeaseSet and publishes it to the network.
// This method:
// 1. Creates a fresh LeaseSet from current inbound tunnels
// 2. Publishes it to the local NetDB
// 3. Distributes it to floodfill routers (if publisher is configured)
//
// Returns an error if LeaseSet creation or publication fails.
func (s *Session) regenerateAndPublishLeaseSet() error {
	leaseSetBytes, err := s.CreateLeaseSet()
	if err != nil {
		return fmt.Errorf("failed to create LeaseSet: %w", err)
	}

	s.logLeaseSetRegenerated(leaseSetBytes)

	// Publish to network database if publisher is configured
	if err := s.publishLeaseSetToNetwork(leaseSetBytes); err != nil {
		// Log the error but don't fail - LeaseSet is still cached locally
		log.WithFields(logger.Fields{
			"at":        "i2cp.Session.regenerateAndPublishLeaseSet",
			"sessionID": s.ID(),
			"error":     err,
		}).Warn("failed_to_publish_leaseset_to_network")
	}

	return nil
}

// publishLeaseSetToNetwork publishes the LeaseSet to the network database.
// Skips publication if no publisher is configured (allows sessions to work without network integration).
func (s *Session) publishLeaseSetToNetwork(leaseSetBytes []byte) error {
	s.mu.RLock()
	publisher := s.publisher
	s.mu.RUnlock()

	if publisher == nil {
		// No publisher configured - this is acceptable for testing or standalone sessions
		return nil
	}

	// Calculate destination hash (SHA256 of destination bytes)
	destBytes, err := s.destination.Bytes()
	if err != nil {
		return fmt.Errorf("failed to get destination bytes: %w", err)
	}
	destHash := data.HashData(destBytes)

	if err := publisher.PublishLeaseSet(destHash, leaseSetBytes); err != nil {
		return fmt.Errorf("publisher failed: %w", err)
	}

	log.WithFields(logger.Fields{
		"at":        "i2cp.Session.publishLeaseSetToNetwork",
		"sessionID": s.ID(),
		"destHash":  fmt.Sprintf("%x", destHash[:8]),
	}).Debug("leaseset_published_to_network")

	return nil
}

// logLeaseSetRegenerated logs information about successful LeaseSet regeneration.
func (s *Session) logLeaseSetRegenerated(leaseSetBytes []byte) {
	log.WithFields(logger.Fields{
		"at":        "i2cp.Session.maintainLeaseSet",
		"sessionID": s.ID(),
		"size":      len(leaseSetBytes),
	}).Info("leaseset_regenerated")
}

// CurrentLeaseSet returns the currently cached LeaseSet, if any.
// Returns nil if no LeaseSet has been generated yet.
func (s *Session) CurrentLeaseSet() []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.currentLeaseSet
}

// LeaseSetAge returns how long ago the current LeaseSet was published.
// Returns 0 if no LeaseSet exists.
func (s *Session) LeaseSetAge() time.Duration {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.currentLeaseSet == nil {
		return 0
	}

	return time.Since(s.leaseSetPublishedAt)
}

// Stop gracefully stops the session and cleans up resources
func (s *Session) Stop() {
	s.stopOnce.Do(func() {
		s.mu.Lock()
		s.active = false
		s.mu.Unlock()

		close(s.stopCh)

		// Wait for maintenance goroutine to exit
		s.maintWg.Wait()

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

// CreateSession creates a new session with the given destination and config.
func (sm *SessionManager) CreateSession(dest *destination.Destination, config *SessionConfig) (*Session, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Allocate session ID
	sessionID := sm.allocateSessionID()
	if sessionID == SessionIDReservedControl || sessionID == SessionIDReservedBroadcast {
		return nil, fmt.Errorf("no available session IDs")
	}

	// Create session with its own isolated in-memory NetDB
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
