package i2cp

import (
	"fmt"
	"sync"
	"time"

	"github.com/go-i2p/crypto/rand"
	"github.com/go-i2p/crypto/types"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/common/destination"
	"github.com/go-i2p/common/encrypted_leaseset"
	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/lease"
	"github.com/go-i2p/common/lease_set2"
	"github.com/go-i2p/go-i2p/lib/keys"
	"github.com/go-i2p/go-i2p/lib/netdb"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/go-i2p/logger"
)

// simpleRateLimiter implements a token bucket rate limiter with fractional
// token tracking for smooth delivery at low rates.
type simpleRateLimiter struct {
	tokens    float64   // Current token count (fractional for smooth low-rate delivery)
	maxTokens int       // Maximum tokens (burst size)
	rate      int       // Tokens added per second
	lastCheck time.Time // Last time tokens were added
	mu        sync.Mutex
}

// newSimpleRateLimiter creates a new rate limiter
func newSimpleRateLimiter(rate, burst int) *simpleRateLimiter {
	return &simpleRateLimiter{
		tokens:    float64(burst),
		maxTokens: burst,
		rate:      rate,
		lastCheck: time.Now(),
	}
}

// allow checks if an action is allowed under the rate limit
func (rl *simpleRateLimiter) allow() bool {
	if rl == nil || rl.rate == 0 {
		return true // No rate limiting
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(rl.lastCheck)

	// Limit token accumulation to prevent excessive burst after long idle periods.
	// Cap elapsed time at 60 seconds to avoid accumulating tokens beyond reasonable burst.
	// This allows normal traffic patterns and brief idle periods while preventing
	// unbounded accumulation after hours of inactivity.
	const maxAccumulationWindow = 60 * time.Second
	if elapsed > maxAccumulationWindow {
		elapsed = maxAccumulationWindow
	}

	// Add tokens based on elapsed time (fractional for smooth low-rate delivery)
	tokensToAdd := elapsed.Seconds() * float64(rl.rate)
	rl.tokens += tokensToAdd
	if rl.tokens > float64(rl.maxTokens) {
		rl.tokens = float64(rl.maxTokens)
	}
	// Always update lastCheck to prevent token accumulation drift
	rl.lastCheck = now

	// Check if we have a token available
	if rl.tokens >= 1.0 {
		rl.tokens -= 1.0
		return true
	}

	return false
}

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

	// Message queue configuration
	MessageQueueSize     int // Incoming message queue buffer size (default: 100)
	MessageRateLimit     int // Maximum messages per second (default: 100, 0 = unlimited)
	MessageRateBurstSize int // Maximum burst size for rate limiting (default: 200)

	// EncryptedLeaseSet configuration (requires Ed25519 destination)
	UseEncryptedLeaseSet bool   // Enable EncryptedLeaseSet generation (default: false)
	BlindingSecret       []byte // Secret for destination blinding (if empty, random generated)

	// ExplicitlySetFields tracks which fields were explicitly set by the client
	// during reconfiguration, allowing zero values (e.g., zero-hop tunnels) to
	// be distinguished from "not provided".
	ExplicitlySetFields map[string]bool
	LeaseSetExpiration  uint16 // LeaseSet expiration in seconds (default: 600 = 10 minutes)

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
		MessageQueueSize:     100,
		MessageRateLimit:     100, // 100 messages/second
		MessageRateBurstSize: 200, // Allow bursts up to 200 messages
		UseEncryptedLeaseSet: false,
		BlindingSecret:       nil,
		LeaseSetExpiration:   600, // 10 minutes
		Nickname:             "",
	}
}

// Session represents an active I2CP client session
type Session struct {
	mu sync.RWMutex

	// Session identity
	id              uint16                    // Session ID (assigned by router)
	destination     *destination.Destination  // Client's I2P destination
	keys            *keys.DestinationKeyStore // Private keys for LeaseSet signing and decryption
	config          *SessionConfig            // Session configuration
	protocolVersion string                    // Client's I2CP protocol version (from GetDate)

	// Tunnel pools
	inboundPool  *tunnel.Pool // Pool of inbound tunnels
	outboundPool *tunnel.Pool // Pool of outbound tunnels

	// NetDB isolation - each client gets its own LeaseSet-only database
	clientNetDB *netdb.ClientNetDB // Isolated NetDB for this client (LeaseSets only)

	// Session state
	createdAt    time.Time // Session creation time
	lastActivity time.Time // Last activity timestamp for timeout tracking
	active       bool      // Session is active

	// Message queues
	incomingMessages chan *IncomingMessage // Messages received from I2P network

	// Rate limiting for message queue
	messageRateLimiter *simpleRateLimiter // Rate limiter for incoming messages
	queueHighWaterMark int                // Track when queue is getting full

	// LeaseSet state
	currentLeaseSet     []byte            // Currently published LeaseSet
	leaseSetPublishedAt time.Time         // When LeaseSet was last published
	publisher           LeaseSetPublisher // Publisher for distributing LeaseSets to network

	// EncryptedLeaseSet state (only used if UseEncryptedLeaseSet is true)
	blindedDestination *destination.Destination // Blinded destination for EncryptedLeaseSet
	blindingSecret     []byte                   // Secret used for blinding (cached)
	lastBlindingDate   time.Time                // Last date used for blinding (triggers rotation at UTC midnight)

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
// The signingPrivKey and encryptionPrivKey parameters allow clients to provide their own
// key material for persistent identity across sessions. When both private keys are provided,
// the destination is reconstructed from them (honoring the client's identity per I2CP spec).
// When nil, fresh keys are generated.
// Each session gets a completely separate in-memory StdNetDB instance to prevent client linkability.
// Client NetDBs are ephemeral and not persisted to disk.
func NewSession(id uint16, dest *destination.Destination, config *SessionConfig, privKeys ...interface{}) (*Session, error) {
	config = ensureValidConfig(config)

	log.WithFields(logger.Fields{
		"at":                   "i2cp.NewSession",
		"sessionID":            id,
		"hasDestination":       dest != nil,
		"hasPrivateKeys":       len(privKeys) >= 2,
		"inboundTunnelLength":  config.InboundTunnelLength,
		"outboundTunnelLength": config.OutboundTunnelLength,
		"inboundTunnelCount":   config.InboundTunnelCount,
		"outboundTunnelCount":  config.OutboundTunnelCount,
		"messageQueueSize":     config.MessageQueueSize,
		"messageRateLimit":     config.MessageRateLimit,
		"useEncryptedLeaseSet": config.UseEncryptedLeaseSet,
	}).Info("creating_i2cp_session")

	// Extract private keys from variadic args if provided
	var sigPriv types.SigningPrivateKey
	var encPriv types.PrivateEncryptionKey
	if len(privKeys) >= 2 {
		if sp, ok := privKeys[0].(types.SigningPrivateKey); ok {
			sigPriv = sp
		}
		if ep, ok := privKeys[1].(types.PrivateEncryptionKey); ok {
			encPriv = ep
		}
	}

	keyStore, dest, err := prepareDestinationAndKeys(dest, sigPriv, encPriv)
	if err != nil {
		log.WithFields(logger.Fields{
			"at":        "i2cp.NewSession",
			"sessionID": id,
			"error":     err.Error(),
		}).Error("failed_to_prepare_destination")
		return nil, err
	}

	clientNetDB := createIsolatedNetDB()
	queueSize := determineQueueSize(config)
	rateLimiter := createRateLimiterIfNeeded(config, id)

	log.WithFields(logger.Fields{
		"at":        "i2cp.NewSession",
		"sessionID": id,
	}).Info("session_created_successfully")

	return &Session{
		id:                 id,
		destination:        dest,
		keys:               keyStore,
		config:             config,
		clientNetDB:        clientNetDB,
		createdAt:          time.Now(),
		lastActivity:       time.Now(),
		active:             true,
		incomingMessages:   make(chan *IncomingMessage, queueSize),
		messageRateLimiter: rateLimiter,
		queueHighWaterMark: queueSize,
		stopCh:             make(chan struct{}),
	}, nil
}

// ensureValidConfig returns the provided config or a default config if nil.
func ensureValidConfig(config *SessionConfig) *SessionConfig {
	if config == nil {
		return DefaultSessionConfig()
	}
	return config
}

// prepareDestinationAndKeys generates or reconstructs a DestinationKeyStore for the session.
//
// When signingPrivKey and encryptionPrivKey are both non-nil, the keystore is built
// from the provided private keys, preserving the client's persistent identity.
// This is the correct I2CP behavior: clients can maintain a stable .b32.i2p address
// across sessions by providing their own key material.
//
// When private keys are nil, a fresh DestinationKeyStore with new keys and a new
// destination is generated. The dest parameter is ignored in this case because
// we cannot use a destination without its corresponding private keys.
func prepareDestinationAndKeys(dest *destination.Destination, sigPriv types.SigningPrivateKey, encPriv types.PrivateEncryptionKey) (*keys.DestinationKeyStore, *destination.Destination, error) {
	// Case 1: Client provided private keys — reconstruct their identity
	if sigPriv != nil && encPriv != nil {
		log.WithFields(logger.Fields{
			"at":     "prepareDestinationAndKeys",
			"reason": "client_provided_private_keys",
		}).Info("Using client-provided private keys to preserve persistent identity")

		keyStore, err := keys.NewDestinationKeyStoreFromKeys(sigPriv, encPriv)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create keystore from client keys: %w", err)
		}
		return keyStore, keyStore.Destination(), nil
	}

	// Case 2: Client provided only a destination (no private keys)
	// We cannot honor the destination without private keys for LeaseSet signing
	// and message decryption. Log a warning and generate fresh keys.
	if dest != nil {
		log.WithFields(logger.Fields{
			"at":     "prepareDestinationAndKeys",
			"reason": "destination_without_private_keys",
		}).Warn("Client provided destination without private keys; " +
			"generating fresh identity (provide private keys to preserve identity)")
	}

	// Case 3: No destination and no keys — generate everything fresh
	keyStore, err := keys.NewDestinationKeyStore()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate keys: %w", err)
	}

	return keyStore, keyStore.Destination(), nil
}

// createIsolatedNetDB creates an isolated in-memory StdNetDB for a client session.
// The database is ephemeral and not persisted to disk to prevent client linkability.
func createIsolatedNetDB() *netdb.ClientNetDB {
	stdDB := netdb.NewStdNetDB("")
	clientNetDB := netdb.NewClientNetDB(stdDB)
	log.WithFields(logger.Fields{
		"at":     "createIsolatedNetDB",
		"reason": "ephemeral_session_storage",
	}).Debug("created ephemeral in-memory NetDB for client session")
	return clientNetDB
}

// determineQueueSize calculates the message queue size from config or returns default.
func determineQueueSize(config *SessionConfig) int {
	queueSize := config.MessageQueueSize
	if queueSize <= 0 {
		return 100
	}
	return queueSize
}

// createRateLimiterIfNeeded creates a rate limiter if rate limiting is enabled in config.
// Returns nil if rate limiting is disabled (MessageRateLimit <= 0).
func createRateLimiterIfNeeded(config *SessionConfig, sessionID uint16) *simpleRateLimiter {
	if config.MessageRateLimit <= 0 {
		return nil
	}

	burstSize := config.MessageRateBurstSize
	if burstSize <= 0 {
		burstSize = config.MessageRateLimit * 2
	}

	rateLimiter := newSimpleRateLimiter(config.MessageRateLimit, burstSize)
	log.WithFields(logger.Fields{
		"at":        "i2cp.createRateLimiterIfNeeded",
		"sessionID": sessionID,
		"rate":      config.MessageRateLimit,
		"burst":     burstSize,
	}).Debug("created_rate_limiter_for_session")

	return rateLimiter
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

// LastActivity returns when the session was last active
func (s *Session) LastActivity() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastActivity
}

// updateActivity updates the session's last activity timestamp
func (s *Session) updateActivity() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastActivity = time.Now()
}

// SetInboundPool sets the inbound tunnel pool for this session
func (s *Session) SetInboundPool(pool *tunnel.Pool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.inboundPool = pool
	log.WithFields(logger.Fields{
		"at":        "i2cp.Session.SetInboundPool",
		"sessionID": s.id,
		"poolSet":   pool != nil,
	}).Debug("inbound_tunnel_pool_set")
}

// SetOutboundPool sets the outbound tunnel pool for this session
func (s *Session) SetOutboundPool(pool *tunnel.Pool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.outboundPool = pool
	log.WithFields(logger.Fields{
		"at":        "i2cp.Session.SetOutboundPool",
		"sessionID": s.id,
		"poolSet":   pool != nil,
	}).Debug("outbound_tunnel_pool_set")
}

// StopTunnelPools stops both inbound and outbound tunnel pools gracefully.
// This is called before rebuilding pools during reconfiguration.
func (s *Session) StopTunnelPools() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.inboundPool != nil {
		s.inboundPool.Stop()
		s.inboundPool = nil
		log.WithFields(logger.Fields{
			"at":        "i2cp.Session.StopTunnelPools",
			"sessionID": s.id,
		}).Debug("inbound_tunnel_pool_stopped")
	}

	if s.outboundPool != nil {
		s.outboundPool.Stop()
		s.outboundPool = nil
		log.WithFields(logger.Fields{
			"at":        "i2cp.Session.StopTunnelPools",
			"sessionID": s.id,
		}).Debug("outbound_tunnel_pool_stopped")
	}
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

// SetProtocolVersion stores the client's I2CP protocol version from GetDate message.
// This is called when the client sends GetDate with its version string.
func (s *Session) SetProtocolVersion(version string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.protocolVersion = version
}

// ProtocolVersion returns the client's I2CP protocol version.
// Returns empty string if not yet set via GetDate exchange.
func (s *Session) ProtocolVersion() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.protocolVersion
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
	if err := s.checkSessionActive(); err != nil {
		return err
	}

	if err := s.checkRateLimit(); err != nil {
		return err
	}

	s.updateActivity()
	msg := s.createIncomingMessage(payload)
	return s.enqueueMessageWithMonitoring(msg)
}

// checkSessionActive verifies that the session is currently active.
func (s *Session) checkSessionActive() error {
	s.mu.RLock()
	active := s.active
	s.mu.RUnlock()

	if !active {
		return fmt.Errorf("session %d not active", s.id)
	}
	return nil
}

// checkRateLimit applies rate limiting if configured for this session.
func (s *Session) checkRateLimit() error {
	if s.messageRateLimiter != nil && !s.messageRateLimiter.allow() {
		log.WithFields(logger.Fields{
			"at":              "(Session) SendMessage",
			"reason":          "rate_limit_exceeded",
			"session_id":      s.id,
			"rate_limit_msgs": s.config.MessageRateLimit,
		}).Warn("message rate limit exceeded")
		return fmt.Errorf("message rate limit exceeded for session %d", s.id)
	}
	return nil
}

// createIncomingMessage constructs a new IncomingMessage with the given payload.
func (s *Session) createIncomingMessage(payload []byte) *IncomingMessage {
	return &IncomingMessage{
		Payload:   payload,
		Timestamp: time.Now(),
	}
}

// enqueueMessageWithMonitoring attempts to queue the message and monitors queue health.
func (s *Session) enqueueMessageWithMonitoring(msg *IncomingMessage) error {
	select {
	case s.incomingMessages <- msg:
		queueLen := len(s.incomingMessages)
		log.WithFields(logger.Fields{
			"at":          "i2cp.Session.enqueueMessageWithMonitoring",
			"sessionID":   s.id,
			"queueLen":    queueLen,
			"queueCap":    cap(s.incomingMessages),
			"payloadSize": len(msg.Payload),
		}).Debug("message_queued")
		s.checkQueueHighWaterMark()
		return nil
	default:
		return s.handleQueueFull()
	}
}

// checkQueueHighWaterMark logs a warning if the queue is filling up (>80% full).
func (s *Session) checkQueueHighWaterMark() {
	queueLen := len(s.incomingMessages)
	if queueLen > s.queueHighWaterMark*8/10 {
		log.WithFields(logger.Fields{
			"session_id": s.id,
			"queue_len":  queueLen,
			"queue_cap":  cap(s.incomingMessages),
		}).Warn("Incoming message queue filling up")
	}
}

// handleQueueFull logs an error and returns an error when the incoming message queue is full.
func (s *Session) handleQueueFull() error {
	log.WithFields(logger.Fields{
		"session_id": s.id,
		"queue_cap":  cap(s.incomingMessages),
	}).Error("Incoming message queue full")
	return fmt.Errorf("incoming message queue full for session %d", s.id)
}

// QueueIncomingMessageWithID queues a message for delivery to the client with a message ID.
// This is a higher-level method that wraps the payload in a MessagePayloadPayload structure
// before queuing it for delivery. The message ID can be used for tracking and correlation.
// Returns an error if the session is not active, rate limited, or the queue is full.
func (s *Session) QueueIncomingMessageWithID(messageID uint32, payload []byte) error {
	if err := s.checkSessionActive(); err != nil {
		return err
	}

	if err := s.checkRateLimit(); err != nil {
		return err
	}

	s.updateActivity()
	msg := s.createIncomingMessage(payload)
	return s.enqueueMessageWithMonitoring(msg)
}

// ReceiveMessage blocks until a message is available or the session is stopped
// Returns nil, nil if the session is stopped
func (s *Session) ReceiveMessage() (*IncomingMessage, error) {
	select {
	case msg := <-s.incomingMessages:
		s.updateActivity()
		return msg, nil
	case <-s.stopCh:
		return nil, nil
	}
}

// Reconfigure updates the session configuration by merging new values with existing config.
// Only non-zero values from newConfig are applied, preserving existing values for zero fields.
// Note: Tunnel pools need to be recreated separately to apply tunnel configuration changes.
func (s *Session) Reconfigure(newConfig *SessionConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := validateSessionActive(s.active, s.id); err != nil {
		return err
	}

	// Value copy of config before mutation so logConfigurationChanges sees the diff
	oldConfigCopy := *s.config
	mergeConfigUpdates(s.config, newConfig)
	logConfigurationChanges(s.id, &oldConfigCopy, s.config)

	return nil
}

// validateSessionActive checks if the session is active before reconfiguration.
func validateSessionActive(active bool, sessionID uint16) error {
	if !active {
		return fmt.Errorf("cannot reconfigure inactive session %d", sessionID)
	}
	return nil
}

// mergeConfigUpdates merges non-zero values from newConfig into existing config.
func mergeConfigUpdates(existing, newConfig *SessionConfig) {
	mergeTunnelParameters(existing, newConfig)
	mergeMessageParameters(existing, newConfig)
	mergeEncryptionParameters(existing, newConfig)
	mergeMetadataParameters(existing, newConfig)
}

// mergeTunnelParameters updates tunnel-related configuration fields.
// Uses ExplicitlySetFields to allow zero values (zero-hop tunnels).
func mergeTunnelParameters(existing, newConfig *SessionConfig) {
	if isExplicitlySet(newConfig, "InboundTunnelLength") || newConfig.InboundTunnelLength > 0 {
		existing.InboundTunnelLength = newConfig.InboundTunnelLength
	}
	if isExplicitlySet(newConfig, "OutboundTunnelLength") || newConfig.OutboundTunnelLength > 0 {
		existing.OutboundTunnelLength = newConfig.OutboundTunnelLength
	}
	if newConfig.InboundTunnelCount > 0 {
		existing.InboundTunnelCount = newConfig.InboundTunnelCount
	}
	if newConfig.OutboundTunnelCount > 0 {
		existing.OutboundTunnelCount = newConfig.OutboundTunnelCount
	}
	if newConfig.TunnelLifetime > 0 {
		existing.TunnelLifetime = newConfig.TunnelLifetime
	}
}

// isExplicitlySet checks whether a field was explicitly set in the session config.
func isExplicitlySet(config *SessionConfig, field string) bool {
	if config.ExplicitlySetFields == nil {
		return false
	}
	return config.ExplicitlySetFields[field]
}

// mergeMessageParameters updates message-related configuration fields.
func mergeMessageParameters(existing, newConfig *SessionConfig) {
	if newConfig.MessageTimeout > 0 {
		existing.MessageTimeout = newConfig.MessageTimeout
	}
	if newConfig.MessageQueueSize > 0 {
		existing.MessageQueueSize = newConfig.MessageQueueSize
	}
	if newConfig.MessageRateLimit > 0 {
		existing.MessageRateLimit = newConfig.MessageRateLimit
	}
	if newConfig.MessageRateBurstSize > 0 {
		existing.MessageRateBurstSize = newConfig.MessageRateBurstSize
	}
}

// mergeEncryptionParameters updates encryption-related configuration fields.
func mergeEncryptionParameters(existing, newConfig *SessionConfig) {
	if newConfig.LeaseSetExpiration > 0 {
		existing.LeaseSetExpiration = newConfig.LeaseSetExpiration
	}
	// UseEncryptedLeaseSet and BlindingSecret are set explicitly (allow false/nil)
	// Only update if explicitly provided
	if len(newConfig.BlindingSecret) > 0 {
		existing.BlindingSecret = newConfig.BlindingSecret
		existing.UseEncryptedLeaseSet = newConfig.UseEncryptedLeaseSet
	}
}

// mergeMetadataParameters updates metadata-related configuration fields.
func mergeMetadataParameters(existing, newConfig *SessionConfig) {
	if newConfig.Nickname != "" {
		existing.Nickname = newConfig.Nickname
	}
}

// logConfigurationChanges logs the before and after state of tunnel configuration.
func logConfigurationChanges(sessionID uint16, oldConfig, newConfig *SessionConfig) {
	log.WithFields(logger.Fields{
		"at":                      "i2cp.Session.Reconfigure",
		"sessionID":               sessionID,
		"oldInboundTunnelLength":  oldConfig.InboundTunnelLength,
		"newInboundTunnelLength":  newConfig.InboundTunnelLength,
		"oldOutboundTunnelLength": oldConfig.OutboundTunnelLength,
		"newOutboundTunnelLength": newConfig.OutboundTunnelLength,
		"oldInboundTunnelCount":   oldConfig.InboundTunnelCount,
		"newInboundTunnelCount":   newConfig.InboundTunnelCount,
		"oldOutboundTunnelCount":  oldConfig.OutboundTunnelCount,
		"newOutboundTunnelCount":  newConfig.OutboundTunnelCount,
	}).Info("session_reconfigured")
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
		return fmt.Errorf("session %d not active", s.id)
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
	skippedCount := 0

	for _, tun := range tunnels {
		if tun == nil || tun.State != tunnel.TunnelReady {
			skippedCount++
			continue
		}

		if len(tun.Hops) == 0 {
			skippedCount++
			continue
		}

		l, err := s.createLeaseFromTunnel(tun)
		if err != nil {
			// Skip tunnels that would expire too soon instead of failing entirely
			// This can happen with old tunnels or very short tunnel lifetimes
			log.WithFields(logger.Fields{
				"at":        "i2cp.Session.buildLeasesFromTunnels",
				"sessionID": s.id,
				"tunnelID":  tun.ID,
				"error":     err.Error(),
			}).Debug("skipping_tunnel_lease_creation")
			skippedCount++
			continue
		}

		leases = append(leases, *l)
	}

	log.WithFields(logger.Fields{
		"at":           "i2cp.Session.buildLeasesFromTunnels",
		"sessionID":    s.id,
		"totalTunnels": len(tunnels),
		"validLeases":  len(leases),
		"skipped":      skippedCount,
	}).Debug("built_leases_from_tunnels")

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

	// Validate lease expiration: must have meaningful time remaining
	// Use smaller of 30 seconds or 10% of tunnel lifetime to handle both
	// production (10 minute tunnels) and test scenarios (short tunnels)
	minValidity := 30 * time.Second
	proportionalMin := s.config.TunnelLifetime / 10
	if proportionalMin < minValidity {
		minValidity = proportionalMin
	}

	timeUntilExpiration := time.Until(expiration)
	if timeUntilExpiration < minValidity {
		return nil, fmt.Errorf("lease would expire too soon (%v remaining, min %v required)",
			timeUntilExpiration.Round(time.Second), minValidity)
	}

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

// CreateEncryptedLeaseSet generates an EncryptedLeaseSet from the session's active tunnels.
//
// EncryptedLeaseSet provides enhanced privacy by:
// - Blinding the destination (changes daily based on UTC date)
// - Encrypting the inner LeaseSet2 data
// - Using a cookie-based authentication scheme
//
// This method will:
// 1. Validate the destination supports EncryptedLeaseSet (Ed25519 only)
// 2. Derive/update the blinded destination (rotates daily at UTC midnight)
// 3. Collect active inbound tunnels
// 4. Build leases from tunnels
// 5. Create inner LeaseSet2
// 6. Encrypt inner LeaseSet2
// 7. Sign EncryptedLeaseSet with blinded signing key
//
// Returns serialized EncryptedLeaseSet bytes or error.
func (s *Session) CreateEncryptedLeaseSet() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.prepareEncryptedLeaseSetContext(); err != nil {
		return nil, err
	}

	leases, err := s.gatherActiveLeasesForEncryption()
	if err != nil {
		return nil, err
	}

	encryptedData, cookie, err := s.buildEncryptedLeaseSetData(leases)
	if err != nil {
		return nil, err
	}

	return s.finalizeEncryptedLeaseSet(cookie, encryptedData)
}

// prepareEncryptedLeaseSetContext validates and prepares the session for EncryptedLeaseSet creation.
// This includes validating Ed25519 support and ensuring the blinded destination is current.
func (s *Session) prepareEncryptedLeaseSetContext() error {
	if err := s.validateEncryptedLeaseSetSupport(); err != nil {
		return err
	}

	return s.updateBlindedDestination()
}

// gatherActiveLeasesForEncryption collects and prepares active leases from the inbound tunnel pool.
// Returns lease structures ready for inclusion in the encrypted LeaseSet.
func (s *Session) gatherActiveLeasesForEncryption() ([]lease.Lease2, error) {
	tunnels, err := s.collectActiveTunnels()
	if err != nil {
		return nil, err
	}

	return s.buildLeasesFromTunnels(tunnels)
}

// buildEncryptedLeaseSetData creates and encrypts the inner LeaseSet2 data.
// Returns the encrypted data and the cookie used for encryption.
func (s *Session) buildEncryptedLeaseSetData(leases []lease.Lease2) ([]byte, [32]byte, error) {
	innerLS2, err := s.createInnerLeaseSet2(leases)
	if err != nil {
		return nil, [32]byte{}, err
	}

	cookie, err := s.generateEncryptionCookie()
	if err != nil {
		return nil, [32]byte{}, err
	}

	encryptedData, err := s.encryptInnerLeaseSet(innerLS2, cookie)
	if err != nil {
		return nil, [32]byte{}, err
	}

	return encryptedData, cookie, nil
}

// finalizeEncryptedLeaseSet assembles and serializes the final EncryptedLeaseSet structure.
// Takes the encryption cookie and encrypted inner data, creates the EncryptedLeaseSet,
// and returns the serialized bytes ready for network publication.
func (s *Session) finalizeEncryptedLeaseSet(cookie [32]byte, encryptedData []byte) ([]byte, error) {
	els, err := s.assembleEncryptedLeaseSet(cookie, encryptedData)
	if err != nil {
		return nil, err
	}

	elsBytes, err := els.Bytes()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize EncryptedLeaseSet: %w", err)
	}

	return elsBytes, nil
}

// validateEncryptedLeaseSetSupport ensures the destination supports EncryptedLeaseSet.
// Only Ed25519 (type 7) signatures are supported for destination blinding.
func (s *Session) validateEncryptedLeaseSetSupport() error {
	sigType := s.destination.KeyCertificate.SigningPublicKeyType()
	if sigType != key_certificate.KEYCERT_SIGN_ED25519 {
		return fmt.Errorf("EncryptedLeaseSet requires Ed25519 signature type (type 7), got type %d", sigType)
	}
	return nil
}

// updateBlindedDestination derives or updates the blinded destination.
// The blinded destination rotates daily at UTC midnight to prevent correlation.
func (s *Session) updateBlindedDestination() error {
	now := time.Now().UTC()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)

	// Check if we need to derive a new blinded destination
	// (first time, or date has changed since last blinding)
	if s.blindedDestination == nil || !s.lastBlindingDate.Equal(today) {
		// Ensure we have a blinding secret
		if err := s.ensureBlindingSecret(); err != nil {
			return err
		}

		// Derive blinded destination for today
		blindedDest, err := encrypted_leaseset.CreateBlindedDestination(
			*s.destination,
			s.blindingSecret,
			today,
		)
		if err != nil {
			return fmt.Errorf("failed to create blinded destination: %w", err)
		}

		s.blindedDestination = &blindedDest
		s.lastBlindingDate = today

		log.WithFields(logger.Fields{
			"at":        "i2cp.Session.updateBlindedDestination",
			"sessionID": s.id,
			"date":      today.Format("2006-01-02"),
		}).Debug("updated_blinded_destination")
	}

	return nil
}

// ensureBlindingSecret ensures a blinding secret exists.
// If configured, uses the provided secret; otherwise generates a random one.
func (s *Session) ensureBlindingSecret() error {
	if s.blindingSecret != nil {
		return nil // Already have a secret
	}

	// Use configured secret if provided
	if len(s.config.BlindingSecret) > 0 {
		s.blindingSecret = s.config.BlindingSecret
		return nil
	}

	// Generate random 32-byte secret
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return fmt.Errorf("failed to generate random blinding secret: %w", err)
	}

	s.blindingSecret = secret
	log.WithFields(logger.Fields{
		"at":        "i2cp.Session.ensureBlindingSecret",
		"sessionID": s.id,
	}).Debug("generated_random_blinding_secret")

	return nil
}

// createInnerLeaseSet2 creates the inner LeaseSet2 that will be encrypted.
func (s *Session) createInnerLeaseSet2(leases []lease.Lease2) (*lease_set2.LeaseSet2, error) {
	// Prepare encryption key
	encKey, err := s.prepareEncryptionKey()
	if err != nil {
		return nil, err
	}

	// Get signing private key from keystore (no error returned)
	signingPrivateKey := s.keys.SigningPrivateKey()

	// Calculate published time and expiration
	publishedTime := uint32(time.Now().Unix())

	// Create LeaseSet2 (this will be the inner encrypted content)
	ls2, err := lease_set2.NewLeaseSet2(
		*s.destination,
		publishedTime,
		s.config.LeaseSetExpiration,
		0,   // flags
		nil, // no offline signature for inner LeaseSet2
		data.Mapping{},
		[]lease_set2.EncryptionKey{encKey},
		leases,
		signingPrivateKey,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create inner LeaseSet2: %w", err)
	}

	return &ls2, nil
}

// generateEncryptionCookie generates a random 32-byte cookie for encryption.
func (s *Session) generateEncryptionCookie() ([32]byte, error) {
	var cookie [32]byte
	if _, err := rand.Read(cookie[:]); err != nil {
		return [32]byte{}, fmt.Errorf("failed to generate encryption cookie: %w", err)
	}
	return cookie, nil
}

// encryptInnerLeaseSet encrypts the inner LeaseSet2 data.
func (s *Session) encryptInnerLeaseSet(ls2 *lease_set2.LeaseSet2, cookie [32]byte) ([]byte, error) {
	// For EncryptedLeaseSet, we encrypt for the blinded destination's public key
	blindedPubKey, err := s.blindedDestination.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get blinded encryption public key: %w", err)
	}

	// Encrypt inner LeaseSet2
	encryptedData, err := encrypted_leaseset.EncryptInnerLeaseSet2(ls2, cookie, blindedPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt inner LeaseSet2: %w", err)
	}

	return encryptedData, nil
}

// assembleEncryptedLeaseSet assembles and signs the final EncryptedLeaseSet.
func (s *Session) assembleEncryptedLeaseSet(cookie [32]byte, encryptedInnerData []byte) (*encrypted_leaseset.EncryptedLeaseSet, error) {
	// Calculate published time
	publishedTime := uint32(time.Now().Unix())

	// Get the blinded signing private key
	// Note: For EncryptedLeaseSet, we need to sign with the BLINDED key, not the original
	// The encrypted_leaseset library's NewEncryptedLeaseSet expects the blinded private key
	signingPrivateKey := s.keys.SigningPrivateKey()

	// Create EncryptedLeaseSet
	// Flags: bit 2 = blinded (0x04)
	const ENCRYPTED_LEASESET_FLAG_BLINDED = 0x04

	els, err := encrypted_leaseset.NewEncryptedLeaseSet(
		*s.blindedDestination,
		publishedTime,
		s.config.LeaseSetExpiration,
		ENCRYPTED_LEASESET_FLAG_BLINDED,
		nil, // no offline signature
		data.Mapping{},
		cookie,
		encryptedInnerData,
		signingPrivateKey,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create EncryptedLeaseSet: %w", err)
	}

	log.WithFields(logger.Fields{
		"at":             "i2cp.Session.assembleEncryptedLeaseSet",
		"sessionID":      s.id,
		"published":      publishedTime,
		"expires_offset": s.config.LeaseSetExpiration,
		"inner_length":   len(encryptedInnerData),
	}).Debug("created_encrypted_leaseset")

	return els, nil
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
	// For default 10-minute tunnels, this means checking every 2.5 minutes.
	// Enforce a minimum of 1ms to prevent ticker panic on zero duration.
	maintenanceInterval := s.config.TunnelLifetime / 4
	if maintenanceInterval <= 0 {
		maintenanceInterval = 15 * time.Second
	}

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
// 1. Creates a fresh LeaseSet from current inbound tunnels (LeaseSet2 or EncryptedLeaseSet)
// 2. Publishes it to the local NetDB
// 3. Distributes it to floodfill routers (if publisher is configured)
//
// Returns an error if LeaseSet creation or publication fails.
func (s *Session) regenerateAndPublishLeaseSet() error {
	var leaseSetBytes []byte
	var err error

	// Read config under lock to avoid data race with Reconfigure
	s.mu.RLock()
	useEncrypted := s.config.UseEncryptedLeaseSet
	s.mu.RUnlock()

	// Choose LeaseSet type based on configuration
	if useEncrypted {
		leaseSetBytes, err = s.CreateEncryptedLeaseSet()
		if err != nil {
			return fmt.Errorf("failed to create EncryptedLeaseSet: %w", err)
		}
	} else {
		leaseSetBytes, err = s.CreateLeaseSet()
		if err != nil {
			return fmt.Errorf("failed to create LeaseSet: %w", err)
		}
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
// For EncryptedLeaseSet, publishes using the blinded destination hash instead of the original.
func (s *Session) publishLeaseSetToNetwork(leaseSetBytes []byte) error {
	s.mu.RLock()
	publisher := s.publisher
	useEncrypted := s.config.UseEncryptedLeaseSet
	blindedDest := s.blindedDestination
	s.mu.RUnlock()

	if publisher == nil {
		// No publisher configured - this is acceptable for testing or standalone sessions
		return nil
	}

	// Calculate destination hash for publication
	destHash, err := s.calculatePublicationHash(useEncrypted, blindedDest)
	if err != nil {
		return err
	}

	// Publish to network
	if err := s.publishToPublisher(publisher, destHash, leaseSetBytes, useEncrypted); err != nil {
		return err
	}

	return nil
}

// calculatePublicationHash determines the correct hash for LeaseSet publication.
func (s *Session) calculatePublicationHash(useEncrypted bool, blindedDest *destination.Destination) (data.Hash, error) {
	if useEncrypted && blindedDest != nil {
		// For EncryptedLeaseSet, use blinded destination hash
		destBytes, err := blindedDest.Bytes()
		if err != nil {
			return data.Hash{}, fmt.Errorf("failed to get blinded destination bytes: %w", err)
		}
		return data.HashData(destBytes), nil
	}

	// For normal LeaseSet2, use original destination hash
	destBytes, err := s.destination.Bytes()
	if err != nil {
		return data.Hash{}, fmt.Errorf("failed to get destination bytes: %w", err)
	}
	return data.HashData(destBytes), nil
}

// publishToPublisher executes the publication and logs the result.
func (s *Session) publishToPublisher(publisher LeaseSetPublisher, destHash data.Hash, leaseSetBytes []byte, useEncrypted bool) error {
	if err := publisher.PublishLeaseSet(destHash, leaseSetBytes); err != nil {
		return fmt.Errorf("publisher failed: %w", err)
	}

	log.WithFields(logger.Fields{
		"at":          "i2cp.Session.publishLeaseSetToNetwork",
		"sessionID":   s.ID(),
		"destHash":    fmt.Sprintf("%x", destHash[:8]),
		"isEncrypted": useEncrypted,
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

// SetCurrentLeaseSet caches externally-provided LeaseSet bytes (e.g. from CreateLeaseSet2).
// Updates the currentLeaseSet and leaseSetPublishedAt timestamp.
func (s *Session) SetCurrentLeaseSet(leaseSetBytes []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.currentLeaseSet = leaseSetBytes
	s.leaseSetPublishedAt = time.Now()
}

// ValidateLeaseSet2Data parses and validates client-provided LeaseSet2 bytes.
// Ensures the data is structurally valid and that the embedded destination
// matches the session's destination. Returns an error if validation fails.
//
// Checks performed:
//  1. Structural parsing via ReadLeaseSet2 (validates all fields and signature)
//  2. Destination match: the LeaseSet2's destination must match this session's destination
//  3. Expiration: the LeaseSet2 must not already be expired
func (s *Session) ValidateLeaseSet2Data(leaseSetBytes []byte) error {
	// Parse the LeaseSet2 to verify structural validity
	ls2, _, err := lease_set2.ReadLeaseSet2(leaseSetBytes)
	if err != nil {
		return fmt.Errorf("invalid LeaseSet2 structure: %w", err)
	}

	// Verify the LeaseSet2's destination matches this session's destination
	s.mu.RLock()
	sessionDest := s.destination
	s.mu.RUnlock()

	if sessionDest == nil {
		return fmt.Errorf("session has no destination configured")
	}

	if err := matchDestinations(sessionDest, ls2.Destination()); err != nil {
		return fmt.Errorf("destination mismatch: %w", err)
	}

	// Verify the LeaseSet2 is not already expired
	if ls2.IsExpired() {
		return fmt.Errorf("LeaseSet2 is already expired (published: %v, expires offset: %d)",
			ls2.PublishedTime(), ls2.Expires())
	}

	return nil
}

// matchDestinations compares two destinations by their signing public keys.
// The signing public key is the identity-critical component and is stable
// across serialization round-trips (construct → serialize → parse).
// Returns nil if they match, or an error describing the mismatch.
func matchDestinations(sessionDest *destination.Destination, lsDest destination.Destination) error {
	sessionSPK, err := sessionDest.SigningPublicKey()
	if err != nil {
		return fmt.Errorf("failed to get session signing public key: %w", err)
	}

	lsSPK, err := lsDest.SigningPublicKey()
	if err != nil {
		return fmt.Errorf("failed to get LeaseSet2 signing public key: %w", err)
	}

	sessionSPKBytes := sessionSPK.Bytes()
	lsSPKBytes := lsSPK.Bytes()

	if len(sessionSPKBytes) != len(lsSPKBytes) {
		return fmt.Errorf("signing key length mismatch: session=%d, leaseset=%d",
			len(sessionSPKBytes), len(lsSPKBytes))
	}

	sessionHash := data.HashData(sessionSPKBytes)
	lsHash := data.HashData(lsSPKBytes)

	if sessionHash != lsHash {
		return fmt.Errorf("LeaseSet2 destination hash %x does not match session destination hash %x",
			lsHash[:8], sessionHash[:8])
	}

	return nil
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
		log.WithFields(logger.Fields{
			"at":        "i2cp.Session.Stop",
			"sessionID": s.id,
			"uptime":    time.Since(s.createdAt),
		}).Info("stopping_session")

		s.mu.Lock()
		s.active = false
		queuedMessages := len(s.incomingMessages)
		s.mu.Unlock()

		close(s.stopCh)

		// Wait for maintenance goroutine to exit
		s.maintWg.Wait()

		// Drain incoming message queue
		discarded := 0
		for {
			select {
			case <-s.incomingMessages:
				discarded++
			default:
				log.WithFields(logger.Fields{
					"at":                "i2cp.Session.Stop",
					"sessionID":         s.id,
					"queuedMessages":    queuedMessages,
					"discardedMessages": discarded,
				}).Info("session_stopped")
				return
			}
		}
	})
}

// SessionManager manages all active I2CP sessions
type SessionManager struct {
	mu       sync.RWMutex
	sessions map[uint16]*Session // Session ID -> Session
}

// NewSessionManager creates a new session manager
func NewSessionManager() *SessionManager {
	return &SessionManager{
		sessions: make(map[uint16]*Session),
	}
}

// CreateSession creates a new session with the given destination and config.
// Optional private keys (signingPrivKey, encryptionPrivKey) can be provided
// to preserve the client's persistent identity across sessions.
func (sm *SessionManager) CreateSession(dest *destination.Destination, config *SessionConfig, privKeys ...interface{}) (*Session, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Allocate session ID
	sessionID, err := sm.allocateSessionID()
	if err != nil {
		log.WithFields(logger.Fields{
			"at":             "i2cp.SessionManager.CreateSession",
			"activeSessions": len(sm.sessions),
		}).Error("no_available_session_ids")
		return nil, err
	}

	// Create session with its own isolated in-memory NetDB
	session, err := NewSession(sessionID, dest, config, privKeys...)
	if err != nil {
		log.WithFields(logger.Fields{
			"at":        "i2cp.SessionManager.CreateSession",
			"sessionID": sessionID,
			"error":     err.Error(),
		}).Error("failed_to_create_session")
		return nil, err
	}

	// Register session
	sm.sessions[sessionID] = session

	log.WithFields(logger.Fields{
		"at":             "i2cp.SessionManager.CreateSession",
		"sessionID":      sessionID,
		"activeSessions": len(sm.sessions),
	}).Info("session_registered")

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
		log.WithFields(logger.Fields{
			"at":        "i2cp.SessionManager.DestroySession",
			"sessionID": sessionID,
		}).Warn("session_not_found")
		return fmt.Errorf("session %d not found", sessionID)
	}

	delete(sm.sessions, sessionID)
	remainingCount := len(sm.sessions)
	sm.mu.Unlock()

	log.WithFields(logger.Fields{
		"at":                "i2cp.SessionManager.DestroySession",
		"sessionID":         sessionID,
		"remainingSessions": remainingCount,
	}).Info("session_destroyed")

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

// GetAllSessions returns a copy of all active sessions
func (sm *SessionManager) GetAllSessions() []*Session {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	sessions := make([]*Session, 0, len(sm.sessions))
	for _, session := range sm.sessions {
		sessions = append(sessions, session)
	}
	return sessions
}

// RemoveSession removes a session from the manager without stopping it
func (sm *SessionManager) RemoveSession(sessionID uint16) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	delete(sm.sessions, sessionID)
}

// allocateSessionID finds the next available session ID using cryptographic randomness
// to prevent session ID prediction attacks. Must be called with sm.mu locked.
func (sm *SessionManager) allocateSessionID() (uint16, error) {
	// Try up to 100 times to find an unused ID
	// With 16-bit space (65536 IDs) and typical session counts (<100),
	// collision probability is extremely low
	maxAttempts := 100

	for attempt := 0; attempt < maxAttempts; attempt++ {
		id, err := generateSecureSessionID()
		if err != nil {
			// Log error but continue trying - fall back to next attempt
			log.WithFields(logger.Fields{
				"at":      "allocateSessionID",
				"attempt": attempt,
				"error":   err.Error(),
			}).Warn("failed to generate random session ID")
			continue
		}

		// Skip reserved IDs
		if id == SessionIDReservedControl || id == SessionIDReservedBroadcast {
			continue
		}

		// Check if ID is available
		if _, exists := sm.sessions[id]; !exists {
			return id, nil
		}
	}

	// Exhausted all attempts - no available IDs (should never happen in practice)
	log.WithFields(logger.Fields{
		"at":             "allocateSessionID",
		"activeSessions": len(sm.sessions),
		"maxAttempts":    maxAttempts,
	}).Error("failed to allocate session ID after maximum attempts")
	return 0, fmt.Errorf("failed to allocate session ID after %d attempts (%d active sessions)", maxAttempts, len(sm.sessions))
}

// generateSecureSessionID generates a cryptographically random 16-bit session ID
func generateSecureSessionID() (uint16, error) {
	var buf [2]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return 0, fmt.Errorf("failed to read random bytes: %w", err)
	}

	// Convert bytes to uint16 (big-endian)
	id := uint16(buf[0])<<8 | uint16(buf[1])
	return id, nil
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
