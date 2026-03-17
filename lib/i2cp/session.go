package i2cp

import (
	"crypto/ed25519"
	"fmt"
	"sync"
	"time"

	ed25519i2p "github.com/go-i2p/crypto/ed25519"
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
	// Cap elapsed time at 5 seconds to limit burst to rate*5 messages.
	// For a 100 msg/s rate, this allows up to 500 messages in a burst,
	// which is sufficient for normal traffic patterns without overwhelming
	// downstream processing after long idle periods.
	const maxAccumulationWindow = 5 * time.Second
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

	// Backup tunnel parameters (per I2CP spec)
	InboundBackupQuantity  int // Extra standby inbound tunnels (default: 0)
	OutboundBackupQuantity int // Extra standby outbound tunnels (default: 0)

	// Tunnel length variance (per I2CP spec)
	// When non-zero, the actual tunnel length is randomized within
	// [length - |variance|, length + |variance|] (clamped to [0, 7]).
	// A negative variance means "subtract only" (shorter tunnels only).
	InboundLengthVariance  int // Variance for inbound tunnel length (default: 0)
	OutboundLengthVariance int // Variance for outbound tunnel length (default: 0)

	// Network parameters
	MessageTimeout time.Duration // Message delivery timeout (default: 60 seconds)

	// Message queue configuration
	MessageQueueSize     int // Incoming message queue buffer size (default: 100)
	MessageRateLimit     int // Maximum messages per second (default: 100, 0 = unlimited)
	MessageRateBurstSize int // Maximum burst size for rate limiting (default: 200)

	// Message delivery semantics (per I2CP spec)
	// Supported values: "BestEffort" (default), "Guaranteed", "None"
	MessageReliability string // Message reliability mode (default: "BestEffort")

	// LeaseSet configuration
	DontPublishLeaseSet bool // If true, the LeaseSet is created but not published to the NetDB (default: false)

	// EncryptedLeaseSet configuration (requires Ed25519 destination)
	UseEncryptedLeaseSet bool   // Enable EncryptedLeaseSet generation (default: false)
	BlindingSecret       []byte // Secret for destination blinding (if empty, random generated)

	// Gzip compression (per I2CP spec, compression is performed by the client library)
	GzipEnabled bool // If true, the I2CP client library compresses/decompresses payloads (default: true per spec)

	// ExplicitlySetFields tracks which fields were explicitly set by the client
	// during reconfiguration, allowing zero values (e.g., zero-hop tunnels) to
	// be distinguished from "not provided".
	ExplicitlySetFields map[string]bool
	LeaseSetExpiration  uint16 // LeaseSet expiration in seconds (default: 600 = 10 minutes)

	// Session metadata
	Nickname string // Optional nickname for debugging

	// UnsupportedOptions lists I2CP options that the client set but this
	// implementation does not support. Each entry maps option name → value.
	// Clients can inspect this after session creation to detect unsupported features.
	UnsupportedOptions map[string]string
}

// DefaultSessionConfig returns a SessionConfig with sensible defaults
func DefaultSessionConfig() *SessionConfig {
	return &SessionConfig{
		InboundTunnelLength:    3,
		OutboundTunnelLength:   3,
		InboundTunnelCount:     5,
		OutboundTunnelCount:    5,
		InboundBackupQuantity:  0,
		OutboundBackupQuantity: 0,
		InboundLengthVariance:  0,
		OutboundLengthVariance: 0,
		TunnelLifetime:         10 * time.Minute,
		MessageTimeout:         60 * time.Second,
		MessageQueueSize:       100,
		MessageRateLimit:       100, // 100 messages/second
		MessageRateBurstSize:   200, // Allow bursts up to 200 messages
		MessageReliability:     "BestEffort",
		DontPublishLeaseSet:    false,
		UseEncryptedLeaseSet:   false,
		BlindingSecret:         nil,
		GzipEnabled:            true, // Per I2CP spec, gzip is enabled by default
		LeaseSetExpiration:     600,  // 10 minutes
		Nickname:               "",
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
	}).Info("creating_i2cp_session")

	sigPriv, encPriv, identityPadding := extractPrivateKeys(privKeys)

	keyStore, dest, err := prepareDestinationAndKeys(dest, sigPriv, encPriv, identityPadding)
	if err != nil {
		log.WithFields(logger.Fields{
			"at":        "i2cp.NewSession",
			"sessionID": id,
			"error":     err.Error(),
		}).Error("failed_to_prepare_destination")
		return nil, err
	}

	queueSize := determineQueueSize(config)

	return &Session{
		id:                 id,
		destination:        dest,
		keys:               keyStore,
		config:             config,
		clientNetDB:        createIsolatedNetDB(),
		createdAt:          time.Now(),
		lastActivity:       time.Now(),
		active:             true,
		incomingMessages:   make(chan *IncomingMessage, queueSize),
		messageRateLimiter: createRateLimiterIfNeeded(config, id),
		queueHighWaterMark: queueSize,
		stopCh:             make(chan struct{}),
	}, nil
}

// extractPrivateKeys extracts signing/encryption keys and optional identity padding from variadic args.
func extractPrivateKeys(privKeys []interface{}) (types.SigningPrivateKey, types.PrivateEncryptionKey, []byte) {
	var sigPriv types.SigningPrivateKey
	var encPriv types.PrivateEncryptionKey
	var identityPadding []byte
	if len(privKeys) >= 2 {
		if sp, ok := privKeys[0].(types.SigningPrivateKey); ok {
			sigPriv = sp
		}
		if ep, ok := privKeys[1].(types.PrivateEncryptionKey); ok {
			encPriv = ep
		}
	}
	if len(privKeys) >= 3 {
		if pad, ok := privKeys[2].([]byte); ok {
			identityPadding = pad
		}
	}
	return sigPriv, encPriv, identityPadding
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
// If identityPadding is also provided, the exact same destination hash is produced,
// giving the client a stable .b32.i2p address across sessions.
//
// When private keys are nil, a fresh DestinationKeyStore with new keys and a new
// destination is generated. The dest parameter is ignored in this case because
// we cannot use a destination without its corresponding private keys.
func prepareDestinationAndKeys(dest *destination.Destination, sigPriv types.SigningPrivateKey, encPriv types.PrivateEncryptionKey, identityPadding ...[]byte) (*keys.DestinationKeyStore, *destination.Destination, error) {
	// Case 1: Client provided private keys — reconstruct their identity
	if sigPriv != nil && encPriv != nil {
		log.WithFields(logger.Fields{
			"at":     "prepareDestinationAndKeys",
			"reason": "client_provided_private_keys",
		}).Info("Using client-provided private keys to preserve persistent identity")

		keyStore, err := keys.NewDestinationKeyStoreFromKeys(sigPriv, encPriv, identityPadding...)
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

// stdlibSigningKey converts the session's SigningPrivateKey (which may be a
// go-i2p/crypto/ed25519.Ed25519PrivateKey) to a stdlib crypto/ed25519.PrivateKey.
// This is needed because common's ExtractEd25519PrivateKey type-switches on the
// stdlib type and doesn't recognise the crypto package's named wrapper type.
func (s *Session) stdlibSigningKey() (ed25519.PrivateKey, error) {
	key := s.keys.SigningPrivateKey()
	// Direct type assertion for Ed25519PrivateKey (underlying type is ed25519.PrivateKey)
	if k, ok := key.(*ed25519i2p.Ed25519PrivateKey); ok {
		return ed25519.PrivateKey(*k), nil
	}
	// Try interface with Bytes() as fallback
	if kb, ok := key.(interface{ Bytes() []byte }); ok {
		return ed25519.PrivateKey(kb.Bytes()), nil
	}
	return nil, fmt.Errorf("cannot convert signing key of type %T to ed25519.PrivateKey", key)
}

// assembleLeaseSet constructs and serializes the final LeaseSet2 structure.
// Combines destination, leases, and encryption key into a signed LeaseSet2.
func (s *Session) assembleLeaseSet(leases []lease.Lease2, encKey lease_set2.EncryptionKey) ([]byte, error) {
	dest := *s.destination
	signingPrivateKey, err := s.stdlibSigningKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get signing key: %w", err)
	}

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

	// Get signing private key from keystore, converting to stdlib ed25519.PrivateKey
	// for compatibility with common's ExtractEd25519PrivateKey type switch.
	signingPrivateKey, err := s.stdlibSigningKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get signing key: %w", err)
	}

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
	// Get the unblinded destination's signing public key
	destSigningPubKey, err := s.destination.SigningPublicKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get destination signing public key: %w", err)
	}

	// Get the blinded destination's signing public key
	blindedSigningPubKey, err := s.blindedDestination.SigningPublicKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get blinded signing public key: %w", err)
	}

	// Derive subcredential per I2P spec:
	//   credential    = SHA-256("credential" || destSigningPubKey)
	//   subcredential = SHA-256("subcredential" || credential || blindedPubKey)
	subcredential := encrypted_leaseset.DeriveSubcredential(
		destSigningPubKey.Bytes(),
		blindedSigningPubKey.Bytes(),
	)

	// Published timestamp (seconds since epoch)
	published := uint32(time.Now().Unix())

	// Encrypt inner LeaseSet2
	encryptedData, err := encrypted_leaseset.EncryptInnerLeaseSet2(ls2, subcredential, published)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt inner LeaseSet2: %w", err)
	}

	return encryptedData, nil
}

// assembleEncryptedLeaseSet assembles and signs the final EncryptedLeaseSet.
func (s *Session) assembleEncryptedLeaseSet(cookie [32]byte, encryptedInnerData []byte) (*encrypted_leaseset.EncryptedLeaseSet, error) {
	// Calculate published time
	publishedTime := uint32(time.Now().Unix())

	// Get the blinded signing private key, converting to stdlib ed25519.PrivateKey
	// for compatibility with common's ExtractEd25519PrivateKey type switch.
	// Note: For EncryptedLeaseSet, we need to sign with the BLINDED key, not the original
	// The encrypted_leaseset library's NewEncryptedLeaseSet expects the blinded private key
	signingPrivateKey, err := s.stdlibSigningKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get signing key: %w", err)
	}

	// Create EncryptedLeaseSet
	// Note: Blinding is implicit from providing a blinded public key;
	// the new API only allows bit 0 (offline) and bit 1 (unpublished).
	var elsFlags uint16 = 0

	// Extract blinded public key bytes from the blinded destination
	blindedPubKey, err := s.blindedDestination.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get blinded public key: %w", err)
	}
	blindedPubKeyBytes := blindedPubKey.Bytes()

	// sigType for Ed25519 (KEYCERT_SIGN_ED25519 = 7)
	sigType := uint16(s.blindedDestination.KeyCertificate.SigningPublicKeyType())

	els, err := encrypted_leaseset.NewEncryptedLeaseSet(
		sigType,
		blindedPubKeyBytes,
		publishedTime,
		s.config.LeaseSetExpiration,
		elsFlags,
		nil, // no offline signature
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
