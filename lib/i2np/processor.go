package i2np

import (
	"sync"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/session_key"
	"github.com/go-i2p/go-i2p/lib/tunnel/build"
	"github.com/go-i2p/go-i2p/lib/tunnel/buildrecord"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// GarlicCloveForwarder defines the interface for forwarding garlic cloves
// to different delivery targets. This interface enables the MessageProcessor
// to delegate non-LOCAL delivery types to router-level components that have
// access to NetDB, transport, and tunnel infrastructure.
type GarlicCloveForwarder interface {
	// ForwardToDestination forwards a message to a destination hash (delivery type 0x01).
	// The forwarder should lookup the destination's LeaseSet and route through a tunnel.
	ForwardToDestination(destHash common.Hash, msg Message) error

	// ForwardToRouter forwards a message directly to a router hash (delivery type 0x02).
	// The forwarder should send the message via the transport layer.
	ForwardToRouter(routerHash common.Hash, msg Message) error

	// ForwardThroughTunnel forwards a message through a tunnel to a gateway (delivery type 0x03).
	// The forwarder should wrap the message in a TunnelGateway envelope and send to the gateway.
	ForwardThroughTunnel(gatewayHash common.Hash, tunnelID buildrecord.TunnelID, msg Message) error
}

// ParticipantManager defines the interface for processing incoming tunnel build requests.
// This interface enables the MessageProcessor to delegate tunnel participation decisions
// to the tunnel.Manager which handles rate limiting and resource protection.
type ParticipantManager interface {
	// ProcessBuildRequest validates a tunnel build request against all limits.
	// Returns whether the request should be accepted, the rejection code if not,
	// and a human-readable reason for logging.
	//
	// Note: The identifier passed is the target router (the router receiving this
	// tunnel build request), not the original source. Rate limiting is enforced
	// as a global limit, not per-source, because the actual tunnel initiator
	// identity is not available at intermediate hops in the I2P protocol.
	//
	// Parameters:
	// - targetHash: The router hash of the target (from BuildRequestRecord.OurIdent)
	//
	// Returns:
	// - accepted: Whether the request should be accepted
	// - rejectCode: I2P-compliant rejection code if not accepted (0 if accepted)
	// - reason: Human-readable reason for logging (empty if accepted)
	ProcessBuildRequest(targetHash common.Hash) (accepted bool, rejectCode byte, reason string)

	// RegisterParticipant registers a new participating tunnel after acceptance.
	// This should be called after ProcessBuildRequest returns accepted=true.
	//
	// Parameters:
	// - tunnelID: The tunnel ID for the participating tunnel
	// - targetHash: The router hash of the target (our identity from the build request record)
	// - expiry: When the tunnel participation expires
	// - layerKey: The layer encryption key from the build request record
	// - ivKey: The IV key from the build request record
	// - nextHopIdent: The router hash of the next hop for routing (may be empty)
	// - nextHopTunnel: The tunnel ID at the next hop for routing (0 if endpoint)
	RegisterParticipant(tunnelID buildrecord.TunnelID, targetHash common.Hash, expiry time.Time, layerKey, ivKey session_key.SessionKey, nextHopIdent common.Hash, nextHopTunnel buildrecord.TunnelID) error
}

// BuildReplyForwarder defines the interface for forwarding tunnel build replies.
// This interface enables the MessageProcessor to send build response messages
// to the next hop in the tunnel or back through the reply tunnel.
type BuildReplyForwarder interface {
	// ForwardBuildReplyToRouter forwards a build reply message directly to a router.
	// This is used when the next hop is a router that we have a direct transport connection to.
	//
	// Parameters:
	// - routerHash: The hash of the router to forward to (NextIdent from BuildRequestRecord)
	// - messageID: The I2NP message ID for the reply
	// - encryptedRecords: The complete encrypted build reply records
	// - isShortBuild: Whether this is a Short Tunnel Build Message (STBM) format
	ForwardBuildReplyToRouter(routerHash common.Hash, messageID int, encryptedRecords []byte, isShortBuild bool) error

	// ForwardBuildReplyThroughTunnel forwards a build reply message through a reply tunnel.
	// This is used when the build request specifies a reply tunnel for the response.
	//
	// Parameters:
	// - gatewayHash: The hash of the tunnel gateway router
	// - tunnelID: The tunnel ID to use for forwarding
	// - messageID: The I2NP message ID for the reply
	// - encryptedRecords: The complete encrypted build reply records
	// - isShortBuild: Whether this is a Short Tunnel Build Message (STBM) format
	ForwardBuildReplyThroughTunnel(gatewayHash common.Hash, tunnelID buildrecord.TunnelID, messageID int, encryptedRecords []byte, isShortBuild bool) error
}

// TunnelGatewayHandler defines the interface for handling TunnelGateway messages.
// When a TunnelGateway message arrives, the handler looks up the tunnel by ID,
// encrypts the payload using the tunnel's layered encryption, and forwards the
// resulting TunnelData message to the next hop.
type TunnelGatewayHandler interface {
	// HandleGateway processes an incoming TunnelGateway message by looking up the tunnel,
	// encrypting the payload, and forwarding it to the next hop.
	HandleGateway(tunnelID buildrecord.TunnelID, payload []byte) error
}

// TunnelDataHandler defines the interface for handling incoming TunnelData messages.
// When a TunnelData message arrives at our tunnel endpoint, the handler decrypts
// it and delivers the embedded I2NP message to the appropriate I2CP session.
type TunnelDataHandler interface {
	// HandleTunnelData processes an incoming TunnelData message by looking up the
	// tunnel endpoint, decrypting the payload, and delivering it to the owning session.
	HandleTunnelData(msg Message) error
}

// SearchReplyHandler defines the interface for delivering DatabaseSearchReply
// suggestions to pending iterative Kademlia lookups.
type SearchReplyHandler interface {
	// HandleSearchReply delivers suggested peer hashes from a DatabaseSearchReply.
	// The key is the lookup target hash, and peerHashes are the suggested peers.
	HandleSearchReply(key common.Hash, peerHashes []common.Hash)
}

// DataMessageHandler defines the interface for handling incoming Data messages.
// Data messages carry end-to-end payloads that need to be delivered to I2CP sessions.
type DataMessageHandler interface {
	// HandleDataMessage processes a Data message payload.
	// The payload is the raw message bytes extracted from the I2NP Data message.
	HandleDataMessage(payload []byte) error
}

// DeliveryStatusHandler defines the interface for handling delivery status confirmations.
// When a DeliveryStatus message is received, it notifies the original sender that their
// message was delivered, completing the delivery confirmation loop.
type DeliveryStatusHandler interface {
	// HandleDeliveryStatus processes a delivery status notification.
	// msgID is the original message ID being confirmed, timestamp is when it was delivered.
	HandleDeliveryStatus(msgID int, timestamp time.Time) error
}

// TunnelBuildReplyProcessor defines the interface for processing tunnel build reply messages - re-exported from lib/tunnel/build
type TunnelBuildReplyProcessor = build.TunnelBuildReplyProcessor

// GarlicMessageDecryptor provides garlic message decryption for the processor.
// This interface is satisfied by both GarlicSessionManager (the concrete adapter)
// and test mocks.
type GarlicMessageDecryptor interface {
	// DecryptGarlicMessage decrypts an encrypted garlic message.
	// Returns all GarlicClove payloads found in the ratchet payload (a spec-compliant
	// payload may contain more than one GarlicClove block), session tag, session hash
	// (non-nil for New Session), and error.
	DecryptGarlicMessage(encrypted []byte) (cloves [][]byte, sessionTag [8]byte, sessionHash *[32]byte, err error)
}

// GarlicKeyRegistrar allows callers to register one-time symmetric garlic keys - re-exported from lib/tunnel/build
type GarlicKeyRegistrar = build.GarlicKeyRegistrar

// ReplyRecordEncryptor encrypts tunnel build reply records.
// This interface is satisfied by both BuildRecordCrypto (the concrete adapter)
// and test mocks.
type ReplyRecordEncryptor interface {
	// EncryptReplyRecord encrypts a BuildResponseRecord with the given reply key and IV.
	EncryptReplyRecord(record BuildResponseRecord, replyKey session_key.SessionKey, replyIV [16]byte) ([]byte, error)
}

// BuildRequestDecryptor decrypts inbound tunnel build request records.
// When processing build requests from the network, encrypted records destined
// for this router must be decrypted before parsing. This interface abstracts
// the ECIES-X25519-AEAD decryption so that test mocks can be substituted.
type BuildRequestDecryptor interface {
	// DecryptRecord decrypts a 528-byte encrypted build request record
	// using the router's static private key and returns the parsed record.
	DecryptRecord(encrypted [528]byte, privateKey []byte) (BuildRequestRecord, error)
}

// stbmSlotCrypto holds the Noise-derived reply key and transcript hash for a single
// STBM build request record slot. These are computed during ECIES decryption and
// required later when building the AEAD-encrypted reply record.
type stbmSlotCrypto struct {
	replyKey  [32]byte
	noiseHash [32]byte
}

// MessageProcessor routes inbound I2NP messages to type-specific handlers and
// pluggable subsystem interfaces.
type MessageProcessor struct {
	mu                    sync.RWMutex
	factory               *MessageFactory
	garlicSessions        GarlicMessageDecryptor    // Interface for garlic message decryption
	cloveForwarder        GarlicCloveForwarder      // Optional delegate for non-LOCAL garlic clove delivery
	dbManager             *DatabaseManager          // Optional database manager for DatabaseLookup messages
	expirationValidator   *ExpirationValidator      // Validator for checking message expiration
	replayCache           *messageReplayCache       // H-NEW-4: bounded replay cache keyed by message ID
	participantManager    ParticipantManager        // Optional participant manager for tunnel build requests
	buildReplyForwarder   BuildReplyForwarder       // Optional forwarder for tunnel build replies
	buildRecordCrypto     ReplyRecordEncryptor      // Interface for encrypting build response records
	tunnelGatewayHandler  TunnelGatewayHandler      // Optional handler for tunnel gateway messages
	tunnelDataHandler     TunnelDataHandler         // Optional handler for inbound tunnel data messages
	searchReplyHandler    SearchReplyHandler        // Optional handler for DatabaseSearchReply suggestions
	dataMessageHandler    DataMessageHandler        // Optional handler for Data message payloads
	deliveryStatusHandler DeliveryStatusHandler     // Optional handler for delivery status confirmations
	buildReplyProcessor   TunnelBuildReplyProcessor // Optional processor for tunnel build reply messages
	buildRequestDecryptor BuildRequestDecryptor     // Optional decryptor for inbound build request records
	ourRouterHash         common.Hash               // Our router identity hash for filtering build records
	ourPrivateKey         []byte                    // Our router's static X25519 private key for build record decryption
	stbmSlotCrypto        map[int]stbmSlotCrypto    // Per-slot STBM crypto state (valid during one message processing call)
}

// NewMessageProcessor creates a new message processor
func NewMessageProcessor() *MessageProcessor {
	log.WithField("at", "NewMessageProcessor").Debug("Creating new message processor")
	crypto := NewBuildRecordCrypto()
	ev := NewExpirationValidator()
	return &MessageProcessor{
		factory:               NewMessageFactory(),
		expirationValidator:   ev,
		replayCache:           newMessageReplayCache(10_000, time.Duration(ev.toleranceSeconds)*time.Second),
		buildRecordCrypto:     crypto,
		buildRequestDecryptor: crypto,
	}
}

// SetGarlicSessionManager sets the garlic session manager for decrypting garlic messages.
// This must be called before processing garlic messages, otherwise they will fail with an error.
// Accepts any implementation of GarlicMessageDecryptor, including *GarlicSessionManager and test mocks.
func (p *MessageProcessor) SetGarlicSessionManager(garlicMgr GarlicMessageDecryptor) {
	p.setField("SetGarlicSessionManager", func() {
		p.garlicSessions = garlicMgr
	})
}

// SetBuildRecordCrypto sets the build record crypto handler for encrypting build response records.
// Accepts any implementation of ReplyRecordEncryptor, including *BuildRecordCrypto and test mocks.
func (p *MessageProcessor) SetBuildRecordCrypto(crypto ReplyRecordEncryptor) {
	p.setField("SetBuildRecordCrypto", func() {
		p.buildRecordCrypto = crypto
	})
}

// SetCloveForwarder sets the garlic clove forwarder for handling non-LOCAL delivery types.
// This is optional - if not set, only LOCAL delivery (0x00) will be processed.
// The forwarder enables DESTINATION (0x01), ROUTER (0x02), and TUNNEL (0x03) deliveries.
func (p *MessageProcessor) SetCloveForwarder(forwarder GarlicCloveForwarder) {
	p.setField("SetCloveForwarder", func() {
		p.cloveForwarder = forwarder
	})
}

// SetDatabaseManager sets the database manager for processing DatabaseLookup messages.
// This must be called before processing DatabaseLookup messages, otherwise they will fail with an error.
func (p *MessageProcessor) SetDatabaseManager(dbMgr *DatabaseManager) {
	p.setField("SetDatabaseManager", func() {
		p.dbManager = dbMgr
	})
}

// SetParticipantManager sets the participant manager for processing incoming tunnel build requests.
// This enables the router to participate in tunnels built by other routers.
// If not set, tunnel build requests will be rejected with an error.
func (p *MessageProcessor) SetParticipantManager(pm ParticipantManager) {
	p.setField("SetParticipantManager", func() {
		p.participantManager = pm
	})
}

// SetBuildReplyForwarder sets the forwarder for sending tunnel build replies to the next hop.
// This enables the router to participate in tunnel building by forwarding replies.
// If not set, build requests will be processed but replies will not be sent (logged only).
func (p *MessageProcessor) SetBuildReplyForwarder(forwarder BuildReplyForwarder) {
	p.setField("SetBuildReplyForwarder", func() {
		p.buildReplyForwarder = forwarder
	})
}

// SetTunnelGatewayHandler sets the handler for processing TunnelGateway messages.
// When set, incoming TunnelGateway messages will be delegated to this handler for
// tunnel lookup, encryption, and forwarding. If not set, TunnelGateway messages
// will be validated but not forwarded.
func (p *MessageProcessor) SetTunnelGatewayHandler(handler TunnelGatewayHandler) {
	p.setField("SetTunnelGatewayHandler", func() {
		p.tunnelGatewayHandler = handler
	})
}

// SetTunnelDataHandler sets the handler for processing inbound TunnelData messages.
// When set, incoming TunnelData messages will be delegated to this handler for
// tunnel endpoint decryption and I2CP session delivery. If not set, TunnelData
// messages will be validated but not delivered to any session.
func (p *MessageProcessor) SetTunnelDataHandler(handler TunnelDataHandler) {
	p.setField("SetTunnelDataHandler", func() {
		p.tunnelDataHandler = handler
	})
}

// SetSearchReplyHandler sets the handler for delivering DatabaseSearchReply suggestions
// to pending iterative Kademlia lookups. When set, peer suggestions from search replies
// are forwarded to this handler for follow-up queries.
func (p *MessageProcessor) SetSearchReplyHandler(handler SearchReplyHandler) {
	p.setField("SetSearchReplyHandler", func() {
		p.searchReplyHandler = handler
	})
}

// SetDataMessageHandler sets the handler for processing incoming Data message payloads.
// When set, Data message payloads are forwarded to this handler for delivery to the
// appropriate I2CP session. If not set, Data messages are logged but discarded.
func (p *MessageProcessor) SetDataMessageHandler(handler DataMessageHandler) {
	p.setField("SetDataMessageHandler", func() {
		p.dataMessageHandler = handler
	})
}

// SetDeliveryStatusHandler sets the handler for processing delivery status confirmations.
// When set, delivery status notifications are forwarded to this handler to confirm
// message delivery. If not set, DeliveryStatus messages are logged but discarded.
func (p *MessageProcessor) SetDeliveryStatusHandler(handler DeliveryStatusHandler) {
	p.setField("SetDeliveryStatusHandler", func() {
		p.deliveryStatusHandler = handler
	})
}

// SetBuildReplyProcessor sets the processor for handling incoming tunnel build reply messages.
// When set, tunnel build reply message types (22, 24, 26) are dispatched to this processor
// which correlates them with pending build requests and updates tunnel state.
// If not set, tunnel build replies are logged and discarded.
func (p *MessageProcessor) SetBuildReplyProcessor(processor TunnelBuildReplyProcessor) {
	p.setField("SetBuildReplyProcessor", func() {
		p.buildReplyProcessor = processor
	})
}

// SetOurRouterHash sets our router's identity hash so that processAllBuildRecords
// can skip records not destined for this router.
func (p *MessageProcessor) SetOurRouterHash(hash common.Hash) {
	p.setField("SetOurRouterHash", func() {
		p.ourRouterHash = hash
	})
}

// SetBuildRequestDecryptor sets the decryptor used to decrypt inbound build request
// records that are destined for this router. If not set, encrypted records will be
// attempted as cleartext (testing mode only).
func (p *MessageProcessor) SetBuildRequestDecryptor(dec BuildRequestDecryptor) {
	p.setField("SetBuildRequestDecryptor", func() {
		p.buildRequestDecryptor = dec
	})
}

// SetOurPrivateKey sets the router's static X25519 private key used for
// decrypting inbound build request records.
func (p *MessageProcessor) SetOurPrivateKey(key []byte) {
	p.setField("SetOurPrivateKey", func() {
		p.ourPrivateKey = make([]byte, len(key))
		copy(p.ourPrivateKey, key)
	})
}

// SetExpirationValidator sets a custom expiration validator for message processing.
// If not set, a default validator with 5-minute tolerance is used.
func (p *MessageProcessor) SetExpirationValidator(v *ExpirationValidator) {
	if v != nil {
		p.mu.Lock()
		defer p.mu.Unlock()
		p.expirationValidator = v
	}
}

// DisableExpirationCheck disables expiration validation in the processor.
// Useful for testing or special processing scenarios.
func (p *MessageProcessor) DisableExpirationCheck() {
	if p.expirationValidator != nil {
		p.expirationValidator.Disable()
	}
}

// EnableExpirationCheck enables expiration validation in the processor.
func (p *MessageProcessor) EnableExpirationCheck() {
	if p.expirationValidator != nil {
		p.expirationValidator.Enable()
	}
}

// setField is a helper that acquires the lock, logs the operation, calls assignFn,
// and releases the lock. All 15 Set* methods use this pattern.
func (p *MessageProcessor) setField(methodName string, assignFn func()) {
	p.mu.Lock()
	defer p.mu.Unlock()
	log.WithField("at", methodName).Debug("Setting field via " + methodName)
	assignFn()
}

// ProcessMessage processes any I2NP message using interfaces.
// Messages are first validated for expiration before processing.
// Expired messages are rejected with ErrI2NPMessageExpired.
//
// The lock is acquired only to snapshot handler references and validate
// expiration, then released before dispatching. This avoids a deadlock
// when processing garlic messages with LOCAL delivery cloves, which
// recursively call ProcessMessage (RLock is not re-entrant when a
// concurrent writer is waiting).
func (p *MessageProcessor) ProcessMessage(msg Message) error {
	// Snapshot the expiration validator under the read lock, then release.
	// The process* methods read handler fields that are only mutated by
	// Set* methods during initialization, so they are safe to access
	// without holding the lock after the snapshot.
	p.mu.RLock()
	ev := p.expirationValidator
	p.mu.RUnlock()

	log.WithFields(logger.Fields{
		"at":           "ProcessMessage",
		"message_type": msg.Type(),
	}).Debug("Processing I2NP message")

	// Validate message expiration before processing
	if ev != nil {
		if err := ev.ValidateMessage(msg); err != nil {
			return err
		}
	}

	// H-NEW-4 FIX: replay-cache check. Drop messages whose ID was already
	// processed within the validity window; mark new IDs before dispatching.
	// This prevents DatabaseStore reply-token amplification, build-reply state
	// corruption, and spurious delivery-status callbacks from replayed messages.
	if p.replayCache != nil {
		id := msg.MessageID()
		if p.replayCache.Seen(id) {
			log.WithFields(logger.Fields{
				"at":           "ProcessMessage",
				"message_type": msg.Type(),
				"message_id":   id,
			}).Debug("dropping replayed I2NP message")
			return nil
		}
		p.replayCache.Mark(id)
	}

	// Dispatch without holding the lock so that garlic LOCAL delivery
	// cloves can safely re-enter ProcessMessage.
	return p.processMessageDispatch(msg)
}

// processMessageDispatch routes a message to the appropriate handler.
// It must be called without p.mu held to allow safe re-entrant calls
// from garlic LOCAL delivery (handleLocalDelivery → ProcessMessage).
func (p *MessageProcessor) processMessageDispatch(msg Message) error {
	switch msg.Type() {
	case I2NPMessageTypeData:
		return p.processDataMessage(msg)
	case I2NPMessageTypeDatabaseStore:
		return p.processDatabaseStoreMessage(msg)
	case I2NPMessageTypeDeliveryStatus:
		return p.processDeliveryStatusMessage(msg)
	case I2NPMessageTypeDatabaseLookup:
		return p.processDatabaseLookupMessage(msg)
	case I2NPMessageTypeDatabaseSearchReply:
		return p.processDatabaseSearchReplyMessage(msg)
	case I2NPMessageTypeGarlic:
		return p.processGarlicMessage(msg)
	case I2NPMessageTypeTunnelData:
		return p.processTunnelDataMessage(msg)
	case I2NPMessageTypeTunnelGateway:
		return p.processTunnelGatewayMessage(msg)
	case I2NPMessageTypeShortTunnelBuild:
		return p.processShortTunnelBuildMessage(msg)
	case I2NPMessageTypeVariableTunnelBuild:
		return p.processVariableTunnelBuildMessage(msg)
	case I2NPMessageTypeTunnelBuild:
		return p.processTunnelBuildMessage(msg) // Legacy fixed 8-record format (no count prefix)
	case I2NPMessageTypeTunnelBuildReply:
		return p.processTunnelBuildReplyMessage(msg)
	case I2NPMessageTypeVariableTunnelBuildReply:
		return p.processVariableTunnelBuildReplyMessage(msg)
	case I2NPMessageTypeShortTunnelBuildReply:
		return p.processShortTunnelBuildReplyMessage(msg)
	default:
		// Per I2P spec, message types 224-254 are reserved for experimental use.
		// A production router should silently drop unknown types to support
		// protocol extensibility. Return an error only for truly invalid types.
		if msg.Type() >= 224 && msg.Type() <= 254 {
			log.WithFields(logger.Fields{
				"at":           "processMessageDispatch",
				"message_type": msg.Type(),
			}).Debug("Dropping experimental message type (224-254 range)")
			return nil
		}
		log.WithFields(logger.Fields{
			"at":           "processMessageDispatch",
			"message_type": msg.Type(),
			"reason":       "unknown message type",
		}).Error("Cannot process message")
		return oops.Errorf("unknown message type: %d", msg.Type())
	}
}

// processDataMessage processes data messages using PayloadCarrier interface.
// If a DataMessageHandler is configured, the payload is forwarded for delivery.
// Otherwise, the payload is logged and discarded.
