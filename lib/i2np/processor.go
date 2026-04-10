package i2np

import (
	"sync"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/session_key"
	"github.com/go-i2p/go-i2p/lib/tunnel"
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
	ForwardToDestination(destHash common.Hash, msg I2NPMessage) error

	// ForwardToRouter forwards a message directly to a router hash (delivery type 0x02).
	// The forwarder should send the message via the transport layer.
	ForwardToRouter(routerHash common.Hash, msg I2NPMessage) error

	// ForwardThroughTunnel forwards a message through a tunnel to a gateway (delivery type 0x03).
	// The forwarder should wrap the message in a TunnelGateway envelope and send to the gateway.
	ForwardThroughTunnel(gatewayHash common.Hash, tunnelID tunnel.TunnelID, msg I2NPMessage) error
}

// ParticipantManager defines the interface for processing incoming tunnel build requests.
// This interface enables the MessageProcessor to delegate tunnel participation decisions
// to the tunnel.Manager which handles rate limiting and resource protection.
type ParticipantManager interface {
	// ProcessBuildRequest validates a tunnel build request against all limits.
	// Returns whether the request should be accepted, the rejection code if not,
	// and a human-readable reason for logging.
	//
	// Parameters:
	// - sourceHash: The router hash of the requester (from BuildRequestRecord.OurIdent)
	//
	// Returns:
	// - accepted: Whether the request should be accepted
	// - rejectCode: I2P-compliant rejection code if not accepted (0 if accepted)
	// - reason: Human-readable reason for logging (empty if accepted)
	ProcessBuildRequest(sourceHash common.Hash) (accepted bool, rejectCode byte, reason string)

	// RegisterParticipant registers a new participating tunnel after acceptance.
	// This should be called after ProcessBuildRequest returns accepted=true.
	//
	// Parameters:
	// - tunnelID: The tunnel ID for the participating tunnel
	// - sourceHash: The router hash of the requester
	// - expiry: When the tunnel participation expires
	// - layerKey: The layer encryption key from the build request record
	// - ivKey: The IV key from the build request record
	RegisterParticipant(tunnelID tunnel.TunnelID, sourceHash common.Hash, expiry time.Time, layerKey, ivKey session_key.SessionKey) error
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
	ForwardBuildReplyThroughTunnel(gatewayHash common.Hash, tunnelID tunnel.TunnelID, messageID int, encryptedRecords []byte, isShortBuild bool) error
}

// TunnelGatewayHandler defines the interface for handling TunnelGateway messages.
// When a TunnelGateway message arrives, the handler looks up the tunnel by ID,
// encrypts the payload using the tunnel's layered encryption, and forwards the
// resulting TunnelData message to the next hop.
type TunnelGatewayHandler interface {
	// HandleGateway processes an incoming TunnelGateway message by looking up the tunnel,
	// encrypting the payload, and forwarding it to the next hop.
	HandleGateway(tunnelID tunnel.TunnelID, payload []byte) error
}

// TunnelDataHandler defines the interface for handling incoming TunnelData messages.
// When a TunnelData message arrives at our tunnel endpoint, the handler decrypts
// it and delivers the embedded I2NP message to the appropriate I2CP session.
type TunnelDataHandler interface {
	// HandleTunnelData processes an incoming TunnelData message by looking up the
	// tunnel endpoint, decrypting the payload, and delivering it to the owning session.
	HandleTunnelData(msg I2NPMessage) error
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

// TunnelBuildReplyProcessor defines the interface for processing tunnel build reply messages.
// When a tunnel build reply (types 22, 24, 26) arrives, the processor correlates it with
// the original build request and updates tunnel state accordingly.
type TunnelBuildReplyProcessor interface {
	// ProcessTunnelBuildReply handles a parsed tunnel build reply.
	// handler provides the reply records, messageID correlates with the original request.
	ProcessTunnelBuildReply(handler TunnelReplyHandler, messageID int) error
}

// GarlicMessageDecryptor provides garlic message decryption for the processor.
// This interface is satisfied by both GarlicSessionManager (the concrete adapter)
// and test mocks.
type GarlicMessageDecryptor interface {
	// DecryptGarlicMessage decrypts an encrypted garlic message.
	// Returns plaintext, session tag, session hash (non-nil for New Session), and error.
	DecryptGarlicMessage(encrypted []byte) (plaintext []byte, sessionTag [8]byte, sessionHash *[32]byte, err error)
}

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

// MessageProcessor demonstrates interface-based message processing
type MessageProcessor struct {
	mu                    sync.RWMutex
	factory               *I2NPMessageFactory
	garlicSessions        GarlicMessageDecryptor    // Interface for garlic message decryption
	cloveForwarder        GarlicCloveForwarder      // Optional delegate for non-LOCAL garlic clove delivery
	dbManager             *DatabaseManager          // Optional database manager for DatabaseLookup messages
	expirationValidator   *ExpirationValidator      // Validator for checking message expiration
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
	garlicRecursionDepth  int32                     // Atomic counter for garlic nesting depth
}

// NewMessageProcessor creates a new message processor
func NewMessageProcessor() *MessageProcessor {
	log.WithField("at", "NewMessageProcessor").Debug("Creating new message processor")
	crypto := NewBuildRecordCrypto()
	return &MessageProcessor{
		factory:               NewI2NPMessageFactory(),
		expirationValidator:   NewExpirationValidator(),
		buildRecordCrypto:     crypto,
		buildRequestDecryptor: crypto,
	}
}

// SetGarlicSessionManager sets the garlic session manager for decrypting garlic messages.
// This must be called before processing garlic messages, otherwise they will fail with an error.
// Accepts any implementation of GarlicMessageDecryptor, including *GarlicSessionManager and test mocks.
func (p *MessageProcessor) SetGarlicSessionManager(garlicMgr GarlicMessageDecryptor) {
	p.mu.Lock()
	defer p.mu.Unlock()
	log.WithField("at", "SetGarlicSessionManager").Debug("Setting garlic session manager")
	p.garlicSessions = garlicMgr
}

// SetBuildRecordCrypto sets the build record crypto handler for encrypting build response records.
// Accepts any implementation of ReplyRecordEncryptor, including *BuildRecordCrypto and test mocks.
func (p *MessageProcessor) SetBuildRecordCrypto(crypto ReplyRecordEncryptor) {
	p.mu.Lock()
	defer p.mu.Unlock()
	log.WithField("at", "SetBuildRecordCrypto").Debug("Setting build record crypto")
	p.buildRecordCrypto = crypto
}

// SetCloveForwarder sets the garlic clove forwarder for handling non-LOCAL delivery types.
// This is optional - if not set, only LOCAL delivery (0x00) will be processed.
// The forwarder enables DESTINATION (0x01), ROUTER (0x02), and TUNNEL (0x03) deliveries.
func (p *MessageProcessor) SetCloveForwarder(forwarder GarlicCloveForwarder) {
	p.mu.Lock()
	defer p.mu.Unlock()
	log.WithField("at", "SetCloveForwarder").Debug("Setting garlic clove forwarder")
	p.cloveForwarder = forwarder
}

// SetDatabaseManager sets the database manager for processing DatabaseLookup messages.
// This must be called before processing DatabaseLookup messages, otherwise they will fail with an error.
func (p *MessageProcessor) SetDatabaseManager(dbMgr *DatabaseManager) {
	p.mu.Lock()
	defer p.mu.Unlock()
	log.WithField("at", "SetDatabaseManager").Debug("Setting database manager")
	p.dbManager = dbMgr
}

// SetParticipantManager sets the participant manager for processing incoming tunnel build requests.
// This enables the router to participate in tunnels built by other routers.
// If not set, tunnel build requests will be rejected with an error.
func (p *MessageProcessor) SetParticipantManager(pm ParticipantManager) {
	p.mu.Lock()
	defer p.mu.Unlock()
	log.WithField("at", "SetParticipantManager").Debug("Setting participant manager")
	p.participantManager = pm
}

// SetBuildReplyForwarder sets the forwarder for sending tunnel build replies to the next hop.
// This enables the router to participate in tunnel building by forwarding replies.
// If not set, build requests will be processed but replies will not be sent (logged only).
func (p *MessageProcessor) SetBuildReplyForwarder(forwarder BuildReplyForwarder) {
	p.mu.Lock()
	defer p.mu.Unlock()
	log.WithField("at", "SetBuildReplyForwarder").Debug("Setting build reply forwarder")
	p.buildReplyForwarder = forwarder
}

// SetTunnelGatewayHandler sets the handler for processing TunnelGateway messages.
// When set, incoming TunnelGateway messages will be delegated to this handler for
// tunnel lookup, encryption, and forwarding. If not set, TunnelGateway messages
// will be validated but not forwarded.
func (p *MessageProcessor) SetTunnelGatewayHandler(handler TunnelGatewayHandler) {
	p.mu.Lock()
	defer p.mu.Unlock()
	log.WithField("at", "SetTunnelGatewayHandler").Debug("Setting tunnel gateway handler")
	p.tunnelGatewayHandler = handler
}

// SetTunnelDataHandler sets the handler for processing inbound TunnelData messages.
// When set, incoming TunnelData messages will be delegated to this handler for
// tunnel endpoint decryption and I2CP session delivery. If not set, TunnelData
// messages will be validated but not delivered to any session.
func (p *MessageProcessor) SetTunnelDataHandler(handler TunnelDataHandler) {
	p.mu.Lock()
	defer p.mu.Unlock()
	log.WithField("at", "SetTunnelDataHandler").Debug("Setting tunnel data handler")
	p.tunnelDataHandler = handler
}

// SetSearchReplyHandler sets the handler for delivering DatabaseSearchReply suggestions
// to pending iterative Kademlia lookups. When set, peer suggestions from search replies
// are forwarded to this handler for follow-up queries.
func (p *MessageProcessor) SetSearchReplyHandler(handler SearchReplyHandler) {
	p.mu.Lock()
	defer p.mu.Unlock()
	log.WithField("at", "SetSearchReplyHandler").Debug("Setting search reply handler")
	p.searchReplyHandler = handler
}

// SetDataMessageHandler sets the handler for processing incoming Data message payloads.
// When set, Data message payloads are forwarded to this handler for delivery to the
// appropriate I2CP session. If not set, Data messages are logged but discarded.
func (p *MessageProcessor) SetDataMessageHandler(handler DataMessageHandler) {
	p.mu.Lock()
	defer p.mu.Unlock()
	log.WithField("at", "SetDataMessageHandler").Debug("Setting data message handler")
	p.dataMessageHandler = handler
}

// SetDeliveryStatusHandler sets the handler for processing delivery status confirmations.
// When set, delivery status notifications are forwarded to this handler to confirm
// message delivery. If not set, DeliveryStatus messages are logged but discarded.
func (p *MessageProcessor) SetDeliveryStatusHandler(handler DeliveryStatusHandler) {
	p.mu.Lock()
	defer p.mu.Unlock()
	log.WithField("at", "SetDeliveryStatusHandler").Debug("Setting delivery status handler")
	p.deliveryStatusHandler = handler
}

// SetBuildReplyProcessor sets the processor for handling incoming tunnel build reply messages.
// When set, tunnel build reply message types (22, 24, 26) are dispatched to this processor
// which correlates them with pending build requests and updates tunnel state.
// If not set, tunnel build replies are logged and discarded.
func (p *MessageProcessor) SetBuildReplyProcessor(processor TunnelBuildReplyProcessor) {
	p.mu.Lock()
	defer p.mu.Unlock()
	log.WithField("at", "SetBuildReplyProcessor").Debug("Setting tunnel build reply processor")
	p.buildReplyProcessor = processor
}

// SetOurRouterHash sets our router's identity hash so that processAllBuildRecords
// can skip records not destined for this router.
func (p *MessageProcessor) SetOurRouterHash(hash common.Hash) {
	p.mu.Lock()
	defer p.mu.Unlock()
	log.WithField("at", "SetOurRouterHash").Debug("Setting our router hash for build record filtering")
	p.ourRouterHash = hash
}

// SetBuildRequestDecryptor sets the decryptor used to decrypt inbound build request
// records that are destined for this router. If not set, encrypted records will be
// attempted as cleartext (testing mode only).
func (p *MessageProcessor) SetBuildRequestDecryptor(dec BuildRequestDecryptor) {
	p.mu.Lock()
	defer p.mu.Unlock()
	log.WithField("at", "SetBuildRequestDecryptor").Debug("Setting build request decryptor")
	p.buildRequestDecryptor = dec
}

// SetOurPrivateKey sets the router's static X25519 private key used for
// decrypting inbound build request records.
func (p *MessageProcessor) SetOurPrivateKey(key []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	log.WithField("at", "SetOurPrivateKey").Debug("Setting our private key for build record decryption")
	p.ourPrivateKey = make([]byte, len(key))
	copy(p.ourPrivateKey, key)
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

// ProcessMessage processes any I2NP message using interfaces.
// Messages are first validated for expiration before processing.
// Expired messages are rejected with ErrI2NPMessageExpired.
//
// The lock is acquired only to snapshot handler references and validate
// expiration, then released before dispatching. This avoids a deadlock
// when processing garlic messages with LOCAL delivery cloves, which
// recursively call ProcessMessage (RLock is not re-entrant when a
// concurrent writer is waiting).
func (p *MessageProcessor) ProcessMessage(msg I2NPMessage) error {
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

	// Dispatch without holding the lock so that garlic LOCAL delivery
	// cloves can safely re-enter ProcessMessage.
	return p.processMessageDispatch(msg)
}

// processMessageDispatch routes a message to the appropriate handler.
// It must be called without p.mu held to allow safe re-entrant calls
// from garlic LOCAL delivery (handleLocalDelivery → ProcessMessage).
func (p *MessageProcessor) processMessageDispatch(msg I2NPMessage) error {
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
