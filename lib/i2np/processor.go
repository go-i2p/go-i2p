package i2np

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/session_key"
	"github.com/go-i2p/crypto/rand"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/go-i2p/logger"
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
	ourRouterHash         common.Hash               // Our router identity hash for filtering build records
	garlicRecursionDepth  int32                     // Atomic counter for garlic nesting depth
}

// NewMessageProcessor creates a new message processor
func NewMessageProcessor() *MessageProcessor {
	log.WithField("at", "NewMessageProcessor").Debug("Creating new message processor")
	return &MessageProcessor{
		factory:             NewI2NPMessageFactory(),
		expirationValidator: NewExpirationValidator(),
		buildRecordCrypto:   NewBuildRecordCrypto(),
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
// Expired messages are rejected with ERR_I2NP_MESSAGE_EXPIRED.
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
	case I2NP_MESSAGE_TYPE_DATA:
		return p.processDataMessage(msg)
	case I2NP_MESSAGE_TYPE_DATABASE_STORE:
		return p.processDatabaseStoreMessage(msg)
	case I2NP_MESSAGE_TYPE_DELIVERY_STATUS:
		return p.processDeliveryStatusMessage(msg)
	case I2NP_MESSAGE_TYPE_DATABASE_LOOKUP:
		return p.processDatabaseLookupMessage(msg)
	case I2NP_MESSAGE_TYPE_DATABASE_SEARCH_REPLY:
		return p.processDatabaseSearchReplyMessage(msg)
	case I2NP_MESSAGE_TYPE_GARLIC:
		return p.processGarlicMessage(msg)
	case I2NP_MESSAGE_TYPE_TUNNEL_DATA:
		return p.processTunnelDataMessage(msg)
	case I2NP_MESSAGE_TYPE_TUNNEL_GATEWAY:
		return p.processTunnelGatewayMessage(msg)
	case I2NP_MESSAGE_TYPE_SHORT_TUNNEL_BUILD:
		return p.processShortTunnelBuildMessage(msg)
	case I2NP_MESSAGE_TYPE_VARIABLE_TUNNEL_BUILD:
		return p.processVariableTunnelBuildMessage(msg)
	case I2NP_MESSAGE_TYPE_TUNNEL_BUILD:
		return p.processTunnelBuildMessage(msg) // Legacy fixed 8-record format (no count prefix)
	case I2NP_MESSAGE_TYPE_TUNNEL_BUILD_REPLY:
		return p.processTunnelBuildReplyMessage(msg)
	case I2NP_MESSAGE_TYPE_VARIABLE_TUNNEL_BUILD_REPLY:
		return p.processVariableTunnelBuildReplyMessage(msg)
	case I2NP_MESSAGE_TYPE_SHORT_TUNNEL_BUILD_REPLY:
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
		return fmt.Errorf("unknown message type: %d", msg.Type())
	}
}

// processDataMessage processes data messages using PayloadCarrier interface.
// If a DataMessageHandler is configured, the payload is forwarded for delivery.
// Otherwise, the payload is logged and discarded.
func (p *MessageProcessor) processDataMessage(msg I2NPMessage) error {
	payloadCarrier, ok := msg.(PayloadCarrier)
	if !ok {
		return fmt.Errorf("message does not implement PayloadCarrier interface")
	}

	payload := payloadCarrier.GetPayload()
	log.WithField("payload_size", len(payload)).Debug("Processing data message")

	if p.dataMessageHandler != nil {
		return p.dataMessageHandler.HandleDataMessage(payload)
	}

	log.WithFields(logger.Fields{
		"at":           "processDataMessage",
		"payload_size": len(payload),
		"reason":       "no handler configured",
	}).Warn("Data message payload discarded - no DataMessageHandler set")
	return nil
}

// processDatabaseStoreMessage processes DatabaseStore messages received from floodfills or peers.
// DatabaseStore messages contain RouterInfo or LeaseSet data that should be stored in our NetDB.
func (p *MessageProcessor) processDatabaseStoreMessage(msg I2NPMessage) error {
	if p.dbManager == nil {
		log.WithFields(logger.Fields{
			"at":     "processDatabaseStoreMessage",
			"reason": "no_database_manager",
		}).Warn("DatabaseStore received but no database manager configured")
		return fmt.Errorf("database manager not configured")
	}

	// Type assert to *DatabaseStore
	dbStore, ok := msg.(*DatabaseStore)
	if !ok {
		log.WithFields(logger.Fields{
			"at":     "processDatabaseStoreMessage",
			"reason": "type_assertion_failed",
		}).Error("Message is not a DatabaseStore")
		return fmt.Errorf("message is not a DatabaseStore")
	}

	key := dbStore.GetStoreKey()
	storeType := dbStore.GetStoreType()
	data := dbStore.GetStoreData()

	log.WithFields(logger.Fields{
		"at":         "processDatabaseStoreMessage",
		"key":        fmt.Sprintf("%x", key[:8]),
		"store_type": storeType,
		"data_size":  len(data),
	}).Debug("Processing DatabaseStore message")

	// Store in NetDB — dispatched by type to appropriate handler
	if err := p.dbManager.netdb.Store(key, data, storeType); err != nil {
		log.WithFields(logger.Fields{
			"at":     "processDatabaseStoreMessage",
			"reason": "store_failed",
			"key":    fmt.Sprintf("%x", key[:8]),
		}).WithError(err).Error("Failed to store data in NetDB")
		return fmt.Errorf("failed to store in NetDB: %w", err)
	}

	log.WithFields(logger.Fields{
		"at":         "processDatabaseStoreMessage",
		"key":        fmt.Sprintf("%x", key[:8]),
		"store_type": storeType,
	}).Debug("Successfully stored data in NetDB")

	return nil
}

// processDatabaseSearchReplyMessage processes DatabaseSearchReply messages from peers.
// These messages contain peer hash suggestions when a lookup fails to find the exact key.
// The suggested peers are delivered to the search reply handler for iterative lookup follow-up.
func (p *MessageProcessor) processDatabaseSearchReplyMessage(msg I2NPMessage) error {
	// Type assert to *DatabaseSearchReply
	searchReply, ok := msg.(*DatabaseSearchReply)
	if !ok {
		log.WithFields(logger.Fields{
			"at":     "processDatabaseSearchReplyMessage",
			"reason": "type_assertion_failed",
		}).Error("Message is not a DatabaseSearchReply")
		return fmt.Errorf("message is not a DatabaseSearchReply")
	}

	log.WithFields(logger.Fields{
		"at":          "processDatabaseSearchReplyMessage",
		"key":         fmt.Sprintf("%x", searchReply.Key[:8]),
		"from":        fmt.Sprintf("%x", searchReply.From[:8]),
		"peer_count":  searchReply.Count,
		"peer_hashes": len(searchReply.PeerHashes),
	}).Debug("Processing DatabaseSearchReply message")

	// Deliver suggestions to the search reply handler for iterative Kademlia lookup
	if p.searchReplyHandler != nil && len(searchReply.PeerHashes) > 0 {
		p.searchReplyHandler.HandleSearchReply(searchReply.Key, searchReply.PeerHashes)
		log.WithFields(logger.Fields{
			"at":          "processDatabaseSearchReplyMessage",
			"key":         fmt.Sprintf("%x", searchReply.Key[:8]),
			"suggestions": len(searchReply.PeerHashes),
		}).Debug("Delivered search reply suggestions to handler")
	} else {
		// Log peer suggestions for debugging when no handler is set
		for i, peerHash := range searchReply.PeerHashes {
			log.WithFields(logger.Fields{
				"at":        "processDatabaseSearchReplyMessage",
				"peer_idx":  i,
				"peer_hash": fmt.Sprintf("%x", peerHash[:8]),
			}).Debug("Suggested peer from search reply (no handler configured)")
		}
	}

	return nil
}

// processTunnelGatewayMessage processes TunnelGateway messages.
// These messages wrap I2NP messages destined for delivery through a tunnel.
// The gateway extracts the inner message and forwards it into the tunnel.
func (p *MessageProcessor) processTunnelGatewayMessage(msg I2NPMessage) error {
	// Type assert to *TunnelGateway
	tgMsg, ok := msg.(*TunnelGateway)
	if !ok {
		log.WithFields(logger.Fields{
			"at":     "processTunnelGatewayMessage",
			"reason": "type_assertion_failed",
		}).Error("Message is not a TunnelGateway")
		return fmt.Errorf("message is not a TunnelGateway")
	}

	log.WithFields(logger.Fields{
		"at":           "processTunnelGatewayMessage",
		"tunnel_id":    tgMsg.TunnelID,
		"payload_size": tgMsg.Length,
	}).Debug("Processing TunnelGateway message")

	if tgMsg.Length == 0 || len(tgMsg.Data) == 0 {
		log.WithFields(logger.Fields{
			"at":        "processTunnelGatewayMessage",
			"tunnel_id": tgMsg.TunnelID,
			"reason":    "empty_payload",
		}).Warn("TunnelGateway message has empty payload")
		return fmt.Errorf("TunnelGateway message has empty payload")
	}

	// Delegate to the tunnel gateway handler if one is configured.
	// The handler is responsible for looking up the tunnel, encrypting
	// the payload with layered encryption, and forwarding to the next hop.
	if p.tunnelGatewayHandler != nil {
		if err := p.tunnelGatewayHandler.HandleGateway(tgMsg.TunnelID, tgMsg.Data); err != nil {
			log.WithFields(logger.Fields{
				"at":        "processTunnelGatewayMessage",
				"tunnel_id": tgMsg.TunnelID,
				"error":     err,
			}).Error("Failed to handle TunnelGateway message")
			return fmt.Errorf("tunnel gateway handling failed: %w", err)
		}
		return nil
	}

	log.WithFields(logger.Fields{
		"at":        "processTunnelGatewayMessage",
		"tunnel_id": tgMsg.TunnelID,
		"reason":    "no tunnel gateway handler configured",
	}).Warn("TunnelGateway message received but no handler configured")
	return fmt.Errorf("no tunnel gateway handler configured")
}

// processDeliveryStatusMessage processes delivery status messages using StatusReporter interface.
// If a DeliveryStatusHandler is configured, the status is forwarded to confirm delivery.
// Otherwise, the status is logged and discarded.
func (p *MessageProcessor) processDeliveryStatusMessage(msg I2NPMessage) error {
	statusReporter, ok := msg.(StatusReporter)
	if !ok {
		return fmt.Errorf("message does not implement StatusReporter interface")
	}

	msgID := statusReporter.GetStatusMessageID()
	timestamp := statusReporter.GetTimestamp()
	log.WithFields(logger.Fields{
		"message_id": msgID,
		"timestamp":  timestamp,
	}).Debug("Processing delivery status")

	if p.deliveryStatusHandler != nil {
		return p.deliveryStatusHandler.HandleDeliveryStatus(msgID, timestamp)
	}

	log.WithFields(logger.Fields{
		"at":         "processDeliveryStatusMessage",
		"message_id": msgID,
		"reason":     "no handler configured",
	}).Warn("Delivery status discarded - no DeliveryStatusHandler set")
	return nil
}

// processDatabaseLookupMessage processes database lookup messages using DatabaseReader interface
func (p *MessageProcessor) processDatabaseLookupMessage(msg I2NPMessage) error {
	if p.dbManager == nil {
		return fmt.Errorf("database manager not configured")
	}

	if reader, ok := msg.(DatabaseReader); ok {
		key := reader.GetKey()
		from := reader.GetFrom()
		log.WithFields(logger.Fields{
			"key":  fmt.Sprintf("%x", key[:8]),
			"from": fmt.Sprintf("%x", from[:8]),
		}).Debug("Processing database lookup")
		return p.dbManager.PerformLookup(reader)
	}
	return fmt.Errorf("message does not implement DatabaseReader interface")
}

// processGarlicMessage processes encrypted garlic messages by decrypting them
// and routing the contained cloves based on their delivery instructions.
//
// Process:
// 1. Extract encrypted garlic data from the message
// 2. Decrypt using GarlicSessionManager (handles ECIES-X25519-AEAD-Ratchet)
// 3. Parse decrypted data into Garlic structure with cloves
// 4. For each clove, route based on delivery type:
//   - LOCAL (0x00): Process wrapped message locally via ProcessMessage()
//   - DESTINATION/ROUTER/TUNNEL: Require router-level forwarding (not implemented here)
//
// Note: This processor handles LOCAL delivery only. Other delivery types require
// router context and would be implemented at the router layer.
func (p *MessageProcessor) processGarlicMessage(msg I2NPMessage) error {
	if err := p.validateGarlicSession(); err != nil {
		return err
	}

	encryptedData, err := p.extractGarlicData(msg)
	if err != nil {
		return err
	}

	decryptedData, sessionTag, err := p.decryptGarlicData(msg.MessageID(), encryptedData)
	if err != nil {
		return err
	}

	garlic, err := p.parseAndLogGarlic(msg.MessageID(), decryptedData, sessionTag)
	if err != nil {
		return err
	}

	p.processGarlicCloves(garlic.Cloves)
	return nil
}

// validateGarlicSession verifies that the garlic session manager is configured.
func (p *MessageProcessor) validateGarlicSession() error {
	if p.garlicSessions == nil {
		return fmt.Errorf("garlic session manager not configured - cannot decrypt garlic messages")
	}
	return nil
}

// extractGarlicData extracts encrypted data from the garlic message.
func (p *MessageProcessor) extractGarlicData(msg I2NPMessage) ([]byte, error) {
	carrier, ok := msg.(DataCarrier)
	if !ok {
		return nil, fmt.Errorf("garlic message does not implement DataCarrier")
	}

	encryptedData := carrier.GetData()
	if len(encryptedData) == 0 {
		return nil, fmt.Errorf("garlic message contains no data")
	}

	return encryptedData, nil
}

// decryptGarlicData decrypts the garlic message using the session manager.
func (p *MessageProcessor) decryptGarlicData(msgID int, encryptedData []byte) ([]byte, [8]byte, error) {
	log.WithFields(logger.Fields{
		"msg_id":         msgID,
		"encrypted_size": len(encryptedData),
	}).Debug("Decrypting garlic message")

	decryptedData, sessionTag, _, err := p.garlicSessions.DecryptGarlicMessage(encryptedData)
	if err != nil {
		return nil, [8]byte{}, fmt.Errorf("failed to decrypt garlic message: %w", err)
	}

	log.WithFields(logger.Fields{
		"msg_id":         msgID,
		"decrypted_size": len(decryptedData),
		"session_tag":    fmt.Sprintf("%x", sessionTag[:8]),
	}).Debug("Garlic message decrypted successfully")

	return decryptedData, sessionTag, nil
}

// parseAndLogGarlic parses the decrypted garlic structure and logs the result.
// Uses DeserializeGarlic from garlic_builder.go as the single canonical parser
// to avoid duplicate parsing logic and ensure consistent validation.
func (p *MessageProcessor) parseAndLogGarlic(msgID int, decryptedData []byte, sessionTag [8]byte) (*Garlic, error) {
	garlic, err := DeserializeGarlic(decryptedData, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to parse decrypted garlic structure: %w", err)
	}

	log.WithFields(logger.Fields{
		"msg_id":      msgID,
		"clove_count": len(garlic.Cloves),
	}).Debug("Processing garlic cloves")

	return garlic, nil
}

// processGarlicCloves processes each clove in the garlic message.
func (p *MessageProcessor) processGarlicCloves(cloves []GarlicClove) {
	for i, clove := range cloves {
		p.processSingleClove(i, clove)
	}
}

// processSingleClove processes a single garlic clove based on its delivery type.
func (p *MessageProcessor) processSingleClove(index int, clove GarlicClove) {
	deliveryType := (clove.DeliveryInstructions.Flag >> 5) & 0x03

	log.WithFields(logger.Fields{
		"clove_index":   index,
		"clove_id":      clove.CloveID,
		"delivery_type": deliveryType,
		"wrapped_type":  clove.I2NPMessage.Type(),
	}).Debug("Processing garlic clove")

	if clove.I2NPMessage == nil {
		log.WithField("clove_index", index).Warn("Garlic clove contains nil I2NP message")
		return
	}

	p.routeCloveByType(index, deliveryType, clove)
}

// routeCloveByType routes a clove to its destination based on delivery type.
func (p *MessageProcessor) routeCloveByType(index int, deliveryType byte, clove GarlicClove) {
	switch deliveryType {
	case 0x00:
		p.handleLocalDelivery(index, clove)
	case 0x01:
		p.handleDestinationDelivery(index, clove)
	case 0x02:
		p.handleRouterDelivery(index, clove)
	case 0x03:
		p.handleTunnelDelivery(index, clove)
	}
}

// handleLocalDelivery processes a LOCAL delivery clove.
// Guards against infinite recursion from nested garlic messages by tracking depth.
func (p *MessageProcessor) handleLocalDelivery(index int, clove GarlicClove) {
	const maxGarlicNestingDepth = 4
	depth := atomic.AddInt32(&p.garlicRecursionDepth, 1)
	defer atomic.AddInt32(&p.garlicRecursionDepth, -1)

	if depth > maxGarlicNestingDepth {
		log.WithFields(logger.Fields{
			"clove_index":   index,
			"nesting_depth": depth,
			"max_depth":     maxGarlicNestingDepth,
		}).Error("Garlic nesting depth exceeded, dropping clove to prevent recursion bomb")
		return
	}

	if err := p.ProcessMessage(clove.I2NPMessage); err != nil {
		log.WithFields(logger.Fields{
			"clove_index": index,
			"error":       err,
		}).Error("Failed to process LOCAL clove message")
		return
	}
	log.WithField("clove_index", index).Debug("Successfully processed LOCAL clove")
}

// handleDestinationDelivery forwards a clove to a destination hash.
func (p *MessageProcessor) handleDestinationDelivery(index int, clove GarlicClove) {
	if p.cloveForwarder == nil {
		log.WithFields(logger.Fields{
			"clove_index": index,
			"dest_hash":   fmt.Sprintf("%x", clove.DeliveryInstructions.Hash[:8]),
		}).Warn("DESTINATION delivery requires clove forwarder")
		return
	}

	err := p.cloveForwarder.ForwardToDestination(
		clove.DeliveryInstructions.Hash,
		clove.I2NPMessage,
	)
	if err != nil {
		log.WithFields(logger.Fields{
			"clove_index": index,
			"dest_hash":   fmt.Sprintf("%x", clove.DeliveryInstructions.Hash[:8]),
			"error":       err,
		}).Error("Failed to forward clove to destination")
		return
	}

	log.WithFields(logger.Fields{
		"clove_index": index,
		"dest_hash":   fmt.Sprintf("%x", clove.DeliveryInstructions.Hash[:8]),
	}).Debug("Successfully forwarded clove to destination")
}

// handleRouterDelivery forwards a clove to a router hash.
func (p *MessageProcessor) handleRouterDelivery(index int, clove GarlicClove) {
	if p.cloveForwarder == nil {
		log.WithFields(logger.Fields{
			"clove_index": index,
			"router_hash": fmt.Sprintf("%x", clove.DeliveryInstructions.Hash[:8]),
		}).Warn("ROUTER delivery requires clove forwarder")
		return
	}

	err := p.cloveForwarder.ForwardToRouter(
		clove.DeliveryInstructions.Hash,
		clove.I2NPMessage,
	)
	if err != nil {
		log.WithFields(logger.Fields{
			"clove_index": index,
			"router_hash": fmt.Sprintf("%x", clove.DeliveryInstructions.Hash[:8]),
			"error":       err,
		}).Error("Failed to forward clove to router")
		return
	}

	log.WithFields(logger.Fields{
		"clove_index": index,
		"router_hash": fmt.Sprintf("%x", clove.DeliveryInstructions.Hash[:8]),
	}).Debug("Successfully forwarded clove to router")
}

// handleTunnelDelivery forwards a clove through a tunnel.
func (p *MessageProcessor) handleTunnelDelivery(index int, clove GarlicClove) {
	if p.cloveForwarder == nil {
		log.WithFields(logger.Fields{
			"clove_index":  index,
			"gateway_hash": fmt.Sprintf("%x", clove.DeliveryInstructions.Hash[:8]),
			"tunnel_id":    clove.DeliveryInstructions.TunnelID,
		}).Warn("TUNNEL delivery requires clove forwarder")
		return
	}

	err := p.cloveForwarder.ForwardThroughTunnel(
		clove.DeliveryInstructions.Hash,
		clove.DeliveryInstructions.TunnelID,
		clove.I2NPMessage,
	)
	if err != nil {
		log.WithFields(logger.Fields{
			"clove_index":  index,
			"gateway_hash": fmt.Sprintf("%x", clove.DeliveryInstructions.Hash[:8]),
			"tunnel_id":    clove.DeliveryInstructions.TunnelID,
			"error":        err,
		}).Error("Failed to forward clove through tunnel")
		return
	}

	log.WithFields(logger.Fields{
		"clove_index":  index,
		"gateway_hash": fmt.Sprintf("%x", clove.DeliveryInstructions.Hash[:8]),
		"tunnel_id":    clove.DeliveryInstructions.TunnelID,
	}).Debug("Successfully forwarded clove through tunnel")
}

// processTunnelDataMessage processes tunnel data messages using TunnelCarrier interface.
// If a TunnelDataHandler is configured, the message is delegated for endpoint decryption
// and delivery to the owning I2CP session. Otherwise the message is validated and logged.
func (p *MessageProcessor) processTunnelDataMessage(msg I2NPMessage) error {
	if _, ok := msg.(TunnelCarrier); !ok {
		return fmt.Errorf("message does not implement TunnelCarrier interface")
	}

	// Delegate to handler if available
	if p.tunnelDataHandler != nil {
		log.WithField("at", "processTunnelDataMessage").Debug("Delegating TunnelData to handler")
		return p.tunnelDataHandler.HandleTunnelData(msg)
	}

	// No handler configured — validate only
	tunnelCarrier := msg.(TunnelCarrier)
	data := tunnelCarrier.GetTunnelData()
	log.WithFields(logger.Fields{
		"at":        "processTunnelDataMessage",
		"data_size": len(data),
		"reason":    "no tunnel data handler configured",
	}).Debug("TunnelData message validated but not delivered")
	return nil
}

// processShortTunnelBuildMessage processes Short Tunnel Build Messages (STBM).
// This handles incoming requests from other routers asking us to participate in their tunnels.
//
// Process:
// 1. Extract and parse the build request records from the message
// 2. Find the record intended for this router (by matching our identity hash)
// 3. Validate the request against resource limits using ParticipantManager
// 4. Accept or reject based on available capacity and rate limits
// 5. Generate and send appropriate build reply
func (p *MessageProcessor) processShortTunnelBuildMessage(msg I2NPMessage) error {
	return p.processTunnelBuildRequest(msg, true)
}

// processVariableTunnelBuildMessage processes Variable Tunnel Build Messages (legacy format).
// This handles incoming requests using the older VTB format for backward compatibility.
func (p *MessageProcessor) processVariableTunnelBuildMessage(msg I2NPMessage) error {
	return p.processTunnelBuildRequest(msg, false)
}

// processTunnelBuildMessage processes TunnelBuild (type 21) messages.
// TunnelBuild has a fixed format: exactly 8 records × 528 bytes = 4224 bytes,
// with NO count prefix byte (unlike VariableTunnelBuild type 23).
func (p *MessageProcessor) processTunnelBuildMessage(msg I2NPMessage) error {
	return p.processFixedTunnelBuildRequest(msg)
}

// processFixedTunnelBuildRequest handles TunnelBuild (type 21) messages with
// fixed 8-record format. Unlike VTB/STBM, type 21 has no count prefix byte.
func (p *MessageProcessor) processFixedTunnelBuildRequest(msg I2NPMessage) error {
	if err := p.validateParticipantManager(false, msg.Type()); err != nil {
		return err
	}

	data, err := p.extractBuildMessageData(msg)
	if err != nil {
		return err
	}

	records, err := p.parseFixedTunnelBuildRecords(data)
	if err != nil {
		return fmt.Errorf("failed to parse fixed tunnel build records: %w", err)
	}

	p.logParsedBuildRequest(msg.MessageID(), len(records), false)
	return p.processAllBuildRecords(msg.MessageID(), records, false)
}

// parseFixedTunnelBuildRecords parses TunnelBuild (type 21) records.
// Type 21 has exactly 8 records at 528 bytes each with no count prefix byte.
func (p *MessageProcessor) parseFixedTunnelBuildRecords(data []byte) ([]BuildRequestRecord, error) {
	const fixedRecordCount = 8
	const recordSize = 528                             // VTB record size
	const expectedSize = fixedRecordCount * recordSize // 4224 bytes

	if len(data) < expectedSize {
		return nil, fmt.Errorf("insufficient data for TunnelBuild: have %d, need %d", len(data), expectedSize)
	}

	records := make([]BuildRequestRecord, 0, fixedRecordCount)
	offset := 0 // No count prefix byte for type 21

	for i := 0; i < fixedRecordCount; i++ {
		recordData := data[offset : offset+recordSize]
		p.tryParseAndAppendRecord(&records, recordData, i, false)
		offset += recordSize
	}

	return records, nil
}

// processTunnelBuildReplyMessage processes TunnelBuildReply (type 22) messages.
// The reply contains 8 fixed BuildResponseRecords with NO count prefix byte.
func (p *MessageProcessor) processTunnelBuildReplyMessage(msg I2NPMessage) error {
	return p.processFixedBuildReply(msg)
}

// processFixedBuildReply handles TunnelBuildReply (type 22) with fixed 8-record format.
func (p *MessageProcessor) processFixedBuildReply(msg I2NPMessage) error {
	if p.buildReplyProcessor == nil {
		log.WithFields(logger.Fields{
			"at":           "processFixedBuildReply",
			"message_type": msg.Type(),
			"message_id":   msg.MessageID(),
			"reason":       "no build reply processor configured",
		}).Warn("Tunnel build reply discarded - no TunnelBuildReplyProcessor set")
		return nil
	}

	carrier, ok := msg.(DataCarrier)
	if !ok {
		return fmt.Errorf("tunnel build reply does not implement DataCarrier")
	}

	data := carrier.GetData()
	if len(data) == 0 {
		return fmt.Errorf("tunnel build reply contains no data")
	}

	const fixedRecordCount = 8
	const recordSize = 528
	const expectedSize = fixedRecordCount * recordSize

	if len(data) < expectedSize {
		return fmt.Errorf("insufficient data for TunnelBuildReply: have %d, need %d", len(data), expectedSize)
	}

	var records [8]BuildResponseRecord
	rawRecords := make([][]byte, fixedRecordCount)
	offset := 0 // No count prefix byte for type 22

	for i := 0; i < fixedRecordCount; i++ {
		recordData := data[offset : offset+recordSize]
		rawCopy := make([]byte, recordSize)
		copy(rawCopy, recordData)
		rawRecords[i] = rawCopy

		record, err := ReadBuildResponseRecord(recordData)
		if err != nil {
			return fmt.Errorf("failed to parse response record %d: %w", i, err)
		}
		records[i] = record
		offset += recordSize
	}

	handler := &TunnelBuildReply{
		Records:       records,
		RawRecordData: rawRecords,
	}

	log.WithFields(logger.Fields{
		"at":           "processFixedBuildReply",
		"message_id":   msg.MessageID(),
		"record_count": fixedRecordCount,
	}).Debug("Dispatching fixed tunnel build reply to processor")

	return p.buildReplyProcessor.ProcessTunnelBuildReply(handler, msg.MessageID())
}

// processVariableTunnelBuildReplyMessage processes VariableTunnelBuildReply (type 24) messages.
// The reply contains a variable number of BuildResponseRecords.
func (p *MessageProcessor) processVariableTunnelBuildReplyMessage(msg I2NPMessage) error {
	return p.processBuildReplyCommon(msg, false)
}

// processShortTunnelBuildReplyMessage processes ShortTunnelBuildReply (type 26) messages.
// Uses the newer short tunnel build format (v0.9.51+).
func (p *MessageProcessor) processShortTunnelBuildReplyMessage(msg I2NPMessage) error {
	return p.processBuildReplyCommon(msg, true)
}

// processBuildReplyCommon is the common handler for all tunnel build reply message types.
// It extracts the response records from the raw message data, wraps them in the
// appropriate TunnelReplyHandler, and delegates to the configured TunnelBuildReplyProcessor.
func (p *MessageProcessor) processBuildReplyCommon(msg I2NPMessage, isShortBuild bool) error {
	if p.buildReplyProcessor == nil {
		log.WithFields(logger.Fields{
			"at":           "processBuildReplyCommon",
			"message_type": msg.Type(),
			"message_id":   msg.MessageID(),
			"reason":       "no build reply processor configured",
		}).Warn("Tunnel build reply discarded - no TunnelBuildReplyProcessor set")
		return nil
	}

	carrier, ok := msg.(DataCarrier)
	if !ok {
		return fmt.Errorf("tunnel build reply does not implement DataCarrier")
	}

	data := carrier.GetData()
	if len(data) == 0 {
		return fmt.Errorf("tunnel build reply contains no data")
	}

	records, rawRecords, err := p.parseBuildResponseRecords(data, isShortBuild)
	if err != nil {
		return fmt.Errorf("failed to parse build reply records: %w", err)
	}

	// Wrap parsed records in a TunnelReplyHandler
	var handler TunnelReplyHandler
	if isShortBuild {
		handler = &ShortTunnelBuildReply{
			Count:                len(records),
			BuildResponseRecords: records,
			RawRecordData:        rawRecords,
		}
	} else {
		handler = &VariableTunnelBuildReply{
			Count:                len(records),
			BuildResponseRecords: records,
			RawRecordData:        rawRecords,
		}
	}

	log.WithFields(logger.Fields{
		"at":             "processBuildReplyCommon",
		"message_id":     msg.MessageID(),
		"record_count":   len(records),
		"is_short_build": isShortBuild,
	}).Debug("Dispatching tunnel build reply to processor")

	return p.buildReplyProcessor.ProcessTunnelBuildReply(handler, msg.MessageID())
}

// parseBuildResponseRecords parses build response records from raw message data.
// The format is: 1 byte record count followed by N response records.
// Returns both parsed records and the raw encrypted bytes for each record,
// since re-serializing parsed records corrupts the original ciphertext needed for decryption.
func (p *MessageProcessor) parseBuildResponseRecords(data []byte, isShortBuild bool) ([]BuildResponseRecord, [][]byte, error) {
	if len(data) < 1 {
		return nil, nil, fmt.Errorf("insufficient data for record count")
	}

	recordCount := int(data[0])
	if recordCount < 1 || recordCount > 8 {
		return nil, nil, fmt.Errorf("invalid record count: %d (must be 1-8)", recordCount)
	}

	recordSize := p.getRecordSize(isShortBuild)
	expectedLen := 1 + recordCount*recordSize
	if len(data) < expectedLen {
		return nil, nil, fmt.Errorf("insufficient data for %d records: have %d, need %d", recordCount, len(data), expectedLen)
	}

	records := make([]BuildResponseRecord, recordCount)
	rawRecords := make([][]byte, recordCount)
	offset := 1
	for i := 0; i < recordCount; i++ {
		recordData := data[offset : offset+recordSize]
		// Preserve original encrypted bytes before parsing
		rawCopy := make([]byte, recordSize)
		copy(rawCopy, recordData)
		rawRecords[i] = rawCopy

		record, err := ReadBuildResponseRecord(recordData)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse response record %d: %w", i, err)
		}
		records[i] = record
		offset += recordSize
	}

	return records, rawRecords, nil
}

// processTunnelBuildRequest is the common handler for both STBM and VTB messages.
// It extracts the build records, validates the request, and generates a reply.
//
// Parameters:
// - msg: The incoming I2NP tunnel build message
// - isShortBuild: True for STBM format, false for VTB format
func (p *MessageProcessor) processTunnelBuildRequest(msg I2NPMessage, isShortBuild bool) error {
	if err := p.validateParticipantManager(isShortBuild, msg.Type()); err != nil {
		return err
	}

	data, err := p.extractBuildMessageData(msg)
	if err != nil {
		return err
	}

	records, err := p.parseTunnelBuildRecords(data, isShortBuild)
	if err != nil {
		return fmt.Errorf("failed to parse tunnel build records: %w", err)
	}

	p.logParsedBuildRequest(msg.MessageID(), len(records), isShortBuild)
	return p.processAllBuildRecords(msg.MessageID(), records, isShortBuild)
}

// validateParticipantManager checks if the participant manager is configured.
func (p *MessageProcessor) validateParticipantManager(isShortBuild bool, msgType int) error {
	if p.participantManager == nil {
		log.WithFields(logger.Fields{
			"at":             "processTunnelBuildRequest",
			"message_type":   msgType,
			"is_short_build": isShortBuild,
		}).Warn("participant manager not configured - rejecting tunnel build request")
		return fmt.Errorf("participant manager not configured - cannot process tunnel build requests")
	}
	return nil
}

// extractBuildMessageData extracts raw data from the tunnel build message.
func (p *MessageProcessor) extractBuildMessageData(msg I2NPMessage) ([]byte, error) {
	carrier, ok := msg.(DataCarrier)
	if !ok {
		return nil, fmt.Errorf("tunnel build message does not implement DataCarrier")
	}

	data := carrier.GetData()
	if len(data) == 0 {
		return nil, fmt.Errorf("tunnel build message contains no data")
	}

	return data, nil
}

// logParsedBuildRequest logs the parsed build request details.
func (p *MessageProcessor) logParsedBuildRequest(messageID, recordCount int, isShortBuild bool) {
	log.WithFields(logger.Fields{
		"at":             "processTunnelBuildRequest",
		"message_id":     messageID,
		"record_count":   recordCount,
		"is_short_build": isShortBuild,
	}).Debug("parsed tunnel build request")
}

// processAllBuildRecords processes each build record to find ones destined for us.
// Only the record matching our router identity (OurIdent) is processed locally;
// the others belong to different hops and are skipped.
//
// IMPORTANT: If our router hash has not been set (is zero), NO records are processed.
// This prevents the router from incorrectly participating in all hops of a tunnel
// when its identity is unknown. Callers must call SetOurRouterHash before processing
// any tunnel build messages.
func (p *MessageProcessor) processAllBuildRecords(messageID int, records []BuildRequestRecord, isShortBuild bool) error {
	var zeroHash common.Hash
	if p.ourRouterHash == zeroHash {
		log.WithFields(logger.Fields{
			"at":         "processAllBuildRecords",
			"message_id": messageID,
		}).Warn("Router hash not set (zero) — skipping all build records. Call SetOurRouterHash first.")
		return fmt.Errorf("router hash not set: call SetOurRouterHash before processing tunnel build messages")
	}

	for i, record := range records {
		if record.OurIdent != p.ourRouterHash {
			log.WithFields(logger.Fields{
				"at":           "processAllBuildRecords",
				"message_id":   messageID,
				"record_index": i,
				"record_ident": fmt.Sprintf("%x", record.OurIdent[:8]),
			}).Debug("Skipping build record not destined for us")
			continue
		}
		p.processSingleBuildRecord(messageID, i, record, isShortBuild)
	}
	return nil
}

// processSingleBuildRecord validates and processes a single build request record.
// After validating and accepting/rejecting the request, it generates an encrypted
// BuildResponseRecord and forwards it to the next hop.
func (p *MessageProcessor) processSingleBuildRecord(messageID, index int, record BuildRequestRecord, isShortBuild bool) {
	accepted, rejectCode, reason := p.participantManager.ProcessBuildRequest(record.OurIdent)

	if accepted {
		if err := p.handleAcceptedBuildRecord(messageID, index, record); err != nil {
			// Registration failed — send a rejection reply so the tunnel builder
			// knows this hop is non-functional instead of a phantom success.
			rejectCode = TUNNEL_BUILD_REPLY_REJECT
			p.handleRejectedBuildRecord(messageID, index, record, rejectCode,
				fmt.Sprintf("participant registration failed: %v", err))
		} else {
			rejectCode = TUNNEL_BUILD_REPLY_SUCCESS
		}
	} else {
		p.handleRejectedBuildRecord(messageID, index, record, rejectCode, reason)
	}

	// Generate and send build reply message
	if err := p.generateAndSendBuildReply(messageID, index, record, rejectCode, isShortBuild); err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"at":             "processSingleBuildRecord",
			"message_id":     messageID,
			"record_index":   index,
			"receive_tunnel": record.ReceiveTunnel,
		}).Error("failed to generate and send build reply")
	}
}

// generateAndSendBuildReply creates an encrypted BuildResponseRecord and forwards it.
// This implements the core of tunnel participation response handling.
func (p *MessageProcessor) generateAndSendBuildReply(messageID, index int, record BuildRequestRecord, replyCode byte, isShortBuild bool) error {
	// Step 1: Generate random data for the response record
	var randomData [495]byte
	if _, err := rand.Read(randomData[:]); err != nil {
		return fmt.Errorf("failed to generate random data for reply: %w", err)
	}

	// Step 2: Create the BuildResponseRecord with proper hash
	responseRecord := CreateBuildResponseRecord(replyCode, randomData)

	// Step 3: Encrypt the response record using the reply key and IV from the request
	if p.buildRecordCrypto == nil {
		log.WithFields(logger.Fields{
			"at":           "generateAndSendBuildReply",
			"message_id":   messageID,
			"record_index": index,
		}).Warn("build record crypto not initialized - cannot encrypt reply")
		return fmt.Errorf("build record crypto not initialized")
	}

	encryptedReply, err := p.buildRecordCrypto.EncryptReplyRecord(
		responseRecord,
		record.ReplyKey,
		record.ReplyIV,
	)
	if err != nil {
		return fmt.Errorf("failed to encrypt build response record: %w", err)
	}

	// Step 4: Forward the encrypted reply to the next hop
	if err := p.forwardBuildReply(messageID, record, encryptedReply, isShortBuild); err != nil {
		return fmt.Errorf("failed to forward build reply: %w", err)
	}

	log.WithFields(logger.Fields{
		"at":            "generateAndSendBuildReply",
		"message_id":    messageID,
		"record_index":  index,
		"reply_code":    replyCode,
		"next_tunnel":   record.NextTunnel,
		"encrypted_len": len(encryptedReply),
	}).Debug("generated and sent build reply successfully")

	return nil
}

// forwardBuildReply sends the encrypted build reply to the appropriate next hop.
// The next hop is determined by the NextIdent and NextTunnel fields in the BuildRequestRecord.
func (p *MessageProcessor) forwardBuildReply(messageID int, record BuildRequestRecord, encryptedReply []byte, isShortBuild bool) error {
	// Check if we have a forwarder configured
	if p.buildReplyForwarder == nil {
		log.WithFields(logger.Fields{
			"at":          "forwardBuildReply",
			"message_id":  messageID,
			"next_ident":  fmt.Sprintf("%x", record.NextIdent[:8]),
			"next_tunnel": record.NextTunnel,
		}).Warn("build reply forwarder not configured - reply not sent")
		return nil // Not an error - forwarder is optional
	}

	// Determine forwarding method based on NextTunnel value
	// If NextTunnel is 0, forward directly to the next router
	// If NextTunnel is non-zero, forward through the specified tunnel
	if record.NextTunnel == 0 {
		// Direct router forwarding
		return p.buildReplyForwarder.ForwardBuildReplyToRouter(
			record.NextIdent,
			messageID,
			encryptedReply,
			isShortBuild,
		)
	}

	// Tunnel forwarding
	return p.buildReplyForwarder.ForwardBuildReplyThroughTunnel(
		record.NextIdent,
		record.NextTunnel,
		messageID,
		encryptedReply,
		isShortBuild,
	)
}

// handleAcceptedBuildRecord logs acceptance and registers the tunnel participation.
// Returns an error if participant registration fails, so the caller can send a
// rejection reply instead of falsely reporting success.
func (p *MessageProcessor) handleAcceptedBuildRecord(messageID, index int, record BuildRequestRecord) error {
	log.WithFields(logger.Fields{
		"at":             "processTunnelBuildRequest",
		"message_id":     messageID,
		"record_index":   index,
		"receive_tunnel": record.ReceiveTunnel,
		"source_hash":    fmt.Sprintf("%x", record.OurIdent[:8]),
	}).Info("accepting tunnel build request")

	expiry := time.Now().Add(10 * time.Minute) // Tunnel lifetime per I2P spec
	if err := p.participantManager.RegisterParticipant(record.ReceiveTunnel, record.OurIdent, expiry, record.LayerKey, record.IVKey); err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"at":             "processTunnelBuildRequest",
			"receive_tunnel": record.ReceiveTunnel,
		}).Error("failed to register participant after acceptance")
		return fmt.Errorf("RegisterParticipant failed for tunnel %d: %w", record.ReceiveTunnel, err)
	}
	return nil
}

// handleRejectedBuildRecord logs the rejection of a build request.
func (p *MessageProcessor) handleRejectedBuildRecord(messageID, index int, record BuildRequestRecord, rejectCode byte, reason string) {
	log.WithFields(logger.Fields{
		"at":             "processTunnelBuildRequest",
		"message_id":     messageID,
		"record_index":   index,
		"receive_tunnel": record.ReceiveTunnel,
		"reject_code":    rejectCode,
		"reason":         reason,
	}).Info("rejecting tunnel build request")
}

// parseTunnelBuildRecords parses the build request records from message data.
// Returns the parsed records or an error if parsing fails.
func (p *MessageProcessor) parseTunnelBuildRecords(data []byte, isShortBuild bool) ([]BuildRequestRecord, error) {
	recordCount, err := p.validateAndGetRecordCount(data)
	if err != nil {
		return nil, err
	}

	recordSize := p.getRecordSize(isShortBuild)
	return p.parseRecordsFromData(data, recordCount, recordSize, isShortBuild)
}

// validateAndGetRecordCount validates the data and extracts the record count.
func (p *MessageProcessor) validateAndGetRecordCount(data []byte) (int, error) {
	if len(data) < 1 {
		return 0, fmt.Errorf("insufficient data for record count")
	}

	recordCount := int(data[0])
	if recordCount < 1 || recordCount > 8 {
		return 0, fmt.Errorf("invalid record count: %d (must be 1-8)", recordCount)
	}

	return recordCount, nil
}

// getRecordSize returns the record size based on the build type.
// Record sizes differ between STBM (218 bytes encrypted, 154 bytes cleartext) and VTB (528 bytes).
func (p *MessageProcessor) getRecordSize(isShortBuild bool) int {
	if isShortBuild {
		return ShortBuildRecordSize // STBM encrypted record size (ECIES)
	}
	return StandardBuildRecordSize // VTB encrypted record size
}

// parseRecordsFromData iterates through the data and parses each record.
func (p *MessageProcessor) parseRecordsFromData(data []byte, recordCount, recordSize int, isShortBuild bool) ([]BuildRequestRecord, error) {
	records := make([]BuildRequestRecord, 0, recordCount)
	offset := 1

	for i := 0; i < recordCount; i++ {
		if len(data)-offset < recordSize {
			return nil, fmt.Errorf("insufficient data for record %d: have %d, need %d", i, len(data)-offset, recordSize)
		}

		recordData := data[offset : offset+recordSize]
		p.tryParseAndAppendRecord(&records, recordData, i, isShortBuild)
		offset += recordSize
	}

	return records, nil
}

// tryParseAndAppendRecord attempts to parse a single record and appends it if successful.
// Note: In a full implementation, we would:
// 1. Check the first 16 bytes (toPeer) to see if this record is for us
// 2. Decrypt the record if it's for us
// 3. Parse the cleartext record
// For now, attempt to read the record as cleartext (for testing).
// In production, this would be the decrypted cleartext.
func (p *MessageProcessor) tryParseAndAppendRecord(records *[]BuildRequestRecord, recordData []byte, index int, isShortBuild bool) {
	if isShortBuild && len(recordData) >= ShortBuildRecordSize {
		// STBM: 218-byte encrypted records (ECIES). The encrypted payload
		// contains a 154-byte cleartext after decryption (keys are derived
		// via HKDF, not transmitted). For testing, attempt to parse as cleartext.
		record, err := ReadBuildRequestRecord(recordData)
		if err != nil {
			log.WithError(err).WithField("record_index", index).Warn("failed to parse STBM build request record (possible corruption)")
		} else {
			*records = append(*records, record)
		}
	} else if !isShortBuild && len(recordData) >= StandardBuildRecordCleartextLen {
		// VTB: 528-byte encrypted records, parse as cleartext (222 bytes from the record)
		record, err := ReadBuildRequestRecord(recordData)
		if err != nil {
			log.WithError(err).WithField("record_index", index).Warn("failed to parse VTB build request record (possible corruption)")
		} else {
			*records = append(*records, record)
		}
	}
}
