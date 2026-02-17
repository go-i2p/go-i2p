package i2np

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
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

// MessageProcessor demonstrates interface-based message processing
type MessageProcessor struct {
	mu                    sync.RWMutex
	factory               *I2NPMessageFactory
	garlicSessions        *GarlicSessionManager
	cloveForwarder        GarlicCloveForwarder      // Optional delegate for non-LOCAL garlic clove delivery
	dbManager             *DatabaseManager          // Optional database manager for DatabaseLookup messages
	expirationValidator   *ExpirationValidator      // Validator for checking message expiration
	participantManager    ParticipantManager        // Optional participant manager for tunnel build requests
	buildReplyForwarder   BuildReplyForwarder       // Optional forwarder for tunnel build replies
	buildRecordCrypto     *BuildRecordCrypto        // Crypto handler for encrypting build response records
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
func (p *MessageProcessor) SetGarlicSessionManager(garlicMgr *GarlicSessionManager) {
	p.mu.Lock()
	defer p.mu.Unlock()
	log.WithField("at", "SetGarlicSessionManager").Debug("Setting garlic session manager")
	p.garlicSessions = garlicMgr
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

	decryptedData, sessionTag, err := p.garlicSessions.DecryptGarlicMessage(encryptedData)
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

// buildRequest tracks a pending tunnel build request for correlation with replies.
// This enables matching build replies to the original request and managing timeouts.
type buildRequest struct {
	tunnelID      tunnel.TunnelID          // Unique tunnel ID for this request
	messageID     int                      // I2NP message ID for correlation
	hopCount      int                      // Number of hops in the tunnel
	replyKeys     []session_key.SessionKey // Reply decryption keys for each hop
	replyIVs      [][16]byte               // Reply IVs for each hop
	createdAt     time.Time                // When the request was created
	retryCount    int                      // Number of retry attempts
	useShortBuild bool                     // True if using STBM, false for legacy VTB
	isInbound     bool                     // True if this is an inbound tunnel
}

// TunnelManager coordinates tunnel building and management
type TunnelManager struct {
	inboundPool     *tunnel.Pool
	outboundPool    *tunnel.Pool
	sessionProvider SessionProvider
	peerSelector    tunnel.PeerSelector
	pendingBuilds   map[int]*buildRequest // Track pending builds by message ID
	buildMutex      sync.RWMutex          // Protect pending builds map
	cleanupTicker   *time.Ticker          // Periodic cleanup of expired requests
	cleanupStop     chan struct{}         // Signal to stop cleanup goroutine
	cleanupOnce     sync.Once             // Ensures cleanup goroutine starts at most once
	stopOnce        sync.Once             // Ensures Stop() is idempotent (no double-close panic)
	replyProcessor  *ReplyProcessor       // Handles reply decryption and processing
}

// NewTunnelManager creates a new tunnel manager with build request tracking.
// The background cleanup goroutine is started lazily on the first build request,
// avoiding resource leaks if the TunnelManager is created but never used.
// Creates separate inbound and outbound tunnel pools for proper statistics tracking.
func NewTunnelManager(peerSelector tunnel.PeerSelector) *TunnelManager {
	// Create separate pools for inbound and outbound tunnels
	inboundConfig := tunnel.DefaultPoolConfig()
	inboundConfig.IsInbound = true
	inboundPool := tunnel.NewTunnelPoolWithConfig(peerSelector, inboundConfig)

	outboundConfig := tunnel.DefaultPoolConfig()
	outboundConfig.IsInbound = false
	outboundPool := tunnel.NewTunnelPoolWithConfig(peerSelector, outboundConfig)

	tm := &TunnelManager{
		inboundPool:   inboundPool,
		outboundPool:  outboundPool,
		peerSelector:  peerSelector,
		pendingBuilds: make(map[int]*buildRequest),
		cleanupStop:   make(chan struct{}),
	}

	// Initialize ReplyProcessor with default config for reply decryption
	tm.replyProcessor = NewReplyProcessor(DefaultReplyProcessorConfig(), tm)

	// Wire retry callback for both pools: tunnel build timeouts will automatically retry
	tm.replyProcessor.SetRetryCallback(tm.retryTunnelBuild)

	log.WithFields(logger.Fields{
		"at":     "NewTunnelManager",
		"phase":  "initialization",
		"reason": "retry callback configured for automatic tunnel build retry",
	}).Debug("tunnel manager initialized with retry callback")

	// Cleanup goroutine is started lazily via ensureCleanupStarted()
	// to avoid resource leaks when TunnelManager is created but never used.

	log.WithFields(logger.Fields{
		"at":     "NewTunnelManager",
		"phase":  "initialization",
		"reason": "tunnel manager initialized with separate inbound/outbound pools",
	}).Debug("tunnel manager created")

	return tm
}

// ensureCleanupStarted lazily starts the background cleanup goroutine.
// Safe to call multiple times; the goroutine is started at most once.
func (tm *TunnelManager) ensureCleanupStarted() {
	tm.cleanupOnce.Do(func() {
		tm.cleanupTicker = time.NewTicker(30 * time.Second)
		go tm.cleanupExpiredBuilds()
		log.Debug("Tunnel manager cleanup goroutine started (lazy)")
	})
}

// Stop gracefully stops the tunnel manager and cleans up resources.
// Safe to call multiple times — subsequent calls are no-ops.
// Should be called when shutting down the router.
func (tm *TunnelManager) Stop() {
	tm.stopOnce.Do(func() {
		if tm.cleanupTicker != nil {
			tm.cleanupTicker.Stop()
		}
		close(tm.cleanupStop)

		if tm.inboundPool != nil {
			tm.inboundPool.Stop()
		}
		if tm.outboundPool != nil {
			tm.outboundPool.Stop()
		}

		log.Debug("Tunnel manager stopped")
	})
}

// SetSessionProvider sets the session provider for sending tunnel build messages
func (tm *TunnelManager) SetSessionProvider(provider SessionProvider) {
	tm.sessionProvider = provider
}

// GetPool returns the outbound tunnel pool for backward compatibility.
// Deprecated: Use GetInboundPool() or GetOutboundPool() for specific pools.
func (tm *TunnelManager) GetPool() *tunnel.Pool {
	return tm.outboundPool
}

// GetInboundPool returns the inbound tunnel pool.
func (tm *TunnelManager) GetInboundPool() *tunnel.Pool {
	return tm.inboundPool
}

// GetOutboundPool returns the outbound tunnel pool.
func (tm *TunnelManager) GetOutboundPool() *tunnel.Pool {
	return tm.outboundPool
}

// getPoolForTunnel returns the appropriate pool based on tunnel direction.
func (tm *TunnelManager) getPoolForTunnel(isInbound bool) *tunnel.Pool {
	if isInbound {
		return tm.inboundPool
	}
	return tm.outboundPool
}

// retryTunnelBuild routes retry requests to the appropriate pool.
// This wrapper is used by the ReplyProcessor for automatic tunnel build retries.
func (tm *TunnelManager) retryTunnelBuild(tunnelID tunnel.TunnelID, isInbound bool, hopCount int) error {
	pool := tm.getPoolForTunnel(isInbound)
	if pool == nil {
		return fmt.Errorf("pool not initialized for isInbound=%v", isInbound)
	}
	return pool.RetryTunnelBuild(tunnelID, isInbound, hopCount)
}

// BuildTunnel implements tunnel.BuilderInterface for automatic pool maintenance.
// This adapter method wraps BuildTunnelFromRequest to match the interface signature.
// It returns peer hashes extracted from the build request so that failed builds
// can report which peers were involved for progressive exclusion on retry.
func (tm *TunnelManager) BuildTunnel(req tunnel.BuildTunnelRequest) (*tunnel.BuildTunnelResult, error) {
	tunnelID, peerHashes, err := tm.BuildTunnelFromRequest(req)
	if err != nil {
		// Return partial result with peer hashes even on failure,
		// so the caller can exclude these peers on retry
		return &tunnel.BuildTunnelResult{
			TunnelID:   0,
			PeerHashes: peerHashes,
		}, err
	}
	return &tunnel.BuildTunnelResult{
		TunnelID:   tunnelID,
		PeerHashes: peerHashes,
	}, nil
}

// BuildTunnelFromRequest builds a tunnel from a BuildTunnelRequest using the tunnel.TunnelBuilder.
// This is the recommended method for building tunnels with proper request tracking and retry support.
//
// The method:
// 1. Uses tunnel.TunnelBuilder to create encrypted build records
// 2. Generates a unique message ID for request/reply correlation
// 3. Tracks the pending build request with reply decryption keys
// 4. Sends the build request via appropriate transport
// 5. Returns the tunnel ID, selected peer hashes, and any error
func (tm *TunnelManager) BuildTunnelFromRequest(req tunnel.BuildTunnelRequest) (tunnel.TunnelID, []common.Hash, error) {
	result, messageID, err := tm.createBuildRequestAndID(req)
	if err != nil {
		return 0, nil, err
	}

	// Extract peer hashes from the build result for caller tracking
	peerHashes := tm.extractPeerHashes(result)

	tunnelState := tm.createTunnelStateFromResult(result)
	pool := tm.getPoolForTunnel(req.IsInbound)
	pool.AddTunnel(tunnelState)
	tm.trackPendingBuild(result, messageID)

	// Register with ReplyProcessor for decryption key management
	if regErr := tm.replyProcessor.RegisterPendingBuild(
		result.TunnelID,
		result.ReplyKeys,
		result.ReplyIVs,
		req.IsInbound,
		len(result.Hops),
	); regErr != nil {
		tm.cleanupFailedBuild(result.TunnelID, messageID, req.IsInbound)
		return 0, peerHashes, fmt.Errorf("failed to register pending build: %w", regErr)
	}

	// Schedule immediate cleanup on timeout (90 seconds per I2P spec)
	// This prevents memory leaks from failed/timeout builds between periodic cleanups
	time.AfterFunc(90*time.Second, func() {
		tm.cleanupExpiredBuildByID(messageID)
	})

	err = tm.sendBuildMessage(result, messageID)
	if err != nil {
		tm.cleanupFailedBuild(result.TunnelID, messageID, req.IsInbound)
		return 0, peerHashes, fmt.Errorf("failed to send build request: %w", err)
	}

	tm.logBuildRequestSent(result, messageID)
	return result.TunnelID, peerHashes, nil
}

// createBuildRequestAndID validates prerequisites and creates the build request with message ID
func (tm *TunnelManager) createBuildRequestAndID(req tunnel.BuildTunnelRequest) (*tunnel.TunnelBuildResult, int, error) {
	if tm.peerSelector == nil {
		return nil, 0, fmt.Errorf("no peer selector configured")
	}

	builder, err := tunnel.NewTunnelBuilder(tm.peerSelector)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create tunnel builder: %w", err)
	}

	result, err := builder.CreateBuildRequest(req)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create build request: %w", err)
	}

	messageID, err := tm.generateMessageID()
	if err != nil {
		return nil, 0, fmt.Errorf("failed to generate message ID: %w", err)
	}
	return result, messageID, nil
}

// extractPeerHashes extracts identity hashes from the selected peers in a build result.
// Returns the hashes of all peers that were selected for the tunnel build,
// enabling callers to track which peers participated in failed builds.
func (tm *TunnelManager) extractPeerHashes(result *tunnel.TunnelBuildResult) []common.Hash {
	if result == nil || len(result.Hops) == 0 {
		return nil
	}

	hashes := make([]common.Hash, 0, len(result.Hops))
	for i, peer := range result.Hops {
		hash, err := peer.IdentHash()
		if err != nil {
			log.WithError(err).WithField("hop_index", i).Warn("Failed to extract peer hash from build result")
			continue
		}
		hashes = append(hashes, hash)
	}
	return hashes
}

// createTunnelStateFromResult creates tunnel state tracking from build result
func (tm *TunnelManager) createTunnelStateFromResult(result *tunnel.TunnelBuildResult) *tunnel.TunnelState {
	tunnelState := &tunnel.TunnelState{
		ID:        result.TunnelID,
		Hops:      make([]common.Hash, len(result.Hops)),
		State:     tunnel.TunnelBuilding,
		CreatedAt: time.Now(),
		Responses: make([]tunnel.BuildResponse, 0, len(result.Hops)),
		IsInbound: result.IsInbound,
	}

	for i, peer := range result.Hops {
		hash, err := peer.IdentHash()
		if err != nil {
			log.WithError(err).WithField("hop_index", i).Warn("Failed to get peer hash for tunnel state, using zero hash")
			tunnelState.Hops[i] = common.Hash{}
		} else {
			tunnelState.Hops[i] = hash
		}
	}

	return tunnelState
}

// trackPendingBuild records the pending build request for reply correlation
func (tm *TunnelManager) trackPendingBuild(result *tunnel.TunnelBuildResult, messageID int) {
	// Lazily start the cleanup goroutine on the first build request
	tm.ensureCleanupStarted()

	tm.buildMutex.Lock()
	defer tm.buildMutex.Unlock()

	tm.pendingBuilds[messageID] = &buildRequest{
		tunnelID:      result.TunnelID,
		messageID:     messageID,
		hopCount:      len(result.Hops),
		replyKeys:     result.ReplyKeys,
		replyIVs:      result.ReplyIVs,
		createdAt:     time.Now(),
		retryCount:    0,
		useShortBuild: result.UseShortBuild,
		isInbound:     result.IsInbound,
	}
}

// cleanupFailedBuild removes tunnel and pending build request on send failure
func (tm *TunnelManager) cleanupFailedBuild(tunnelID tunnel.TunnelID, messageID int, isInbound bool) {
	pool := tm.getPoolForTunnel(isInbound)
	pool.RemoveTunnel(tunnelID)
	tm.buildMutex.Lock()
	delete(tm.pendingBuilds, messageID)
	tm.buildMutex.Unlock()
}

// logBuildRequestSent logs successful tunnel build request submission
func (tm *TunnelManager) logBuildRequestSent(result *tunnel.TunnelBuildResult, messageID int) {
	log.WithFields(logger.Fields{
		"tunnel_id":  result.TunnelID,
		"message_id": messageID,
		"hop_count":  len(result.Hops),
		"use_stbm":   result.UseShortBuild,
	}).Info("Tunnel build request sent")
}

// sendBuildMessage sends a tunnel build message (STBM or VTB) based on the result.
func (tm *TunnelManager) sendBuildMessage(result *tunnel.TunnelBuildResult, messageID int) error {
	if tm.sessionProvider == nil {
		return fmt.Errorf("no session provider available")
	}

	firstHop, err := validateTunnelBuild(result)
	if err != nil {
		return err
	}

	session, peerHash, err := tm.getGatewaySession(firstHop)
	if err != nil {
		return err
	}

	buildMsg, err := tm.selectBuildMessage(result, messageID)
	if err != nil {
		return fmt.Errorf("failed to create build message: %w", err)
	}
	tm.queueBuildMessageToGateway(session, buildMsg, messageID, peerHash, result.UseShortBuild)

	return nil
}

// validateTunnelBuild validates the tunnel build result has required hops.
func validateTunnelBuild(result *tunnel.TunnelBuildResult) (router_info.RouterInfo, error) {
	if len(result.Hops) == 0 {
		return router_info.RouterInfo{}, fmt.Errorf("no hops in tunnel build result")
	}
	return result.Hops[0], nil
}

// getGatewaySession retrieves the transport session for the gateway router.
func (tm *TunnelManager) getGatewaySession(firstHop router_info.RouterInfo) (TransportSession, [32]byte, error) {
	peerHash, err := firstHop.IdentHash()
	if err != nil {
		return nil, [32]byte{}, fmt.Errorf("failed to get first hop identity: %w", err)
	}

	session, err := tm.sessionProvider.GetSessionByHash(peerHash)
	if err != nil {
		return nil, [32]byte{}, fmt.Errorf("failed to get session for gateway %x: %w", peerHash[:8], err)
	}

	return session, peerHash, nil
}

// selectBuildMessage creates the appropriate build message based on UseShortBuild flag.
// Each build record is encrypted with the corresponding hop's public encryption key
// using ECIES-X25519-AEAD before being placed into the message.
func (tm *TunnelManager) selectBuildMessage(result *tunnel.TunnelBuildResult, messageID int) (I2NPMessage, error) {
	if result.UseShortBuild {
		// Use Short Tunnel Build Message (modern)
		return tm.createShortTunnelBuildMessage(result, messageID)
	}
	// Use TunnelBuild (type 21): fixed 8 records, no count prefix
	return tm.createTunnelBuildMessage(result, messageID)
}

// queueBuildMessageToGateway queues the build message for sending to the gateway.
func (tm *TunnelManager) queueBuildMessageToGateway(session TransportSession, buildMsg I2NPMessage, messageID int, peerHash [32]byte, useShortBuild bool) {
	session.QueueSendI2NP(buildMsg)

	log.WithFields(logger.Fields{
		"message_id":   messageID,
		"gateway_hash": fmt.Sprintf("%x", peerHash[:8]),
		"message_type": buildMsg.Type(),
		"use_stbm":     useShortBuild,
	}).Debug("Queued tunnel build message")
}

// createShortTunnelBuildMessage creates a Short Tunnel Build Message (STBM).
// Each build record is encrypted with the corresponding hop's X25519 public key
// using ECIES-X25519-AEAD encryption before being placed into the message.
func (tm *TunnelManager) createShortTunnelBuildMessage(result *tunnel.TunnelBuildResult, messageID int) (I2NPMessage, error) {
	// Convert tunnel.BuildRequestRecord to i2np.BuildRequestRecord
	i2npRecords := make([]BuildRequestRecord, len(result.Records))
	for i, rec := range result.Records {
		i2npRecords[i] = convertTunnelBuildRecord(rec)
	}

	// Encrypt each record with the corresponding hop's public key.
	// Each encrypted record is 528 bytes (16-byte identity hash prefix + 512 bytes ECIES ciphertext).
	encryptedRecords := make([][528]byte, len(i2npRecords))
	for i, record := range i2npRecords {
		if i >= len(result.Hops) {
			return nil, fmt.Errorf("record %d has no corresponding hop RouterInfo", i)
		}
		encrypted, err := EncryptBuildRequestRecord(record, result.Hops[i])
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt build record %d: %w", i, err)
		}
		encryptedRecords[i] = encrypted
	}

	// Serialize encrypted records: [count:1][encrypted_records...]
	// Each encrypted record is 528 bytes
	data := make([]byte, 1+len(encryptedRecords)*528)
	data[0] = byte(len(encryptedRecords))
	for i, enc := range encryptedRecords {
		copy(data[1+i*528:1+(i+1)*528], enc[:])
	}

	// Wrap in I2NP message
	msg := NewBaseI2NPMessage(I2NP_MESSAGE_TYPE_SHORT_TUNNEL_BUILD)
	msg.SetMessageID(messageID)
	msg.SetData(data)

	log.WithFields(logger.Fields{
		"at":           "createShortTunnelBuildMessage",
		"record_count": len(encryptedRecords),
		"data_size":    len(data),
		"encrypted":    true,
	}).Debug("Created encrypted Short Tunnel Build message")

	return msg, nil
}

// createTunnelBuildMessage creates a TunnelBuild (type 21) message.
// Type 21 has exactly 8 records at 528 bytes each with NO count prefix byte.
// Each build record is encrypted with the corresponding hop's X25519 public key
// using ECIES-X25519-AEAD encryption before being placed into the message.
func (tm *TunnelManager) createTunnelBuildMessage(result *tunnel.TunnelBuildResult, messageID int) (I2NPMessage, error) {
	encryptedData, err := encryptBuildRecords(result)
	if err != nil {
		return nil, err
	}

	data, err := serializeBuildRecords(encryptedData, len(result.Records))
	if err != nil {
		return nil, err
	}

	msg := NewBaseI2NPMessage(I2NP_MESSAGE_TYPE_TUNNEL_BUILD)
	msg.SetMessageID(messageID)
	msg.SetData(data)

	log.WithFields(logger.Fields{
		"at":           "createTunnelBuildMessage",
		"record_count": len(result.Records),
		"data_size":    len(data),
		"encrypted":    true,
	}).Debug("Created encrypted TunnelBuild (type 21) message")

	return msg, nil
}

// createVariableTunnelBuildMessage creates a VariableTunnelBuild (type 23) message.
// Type 23 has a 1-byte count prefix followed by N records at 528 bytes each.
// This is the variable-length format that allows 1-8 records.
func (tm *TunnelManager) createVariableTunnelBuildMessage(result *tunnel.TunnelBuildResult, messageID int) (I2NPMessage, error) {
	encryptedData, err := encryptBuildRecords(result)
	if err != nil {
		return nil, err
	}

	data := serializeVariableBuildRecords(encryptedData, len(result.Records))

	msg := NewBaseI2NPMessage(I2NP_MESSAGE_TYPE_VARIABLE_TUNNEL_BUILD)
	msg.SetMessageID(messageID)
	msg.SetData(data)

	log.WithFields(logger.Fields{
		"at":           "createVariableTunnelBuildMessage",
		"record_count": len(result.Records),
		"data_size":    len(data),
		"encrypted":    true,
	}).Debug("Created encrypted VariableTunnelBuild (type 23) message")

	return msg, nil
}

// convertTunnelBuildRecord converts a tunnel.BuildRequestRecord to an i2np.BuildRequestRecord.
// This avoids duplicating the field-by-field copy in multiple functions.
func convertTunnelBuildRecord(rec tunnel.BuildRequestRecord) BuildRequestRecord {
	return BuildRequestRecord{
		ReceiveTunnel: rec.ReceiveTunnel,
		OurIdent:      rec.OurIdent,
		NextTunnel:    rec.NextTunnel,
		NextIdent:     rec.NextIdent,
		LayerKey:      rec.LayerKey,
		IVKey:         rec.IVKey,
		ReplyKey:      rec.ReplyKey,
		ReplyIV:       rec.ReplyIV,
		Flag:          rec.Flag,
		RequestTime:   rec.RequestTime,
		SendMessageID: rec.SendMessageID,
		Padding:       rec.Padding,
	}
}

// encryptBuildRecords encrypts each build request record with its corresponding
// hop's X25519 public key using ECIES-X25519-AEAD encryption.
func encryptBuildRecords(result *tunnel.TunnelBuildResult) ([8][528]byte, error) {
	var encryptedData [8][528]byte
	for i := 0; i < 8 && i < len(result.Records); i++ {
		i2npRecord := convertTunnelBuildRecord(result.Records[i])

		if i >= len(result.Hops) {
			return encryptedData, fmt.Errorf("record %d has no corresponding hop RouterInfo", i)
		}
		encrypted, err := EncryptBuildRequestRecord(i2npRecord, result.Hops[i])
		if err != nil {
			return encryptedData, fmt.Errorf("failed to encrypt build record %d: %w", i, err)
		}
		encryptedData[i] = encrypted
	}
	return encryptedData, nil
}

// serializeBuildRecords serializes all 8 encrypted records into a contiguous byte slice.
// Used for TunnelBuild (type 21) which has NO count prefix and always 8 records.
// Unused slots are filled with random data to prevent observers from distinguishing
// tunnel length by counting zero-filled records. Returns an error if random padding
// cannot be generated (all-zero slots would reveal the true hop count).
func serializeBuildRecords(encryptedData [8][528]byte, recordCount int) ([]byte, error) {
	data := make([]byte, 8*528)
	for i := 0; i < 8; i++ {
		if i < recordCount {
			copy(data[i*528:(i+1)*528], encryptedData[i][:])
		} else {
			// Fill unused slot with random padding
			if _, err := rand.Read(data[i*528 : (i+1)*528]); err != nil {
				return nil, fmt.Errorf("failed to generate random padding for unused slot %d: %w", i, err)
			}
		}
	}
	return data, nil
}

// serializeVariableBuildRecords serializes encrypted records with a count prefix byte.
// Used for VariableTunnelBuild (type 23) which has a 1-byte count followed by N records.
// Only the actual number of records is included (no padding to 8).
func serializeVariableBuildRecords(encryptedData [8][528]byte, recordCount int) []byte {
	data := make([]byte, 1+recordCount*528)
	data[0] = byte(recordCount)
	for i := 0; i < recordCount; i++ {
		copy(data[1+i*528:1+(i+1)*528], encryptedData[i][:])
	}
	return data
}

// generateMessageID generates a unique message ID for tracking build requests.
// Uses cryptographically secure random to avoid collisions and predictability.
func (tm *TunnelManager) generateMessageID() (int, error) {
	var buf [4]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return 0, fmt.Errorf("failed to generate random message ID: %w", err)
	}
	// Use only 31 bits to ensure positive int on all platforms
	return int(binary.BigEndian.Uint32(buf[:]) & 0x7FFFFFFF), nil
}

// BuildTunnelWithBuilder builds a tunnel using the i2np.TunnelBuilder message interface.
// This is used for message routing and differs from BuildTunnel (tunnel.BuilderInterface).
func (tm *TunnelManager) BuildTunnelWithBuilder(builder TunnelBuilder) error {
	if err := tm.validateTunnelBuilder(builder); err != nil {
		return err
	}

	records := builder.GetBuildRecords()
	count := builder.GetRecordCount()

	peers, err := tm.selectTunnelPeers(count)
	if err != nil {
		return err
	}

	tunnelID, err := tm.generateTunnelID()
	if err != nil {
		return fmt.Errorf("failed to generate tunnel ID: %w", err)
	}
	tunnelState := tm.createTunnelState(tunnelID, count, peers)
	// BuildTunnelWithBuilder is legacy interface, defaults to outbound tunnels
	tm.outboundPool.AddTunnel(tunnelState)

	return tm.sendTunnelBuildRequests(records, peers[:count], tunnelID)
}

// validateTunnelBuilder checks if the tunnel manager and builder are properly configured.
func (tm *TunnelManager) validateTunnelBuilder(builder TunnelBuilder) error {
	if tm.peerSelector == nil {
		return fmt.Errorf("no peer selector configured")
	}

	if builder.GetRecordCount() == 0 {
		return fmt.Errorf("no build records provided")
	}

	return nil
}

// selectTunnelPeers selects the required number of peers for tunnel construction.
func (tm *TunnelManager) selectTunnelPeers(count int) ([]router_info.RouterInfo, error) {
	peers, err := tm.peerSelector.SelectPeers(count, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to select peers for tunnel: %w", err)
	}

	if len(peers) < count {
		return nil, fmt.Errorf("insufficient peers available: need %d, got %d", count, len(peers))
	}

	return peers, nil
}

// createTunnelState initializes a new tunnel state with selected peers.
func (tm *TunnelManager) createTunnelState(tunnelID tunnel.TunnelID, count int, peers []router_info.RouterInfo) *tunnel.TunnelState {
	tunnelState := &tunnel.TunnelState{
		ID:        tunnelID,
		Hops:      make([]common.Hash, count),
		State:     tunnel.TunnelBuilding,
		CreatedAt: time.Now(),
		Responses: make([]tunnel.BuildResponse, 0, count),
	}

	populateTunnelHops(tunnelState, peers[:count])
	return tunnelState
}

// populateTunnelHops fills the tunnel state hops with peer identity hashes.
func populateTunnelHops(tunnelState *tunnel.TunnelState, peers []router_info.RouterInfo) {
	for i, peer := range peers {
		hash, err := peer.IdentHash()
		if err != nil {
			log.WithError(err).WithField("hop_index", i).Warn("Failed to get peer hash, using zero hash")
			tunnelState.Hops[i] = common.Hash{}
		} else {
			tunnelState.Hops[i] = hash
		}
	}
}

// generateTunnelID generates a unique tunnel ID using cryptographically secure random.
func (tm *TunnelManager) generateTunnelID() (tunnel.TunnelID, error) {
	var buf [4]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return 0, fmt.Errorf("failed to generate random tunnel ID: %w", err)
	}
	return tunnel.TunnelID(binary.BigEndian.Uint32(buf[:])), nil
}

// sendTunnelBuildRequests builds a single TunnelBuild message containing all
// encrypted hop records and sends it to the first hop (gateway) only.
// Per the I2P tunnel creation specification, the gateway forwards the message
// through the partially-built tunnel; each hop peels its layer and forwards
// to the next. Sending directly to each hop would break tunnel anonymity.
func (tm *TunnelManager) sendTunnelBuildRequests(records []BuildRequestRecord, peers []router_info.RouterInfo, tunnelID tunnel.TunnelID) error {
	if tm.sessionProvider == nil {
		return fmt.Errorf("no session provider available for sending tunnel build requests")
	}
	if len(peers) == 0 {
		return fmt.Errorf("no peers provided for tunnel build")
	}

	tm.logSendingBuildRequests(tunnelID, len(peers))

	// Encrypt each record with the corresponding hop's public key and
	// assemble all records into a single 8-slot TunnelBuild message.
	msg, err := tm.createCombinedBuildMessage(records, peers, tunnelID)
	if err != nil {
		return fmt.Errorf("failed to create combined tunnel build message: %w", err)
	}

	// Send only to the first hop (gateway) — it will forward onion-style.
	firstPeerHash, err := peers[0].IdentHash()
	if err != nil {
		return fmt.Errorf("failed to get first hop hash: %w", err)
	}
	session, err := tm.getSessionForPeer(firstPeerHash)
	if err != nil {
		return fmt.Errorf("failed to get session for gateway: %w", err)
	}
	session.QueueSendI2NP(msg)

	tm.logBuildRequestsCompleted(tunnelID)
	return nil
}

// createCombinedBuildMessage encrypts each hop's record with its public key and
// packs all records into a single TunnelBuild message. Unused slots (up to 8)
// are filled with random data so observers cannot determine the tunnel length.
func (tm *TunnelManager) createCombinedBuildMessage(records []BuildRequestRecord, peers []router_info.RouterInfo, tunnelID tunnel.TunnelID) (*TunnelBuildMessage, error) {
	data := make([]byte, 8*StandardBuildRecordSize)

	for i := 0; i < 8; i++ {
		slotStart := i * StandardBuildRecordSize
		slotEnd := (i + 1) * StandardBuildRecordSize
		if i < len(records) && i < len(peers) {
			encrypted, err := EncryptBuildRequestRecord(records[i], peers[i])
			if err != nil {
				return nil, fmt.Errorf("failed to encrypt record for hop %d: %w", i, err)
			}
			copy(data[slotStart:slotEnd], encrypted[:])
		} else {
			if _, err := rand.Read(data[slotStart:slotEnd]); err != nil {
				return nil, fmt.Errorf("failed to generate random padding for slot %d: %w", i, err)
			}
		}
	}

	msg := &TunnelBuildMessage{
		BaseI2NPMessage: NewBaseI2NPMessage(I2NP_MESSAGE_TYPE_TUNNEL_BUILD),
	}
	msg.SetData(data)
	msg.SetMessageID(int(tunnelID))
	return msg, nil
}

// logSendingBuildRequests logs the start of tunnel build request sending.
func (tm *TunnelManager) logSendingBuildRequests(tunnelID tunnel.TunnelID, peerCount int) {
	log.WithFields(logger.Fields{
		"tunnel_id":  tunnelID,
		"peer_count": peerCount,
	}).Debug("Sending tunnel build requests")
}

// sendBuildRequestToHop sends a build request to a specific hop in the tunnel.
// The build record is encrypted with the hop's public key before transmission.
func (tm *TunnelManager) sendBuildRequestToHop(hopIndex int, record BuildRequestRecord, peer router_info.RouterInfo, tunnelID tunnel.TunnelID) error {
	peerHash, err := peer.IdentHash()
	if err != nil {
		return fmt.Errorf("failed to get peer hash at hop %d: %w", hopIndex, err)
	}

	session, err := tm.getSessionForPeer(peerHash)
	if err != nil {
		return err
	}

	buildMessage, err := tm.createBuildMessage(hopIndex, record, peer, tunnelID)
	if err != nil {
		return fmt.Errorf("failed to create encrypted build message for hop %d: %w", hopIndex, err)
	}
	session.QueueSendI2NP(buildMessage)

	tm.logHopRequestSent(hopIndex, peerHash, buildMessage.MessageID())
	return nil
}

// getSessionForPeer retrieves a transport session for the specified peer.
func (tm *TunnelManager) getSessionForPeer(peerHash common.Hash) (TransportSession, error) {
	session, err := tm.sessionProvider.GetSessionByHash(peerHash)
	if err != nil {
		log.WithFields(logger.Fields{
			"peer_hash": fmt.Sprintf("%x", peerHash[:8]),
			"error":     err,
		}).Warn("Failed to get session for peer")
		return nil, err
	}
	return session, nil
}

// createBuildMessage constructs a TunnelBuild I2NP message with the given record.
// The record is encrypted with the hop's ECIES-X25519 public key before inclusion.
// Unused record slots are filled with random data per I2P specification to prevent
// observers from determining the tunnel's true hop count.
func (tm *TunnelManager) createBuildMessage(hopIndex int, record BuildRequestRecord, peer router_info.RouterInfo, tunnelID tunnel.TunnelID) (*TunnelBuildMessage, error) {
	// Encrypt the real record with the hop's public key (ECIES-X25519-AEAD)
	encrypted, err := EncryptBuildRequestRecord(record, peer)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt build record for hop %d: %w", hopIndex, err)
	}

	// Build the 8-record serialized data:
	// - Real record at hopIndex (encrypted, 528 bytes)
	// - All other slots filled with random data (528 bytes each)
	// Per I2P spec, unused slots must be indistinguishable from real encrypted records
	data := make([]byte, 8*StandardBuildRecordSize)
	for i := 0; i < 8; i++ {
		slotStart := i * StandardBuildRecordSize
		slotEnd := (i + 1) * StandardBuildRecordSize
		if i == hopIndex {
			copy(data[slotStart:slotEnd], encrypted[:])
		} else {
			// Fill unused slot with random data to hide tunnel structure
			if _, err := rand.Read(data[slotStart:slotEnd]); err != nil {
				log.WithFields(logger.Fields{
					"at":   "createBuildMessage",
					"slot": i,
				}).Warn("Failed to generate random padding for unused slot")
			}
		}
	}

	msg := &TunnelBuildMessage{
		BaseI2NPMessage: NewBaseI2NPMessage(I2NP_MESSAGE_TYPE_TUNNEL_BUILD),
	}
	msg.SetData(data)
	msg.SetMessageID(int(tunnelID))

	return msg, nil
}

// logHopRequestSent logs successful transmission of a build request to a hop.
func (tm *TunnelManager) logHopRequestSent(hopIndex int, peerHash common.Hash, messageID int) {
	log.WithFields(logger.Fields{
		"hop_index":  hopIndex,
		"peer_hash":  fmt.Sprintf("%x", peerHash[:8]),
		"message_id": messageID,
	}).Debug("Sent tunnel build request to hop")
}

// logBuildRequestsCompleted logs completion of all build request transmissions.
func (tm *TunnelManager) logBuildRequestsCompleted(tunnelID tunnel.TunnelID) {
	log.WithField("tunnel_id", tunnelID).Debug("Tunnel build requests sent")
}

// ProcessTunnelReply processes tunnel build replies using TunnelReplyHandler interface.
// This method integrates with the tunnel pool to update tunnel states and handle build completions.
// Uses message ID to correlate the reply with the original build request.
func (tm *TunnelManager) ProcessTunnelReply(handler TunnelReplyHandler, messageID int) error {
	records := handler.GetReplyRecords()
	recordCount := len(records)

	log.WithFields(logger.Fields{
		"record_count": recordCount,
		"message_id":   messageID,
	}).Debug("Processing tunnel reply")

	// Retrieve pending build request
	req, exists := tm.retrievePendingBuildRequest(messageID)

	// Process uncorrelated reply if no pending request exists
	if !exists {
		return tm.processUncorrelatedReply(handler, messageID, records)
	}

	// Process correlated reply with tunnel ID
	err := tm.processCorrelatedReply(handler, req, messageID, records)

	// Clean up pending build request
	tm.removePendingBuildRequest(messageID)

	return err
}

// retrievePendingBuildRequest safely retrieves a pending build request.
func (tm *TunnelManager) retrievePendingBuildRequest(messageID int) (*buildRequest, bool) {
	tm.buildMutex.RLock()
	defer tm.buildMutex.RUnlock()
	req, exists := tm.pendingBuilds[messageID]
	return req, exists
}

// processUncorrelatedReply handles replies without a pending build request.
func (tm *TunnelManager) processUncorrelatedReply(handler TunnelReplyHandler, messageID int, records []BuildResponseRecord) error {
	log.WithField("message_id", messageID).Warn("No pending build request found for reply - processing without correlation")

	err := handler.ProcessReply()
	if err != nil {
		return err
	}

	// Update tunnel states if possible (without decryption)
	if tm.inboundPool != nil || tm.outboundPool != nil {
		tm.updateTunnelStatesFromReply(messageID, records, nil)
	}

	return nil
}

// processCorrelatedReply handles replies with a pending build request.
func (tm *TunnelManager) processCorrelatedReply(handler TunnelReplyHandler, req *buildRequest, messageID int, records []BuildResponseRecord) error {
	// Use ReplyProcessor to decrypt and process the reply with proper key handling
	err := tm.replyProcessor.ProcessBuildReply(handler, req.tunnelID)

	// Update tunnel state based on reply processing results
	if tm.inboundPool != nil || tm.outboundPool != nil {
		tm.updateTunnelStatesFromReply(messageID, records, err)
	} else {
		log.Warn("No tunnel pool available for state updates")
	}

	return err
}

// removePendingBuildRequest safely removes a pending build request.
func (tm *TunnelManager) removePendingBuildRequest(messageID int) {
	tm.buildMutex.Lock()
	defer tm.buildMutex.Unlock()
	delete(tm.pendingBuilds, messageID)
}

// updateTunnelStatesFromReply updates tunnel states in the pool based on build reply results.
// Uses message ID to find the matching tunnel via the pending build request.
func (tm *TunnelManager) updateTunnelStatesFromReply(messageID int, records []BuildResponseRecord, replyErr error) {
	matchingTunnel := tm.findMatchingBuildingTunnel(messageID)

	if matchingTunnel == nil {
		tm.logNoMatchingTunnel(messageID, len(records))
		return
	}

	tm.logTunnelUpdate(matchingTunnel.ID, messageID, len(records), replyErr == nil)

	responses := tm.createBuildResponses(records)
	tm.updateTunnelBasedOnReply(matchingTunnel, messageID, responses, replyErr)
}

// logNoMatchingTunnel logs a warning when no building tunnel matches the reply.
func (tm *TunnelManager) logNoMatchingTunnel(messageID, recordCount int) {
	log.WithFields(logger.Fields{
		"message_id":   messageID,
		"record_count": recordCount,
	}).Warn("No matching building tunnel found for reply")
}

// logTunnelUpdate logs debug information about tunnel state update.
func (tm *TunnelManager) logTunnelUpdate(tunnelID tunnel.TunnelID, messageID, recordCount int, success bool) {
	log.WithFields(logger.Fields{
		"tunnel_id":    tunnelID,
		"message_id":   messageID,
		"record_count": recordCount,
		"success":      success,
	}).Debug("Updating tunnel state from reply")
}

// createBuildResponses converts reply records to BuildResponse structures.
func (tm *TunnelManager) createBuildResponses(records []BuildResponseRecord) []tunnel.BuildResponse {
	responses := make([]tunnel.BuildResponse, len(records))
	for i, record := range records {
		responses[i] = tunnel.BuildResponse{
			HopIndex: i,
			Success:  record.Reply == TUNNEL_BUILD_REPLY_SUCCESS,
			Reply:    []byte{record.Reply},
		}
	}
	return responses
}

// updateTunnelBasedOnReply updates tunnel state based on build reply result.
func (tm *TunnelManager) updateTunnelBasedOnReply(matchingTunnel *tunnel.TunnelState, messageID int, responses []tunnel.BuildResponse, replyErr error) {
	matchingTunnel.Responses = responses
	matchingTunnel.ResponseCount = len(responses)

	if replyErr == nil {
		tm.handleSuccessfulBuild(matchingTunnel, messageID)
	} else {
		tm.handleFailedBuild(matchingTunnel, messageID, replyErr)
	}
}

// handleSuccessfulBuild processes a successful tunnel build.
func (tm *TunnelManager) handleSuccessfulBuild(matchingTunnel *tunnel.TunnelState, messageID int) {
	matchingTunnel.State = tunnel.TunnelReady

	log.WithFields(logger.Fields{
		"tunnel_id":  matchingTunnel.ID,
		"message_id": messageID,
	}).Info("Tunnel build completed successfully")
}

// handleFailedBuild processes a failed tunnel build and schedules cleanup.
func (tm *TunnelManager) handleFailedBuild(matchingTunnel *tunnel.TunnelState, messageID int, replyErr error) {
	matchingTunnel.State = tunnel.TunnelFailed

	log.WithFields(logger.Fields{
		"tunnel_id":  matchingTunnel.ID,
		"message_id": messageID,
		"error":      replyErr,
	}).Warn("Tunnel build failed")

	tm.cleanupFailedTunnel(matchingTunnel.ID, matchingTunnel.IsInbound)
}

// findMatchingBuildingTunnel finds a tunnel that's currently building based on the message ID.
// Uses the pending builds map to correlate build replies with their original requests.
func (tm *TunnelManager) findMatchingBuildingTunnel(messageID int) *tunnel.TunnelState {
	tm.buildMutex.RLock()
	req, exists := tm.pendingBuilds[messageID]
	tm.buildMutex.RUnlock()

	if !exists {
		log.WithField("message_id", messageID).Warn("No pending build request found for message ID")
		return nil
	}

	// Look up the tunnel state from the pool
	pool := tm.getPoolForTunnel(req.isInbound)
	tunnelState, exists := pool.GetTunnel(req.tunnelID)
	if !exists {
		log.WithField("tunnel_id", req.tunnelID).Warn("Tunnel state not found in pool")
		return nil
	}

	log.WithFields(logger.Fields{
		"tunnel_id":  req.tunnelID,
		"message_id": messageID,
		"hop_count":  req.hopCount,
	}).Debug("Found matching building tunnel")

	return tunnelState
}

// cleanupFailedTunnel schedules removal of a failed tunnel from the pool after a delay.
// Uses time.AfterFunc instead of time.Sleep to avoid blocking a goroutine.
func (tm *TunnelManager) cleanupFailedTunnel(tunnelID tunnel.TunnelID, isInbound bool) {
	time.AfterFunc(1*time.Second, func() {
		pool := tm.getPoolForTunnel(isInbound)
		if pool != nil {
			pool.RemoveTunnel(tunnelID)
			log.WithField("tunnel_id", tunnelID).Debug("Cleaned up failed tunnel")
		}
	})
}

// cleanupExpiredBuilds periodically removes expired build requests.
// Build requests timeout after 90 seconds per I2P specification.
func (tm *TunnelManager) cleanupExpiredBuilds() {
	for {
		select {
		case <-tm.cleanupTicker.C:
			tm.removeExpiredBuildRequests()
		case <-tm.cleanupStop:
			return
		}
	}
}

// removeExpiredBuildRequests removes build requests older than 90 seconds.
// Also marks corresponding tunnels as failed and removes them from the pool.
func (tm *TunnelManager) removeExpiredBuildRequests() {
	tm.buildMutex.Lock()
	defer tm.buildMutex.Unlock()

	expired := tm.identifyExpiredRequests()
	tm.removeExpiredFromMap(expired)
	tm.logCleanupResults(expired)
}

// identifyExpiredRequests finds and processes all build requests that have exceeded timeout.
// Returns list of expired message IDs for cleanup.
func (tm *TunnelManager) identifyExpiredRequests() []int {
	now := time.Now()
	const buildTimeout = 90 * time.Second
	var expired []int

	for msgID, req := range tm.pendingBuilds {
		if tm.isRequestExpired(req, now, buildTimeout) {
			expired = append(expired, msgID)
			tm.handleExpiredRequest(req, msgID, now)
		}
	}
	return expired
}

// isRequestExpired checks if a build request has exceeded the timeout threshold.
func (tm *TunnelManager) isRequestExpired(req *buildRequest, now time.Time, timeout time.Duration) bool {
	return now.Sub(req.createdAt) > timeout
}

// handleExpiredRequest marks tunnel as failed and schedules cleanup.
func (tm *TunnelManager) handleExpiredRequest(req *buildRequest, msgID int, now time.Time) {
	pool := tm.getPoolForTunnel(req.isInbound)
	tunnelState, exists := pool.GetTunnel(req.tunnelID)
	if !exists {
		return
	}

	tunnelState.State = tunnel.TunnelFailed
	log.WithFields(logger.Fields{
		"tunnel_id":  req.tunnelID,
		"message_id": msgID,
		"age":        now.Sub(req.createdAt),
	}).Warn("Tunnel build timed out")

	tm.cleanupFailedTunnel(req.tunnelID, req.isInbound)
}

// removeExpiredFromMap deletes expired build requests from the pending map.
func (tm *TunnelManager) removeExpiredFromMap(expired []int) {
	for _, msgID := range expired {
		delete(tm.pendingBuilds, msgID)
	}
}

// logCleanupResults logs the number of expired requests cleaned up.
func (tm *TunnelManager) logCleanupResults(expired []int) {
	if len(expired) > 0 {
		log.WithField("expired_count", len(expired)).Info("Cleaned up expired build requests")
	}
}

// cleanupExpiredBuildByID removes a specific build request if it has expired.
// This is called via time.AfterFunc for immediate cleanup of timed-out requests,
// reducing memory usage between periodic cleanup cycles.
func (tm *TunnelManager) cleanupExpiredBuildByID(messageID int) {
	tm.buildMutex.Lock()
	defer tm.buildMutex.Unlock()

	req, exists := tm.pendingBuilds[messageID]
	if !exists {
		// Request already processed (either successfully or cleaned up)
		return
	}

	// Verify request has actually expired (90 second timeout per I2P spec)
	const buildTimeout = 90 * time.Second
	if time.Since(req.createdAt) > buildTimeout {
		delete(tm.pendingBuilds, messageID)

		// Mark tunnel as failed and schedule async cleanup
		pool := tm.getPoolForTunnel(req.isInbound)
		if tunnelState, exists := pool.GetTunnel(req.tunnelID); exists {
			tunnelState.State = tunnel.TunnelFailed
			tm.cleanupFailedTunnel(req.tunnelID, req.isInbound)
		}

		log.WithFields(logger.Fields{
			"message_id": messageID,
			"tunnel_id":  req.tunnelID,
			"age":        time.Since(req.createdAt),
		}).Debug("Cleaned up expired tunnel build via timeout")
	}
}

// DatabaseManager demonstrates database-related interface usage
// DatabaseManager demonstrates database-related interface usage
type DatabaseManager struct {
	netdb             NetDBStore
	retriever         NetDBRetriever
	floodfillSelector FloodfillSelector
	sessionProvider   SessionProvider
	factory           *I2NPMessageFactory
	ourRouterHash     common.Hash // Our router's identity hash for DatabaseSearchReply

	// Rate limiting for DatabaseLookup messages
	lookupLimiter struct {
		mu      sync.Mutex
		lookups map[common.Hash]time.Time // Track lookup frequency by source hash
	}
}

// NetDBStore defines the interface for storing network database entries.
// Implementations must dispatch to the appropriate storage method based on dataType:
//   - 0: RouterInfo
//   - 1: LeaseSet
//   - 3: LeaseSet2
//   - 5: EncryptedLeaseSet
//   - 7: MetaLeaseSet
type NetDBStore interface {
	Store(key common.Hash, data []byte, dataType byte) error
}

// NetDBRetriever defines the interface for retrieving RouterInfo entries
type NetDBRetriever interface {
	GetRouterInfoBytes(hash common.Hash) ([]byte, error)
	GetRouterInfoCount() int
}

// FloodfillSelector defines the interface for selecting closest floodfill routers
type FloodfillSelector interface {
	SelectFloodfillRouters(targetHash common.Hash, count int) ([]router_info.RouterInfo, error)
}

// TransportSession defines the interface for sending I2NP messages back to requesters
type TransportSession interface {
	QueueSendI2NP(msg I2NPMessage) error
	SendQueueSize() int
}

// SessionProvider defines the interface for obtaining transport sessions
type SessionProvider interface {
	GetSessionByHash(hash common.Hash) (TransportSession, error)
}

// NewDatabaseManager creates a new database manager with NetDB integration
func NewDatabaseManager(netdb NetDBStore) *DatabaseManager {
	dm := &DatabaseManager{
		netdb:             netdb,
		retriever:         nil, // Will be set later via SetRetriever
		floodfillSelector: nil, // Will be set later via SetFloodfillSelector
		sessionProvider:   nil, // Will be set later via SetSessionProvider
		factory:           NewI2NPMessageFactory(),
	}
	dm.lookupLimiter.lookups = make(map[common.Hash]time.Time)
	return dm
}

// SetRetriever sets the NetDB retriever for database operations
func (dm *DatabaseManager) SetRetriever(retriever NetDBRetriever) {
	dm.retriever = retriever
}

// SetFloodfillSelector sets the floodfill selector for selecting closest floodfill routers
func (dm *DatabaseManager) SetFloodfillSelector(selector FloodfillSelector) {
	dm.floodfillSelector = selector
}

// SetOurRouterHash sets our router's identity hash for use in DatabaseSearchReply messages
func (dm *DatabaseManager) SetOurRouterHash(hash common.Hash) {
	dm.ourRouterHash = hash
}

// SetSessionProvider sets the session provider for sending responses
func (dm *DatabaseManager) SetSessionProvider(provider SessionProvider) {
	dm.sessionProvider = provider
}

// SetPeerSelector sets the peer selector for the TunnelManager
func (mr *MessageRouter) SetPeerSelector(selector tunnel.PeerSelector) {
	mr.tunnelMgr.peerSelector = selector
	// Recreate pools with new selector if they exist
	if mr.tunnelMgr.inboundPool != nil || mr.tunnelMgr.outboundPool != nil {
		// Stop existing pools
		if mr.tunnelMgr.inboundPool != nil {
			mr.tunnelMgr.inboundPool.Stop()
		}
		if mr.tunnelMgr.outboundPool != nil {
			mr.tunnelMgr.outboundPool.Stop()
		}
		// Create new pools
		inboundConfig := tunnel.DefaultPoolConfig()
		inboundConfig.IsInbound = true
		mr.tunnelMgr.inboundPool = tunnel.NewTunnelPoolWithConfig(selector, inboundConfig)

		outboundConfig := tunnel.DefaultPoolConfig()
		outboundConfig.IsInbound = false
		mr.tunnelMgr.outboundPool = tunnel.NewTunnelPoolWithConfig(selector, outboundConfig)
	}
}

// SetSessionProvider configures the session provider for message routing responses.
// This method propagates the SessionProvider to both DatabaseManager and TunnelManager,
// enabling them to send I2NP response messages (DatabaseStore, DatabaseSearchReply, etc.)
// back through the appropriate transport sessions.
// The provider must implement SessionProvider interface with GetSessionByHash method.
func (mr *MessageRouter) SetSessionProvider(provider SessionProvider) {
	// Propagate to DatabaseManager for database operation responses
	mr.dbManager.SetSessionProvider(provider)

	// Propagate to TunnelManager for tunnel build responses
	mr.tunnelMgr.SetSessionProvider(provider)

	log.Debug("Session provider configured for message router")
}

// PerformLookup performs a database lookup using DatabaseReader interface and generates appropriate responses
func (dm *DatabaseManager) PerformLookup(reader DatabaseReader) error {
	// Check rate limit before processing
	from := reader.GetFrom()
	if !dm.rateLimitLookup(from) {
		log.WithField("from", fmt.Sprintf("%x", from[:8])).Warn("DatabaseLookup rate limited")
		return fmt.Errorf("lookup rate limit exceeded")
	}

	dm.logLookupRequest(reader)

	if dm.sessionProvider == nil {
		return dm.handleLookupWithoutSession(reader.GetKey())
	}

	return dm.performLookupWithSession(reader.GetKey(), reader.GetFrom())
}

// rateLimitLookup enforces rate limits on DatabaseLookup messages by source.
// Returns true if the lookup is allowed, false if rate limited.
func (dm *DatabaseManager) rateLimitLookup(from common.Hash) bool {
	const (
		minLookupInterval = 100 * time.Millisecond // Minimum 100ms between lookups from same source
		maxTrackedSources = 1000                   // Maximum number of sources to track
		cleanupAge        = 5 * time.Minute        // Clean entries older than 5 minutes
	)

	dm.lookupLimiter.mu.Lock()
	defer dm.lookupLimiter.mu.Unlock()

	lastLookup, exists := dm.lookupLimiter.lookups[from]
	now := time.Now()

	if exists && now.Sub(lastLookup) < minLookupInterval {
		return false // Rate limited
	}

	dm.lookupLimiter.lookups[from] = now

	// Periodically clean old entries to prevent unbounded growth
	if len(dm.lookupLimiter.lookups) > maxTrackedSources {
		for hash, ts := range dm.lookupLimiter.lookups {
			if now.Sub(ts) > cleanupAge {
				delete(dm.lookupLimiter.lookups, hash)
			}
		}
	}

	return true
}

// logLookupRequest logs the incoming database lookup request details.
func (dm *DatabaseManager) logLookupRequest(reader DatabaseReader) {
	key := reader.GetKey()
	from := reader.GetFrom()
	log.WithFields(logger.Fields{
		"key":   fmt.Sprintf("%x", key[:8]),
		"from":  fmt.Sprintf("%x", from[:8]),
		"flags": reader.GetFlags(),
	}).Debug("Performing database lookup")
}

// handleLookupWithoutSession performs lookup without sending responses for backward compatibility.
func (dm *DatabaseManager) handleLookupWithoutSession(key common.Hash) error {
	log.Debug("No session provider available, performing lookup without sending response")

	if dm.retriever == nil {
		log.Debug("No retriever available, cannot perform lookup")
		return nil
	}

	if data, err := dm.retrieveRouterInfo(key); err == nil {
		log.WithField("data_size", len(data)).Debug("RouterInfo found locally")
	} else {
		log.WithField("error", err).Debug("RouterInfo not found locally")
	}
	return nil
}

// performLookupWithSession attempts lookup and sends appropriate response message.
func (dm *DatabaseManager) performLookupWithSession(key, from common.Hash) error {
	if dm.retriever == nil {
		log.Debug("No retriever available, cannot perform lookup")
		return dm.sendDatabaseSearchReply(key, from)
	}

	data, err := dm.retrieveRouterInfo(key)
	if err == nil {
		return dm.sendDatabaseStoreResponse(key, data, from)
	}

	log.WithField("error", err).Debug("RouterInfo not found locally for remote lookup")
	return dm.sendDatabaseSearchReply(key, from)
}

// retrieveRouterInfo attempts to retrieve RouterInfo data from the NetDB
func (dm *DatabaseManager) retrieveRouterInfo(key common.Hash) ([]byte, error) {
	data, err := dm.retriever.GetRouterInfoBytes(key)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve RouterInfo: %w", err)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("RouterInfo not found for key %x", key[:8])
	}
	return data, nil
}

// sendDatabaseStoreResponse sends a DatabaseStore message back to the requester
func (dm *DatabaseManager) sendDatabaseStoreResponse(key common.Hash, data []byte, to common.Hash) error {
	// Create DatabaseStore message with the found RouterInfo
	response := NewDatabaseStore(key, data, 0) // RouterInfo type is 0
	return dm.sendResponse(response, to)
}

// sendDatabaseSearchReply sends a DatabaseSearchReply when RouterInfo is not found.
// This implements floodfill router functionality by selecting and suggesting the closest
// floodfill routers to the target hash using Kademlia XOR distance metric.
//
// Per I2P specification, when acting as a floodfill router:
// 1. If the requested key is not in our NetDB
// 2. We respond with a DatabaseSearchReply containing hashes of other floodfill routers
// 3. These routers are selected as the closest to the target key by XOR distance
// 4. Typically 3-7 peer hashes are included to help the requester continue their search
func (dm *DatabaseManager) sendDatabaseSearchReply(key, to common.Hash) error {
	// Select closest floodfill routers to suggest
	peerHashes := dm.selectClosestFloodfills(key)

	// Create DatabaseSearchReply with our router hash and suggested peers
	response := NewDatabaseSearchReply(key, dm.ourRouterHash, peerHashes)

	dm.logDatabaseSearchReply(key, to, len(peerHashes))
	return dm.sendResponse(response, to)
}

// selectClosestFloodfills selects the closest floodfill routers to suggest for a lookup.
// Returns up to 7 peer hashes (standard I2P practice) sorted by XOR distance to target.
// If no floodfill selector is configured, returns empty list for backward compatibility.
func (dm *DatabaseManager) selectClosestFloodfills(targetKey common.Hash) []common.Hash {
	const defaultFloodfillCount = 7 // I2P standard practice

	if !dm.hasFloodfillSelector() {
		return []common.Hash{}
	}

	floodfills, err := dm.fetchFloodfillRouters(targetKey, defaultFloodfillCount)
	if err != nil || len(floodfills) == 0 {
		return []common.Hash{}
	}

	return dm.convertRoutersToHashes(floodfills)
}

// hasFloodfillSelector checks if a floodfill selector is configured.
func (dm *DatabaseManager) hasFloodfillSelector() bool {
	if dm.floodfillSelector == nil {
		log.Debug("No floodfill selector available, returning empty peer list")
		return false
	}
	return true
}

// fetchFloodfillRouters retrieves floodfill routers for the target key.
func (dm *DatabaseManager) fetchFloodfillRouters(targetKey common.Hash, count int) ([]router_info.RouterInfo, error) {
	floodfills, err := dm.floodfillSelector.SelectFloodfillRouters(targetKey, count)
	if err != nil {
		log.WithError(err).Warn("Failed to select floodfill routers for DatabaseSearchReply")
		return nil, err
	}

	if len(floodfills) == 0 {
		log.Debug("No floodfill routers available for peer suggestions")
	}

	return floodfills, nil
}

// convertRoutersToHashes converts RouterInfo list to hash list, skipping invalid entries.
func (dm *DatabaseManager) convertRoutersToHashes(floodfills []router_info.RouterInfo) []common.Hash {
	peerHashes := make([]common.Hash, 0, len(floodfills))

	for _, ri := range floodfills {
		if hash := dm.extractValidHash(ri); !dm.isEmptyHash(hash) {
			peerHashes = append(peerHashes, hash)
		}
	}

	return peerHashes
}

// extractValidHash extracts identity hash from RouterInfo, returning empty hash on error.
func (dm *DatabaseManager) extractValidHash(ri router_info.RouterInfo) common.Hash {
	hash, err := ri.IdentHash()
	if err != nil {
		log.WithError(err).Debug("Skipping invalid RouterInfo in floodfill selection")
		return common.Hash{}
	}
	return hash
}

// isEmptyHash checks if a hash is the zero value.
func (dm *DatabaseManager) isEmptyHash(hash common.Hash) bool {
	var emptyHash common.Hash
	return hash == emptyHash
}

// logDatabaseSearchReply logs details about the DatabaseSearchReply being sent.
func (dm *DatabaseManager) logDatabaseSearchReply(key, to common.Hash, peerCount int) {
	log.WithFields(logger.Fields{
		"target_key":      fmt.Sprintf("%x", key[:8]),
		"destination":     fmt.Sprintf("%x", to[:8]),
		"suggested_peers": peerCount,
		"our_router_hash": fmt.Sprintf("%x", dm.ourRouterHash[:8]),
	}).Debug("Sending DatabaseSearchReply with floodfill peer suggestions")
}

// sendResponse sends an I2NP message response using the session provider
func (dm *DatabaseManager) sendResponse(response interface{}, to common.Hash) error {
	if dm.sessionProvider == nil {
		return fmt.Errorf("no session provider available for sending response")
	}

	session, err := dm.sessionProvider.GetSessionByHash(to)
	if err != nil {
		return fmt.Errorf("failed to get session for %x: %w", to[:8], err)
	}

	// Convert response to I2NPMessage interface
	var msg I2NPMessage
	switch r := response.(type) {
	case *DatabaseStore:
		msg = dm.createDatabaseStoreMessage(r)
	case *DatabaseSearchReply:
		msg = dm.createDatabaseSearchReplyMessage(r)
	default:
		return fmt.Errorf("unsupported response type: %T", response)
	}

	// Check if message creation failed
	if msg == nil {
		return fmt.Errorf("failed to create response message for %x", to[:8])
	}

	// Send the response
	if err := session.QueueSendI2NP(msg); err != nil {
		return fmt.Errorf("failed to queue response message for %x: %w", to[:8], err)
	}
	log.WithFields(logger.Fields{
		"message_type": msg.Type(),
		"destination":  fmt.Sprintf("%x", to[:8]),
	}).Debug("Queued response message")
	return nil
}

// createDatabaseStoreMessage creates an I2NP message from DatabaseStore.
// Uses MarshalPayload (payload-only serialization) rather than MarshalBinary
// (full I2NP message) because this function creates its own BaseI2NPMessage
// wrapper. This also avoids a panic when the store's embedded BaseI2NPMessage
// is nil (e.g., from deserialized/corrupted data).
func (dm *DatabaseManager) createDatabaseStoreMessage(store *DatabaseStore) I2NPMessage {
	msg := NewBaseI2NPMessage(I2NP_MESSAGE_TYPE_DATABASE_STORE)
	data, err := store.MarshalPayload()
	if err != nil {
		log.WithField("error", err).Error("Failed to marshal DatabaseStore payload")
		return nil
	}
	msg.SetData(data)
	return msg
}

// createDatabaseSearchReplyMessage creates an I2NP message from DatabaseSearchReply.
// Uses MarshalPayload (payload-only serialization) rather than MarshalBinary
// to avoid a panic when the reply's embedded BaseI2NPMessage is nil.
func (dm *DatabaseManager) createDatabaseSearchReplyMessage(reply *DatabaseSearchReply) I2NPMessage {
	msg := NewBaseI2NPMessage(I2NP_MESSAGE_TYPE_DATABASE_SEARCH_REPLY)
	data, err := reply.MarshalPayload()
	if err != nil {
		log.WithField("error", err).Error("Failed to marshal DatabaseSearchReply payload")
		return nil
	}
	msg.SetData(data)
	return msg
}

// validateGzipSize validates gzip compressed data to prevent decompression bombs.
// It checks that the uncompressed size doesn't exceed maxUncompressed and that
// the compression ratio doesn't exceed maxRatio.
// Returns the uncompressed size and an error if validation fails.
func validateGzipSize(data []byte, maxUncompressed, maxRatio int) (int, error) {
	gr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return 0, fmt.Errorf("invalid gzip data: %w", err)
	}
	defer gr.Close()

	// Use limited reader to prevent full decompression of malicious data
	lr := &io.LimitedReader{R: gr, N: int64(maxUncompressed + 1)}
	n, _ := io.Copy(io.Discard, lr)

	if n > int64(maxUncompressed) {
		return int(n), fmt.Errorf("uncompressed size exceeds limit (%d > %d)", n, maxUncompressed)
	}

	ratio := float64(n) / float64(len(data))
	if ratio > float64(maxRatio) {
		return int(n), fmt.Errorf("compression ratio too high (%.2f:1 > %d:1)", ratio, maxRatio)
	}

	return int(n), nil
}

// StoreData stores data using DatabaseWriter interface and NetDB integration
func (dm *DatabaseManager) StoreData(writer DatabaseWriter) error {
	key := writer.GetStoreKey()
	data := writer.GetStoreData()
	dataType := writer.GetStoreType()

	// Validate data before storing
	if err := validateStoreData(data, dataType); err != nil {
		return err
	}

	log.WithFields(logger.Fields{
		"data_size": len(data),
		"data_type": dataType,
		"key":       fmt.Sprintf("%x", key[:8]),
	}).Debug("Storing data in NetDB")

	if dm.netdb != nil {
		return dm.netdb.Store(key, data, dataType)
	}

	return fmt.Errorf("no NetDB available for storage")
}

// validateStoreData validates data size and compression before storing.
func validateStoreData(data []byte, dataType byte) error {
	// I2P spec: RouterInfo is gzip-compressed, typical size 1-2 KB compressed, 3-10 KB uncompressed
	const (
		MaxCompressedSize   = 20 * 1024  // 20 KB compressed (generous limit)
		MaxUncompressedSize = 100 * 1024 // 100 KB uncompressed (generous limit)
		MaxCompressionRatio = 100        // Detect decompression bombs
	)

	// Validate data size before processing to prevent resource exhaustion
	if len(data) > MaxCompressedSize {
		log.WithFields(logger.Fields{
			"data_size": len(data),
			"max_size":  MaxCompressedSize,
		}).Warn("Rejecting oversized database store data")
		return fmt.Errorf("database store data too large: %d bytes (max %d)", len(data), MaxCompressedSize)
	}

	// For RouterInfo (type 0), validate compression if data appears compressed
	if dataType == DATABASE_STORE_TYPE_ROUTER_INFO && len(data) > 2 {
		return validateRouterInfoCompression(data, MaxUncompressedSize, MaxCompressionRatio)
	}

	return nil
}

// validateRouterInfoCompression checks gzip-compressed RouterInfo for decompression bombs.
func validateRouterInfoCompression(data []byte, maxUncompressed, maxRatio int) error {
	// Check if data starts with gzip magic number (0x1f 0x8b)
	if data[0] != 0x1f || data[1] != 0x8b {
		return nil // Not gzip-compressed, skip validation
	}

	// Validate decompression bomb risk before processing
	uncompressedSize, err := validateGzipSize(data, maxUncompressed, maxRatio)
	if err != nil {
		log.WithFields(logger.Fields{
			"compressed_size":   len(data),
			"uncompressed_size": uncompressedSize,
			"error":             err,
		}).Warn("Rejecting suspicious compressed RouterInfo")
		return fmt.Errorf("invalid compressed RouterInfo: %w", err)
	}

	log.WithFields(logger.Fields{
		"compressed_size":   len(data),
		"uncompressed_size": uncompressedSize,
	}).Debug("Validated gzip-compressed RouterInfo")

	return nil
}

// SessionManager demonstrates session-related interface usage
type SessionManager struct{}

// NewSessionManager creates a new session manager
func NewSessionManager() *SessionManager {
	return &SessionManager{}
}

// ProcessKeys processes session keys using SessionKeyProvider interface.
// Note: This is a stub for ECIES-only routers. Key material is intentionally
// NOT logged to avoid leaking sensitive cryptographic data.
func (sm *SessionManager) ProcessKeys(provider SessionKeyProvider) error {
	// Access the keys to validate the interface, but do not log key material
	_ = provider.GetReplyKey()
	_ = provider.GetLayerKey()
	_ = provider.GetIVKey()

	log.Debug("Processing session keys (stub — ECIES-only router)")

	return nil
}

// ProcessTags processes session tags using SessionTagProvider interface.
// Note: This is a stub for ECIES-only routers. Tag data is intentionally
// NOT logged to avoid leaking sensitive cryptographic data.
func (sm *SessionManager) ProcessTags(provider SessionTagProvider) error {
	count := provider.GetTagCount()

	log.WithField("tag_count", count).Debug("Processing session tags (stub — ECIES-only router)")

	return nil
}

// MessageRouterConfig represents configuration for message routing
type MessageRouterConfig struct {
	MaxRetries     int
	DefaultTimeout time.Duration
	EnableLogging  bool
}

// MessageRouter demonstrates advanced interface-based routing
type MessageRouter struct {
	config     MessageRouterConfig
	processor  *MessageProcessor
	dbManager  *DatabaseManager
	tunnelMgr  *TunnelManager
	sessionMgr *SessionManager
}

// NewMessageRouter creates a new message router
func NewMessageRouter(config MessageRouterConfig) *MessageRouter {
	return &MessageRouter{
		config:     config,
		processor:  NewMessageProcessor(),
		dbManager:  NewDatabaseManager(nil), // Will be set later via SetNetDB
		tunnelMgr:  NewTunnelManager(nil),   // Will be set later via SetPeerSelector
		sessionMgr: NewSessionManager(),
	}
}

// SetNetDB sets the NetDB store for database operations.
// If the netdb implements FloodfillSelector, it will also be configured for floodfill functionality.
func (mr *MessageRouter) SetNetDB(netdb NetDBStore) {
	mr.dbManager = NewDatabaseManager(netdb)

	// If NetDB also implements FloodfillSelector, enable floodfill functionality
	if selector, ok := netdb.(FloodfillSelector); ok {
		mr.dbManager.SetFloodfillSelector(selector)
		log.Debug("Floodfill selector configured for message router")
	}

	// If NetDB also implements NetDBRetriever, configure retriever
	if retriever, ok := netdb.(NetDBRetriever); ok {
		mr.dbManager.SetRetriever(retriever)
		log.Debug("NetDB retriever configured for message router")
	}

	// Set database manager on processor for DatabaseLookup message handling
	mr.processor.SetDatabaseManager(mr.dbManager)
}

// SetOurRouterHash sets our router's identity hash for use in DatabaseSearchReply messages.
// This should be called during router initialization with the router's own identity hash.
// The hash is used in DatabaseSearchReply "from" field to indicate which router sent the reply.
func (mr *MessageRouter) SetOurRouterHash(hash common.Hash) {
	mr.dbManager.SetOurRouterHash(hash)
	log.WithField("router_hash", fmt.Sprintf("%x", hash[:8])).Debug("Configured router identity for floodfill responses")
}

// RouteMessage routes messages based on their interfaces
func (mr *MessageRouter) RouteMessage(msg I2NPMessage) error {
	// Log message if enabled
	if mr.config.EnableLogging {
		log.WithFields(logger.Fields{
			"message_type": msg.Type(),
			"message_id":   msg.MessageID(),
		}).Debug("Routing message")
	}

	// Check for expiration
	if time.Now().After(msg.Expiration()) {
		return fmt.Errorf("message %d has expired", msg.MessageID())
	}

	// Process using the appropriate interface
	return mr.processor.ProcessMessage(msg)
}

// RouteDatabaseMessage routes database-related messages
func (mr *MessageRouter) RouteDatabaseMessage(msg interface{}) error {
	if reader, ok := msg.(DatabaseReader); ok {
		return mr.dbManager.PerformLookup(reader)
	}

	if writer, ok := msg.(DatabaseWriter); ok {
		return mr.dbManager.StoreData(writer)
	}

	return fmt.Errorf("message does not implement database interfaces")
}

// RouteTunnelMessage routes tunnel-related messages
func (mr *MessageRouter) RouteTunnelMessage(msg interface{}) error {
	if builder, ok := msg.(TunnelBuilder); ok {
		return mr.tunnelMgr.BuildTunnelWithBuilder(builder)
	}

	if handler, ok := msg.(TunnelReplyHandler); ok {
		// Extract message ID from the message interface
		var messageID int
		if i2npMsg, ok := msg.(I2NPMessage); ok {
			messageID = i2npMsg.MessageID()
		}
		return mr.tunnelMgr.ProcessTunnelReply(handler, messageID)
	}

	return fmt.Errorf("message does not implement tunnel interfaces")
}

// GetProcessor returns the underlying MessageProcessor for direct access.
// This is used by the router to set up garlic clove forwarding.
func (mr *MessageRouter) GetProcessor() *MessageProcessor {
	return mr.processor
}

// Helper functions have been moved to utils.go
