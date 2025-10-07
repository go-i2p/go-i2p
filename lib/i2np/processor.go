package i2np

import (
	"fmt"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/sirupsen/logrus"
)

// MessageProcessor demonstrates interface-based message processing
type MessageProcessor struct {
	factory *I2NPMessageFactory
}

// NewMessageProcessor creates a new message processor
func NewMessageProcessor() *MessageProcessor {
	return &MessageProcessor{
		factory: NewI2NPMessageFactory(),
	}
}

// ProcessMessage processes any I2NP message using interfaces
func (p *MessageProcessor) ProcessMessage(msg I2NPMessage) error {
	switch msg.Type() {
	case I2NP_MESSAGE_TYPE_DATA:
		return p.processDataMessage(msg)
	case I2NP_MESSAGE_TYPE_DELIVERY_STATUS:
		return p.processDeliveryStatusMessage(msg)
	case I2NP_MESSAGE_TYPE_TUNNEL_DATA:
		return p.processTunnelDataMessage(msg)
	default:
		return fmt.Errorf("unknown message type: %d", msg.Type())
	}
}

// processDataMessage processes data messages using PayloadCarrier interface
func (p *MessageProcessor) processDataMessage(msg I2NPMessage) error {
	if payloadCarrier, ok := msg.(PayloadCarrier); ok {
		payload := payloadCarrier.GetPayload()
		log.WithField("payload_size", len(payload)).Debug("Processing data message")
		return nil
	}
	return fmt.Errorf("message does not implement PayloadCarrier interface")
}

// processDeliveryStatusMessage processes delivery status messages using StatusReporter interface
func (p *MessageProcessor) processDeliveryStatusMessage(msg I2NPMessage) error {
	if statusReporter, ok := msg.(StatusReporter); ok {
		msgID := statusReporter.GetStatusMessageID()
		timestamp := statusReporter.GetTimestamp()
		log.WithFields(logrus.Fields{
			"message_id": msgID,
			"timestamp":  timestamp,
		}).Debug("Processing delivery status")
		return nil
	}
	return fmt.Errorf("message does not implement StatusReporter interface")
}

// processTunnelDataMessage processes tunnel data messages using TunnelCarrier interface
func (p *MessageProcessor) processTunnelDataMessage(msg I2NPMessage) error {
	if tunnelCarrier, ok := msg.(TunnelCarrier); ok {
		data := tunnelCarrier.GetTunnelData()
		log.WithField("data_size", len(data)).Debug("Processing tunnel data message")
		return nil
	}
	return fmt.Errorf("message does not implement TunnelCarrier interface")
}

// TunnelManager coordinates tunnel building and management
type TunnelManager struct {
	pool            *tunnel.Pool
	sessionProvider SessionProvider
	peerSelector    tunnel.PeerSelector
}

// NewTunnelManager creates a new tunnel manager
func NewTunnelManager(peerSelector tunnel.PeerSelector) *TunnelManager {
	pool := tunnel.NewTunnelPool(peerSelector)
	return &TunnelManager{
		pool:         pool,
		peerSelector: peerSelector,
	}
}

// SetSessionProvider sets the session provider for sending tunnel build messages
func (tm *TunnelManager) SetSessionProvider(provider SessionProvider) {
	tm.sessionProvider = provider
}

// BuildTunnel builds a tunnel using TunnelBuilder interface
func (tm *TunnelManager) BuildTunnel(builder TunnelBuilder) error {
	if tm.peerSelector == nil {
		return fmt.Errorf("no peer selector configured")
	}

	records := builder.GetBuildRecords()
	count := builder.GetRecordCount()

	if count == 0 {
		return fmt.Errorf("no build records provided")
	}

	// Select peers for tunnel hops (excluding ourselves)
	peers, err := tm.peerSelector.SelectPeers(count, nil)
	if err != nil {
		return fmt.Errorf("failed to select peers for tunnel: %w", err)
	}

	if len(peers) < count {
		return fmt.Errorf("insufficient peers available: need %d, got %d", count, len(peers))
	}

	// Generate tunnel ID for this tunnel
	tunnelID := tm.generateTunnelID()

	// Create tunnel state tracking
	tunnelState := &tunnel.TunnelState{
		ID:        tunnelID,
		Hops:      make([]common.Hash, count),
		State:     tunnel.TunnelBuilding,
		CreatedAt: time.Now(),
		Responses: make([]tunnel.BuildResponse, 0, count),
	}

	// Populate hops with selected peer hashes
	for i, peer := range peers[:count] {
		tunnelState.Hops[i] = peer.IdentHash()
	}

	// Add tunnel to pool for tracking
	tm.pool.AddTunnel(tunnelState)

	// Send build requests to each hop
	return tm.sendTunnelBuildRequests(records, peers[:count], tunnelID)
}

// generateTunnelID generates a new unique tunnel ID
func (tm *TunnelManager) generateTunnelID() tunnel.TunnelID {
	// Simple tunnel ID generation - in production this should be cryptographically secure
	return tunnel.TunnelID(time.Now().UnixNano() & 0xFFFFFFFF)
}

// sendTunnelBuildRequests sends tunnel build requests to each selected peer
func (tm *TunnelManager) sendTunnelBuildRequests(records []BuildRequestRecord, peers []router_info.RouterInfo, tunnelID tunnel.TunnelID) error {
	if tm.sessionProvider == nil {
		return fmt.Errorf("no session provider available for sending tunnel build requests")
	}

	log.WithFields(logrus.Fields{
		"tunnel_id":  tunnelID,
		"peer_count": len(peers),
	}).Debug("Sending tunnel build requests")

	// Send build request to each peer
	for i := range records {
		if i >= len(peers) {
			break
		}

		peer := peers[i]
		peerHash := peer.IdentHash()

		// Get transport session to this peer
		_, err := tm.sessionProvider.GetSessionByHash(peerHash)
		if err != nil {
			log.WithFields(logrus.Fields{
				"peer_hash": fmt.Sprintf("%x", peerHash[:8]),
				"error":     err,
			}).Warn("Failed to get session for peer")
			continue
		}

		// Create a tunnel build message (simplified - would need proper I2NP message creation)
		log.WithFields(logrus.Fields{
			"hop_index": i,
			"peer_hash": fmt.Sprintf("%x", peerHash[:8]),
		}).Debug("Sending build request to hop")
		// In a real implementation, we would create a proper TunnelBuild I2NP message
		// session.QueueSendI2NP(buildMessage)
	}

	log.WithField("tunnel_id", tunnelID).Debug("Tunnel build requests sent")
	return nil
}

// ProcessTunnelReply processes tunnel build replies using TunnelReplyHandler interface
func (tm *TunnelManager) ProcessTunnelReply(handler TunnelReplyHandler) error {
	records := handler.GetReplyRecords()
	log.WithField("record_count", len(records)).Debug("Processing tunnel reply")

	return handler.ProcessReply()
}

// DatabaseManager demonstrates database-related interface usage
type DatabaseManager struct {
	netdb           NetDBStore
	retriever       NetDBRetriever
	sessionProvider SessionProvider
	factory         *I2NPMessageFactory
}

// NetDBStore defines the interface for storing RouterInfo entries
type NetDBStore interface {
	StoreRouterInfo(key common.Hash, data []byte, dataType byte) error
}

// NetDBRetriever defines the interface for retrieving RouterInfo entries
type NetDBRetriever interface {
	GetRouterInfoBytes(hash common.Hash) ([]byte, error)
	GetRouterInfoCount() int
}

// TransportSession defines the interface for sending I2NP messages back to requesters
type TransportSession interface {
	QueueSendI2NP(msg I2NPMessage)
	SendQueueSize() int
}

// SessionProvider defines the interface for obtaining transport sessions
type SessionProvider interface {
	GetSessionByHash(hash common.Hash) (TransportSession, error)
}

// NewDatabaseManager creates a new database manager with NetDB integration
func NewDatabaseManager(netdb NetDBStore) *DatabaseManager {
	return &DatabaseManager{
		netdb:           netdb,
		retriever:       nil, // Will be set later via SetRetriever
		sessionProvider: nil, // Will be set later via SetSessionProvider
		factory:         NewI2NPMessageFactory(),
	}
}

// SetRetriever sets the NetDB retriever for database operations
func (dm *DatabaseManager) SetRetriever(retriever NetDBRetriever) {
	dm.retriever = retriever
}

// SetSessionProvider sets the session provider for sending responses
func (dm *DatabaseManager) SetSessionProvider(provider SessionProvider) {
	dm.sessionProvider = provider
}

// SetPeerSelector sets the peer selector for the TunnelManager
func (mr *MessageRouter) SetPeerSelector(selector tunnel.PeerSelector) {
	mr.tunnelMgr.peerSelector = selector
	if mr.tunnelMgr.pool != nil {
		mr.tunnelMgr.pool = tunnel.NewTunnelPool(selector)
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
	key := reader.GetKey()
	from := reader.GetFrom()
	flags := reader.GetFlags()

	log.WithFields(logrus.Fields{
		"key":   fmt.Sprintf("%x", key[:8]),
		"from":  fmt.Sprintf("%x", from[:8]),
		"flags": flags,
	}).Debug("Performing database lookup")

	// If no session provider is available, just perform the lookup logic without sending responses
	// This maintains backward compatibility with existing tests
	if dm.sessionProvider == nil {
		log.Debug("No session provider available, performing lookup without sending response")
		if dm.retriever != nil {
			if data, err := dm.retrieveRouterInfo(key); err == nil {
				log.WithField("data_size", len(data)).Debug("RouterInfo found locally")
			} else {
				log.WithField("error", err).Debug("RouterInfo not found locally")
			}
		} else {
			log.Debug("No retriever available, cannot perform lookup")
		}
		return nil
	}

	// Attempt to retrieve RouterInfo from NetDB
	if dm.retriever != nil {
		if data, err := dm.retrieveRouterInfo(key); err == nil {
			// RouterInfo found - send DatabaseStore response
			return dm.sendDatabaseStoreResponse(key, data, from)
		} else {
			log.WithField("error", err).Debug("RouterInfo not found locally for remote lookup")
		}
	} else {
		log.Debug("No retriever available, cannot perform lookup")
	}

	// RouterInfo not found - send DatabaseSearchReply response
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

// sendDatabaseSearchReply sends a DatabaseSearchReply when RouterInfo is not found
func (dm *DatabaseManager) sendDatabaseSearchReply(key common.Hash, to common.Hash) error {
	// Create DatabaseSearchReply with empty peer list (we're not implementing peer suggestions for MVP)
	response := NewDatabaseSearchReply(key, common.Hash{}, []common.Hash{}) // TODO: Should use our router hash as from
	return dm.sendResponse(response, to)
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

	// Send the response
	session.QueueSendI2NP(msg)
	log.WithFields(logrus.Fields{
		"message_type": msg.Type(),
		"destination":  fmt.Sprintf("%x", to[:8]),
	}).Debug("Queued response message")
	return nil
}

// createDatabaseStoreMessage creates an I2NP message from DatabaseStore
func (dm *DatabaseManager) createDatabaseStoreMessage(store *DatabaseStore) I2NPMessage {
	msg := NewBaseI2NPMessage(I2NP_MESSAGE_TYPE_DATABASE_STORE)
	if data, err := store.MarshalBinary(); err == nil {
		msg.SetData(data)
	} else {
		log.WithField("error", err).Error("Failed to marshal DatabaseStore")
	}
	return msg
}

// createDatabaseSearchReplyMessage creates an I2NP message from DatabaseSearchReply
func (dm *DatabaseManager) createDatabaseSearchReplyMessage(reply *DatabaseSearchReply) I2NPMessage {
	msg := NewBaseI2NPMessage(I2NP_MESSAGE_TYPE_DATABASE_SEARCH_REPLY)
	if data, err := reply.MarshalBinary(); err == nil {
		msg.SetData(data)
	} else {
		log.WithField("error", err).Error("Failed to marshal DatabaseSearchReply")
	}
	return msg
}

// StoreData stores data using DatabaseWriter interface and NetDB integration
func (dm *DatabaseManager) StoreData(writer DatabaseWriter) error {
	key := writer.GetStoreKey()
	data := writer.GetStoreData()
	dataType := writer.GetStoreType()

	log.WithFields(logrus.Fields{
		"data_size": len(data),
		"data_type": dataType,
		"key":       fmt.Sprintf("%x", key[:8]),
	}).Debug("Storing RouterInfo data")

	if dm.netdb != nil {
		return dm.netdb.StoreRouterInfo(key, data, dataType)
	}

	return fmt.Errorf("no NetDB available for storage")
}

// SessionManager demonstrates session-related interface usage
type SessionManager struct{}

// NewSessionManager creates a new session manager
func NewSessionManager() *SessionManager {
	return &SessionManager{}
}

// ProcessKeys processes session keys using SessionKeyProvider interface
func (sm *SessionManager) ProcessKeys(provider SessionKeyProvider) error {
	replyKey := provider.GetReplyKey()
	layerKey := provider.GetLayerKey()
	ivKey := provider.GetIVKey()

	log.WithFields(logrus.Fields{
		"reply_key": fmt.Sprintf("%x", replyKey[:8]),
		"layer_key": fmt.Sprintf("%x", layerKey[:8]),
		"iv_key":    fmt.Sprintf("%x", ivKey[:8]),
	}).Debug("Processing session keys")

	return nil
}

// ProcessTags processes session tags using SessionTagProvider interface
func (sm *SessionManager) ProcessTags(provider SessionTagProvider) error {
	tags := provider.GetReplyTags()
	count := provider.GetTagCount()

	log.WithField("tag_count", count).Debug("Processing session tags")
	for i, tag := range tags {
		if i >= count {
			break
		}
		// Convert session tag to bytes for display
		tagBytes := tag.Bytes()
		log.WithFields(logrus.Fields{
			"tag_index": i,
			"tag":       fmt.Sprintf("%x", tagBytes[:8]),
		}).Debug("Processing session tag")
	}

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

// SetNetDB sets the NetDB store for database operations
func (mr *MessageRouter) SetNetDB(netdb NetDBStore) {
	mr.dbManager = NewDatabaseManager(netdb)
}

// RouteMessage routes messages based on their interfaces
func (mr *MessageRouter) RouteMessage(msg I2NPMessage) error {
	// Log message if enabled
	if mr.config.EnableLogging {
		log.WithFields(logrus.Fields{
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
		return mr.tunnelMgr.BuildTunnel(builder)
	}

	if handler, ok := msg.(TunnelReplyHandler); ok {
		return mr.tunnelMgr.ProcessTunnelReply(handler)
	}

	return fmt.Errorf("message does not implement tunnel interfaces")
}

// Helper functions have been moved to utils.go
