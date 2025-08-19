package i2np

import (
	"fmt"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/go-i2p/lib/tunnel"
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
		fmt.Printf("Processing data message with %d bytes of payload\n", len(payload))
		return nil
	}
	return fmt.Errorf("message does not implement PayloadCarrier interface")
}

// processDeliveryStatusMessage processes delivery status messages using StatusReporter interface
func (p *MessageProcessor) processDeliveryStatusMessage(msg I2NPMessage) error {
	if statusReporter, ok := msg.(StatusReporter); ok {
		msgID := statusReporter.GetStatusMessageID()
		timestamp := statusReporter.GetTimestamp()
		fmt.Printf("Processing delivery status for message %d at %v\n", msgID, timestamp)
		return nil
	}
	return fmt.Errorf("message does not implement StatusReporter interface")
}

// processTunnelDataMessage processes tunnel data messages using TunnelCarrier interface
func (p *MessageProcessor) processTunnelDataMessage(msg I2NPMessage) error {
	if tunnelCarrier, ok := msg.(TunnelCarrier); ok {
		data := tunnelCarrier.GetTunnelData()
		fmt.Printf("Processing tunnel data message with %d bytes\n", len(data))
		return nil
	}
	return fmt.Errorf("message does not implement TunnelCarrier interface")
}

// TunnelManager demonstrates tunnel-related interface usage
type TunnelManager struct{}

// NewTunnelManager creates a new tunnel manager
func NewTunnelManager() *TunnelManager {
	return &TunnelManager{}
}

// BuildTunnel builds a tunnel using TunnelBuilder interface
func (tm *TunnelManager) BuildTunnel(builder TunnelBuilder) error {
	records := builder.GetBuildRecords()
	count := builder.GetRecordCount()

	fmt.Printf("Building tunnel with %d records\n", count)
	for i, record := range records {
		if i >= count {
			break
		}
		fmt.Printf("Record %d: Receive Tunnel %d, Next Tunnel %d\n",
			i, record.GetReceiveTunnel(), record.GetNextTunnel())
	}

	return nil
}

// ProcessTunnelReply processes tunnel build replies using TunnelReplyHandler interface
func (tm *TunnelManager) ProcessTunnelReply(handler TunnelReplyHandler) error {
	records := handler.GetReplyRecords()
	fmt.Printf("Processing tunnel reply with %d records\n", len(records))

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

// PerformLookup performs a database lookup using DatabaseReader interface and generates appropriate responses
func (dm *DatabaseManager) PerformLookup(reader DatabaseReader) error {
	key := reader.GetKey()
	from := reader.GetFrom()
	flags := reader.GetFlags()

	fmt.Printf("Performing lookup for key %x from %x with flags %d\n",
		key[:8], from[:8], flags)

	// If no session provider is available, just perform the lookup logic without sending responses
	// This maintains backward compatibility with existing tests
	if dm.sessionProvider == nil {
		fmt.Println("No session provider available, performing lookup without sending response")
		if dm.retriever != nil {
			if data, err := dm.retrieveRouterInfo(key); err == nil {
				fmt.Printf("RouterInfo found locally: %d bytes\n", len(data))
			} else {
				fmt.Printf("RouterInfo not found locally: %v\n", err)
			}
		} else {
			fmt.Println("No retriever available, cannot perform lookup")
		}
		return nil
	}

	// Attempt to retrieve RouterInfo from NetDB
	if dm.retriever != nil {
		if data, err := dm.retrieveRouterInfo(key); err == nil {
			// RouterInfo found - send DatabaseStore response
			return dm.sendDatabaseStoreResponse(key, data, from)
		} else {
			fmt.Printf("RouterInfo not found locally: %v\n", err)
		}
	} else {
		fmt.Println("No retriever available, cannot perform lookup")
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
	fmt.Printf("Queued response message type %d for %x\n", msg.Type(), to[:8])
	return nil
}

// createDatabaseStoreMessage creates an I2NP message from DatabaseStore
func (dm *DatabaseManager) createDatabaseStoreMessage(store *DatabaseStore) I2NPMessage {
	msg := NewBaseI2NPMessage(I2NP_MESSAGE_TYPE_DATABASE_STORE)
	if data, err := store.MarshalBinary(); err == nil {
		msg.SetData(data)
	} else {
		fmt.Printf("Failed to marshal DatabaseStore: %v\n", err)
	}
	return msg
}

// createDatabaseSearchReplyMessage creates an I2NP message from DatabaseSearchReply
func (dm *DatabaseManager) createDatabaseSearchReplyMessage(reply *DatabaseSearchReply) I2NPMessage {
	msg := NewBaseI2NPMessage(I2NP_MESSAGE_TYPE_DATABASE_SEARCH_REPLY)
	if data, err := reply.MarshalBinary(); err == nil {
		msg.SetData(data)
	} else {
		fmt.Printf("Failed to marshal DatabaseSearchReply: %v\n", err)
	}
	return msg
}

// StoreData stores data using DatabaseWriter interface and NetDB integration
func (dm *DatabaseManager) StoreData(writer DatabaseWriter) error {
	key := writer.GetStoreKey()
	data := writer.GetStoreData()
	dataType := writer.GetStoreType()

	fmt.Printf("Storing %d bytes of type %d for key %x\n",
		len(data), dataType, key[:8])

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

	fmt.Printf("Processing session keys: reply=%x, layer=%x, iv=%x\n",
		replyKey[:8], layerKey[:8], ivKey[:8])

	return nil
}

// ProcessTags processes session tags using SessionTagProvider interface
func (sm *SessionManager) ProcessTags(provider SessionTagProvider) error {
	tags := provider.GetReplyTags()
	count := provider.GetTagCount()

	fmt.Printf("Processing %d session tags\n", count)
	for i, tag := range tags {
		if i >= count {
			break
		}
		// Convert session tag to bytes for display
		tagBytes := tag.Bytes()
		fmt.Printf("Tag %d: %x\n", i, tagBytes[:8])
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
		tunnelMgr:  NewTunnelManager(),
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
		fmt.Printf("Routing message type %d with ID %d\n", msg.Type(), msg.MessageID())
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

// Helper functions for creating common interface combinations

// CreateTunnelRecord creates a build request record with interface methods
func CreateTunnelRecord(receiveTunnel, nextTunnel tunnel.TunnelID,
	ourIdent, nextIdent common.Hash,
) TunnelIdentifier {
	return &BuildRequestRecord{
		ReceiveTunnel: receiveTunnel,
		NextTunnel:    nextTunnel,
		OurIdent:      ourIdent,
		NextIdent:     nextIdent,
	}
}

// CreateDatabaseQuery creates a database lookup with interface methods
func CreateDatabaseQuery(key, from common.Hash, flags byte) DatabaseReader {
	return &DatabaseLookup{
		Key:   key,
		From:  from,
		Flags: flags,
	}
}

// CreateDatabaseEntry creates a database store with interface methods
func CreateDatabaseEntry(key common.Hash, data []byte, dataType byte) DatabaseWriter {
	return &DatabaseStore{
		Key:  key,
		Data: data,
		Type: dataType,
	}
}
