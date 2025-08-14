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
type DatabaseManager struct{}

// NewDatabaseManager creates a new database manager
func NewDatabaseManager() *DatabaseManager {
	return &DatabaseManager{}
}

// PerformLookup performs a database lookup using DatabaseReader interface
func (dm *DatabaseManager) PerformLookup(reader DatabaseReader) error {
	key := reader.GetKey()
	from := reader.GetFrom()
	flags := reader.GetFlags()

	fmt.Printf("Performing lookup for key %x from %x with flags %d\n",
		key[:8], from[:8], flags)

	return nil
}

// StoreData stores data using DatabaseWriter interface
func (dm *DatabaseManager) StoreData(writer DatabaseWriter) error {
	key := writer.GetStoreKey()
	data := writer.GetStoreData()
	dataType := writer.GetStoreType()

	fmt.Printf("Storing %d bytes of type %d for key %x\n",
		len(data), dataType, key[:8])

	return nil
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
		dbManager:  NewDatabaseManager(),
		tunnelMgr:  NewTunnelManager(),
		sessionMgr: NewSessionManager(),
	}
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
