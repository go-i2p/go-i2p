package i2np

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"io"
	"sync"
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
	RegisterParticipant(tunnelID tunnel.TunnelID, sourceHash common.Hash, expiry time.Time) error
}

// MessageProcessor demonstrates interface-based message processing
type MessageProcessor struct {
	factory             *I2NPMessageFactory
	garlicSessions      *GarlicSessionManager
	cloveForwarder      GarlicCloveForwarder // Optional delegate for non-LOCAL garlic clove delivery
	dbManager           *DatabaseManager     // Optional database manager for DatabaseLookup messages
	expirationValidator *ExpirationValidator // Validator for checking message expiration
	participantManager  ParticipantManager   // Optional participant manager for tunnel build requests
}

// NewMessageProcessor creates a new message processor
func NewMessageProcessor() *MessageProcessor {
	log.WithField("at", "NewMessageProcessor").Debug("Creating new message processor")
	return &MessageProcessor{
		factory:             NewI2NPMessageFactory(),
		expirationValidator: NewExpirationValidator(),
	}
}

// SetGarlicSessionManager sets the garlic session manager for decrypting garlic messages.
// This must be called before processing garlic messages, otherwise they will fail with an error.
func (p *MessageProcessor) SetGarlicSessionManager(garlicMgr *GarlicSessionManager) {
	log.WithField("at", "SetGarlicSessionManager").Debug("Setting garlic session manager")
	p.garlicSessions = garlicMgr
}

// SetCloveForwarder sets the garlic clove forwarder for handling non-LOCAL delivery types.
// This is optional - if not set, only LOCAL delivery (0x00) will be processed.
// The forwarder enables DESTINATION (0x01), ROUTER (0x02), and TUNNEL (0x03) deliveries.
func (p *MessageProcessor) SetCloveForwarder(forwarder GarlicCloveForwarder) {
	log.WithField("at", "SetCloveForwarder").Debug("Setting garlic clove forwarder")
	p.cloveForwarder = forwarder
}

// SetDatabaseManager sets the database manager for processing DatabaseLookup messages.
// This must be called before processing DatabaseLookup messages, otherwise they will fail with an error.
func (p *MessageProcessor) SetDatabaseManager(dbMgr *DatabaseManager) {
	log.WithField("at", "SetDatabaseManager").Debug("Setting database manager")
	p.dbManager = dbMgr
}

// SetParticipantManager sets the participant manager for processing incoming tunnel build requests.
// This enables the router to participate in tunnels built by other routers.
// If not set, tunnel build requests will be rejected with an error.
func (p *MessageProcessor) SetParticipantManager(pm ParticipantManager) {
	log.WithField("at", "SetParticipantManager").Debug("Setting participant manager")
	p.participantManager = pm
}

// SetExpirationValidator sets a custom expiration validator for message processing.
// If not set, a default validator with 5-minute tolerance is used.
func (p *MessageProcessor) SetExpirationValidator(v *ExpirationValidator) {
	if v != nil {
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
func (p *MessageProcessor) ProcessMessage(msg I2NPMessage) error {
	log.WithFields(logger.Fields{
		"at":           "ProcessMessage",
		"message_type": msg.Type(),
	}).Debug("Processing I2NP message")

	// Validate message expiration before processing
	if p.expirationValidator != nil {
		if err := p.expirationValidator.ValidateMessage(msg); err != nil {
			return err
		}
	}

	switch msg.Type() {
	case I2NP_MESSAGE_TYPE_DATA:
		return p.processDataMessage(msg)
	case I2NP_MESSAGE_TYPE_DELIVERY_STATUS:
		return p.processDeliveryStatusMessage(msg)
	case I2NP_MESSAGE_TYPE_DATABASE_LOOKUP:
		return p.processDatabaseLookupMessage(msg)
	case I2NP_MESSAGE_TYPE_GARLIC:
		return p.processGarlicMessage(msg)
	case I2NP_MESSAGE_TYPE_TUNNEL_DATA:
		return p.processTunnelDataMessage(msg)
	case I2NP_MESSAGE_TYPE_SHORT_TUNNEL_BUILD:
		return p.processShortTunnelBuildMessage(msg)
	case I2NP_MESSAGE_TYPE_VARIABLE_TUNNEL_BUILD:
		return p.processVariableTunnelBuildMessage(msg)
	case I2NP_MESSAGE_TYPE_TUNNEL_BUILD:
		return p.processVariableTunnelBuildMessage(msg) // Legacy format, same processing
	default:
		log.WithFields(logger.Fields{
			"at":           "ProcessMessage",
			"message_type": msg.Type(),
			"reason":       "unknown message type",
		}).Error("Cannot process message")
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
		log.WithFields(logger.Fields{
			"message_id": msgID,
			"timestamp":  timestamp,
		}).Debug("Processing delivery status")
		return nil
	}
	return fmt.Errorf("message does not implement StatusReporter interface")
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
	baseMsg, ok := msg.(*BaseI2NPMessage)
	if !ok {
		return nil, fmt.Errorf("garlic message does not extend BaseI2NPMessage")
	}

	encryptedData := baseMsg.GetData()
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
func (p *MessageProcessor) parseAndLogGarlic(msgID int, decryptedData []byte, sessionTag [8]byte) (*Garlic, error) {
	garlic, err := p.parseGarlicStructure(decryptedData)
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
func (p *MessageProcessor) handleLocalDelivery(index int, clove GarlicClove) {
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

// parseGarlicStructure parses decrypted garlic data into a Garlic structure.
// The decrypted format is:
//
//	[count:1] [clove1] [clove2] ... [certificate:3] [messageID:4] [expiration:8]
//
// This is a simplified parser - full implementation would use the existing
// garlic parsing code from garlic_builder.go
func (p *MessageProcessor) parseGarlicStructure(data []byte) (*Garlic, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("garlic data too short: need at least 1 byte for count")
	}

	count := int(data[0])
	offset := 1

	log.WithFields(logger.Fields{
		"count":     count,
		"data_size": len(data),
	}).Debug("Parsing garlic structure")

	garlic := &Garlic{
		Count:  count,
		Cloves: make([]GarlicClove, 0, count),
	}

	// Parse each clove
	offset, err := p.parseGarlicCloves(garlic, data, offset, count)
	if err != nil {
		return nil, err
	}

	// Parse trailing fields (certificate, message ID, expiration)
	if err := p.validateGarlicTrailingFields(data, offset); err != nil {
		return nil, err
	}

	return garlic, nil
}

// parseGarlicCloves parses all garlic cloves from the data and appends them to the garlic structure.
// Returns the updated offset after parsing all cloves.
func (p *MessageProcessor) parseGarlicCloves(garlic *Garlic, data []byte, offset, count int) (int, error) {
	for i := 0; i < count; i++ {
		clove, bytesRead, err := p.parseGarlicClove(data[offset:])
		if err != nil {
			return 0, fmt.Errorf("failed to parse clove %d: %w", i, err)
		}
		garlic.Cloves = append(garlic.Cloves, *clove)
		offset += bytesRead
	}
	return offset, nil
}

// validateGarlicTrailingFields validates that the garlic data contains the required trailing fields.
// These fields are: certificate (3 bytes), message ID (4 bytes), and expiration (8 bytes).
func (p *MessageProcessor) validateGarlicTrailingFields(data []byte, offset int) error {
	if err := p.validateGarlicCertificate(data, offset); err != nil {
		return err
	}
	offset += 3

	if err := p.validateGarlicMessageID(data, offset); err != nil {
		return err
	}
	offset += 4

	return p.validateGarlicExpiration(data, offset)
}

// validateGarlicCertificate validates that sufficient data exists for the certificate field.
// The certificate is always 3 bytes and currently always null in the implementation.
func (p *MessageProcessor) validateGarlicCertificate(data []byte, offset int) error {
	if len(data)-offset < 3 {
		return fmt.Errorf("insufficient data for certificate at offset %d", offset)
	}
	return nil
}

// validateGarlicMessageID validates that sufficient data exists for the message ID field.
// The message ID is 4 bytes.
func (p *MessageProcessor) validateGarlicMessageID(data []byte, offset int) error {
	if len(data)-offset < 4 {
		return fmt.Errorf("insufficient data for message ID at offset %d", offset)
	}
	return nil
}

// validateGarlicExpiration validates that sufficient data exists for the expiration field.
// The expiration is 8 bytes.
func (p *MessageProcessor) validateGarlicExpiration(data []byte, offset int) error {
	if len(data)-offset < 8 {
		return fmt.Errorf("insufficient data for expiration at offset %d", offset)
	}
	return nil
}

// parseGarlicClove parses a single garlic clove from the data.
// Returns the clove, number of bytes consumed, and any error.
//
// Clove format:
//
//	[delivery_instructions] [i2np_message] [clove_id:4] [expiration:8] [certificate:3]
func (p *MessageProcessor) parseGarlicClove(data []byte) (*GarlicClove, int, error) {
	if len(data) < 1 {
		return nil, 0, fmt.Errorf("clove data too short for delivery instructions")
	}

	offset := 0

	// Parse delivery instructions
	deliveryInstr, bytesRead, err := p.parseDeliveryInstructions(data[offset:])
	if err != nil {
		return nil, 0, fmt.Errorf("failed to parse delivery instructions: %w", err)
	}
	offset += bytesRead

	// Parse the wrapped I2NP message
	i2npMsg, bytesRead, err := p.parseI2NPMessage(data[offset:])
	if err != nil {
		return nil, 0, fmt.Errorf("failed to parse wrapped I2NP message: %w", err)
	}
	offset += bytesRead

	// Parse clove metadata
	cloveID, bytesRead, err := parseGarlicCloveTrailer(data[offset:])
	if err != nil {
		return nil, 0, err
	}
	offset += bytesRead

	clove := &GarlicClove{
		DeliveryInstructions: *deliveryInstr,
		I2NPMessage:          i2npMsg,
		CloveID:              cloveID,
	}

	return clove, offset, nil
}

// parseGarlicCloveTrailer extracts clove ID, expiration, and certificate from clove trailer.
// Returns clove ID and total bytes consumed (15 bytes: 4 for ID + 8 for expiration + 3 for certificate).
func parseGarlicCloveTrailer(data []byte) (int, int, error) {
	// Validate sufficient data for full trailer
	if len(data) < 15 {
		return 0, 0, fmt.Errorf("insufficient data for clove trailer (need 15 bytes, have %d)", len(data))
	}

	// Parse clove ID (4 bytes, big-endian)
	cloveID := parseCloveID(data[0:4])

	// Skip expiration (8 bytes) and certificate (3 bytes)
	// Total bytes consumed: 4 + 8 + 3 = 15
	return cloveID, 15, nil
}

// parseCloveID extracts a 4-byte big-endian integer clove ID.
func parseCloveID(data []byte) int {
	return int(data[0])<<24 | int(data[1])<<16 | int(data[2])<<8 | int(data[3])
}

// parseDeliveryInstructions parses garlic clove delivery instructions.
// Returns the instructions, number of bytes consumed, and any error.
//
// Format:
//
//	[flag:1] [session_key:32]? [hash:32]? [tunnel_id:4]? [delay:4]?
func (p *MessageProcessor) parseDeliveryInstructions(data []byte) (*GarlicCloveDeliveryInstructions, int, error) {
	if len(data) < 1 {
		return nil, 0, fmt.Errorf("no data for delivery instructions flag")
	}

	deliveryInstr := &GarlicCloveDeliveryInstructions{
		Flag: data[0],
	}

	// Parse all instruction fields sequentially
	offset, err := p.parseInstructionFields(data, deliveryInstr)
	if err != nil {
		return nil, 0, err
	}

	return deliveryInstr, offset, nil
}

// parseInstructionFields parses all delivery instruction fields.
func (p *MessageProcessor) parseInstructionFields(data []byte, deliveryInstr *GarlicCloveDeliveryInstructions) (int, error) {
	offset := 1
	flag := deliveryInstr.Flag

	// Parse optional session key (bit 7)
	var err error
	offset, err = parseSessionKey(data, offset, flag, deliveryInstr)
	if err != nil {
		return 0, err
	}

	// Extract delivery type for subsequent parsing
	deliveryType := extractDeliveryType(flag)

	// Parse optional hash field
	offset, err = parseDeliveryHash(data, offset, deliveryType, deliveryInstr)
	if err != nil {
		return 0, err
	}

	// Parse optional tunnel ID
	offset, err = parseTunnelID(data, offset, deliveryType, deliveryInstr)
	if err != nil {
		return 0, err
	}

	// Parse optional delay field
	offset, err = parseDelay(data, offset, flag, deliveryInstr)
	if err != nil {
		return 0, err
	}

	return offset, nil
}

// parseSessionKey extracts the optional session key from delivery instructions.
// Returns the updated offset and any parsing error.
func parseSessionKey(data []byte, offset int, flag byte, deliveryInstr *GarlicCloveDeliveryInstructions) (int, error) {
	if (flag>>7)&0x01 == 1 {
		if len(data)-offset < 32 {
			return 0, fmt.Errorf("insufficient data for session key")
		}
		copy(deliveryInstr.SessionKey[:], data[offset:offset+32])
		return offset + 32, nil
	}
	return offset, nil
}

// parseDeliveryHash extracts the optional hash field for DESTINATION, ROUTER, or TUNNEL delivery.
// Returns the updated offset and any parsing error.
func parseDeliveryHash(data []byte, offset int, deliveryType byte, deliveryInstr *GarlicCloveDeliveryInstructions) (int, error) {
	if deliveryType >= 1 && deliveryType <= 3 {
		if len(data)-offset < 32 {
			return 0, fmt.Errorf("insufficient data for hash")
		}
		copy(deliveryInstr.Hash[:], data[offset:offset+32])
		return offset + 32, nil
	}
	return offset, nil
}

// parseTunnelID extracts the optional tunnel ID field for TUNNEL delivery type.
// Returns the updated offset and any parsing error.
func parseTunnelID(data []byte, offset int, deliveryType byte, deliveryInstr *GarlicCloveDeliveryInstructions) (int, error) {
	if deliveryType == 3 {
		if len(data)-offset < 4 {
			return 0, fmt.Errorf("insufficient data for tunnel ID")
		}
		tunnelID := uint32(data[offset])<<24 | uint32(data[offset+1])<<16 | uint32(data[offset+2])<<8 | uint32(data[offset+3])
		deliveryInstr.TunnelID = tunnel.TunnelID(tunnelID)
		return offset + 4, nil
	}
	return offset, nil
}

// parseDelay extracts the optional delay field from delivery instructions.
// Returns the updated offset and any parsing error.
func parseDelay(data []byte, offset int, flag byte, deliveryInstr *GarlicCloveDeliveryInstructions) (int, error) {
	if (flag>>4)&0x01 == 1 {
		if len(data)-offset < 4 {
			return 0, fmt.Errorf("insufficient data for delay")
		}
		delay := int(data[offset])<<24 | int(data[offset+1])<<16 | int(data[offset+2])<<8 | int(data[offset+3])
		deliveryInstr.Delay = delay
		return offset + 4, nil
	}
	return offset, nil
}

// parseI2NPMessage parses a wrapped I2NP message from garlic clove data.
// Returns the message, number of bytes consumed, and any error.
func (p *MessageProcessor) parseI2NPMessage(data []byte) (I2NPMessage, int, error) {
	// I2NP message format: [header] [payload]
	// Header is at least 16 bytes (type, ID, expiration, size, checksum)
	if len(data) < 16 {
		return nil, 0, fmt.Errorf("insufficient data for I2NP message header")
	}

	// Create a base message and unmarshal
	msg := NewBaseI2NPMessage(0)
	if err := msg.UnmarshalBinary(data); err != nil {
		return nil, 0, fmt.Errorf("failed to unmarshal I2NP message: %w", err)
	}

	// Calculate bytes consumed: header (16) + data size
	dataSize := len(msg.GetData())
	bytesRead := 16 + dataSize

	return msg, bytesRead, nil
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
	p.processAllBuildRecords(msg.MessageID(), records)

	return nil
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
	baseMsg, ok := msg.(*BaseI2NPMessage)
	if !ok {
		return nil, fmt.Errorf("tunnel build message does not extend BaseI2NPMessage")
	}

	data := baseMsg.GetData()
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
// In a full implementation, we would:
// 1. Try to decrypt each record with our identity key
// 2. If decryption succeeds, this record is for us
// 3. Validate the request using ProcessBuildRequest
// 4. Create response record and forward the message
func (p *MessageProcessor) processAllBuildRecords(messageID int, records []BuildRequestRecord) {
	for i, record := range records {
		p.processSingleBuildRecord(messageID, i, record)
	}
}

// processSingleBuildRecord validates and processes a single build request record.
func (p *MessageProcessor) processSingleBuildRecord(messageID, index int, record BuildRequestRecord) {
	accepted, rejectCode, reason := p.participantManager.ProcessBuildRequest(record.OurIdent)

	if accepted {
		p.handleAcceptedBuildRecord(messageID, index, record)
	} else {
		p.handleRejectedBuildRecord(messageID, index, record, rejectCode, reason)
	}

	// TODO: Generate and send build reply message
	// This requires:
	// 1. Creating a BuildResponseRecord with accept/reject status
	// 2. Encrypting the response with the reply key
	// 3. Forwarding the message to the next hop (or reply tunnel)
	_ = rejectCode // Will be used in reply generation
}

// handleAcceptedBuildRecord logs acceptance and registers the tunnel participation.
func (p *MessageProcessor) handleAcceptedBuildRecord(messageID, index int, record BuildRequestRecord) {
	log.WithFields(logger.Fields{
		"at":             "processTunnelBuildRequest",
		"message_id":     messageID,
		"record_index":   index,
		"receive_tunnel": record.ReceiveTunnel,
		"source_hash":    fmt.Sprintf("%x", record.OurIdent[:8]),
	}).Info("accepting tunnel build request")

	expiry := time.Now().Add(10 * time.Minute) // Tunnel lifetime per I2P spec
	if err := p.participantManager.RegisterParticipant(record.ReceiveTunnel, record.OurIdent, expiry); err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"at":             "processTunnelBuildRequest",
			"receive_tunnel": record.ReceiveTunnel,
		}).Error("failed to register participant after acceptance")
		// Continue anyway - the tunnel may still work
	}
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
// Record sizes differ between STBM (218 bytes encrypted, 222 cleartext) and VTB (528 bytes).
func (p *MessageProcessor) getRecordSize(isShortBuild bool) int {
	if isShortBuild {
		return 218 // STBM encrypted record size (ECIES)
	}
	return 528 // VTB encrypted record size
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
	// Try to parse as cleartext (222 bytes for STBM cleartext)
	if isShortBuild && len(recordData) >= 222 {
		record, err := ReadBuildRequestRecord(recordData)
		if err != nil {
			log.WithError(err).WithField("record_index", index).Debug("failed to parse build request record")
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
	replyProcessor  *ReplyProcessor       // Handles reply decryption and processing
}

// NewTunnelManager creates a new tunnel manager with build request tracking.
// Starts a background goroutine for cleaning up expired build requests.
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
	// This fixes Issue #4 from AUDIT.md: "No retry callback configured"
	tm.replyProcessor.SetRetryCallback(tm.retryTunnelBuild)

	log.WithFields(logger.Fields{
		"at":     "NewTunnelManager",
		"phase":  "initialization",
		"reason": "retry callback configured for automatic tunnel build retry",
	}).Debug("tunnel manager initialized with retry callback")

	// Start periodic cleanup of expired build requests (every 30 seconds)
	tm.cleanupTicker = time.NewTicker(30 * time.Second)
	go tm.cleanupExpiredBuilds()

	log.WithFields(logger.Fields{
		"at":     "NewTunnelManager",
		"phase":  "initialization",
		"reason": "tunnel manager initialized with separate inbound/outbound pools",
	}).Debug("tunnel manager created")

	return tm
}

// Stop gracefully stops the tunnel manager and cleans up resources.
// Should be called when shutting down the router.
func (tm *TunnelManager) Stop() {
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
func (tm *TunnelManager) BuildTunnel(req tunnel.BuildTunnelRequest) (tunnel.TunnelID, error) {
	return tm.BuildTunnelFromRequest(req)
}

// BuildTunnelFromRequest builds a tunnel from a BuildTunnelRequest using the tunnel.TunnelBuilder.
// This is the recommended method for building tunnels with proper request tracking and retry support.
//
// The method:
// 1. Uses tunnel.TunnelBuilder to create encrypted build records
// 2. Generates a unique message ID for request/reply correlation
// 3. Tracks the pending build request with reply decryption keys
// 4. Sends the build request via appropriate transport
// 5. Returns the tunnel ID for tracking
func (tm *TunnelManager) BuildTunnelFromRequest(req tunnel.BuildTunnelRequest) (tunnel.TunnelID, error) {
	result, messageID, err := tm.createBuildRequestAndID(req)
	if err != nil {
		return 0, err
	}

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
		return 0, fmt.Errorf("failed to register pending build: %w", regErr)
	}

	// Schedule immediate cleanup on timeout (90 seconds per I2P spec)
	// This prevents memory leaks from failed/timeout builds between periodic cleanups
	time.AfterFunc(90*time.Second, func() {
		tm.cleanupExpiredBuildByID(messageID)
	})

	err = tm.sendBuildMessage(result, messageID)
	if err != nil {
		tm.cleanupFailedBuild(result.TunnelID, messageID, req.IsInbound)
		return 0, fmt.Errorf("failed to send build request: %w", err)
	}

	tm.logBuildRequestSent(result, messageID)
	return result.TunnelID, nil
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

	messageID := tm.generateMessageID()
	return result, messageID, nil
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

	buildMsg := tm.selectBuildMessage(result, messageID)
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
func (tm *TunnelManager) selectBuildMessage(result *tunnel.TunnelBuildResult, messageID int) I2NPMessage {
	if result.UseShortBuild {
		// Use Short Tunnel Build Message (modern)
		return tm.createShortTunnelBuildMessage(result, messageID)
	}
	// Use Variable Tunnel Build Message (legacy)
	return tm.createVariableTunnelBuildMessage(result, messageID)
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
func (tm *TunnelManager) createShortTunnelBuildMessage(result *tunnel.TunnelBuildResult, messageID int) I2NPMessage {
	// Convert tunnel.BuildRequestRecord to i2np.BuildRequestRecord
	i2npRecords := make([]BuildRequestRecord, len(result.Records))
	for i, rec := range result.Records {
		i2npRecords[i] = BuildRequestRecord{
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

	// Create Short Tunnel Build (STBM) using the builder constructor
	stbm := NewShortTunnelBuilder(i2npRecords)

	// Wrap in I2NP message
	msg := NewBaseI2NPMessage(I2NP_MESSAGE_TYPE_SHORT_TUNNEL_BUILD)
	msg.SetMessageID(messageID)

	// Serialize ShortTunnelBuild to bytes and set as message data
	msg.SetData(stbm.(*ShortTunnelBuild).Bytes())

	return msg
}

// createVariableTunnelBuildMessage creates a Variable Tunnel Build Message (legacy).
func (tm *TunnelManager) createVariableTunnelBuildMessage(result *tunnel.TunnelBuildResult, messageID int) I2NPMessage {
	// Convert to fixed 8-record array (pad with empty records if needed)
	var records [8]BuildRequestRecord
	for i := 0; i < 8 && i < len(result.Records); i++ {
		rec := result.Records[i]
		records[i] = BuildRequestRecord{
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

	msg := NewTunnelBuildMessage(records)
	msg.SetMessageID(messageID)
	return msg
}

// generateMessageID generates a unique message ID for tracking build requests.
// Uses cryptographically secure random to avoid collisions and predictability.
func (tm *TunnelManager) generateMessageID() int {
	var buf [4]byte
	if _, err := rand.Read(buf[:]); err != nil {
		// Fallback to time-based if rand fails (should never happen)
		log.WithError(err).Warn("Failed to generate random message ID, using time-based fallback")
		return int(time.Now().UnixNano() & 0x7FFFFFFF)
	}
	// Use only 31 bits to ensure positive int on all platforms
	return int(binary.BigEndian.Uint32(buf[:]) & 0x7FFFFFFF)
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

	tunnelID := tm.generateTunnelID()
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
func (tm *TunnelManager) generateTunnelID() tunnel.TunnelID {
	var buf [4]byte
	if _, err := rand.Read(buf[:]); err != nil {
		// Fallback to time-based if rand fails (should never happen)
		log.WithError(err).Warn("Failed to generate random tunnel ID, using time-based fallback")
		return tunnel.TunnelID(time.Now().UnixNano() & 0xFFFFFFFF)
	}
	return tunnel.TunnelID(binary.BigEndian.Uint32(buf[:]))
}

// sendTunnelBuildRequests sends tunnel build requests to each selected peer
func (tm *TunnelManager) sendTunnelBuildRequests(records []BuildRequestRecord, peers []router_info.RouterInfo, tunnelID tunnel.TunnelID) error {
	if tm.sessionProvider == nil {
		return fmt.Errorf("no session provider available for sending tunnel build requests")
	}

	tm.logSendingBuildRequests(tunnelID, len(peers))

	for i := range records {
		if i >= len(peers) {
			break
		}

		if err := tm.sendBuildRequestToHop(i, records[i], peers[i], tunnelID); err != nil {
			continue
		}
	}

	tm.logBuildRequestsCompleted(tunnelID)
	return nil
}

// logSendingBuildRequests logs the start of tunnel build request sending.
func (tm *TunnelManager) logSendingBuildRequests(tunnelID tunnel.TunnelID, peerCount int) {
	log.WithFields(logger.Fields{
		"tunnel_id":  tunnelID,
		"peer_count": peerCount,
	}).Debug("Sending tunnel build requests")
}

// sendBuildRequestToHop sends a build request to a specific hop in the tunnel.
func (tm *TunnelManager) sendBuildRequestToHop(hopIndex int, record BuildRequestRecord, peer router_info.RouterInfo, tunnelID tunnel.TunnelID) error {
	peerHash, err := peer.IdentHash()
	if err != nil {
		return fmt.Errorf("failed to get peer hash at hop %d: %w", hopIndex, err)
	}

	session, err := tm.getSessionForPeer(peerHash)
	if err != nil {
		return err
	}

	buildMessage := tm.createBuildMessage(hopIndex, record, tunnelID)
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
func (tm *TunnelManager) createBuildMessage(hopIndex int, record BuildRequestRecord, tunnelID tunnel.TunnelID) *TunnelBuildMessage {
	var buildRecords [8]BuildRequestRecord
	if hopIndex < 8 {
		buildRecords[hopIndex] = record
	}

	buildMessage := NewTunnelBuildMessage(buildRecords)
	buildMessage.SetMessageID(int(tunnelID))
	return buildMessage
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

	go tm.cleanupFailedTunnel(matchingTunnel.ID, matchingTunnel.IsInbound)
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

// cleanupFailedTunnel removes a failed tunnel from the pool after a delay
func (tm *TunnelManager) cleanupFailedTunnel(tunnelID tunnel.TunnelID, isInbound bool) {
	// Small delay before cleanup to allow for logging/debugging
	time.Sleep(1 * time.Second)

	pool := tm.getPoolForTunnel(isInbound)
	if pool != nil {
		pool.RemoveTunnel(tunnelID)
		log.WithField("tunnel_id", tunnelID).Debug("Cleaned up failed tunnel")
	}
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

	go tm.cleanupFailedTunnel(req.tunnelID, req.isInbound)
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
			go tm.cleanupFailedTunnel(req.tunnelID, req.isInbound)
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

// NetDBStore defines the interface for storing RouterInfo entries
type NetDBStore interface {
	StoreRouterInfo(key common.Hash, data []byte, dataType byte) error
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
	QueueSendI2NP(msg I2NPMessage)
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

	// Send the response
	session.QueueSendI2NP(msg)
	log.WithFields(logger.Fields{
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
	}).Debug("Storing RouterInfo data")

	if dm.netdb != nil {
		return dm.netdb.StoreRouterInfo(key, data, dataType)
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

// ProcessKeys processes session keys using SessionKeyProvider interface
func (sm *SessionManager) ProcessKeys(provider SessionKeyProvider) error {
	replyKey := provider.GetReplyKey()
	layerKey := provider.GetLayerKey()
	ivKey := provider.GetIVKey()

	log.WithFields(logger.Fields{
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
		log.WithFields(logger.Fields{
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
