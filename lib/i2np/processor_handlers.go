package i2np

import (
	"encoding/binary"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"

	"github.com/go-i2p/go-i2p/lib/tunnel"
)

func (p *MessageProcessor) processDataMessage(msg I2NPMessage) error {
	payloadCarrier, ok := msg.(PayloadCarrier)
	if !ok {
		return oops.Errorf("message does not implement PayloadCarrier interface")
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
		return oops.Errorf("database manager not configured")
	}

	// Type assert to *DatabaseStore
	dbStore, ok := msg.(*DatabaseStore)
	if !ok {
		log.WithFields(logger.Fields{
			"at":     "processDatabaseStoreMessage",
			"reason": "type_assertion_failed",
		}).Error("Message is not a DatabaseStore")
		return oops.Errorf("message is not a DatabaseStore")
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
		return oops.Wrapf(err, "failed to store in NetDB")
	}

	log.WithFields(logger.Fields{
		"at":         "processDatabaseStoreMessage",
		"key":        fmt.Sprintf("%x", key[:8]),
		"store_type": storeType,
	}).Debug("Successfully stored data in NetDB")

	// Send DeliveryStatus acknowledgment when a non-zero reply token is present.
	p.sendDatabaseStoreAck(dbStore)

	return nil
}

// sendDatabaseStoreAck sends a DeliveryStatus to the reply tunnel if the
// DatabaseStore has a non-zero reply token. Per the I2P spec, the ack uses
// the reply token as the message ID and is forwarded through the reply tunnel.
func (p *MessageProcessor) sendDatabaseStoreAck(dbStore *DatabaseStore) {
	token := binary.BigEndian.Uint32(dbStore.ReplyToken[:])
	if token == 0 {
		return
	}
	if p.cloveForwarder == nil {
		log.WithFields(logger.Fields{"at": "sendDatabaseStoreAck"}).Debug("cannot send DatabaseStore ack: no clove forwarder")
		return
	}
	tunnelID := tunnel.TunnelID(binary.BigEndian.Uint32(dbStore.ReplyTunnelID[:]))
	ack := NewDeliveryStatusMessage(int(token), time.Now())
	if err := p.cloveForwarder.ForwardThroughTunnel(dbStore.ReplyGateway, tunnelID, ack); err != nil {
		log.WithField("error", err).Debug("failed to send DatabaseStore ack")
	}
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
		return oops.Errorf("message is not a DatabaseSearchReply")
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
		return oops.Errorf("message is not a TunnelGateway")
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
		return oops.Errorf("TunnelGateway message has empty payload")
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
			return oops.Wrapf(err, "tunnel gateway handling failed")
		}
		return nil
	}

	log.WithFields(logger.Fields{
		"at":        "processTunnelGatewayMessage",
		"tunnel_id": tgMsg.TunnelID,
		"reason":    "no tunnel gateway handler configured",
	}).Warn("TunnelGateway message received but no handler configured")
	return oops.Errorf("no tunnel gateway handler configured")
}

// processDeliveryStatusMessage processes delivery status messages using StatusReporter interface.
// If a DeliveryStatusHandler is configured, the status is forwarded to confirm delivery.
// Otherwise, the status is logged and discarded.
func (p *MessageProcessor) processDeliveryStatusMessage(msg I2NPMessage) error {
	statusReporter, ok := msg.(StatusReporter)
	if !ok {
		return oops.Errorf("message does not implement StatusReporter interface")
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
		return oops.Errorf("database manager not configured")
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
	return oops.Errorf("message does not implement DatabaseReader interface")
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
		return oops.Errorf("garlic session manager not configured - cannot decrypt garlic messages")
	}
	return nil
}

// extractGarlicData extracts encrypted data from the garlic message.
func (p *MessageProcessor) extractGarlicData(msg I2NPMessage) ([]byte, error) {
	carrier, ok := msg.(DataCarrier)
	if !ok {
		return nil, oops.Errorf("garlic message does not implement DataCarrier")
	}

	encryptedData := carrier.GetData()
	if len(encryptedData) == 0 {
		return nil, oops.Errorf("garlic message contains no data")
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
		return nil, [8]byte{}, oops.Wrapf(err, "failed to decrypt garlic message")
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
		return nil, oops.Wrapf(err, "failed to parse decrypted garlic structure")
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
		return oops.Errorf("message does not implement TunnelCarrier interface")
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
