package i2np

import (
	"encoding/binary"
	"fmt"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/go-i2p/lib/util/logutil"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"

	"github.com/go-i2p/go-i2p/lib/tunnel/buildrecord"
)

func (p *MessageProcessor) processDataMessage(msg Message) error {
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
func (p *MessageProcessor) processDatabaseStoreMessage(msg Message) error {
	if p.dbManager == nil {
		log.WithFields(logger.Fields{
			"at":     "processDatabaseStoreMessage",
			"reason": "no_database_manager",
		}).Warn("DatabaseStore received but no database manager configured")
		return oops.Errorf("database manager not configured")
	}

	dbStore, err := coerceDatabaseStoreMessage(msg)
	if err != nil {
		log.WithFields(logger.Fields{
			"at":     "processDatabaseStoreMessage",
			"reason": "coerce_failed",
		}).WithError(err).Error("Message is not a parseable DatabaseStore")
		return err
	}

	key := dbStore.GetStoreKey()
	storeType := dbStore.GetStoreType()
	data := dbStore.GetStoreData()

	log.WithFields(logger.Fields{
		"at":         "processDatabaseStoreMessage",
		"key":        logutil.HashPrefix(key),
		"store_type": storeType,
		"data_size":  len(data),
	}).Debug("Processing DatabaseStore message")

	storeErr := p.dbManager.StoreData(dbStore)
	if sourceProvider, ok := msg.(SourceHashProvider); ok {
		storeErr = p.dbManager.StoreDataFromPeer(dbStore, sourceProvider.SourceHash())
	}

	// Store in NetDB — dispatched by type to appropriate handler
	if err := storeErr; err != nil {
		log.WithFields(logger.Fields{
			"at":     "processDatabaseStoreMessage",
			"reason": "store_failed",
			"key":    logutil.HashPrefix(key),
		}).WithError(err).Error("Failed to store data in NetDB")
		return oops.Wrapf(err, "failed to store in NetDB")
	}

	log.WithFields(logger.Fields{
		"at":         "processDatabaseStoreMessage",
		"key":        logutil.HashPrefix(key),
		"store_type": storeType,
	}).Debug("Successfully stored data in NetDB")

	// Correlate this store with any outstanding direct DatabaseLookup waiting on
	// this key so a blocked SendDatabaseLookup can return the RouterInfo. The
	// payload is forwarded because resolver parse helpers expect payload bytes.
	if deliverer := p.lookupReplyDeliverer; deliverer != nil {
		deliverer.DeliverLookupReply(key, I2NPMessageTypeDatabaseStore, dbStore.GetData())
	}

	// In floodfill mode, a successful store carrying a non-zero reply token must
	// be re-propagated to nearby floodfills so the entry becomes network-visible
	// beyond this single accepting router.
	if replicator := p.floodfillReplicator; replicator != nil {
		if token := binary.BigEndian.Uint32(dbStore.ReplyToken[:]); token != 0 {
			replicator.FloodDatabaseStore(key, data, storeType)
		}
	}

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
	if dbStore.ReplyGateway == (common.Hash{}) {
		log.WithFields(logger.Fields{"at": "sendDatabaseStoreAck"}).Debug("skipping DatabaseStore ack: missing reply gateway")
		return
	}
	if p.cloveForwarder == nil {
		log.WithFields(logger.Fields{"at": "sendDatabaseStoreAck"}).Debug("cannot send DatabaseStore ack: no clove forwarder")
		return
	}
	tunnelID := buildrecord.TunnelID(binary.BigEndian.Uint32(dbStore.ReplyTunnelID[:]))
	ack := NewDeliveryStatusMessage(int(token), time.Now())
	if tunnelID == 0 {
		log.WithFields(logger.Fields{
			"at":           "sendDatabaseStoreAck",
			"reply_token":  token,
			"reply_tunnel": uint32(tunnelID),
			"path":         "router",
		}).Debug("sending DatabaseStore ack via router delivery")
		if err := p.cloveForwarder.ForwardToRouter(dbStore.ReplyGateway, ack); err != nil {
			log.WithField("error", err).Debug("failed to send DatabaseStore ack via router delivery")
		}
		return
	}
	log.WithFields(logger.Fields{
		"at":           "sendDatabaseStoreAck",
		"reply_token":  token,
		"reply_tunnel": uint32(tunnelID),
		"path":         "tunnel",
	}).Debug("sending DatabaseStore ack via tunnel delivery")
	if err := p.cloveForwarder.ForwardThroughTunnel(dbStore.ReplyGateway, tunnelID, ack); err != nil {
		log.WithField("error", err).Debug("failed to send DatabaseStore ack via tunnel delivery")
	}
}

// processDatabaseSearchReplyMessage processes DatabaseSearchReply messages from peers.
// These messages contain peer hash suggestions when a lookup fails to find the exact key.
// The suggested peers are delivered to the search reply handler for iterative lookup follow-up.
func (p *MessageProcessor) processDatabaseSearchReplyMessage(msg Message) error {
	searchReply, err := coerceDatabaseSearchReplyMessage(msg)
	if err != nil {
		log.WithFields(logger.Fields{
			"at":     "processDatabaseSearchReplyMessage",
			"reason": "coerce_failed",
		}).WithError(err).Error("Message is not a parseable DatabaseSearchReply")
		return err
	}

	log.WithFields(logger.Fields{
		"at":          "processDatabaseSearchReplyMessage",
		"key":         logutil.HashPrefix(searchReply.Key),
		"from":        logutil.HashPrefix(searchReply.From),
		"peer_count":  searchReply.Count,
		"peer_hashes": len(searchReply.PeerHashes),
	}).Debug("Processing DatabaseSearchReply message")

	// Deliver suggestions to the search reply handler for iterative Kademlia lookup
	if p.searchReplyHandler != nil && len(searchReply.PeerHashes) > 0 {
		p.searchReplyHandler.HandleSearchReply(searchReply.Key, searchReply.PeerHashes)
		log.WithFields(logger.Fields{
			"at":          "processDatabaseSearchReplyMessage",
			"key":         logutil.HashPrefix(searchReply.Key),
			"suggestions": len(searchReply.PeerHashes),
		}).Debug("Delivered search reply suggestions to handler")
	} else {
		// Log peer suggestions for debugging when no handler is set
		for i, peerHash := range searchReply.PeerHashes {
			log.WithFields(logger.Fields{
				"at":        "processDatabaseSearchReplyMessage",
				"peer_idx":  i,
				"peer_hash": logutil.HashPrefix(peerHash),
			}).Debug("Suggested peer from search reply (no handler configured)")
		}
	}

	// Correlate this reply with any outstanding direct DatabaseLookup waiting on
	// this key so a blocked SendDatabaseLookup returns the suggestions and the
	// resolver can follow them to the next iterative round.
	if deliverer := p.lookupReplyDeliverer; deliverer != nil {
		if payload, err := searchReply.MarshalPayload(); err == nil {
			deliverer.DeliverLookupReply(searchReply.Key, I2NPMessageTypeDatabaseSearchReply, payload)
		} else {
			log.WithError(err).WithField("at", "processDatabaseSearchReplyMessage").
				Debug("could not serialize DatabaseSearchReply payload for lookup correlation")
		}
	}

	return nil
}

// coerceDatabaseStoreMessage returns a concrete DatabaseStore by accepting either
// an already-parsed *DatabaseStore or a DataCarrier payload that can be parsed.
func coerceDatabaseStoreMessage(msg Message) (*DatabaseStore, error) {
	if dbStore, ok := msg.(*DatabaseStore); ok {
		return dbStore, nil
	}

	carrier, ok := msg.(DataCarrier)
	if !ok {
		return nil, oops.Errorf("message is not a DatabaseStore and does not implement DataCarrier")
	}

	payload := carrier.GetData()
	if len(payload) == 0 {
		return nil, oops.Errorf("DatabaseStore payload is empty")
	}

	dbStore := &DatabaseStore{}
	if err := dbStore.UnmarshalBinary(payload); err != nil {
		return nil, oops.Wrapf(err, "failed to parse DatabaseStore payload")
	}

	return dbStore, nil
}

// coerceDatabaseSearchReplyMessage returns a concrete DatabaseSearchReply by
// accepting either an already-parsed *DatabaseSearchReply or a DataCarrier payload.
func coerceDatabaseSearchReplyMessage(msg Message) (*DatabaseSearchReply, error) {
	if searchReply, ok := msg.(*DatabaseSearchReply); ok {
		return searchReply, nil
	}

	carrier, ok := msg.(DataCarrier)
	if !ok {
		return nil, oops.Errorf("message is not a DatabaseSearchReply and does not implement DataCarrier")
	}

	payload := carrier.GetData()
	if len(payload) == 0 {
		return nil, oops.Errorf("DatabaseSearchReply payload is empty")
	}

	searchReply, err := ReadDatabaseSearchReply(payload)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to parse DatabaseSearchReply payload")
	}

	return searchReply, nil
}

// processTunnelGatewayMessage processes TunnelGateway messages.
// These messages wrap I2NP messages destined for delivery through a tunnel.
// The gateway extracts the inner message and forwards it into the tunnel.
func (p *MessageProcessor) processTunnelGatewayMessage(msg Message) error {
	tgMsg, err := p.extractTunnelGatewayMessage(msg)
	if err != nil {
		return err
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

	if p.tunnelGatewayHandler == nil {
		log.WithFields(logger.Fields{
			"at":        "processTunnelGatewayMessage",
			"tunnel_id": tgMsg.TunnelID,
			"reason":    "no tunnel gateway handler configured",
		}).Warn("TunnelGateway message received but no handler configured")
		return oops.Errorf("no tunnel gateway handler configured")
	}

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

// extractTunnelGatewayMessage extracts a TunnelGateway from an I2NP message.
func (p *MessageProcessor) extractTunnelGatewayMessage(msg Message) (*TunnelGateway, error) {
	tgMsg, ok := msg.(*TunnelGateway)
	if ok {
		return tgMsg, nil
	}

	// Fall back: unmarshal from raw payload
	carrier, ok := msg.(DataCarrier)
	if !ok {
		log.WithFields(logger.Fields{
			"at":     "processTunnelGatewayMessage",
			"reason": "type_assertion_failed",
		}).Error("Message is not a TunnelGateway and has no data carrier")
		return nil, oops.Errorf("message is not a TunnelGateway")
	}

	payload := carrier.GetData()
	if len(payload) < 6 {
		return nil, oops.Errorf("TunnelGateway payload too short: %d bytes", len(payload))
	}

	tgMsg = &TunnelGateway{}
	tgMsg.TunnelID = buildrecord.TunnelID(binary.BigEndian.Uint32(payload[0:4]))
	tgMsg.Length = int(binary.BigEndian.Uint16(payload[4:6]))

	if len(payload) < 6+tgMsg.Length {
		return nil, oops.Errorf("TunnelGateway payload truncated: expected %d bytes, got %d", 6+tgMsg.Length, len(payload))
	}

	tgMsg.Data = make([]byte, tgMsg.Length)
	copy(tgMsg.Data, payload[6:6+tgMsg.Length])
	return tgMsg, nil
}

// forwardToTunnelGatewayHandler forwards the TunnelGateway message to the configured handler.
func (p *MessageProcessor) forwardToTunnelGatewayHandler(tgMsg *TunnelGateway) error {
	if p.tunnelGatewayHandler == nil {
		log.WithFields(logger.Fields{
			"at":        "processTunnelGatewayMessage",
			"tunnel_id": tgMsg.TunnelID,
			"reason":    "no tunnel gateway handler configured",
		}).Warn("TunnelGateway message received but no handler configured")
		return oops.Errorf("no tunnel gateway handler configured")
	}

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

// processDeliveryStatusMessage processes delivery status messages using StatusReporter interface.
// If a DeliveryStatusHandler is configured, the status is forwarded to confirm delivery.
// Otherwise, the status is logged and discarded.
func (p *MessageProcessor) processDeliveryStatusMessage(msg Message) error {
	log.WithFields(logger.Fields{
		"at": "processDeliveryStatusMessage",
	}).Info("delivery status dispatch entered")

	// Try the typed path first (locally constructed messages).
	if statusReporter, ok := msg.(StatusReporter); ok {
		msgID := statusReporter.GetStatusMessageID()
		timestamp := statusReporter.GetTimestamp()
		log.WithFields(logger.Fields{
			"at":         "processDeliveryStatusMessage",
			"message_id": msgID,
			"timestamp":  timestamp,
		}).Info("Processing typed delivery status")
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

	// Wire-received messages arrive as *BaseI2NPMessage (DataCarrier) — parse payload directly.
	carrier, ok := msg.(DataCarrier)
	if !ok {
		return oops.Errorf("DeliveryStatus message does not implement DataCarrier interface")
	}
	payload := carrier.GetData()
	if len(payload) < 12 {
		return oops.Errorf("DeliveryStatus payload too short: %d bytes (need 12)", len(payload))
	}

	msgID := int(binary.BigEndian.Uint32(payload[0:4]))
	var date common.Date
	copy(date[:], payload[4:12])
	timestamp := date.Time()

	log.WithFields(logger.Fields{
		"at":          "processDeliveryStatusMessage",
		"message_id":  msgID,
		"timestamp":   timestamp,
		"payload_len": len(payload),
	}).Info("Processing wire-received delivery status")

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
func (p *MessageProcessor) processDatabaseLookupMessage(msg Message) error {
	if p.dbManager == nil {
		return oops.Errorf("database manager not configured")
	}

	if reader, ok := msg.(DatabaseReader); ok {
		key := reader.GetKey()
		from := reader.GetFrom()
		log.WithFields(logger.Fields{
			"key":  logutil.HashPrefix(key),
			"from": logutil.HashPrefix(from),
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
// 3. Parse each decrypted clove payload into a Garlic structure
// 4. For each clove, route based on delivery type:
//   - LOCAL (0x00): Process wrapped message locally via ProcessMessage()
//   - DESTINATION/ROUTER/TUNNEL: forwarded by lib/router/garlic_router.go
//
// A spec-compliant ratchet payload may contain more than one GarlicClove block;
// all cloves are processed so no delivery instructions are silently dropped.
//
// Note: This processor handles LOCAL delivery only. Other delivery types require
// router context and would be implemented at the router layer.
// H6 FIX: depth parameter threads garlic nesting level through process pipeline.
//
// TROUBLESHOOTING: If garlic_decrypt_succeeded=0 (100% failures):
//  1. Peers have cached OLD RouterInfo with different X25519 encryption key
//  2. Call publisher.ForceRouterInfoRepublish() to push current key to floodfill
//  3. Monitor garlic_decrypt_succeeded counter - should increase as peers get new RouterInfo
//  4. Process exploratory replies via tunnel_manager_reply.go metrics tracking
func (p *MessageProcessor) processGarlicMessage(msg Message, depth int) error {
	if err := p.validateGarlicSession(); err != nil {
		return err
	}

	encryptedData, err := p.extractGarlicData(msg)
	if err != nil {
		return err
	}

	decryptedCloves, sessionTag, err := p.decryptGarlicData(msg.MessageID(), encryptedData)
	if err != nil {
		// CRITICAL-5 FIX: Garlic decryption failures should NOT be fatal.
		// This happens when:
		//  1. Garlic message is transit traffic (meant for other routers, not us)
		//  2. Peers encrypted with old X25519 key (they have cached RouterInfo)
		//  3. Message is not actually encrypted to our public key for some reason
		//
		// Solution: Log and skip instead of returning error. This allows router
		// to continue processing other messages. Only LOCAL garlic messages for
		// this router would decrypt successfully anyway.
		log.WithFields(logger.Fields{
			"msg_id":         msg.MessageID(),
			"message_type":   msg.Type(),
			"encrypted_size": len(encryptedData),
			"skip_reason":    "garlic_decrypt_failed",
			"error":          err,
			"mitigation":     "router will skip this message and continue processing others",
			"root_cause":     "peers may have old cached RouterInfo - call publisher.ForceRouterInfoRepublish()",
		}).Debug("Skipping garlic message - decryption failed (likely transit traffic or key mismatch)")
		return nil // ← CRITICAL: Return nil instead of error to allow message processing to continue
	}

	var allCloves []GarlicClove
	for _, cloveData := range decryptedCloves {
		garlic, err := p.parseAndLogGarlic(msg.MessageID(), cloveData, sessionTag)
		if err != nil {
			return err
		}
		allCloves = append(allCloves, garlic.Cloves...)
	}

	return p.processGarlicCloves(allCloves, depth)
}

// validateGarlicSession verifies that the garlic session manager is configured.
func (p *MessageProcessor) validateGarlicSession() error {
	if p.garlicSessions == nil {
		return oops.Errorf("garlic session manager not configured - cannot decrypt garlic messages")
	}
	return nil
}

// extractGarlicData extracts encrypted data from the garlic message.
func (p *MessageProcessor) extractGarlicData(msg Message) ([]byte, error) {
	carrier, ok := msg.(DataCarrier)
	if !ok {
		return nil, oops.Errorf("garlic message does not implement DataCarrier")
	}

	encryptedData := carrier.GetData()
	if len(encryptedData) == 0 {
		return nil, oops.Errorf("garlic message contains no data")
	}

	return stripGarlicLengthPrefixIfPresent(encryptedData, int(msg.MessageID()))
}

// stripGarlicLengthPrefixIfPresent removes the 4-byte length prefix from garlic ciphertext.
// Garlic (type 11) encrypted payload on the wire is length-prefixed:
//
//	[4-byte big-endian length][ciphertext bytes]
//
// DecryptGarlicMessage expects ciphertext to begin with the 8-byte session tag,
// so we strip the prefix when it is present and consistent.
func stripGarlicLengthPrefixIfPresent(encryptedData []byte, messageID int) ([]byte, error) {
	if len(encryptedData) < 4 {
		return encryptedData, nil
	}

	declaredLen := int(binary.BigEndian.Uint32(encryptedData[0:4]))
	if declaredLen != len(encryptedData)-4 {
		return encryptedData, nil
	}

	payload := encryptedData[4:]
	logGarlicPrefixStripped(messageID, len(encryptedData), declaredLen, len(payload), payload)
	return payload, nil
}

// logGarlicPrefixStripped logs the removal of the length prefix.
func logGarlicPrefixStripped(messageID, framedSize, declaredSize, ciphertextSize int, payload []byte) {
	tagHead := logutil.BytePrefix(payload)

	log.WithFields(logger.Fields{
		"msg_id":              messageID,
		"framed_size":         framedSize,
		"declared_size":       declaredSize,
		"ciphertext_size":     ciphertextSize,
		"ciphertext_tag_head": tagHead,
	}).Debug("Stripped Garlic length prefix before decryption")
}

func parseECIESGarlicClove(data []byte) (*Garlic, error) {
	if len(data) == 0 {
		return nil, oops.Errorf("empty ECIES garlic clove")
	}

	deliveryInstructions, bytesRead, err := deserializeDeliveryInstructions(data)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to parse ECIES garlic delivery instructions")
	}
	if len(data) < bytesRead+ShortI2NPHeaderSize {
		return nil, oops.Errorf("ECIES garlic clove too short for short I2NP header: have %d bytes, need at least %d", len(data)-bytesRead, ShortI2NPHeaderSize)
	}

	msgType := int(data[bytesRead])
	i2npMsg := NewI2NPMessage(msgType)
	baseMsg, ok := i2npMsg.(*BaseI2NPMessage)
	if !ok {
		return nil, oops.Errorf("failed to create base I2NP message for type %d", msgType)
	}
	if err := baseMsg.UnmarshalShortI2NP(data[bytesRead:]); err != nil {
		return nil, oops.Wrapf(err, "failed to parse ECIES short I2NP message (type %d)", msgType)
	}

	clove := GarlicClove{
		DeliveryInstructions: *deliveryInstructions,
		Message:              baseMsg,
	}

	return &Garlic{
		Count:      1,
		Cloves:     []GarlicClove{clove},
		MessageID:  baseMsg.MessageID(),
		Expiration: baseMsg.Expiration(),
	}, nil
}

// decryptGarlicData decrypts the garlic message using the session manager.
// Returns all GarlicClove payloads found in the ratchet payload so that callers
// can process every clove rather than only the first.
func (p *MessageProcessor) decryptGarlicData(msgID int, encryptedData []byte) ([][]byte, [8]byte, error) {
	RecordExploratoryReplyStage(ExploratoryReplyStageGarlicDecryptAttempt)
	incomingTag := logutil.BytePrefix(encryptedData)

	log.WithFields(logger.Fields{
		"msg_id":         msgID,
		"encrypted_size": len(encryptedData),
		"incoming_tag":   incomingTag,
	}).Debug("Decrypting garlic message")

	decryptedCloves, sessionTag, _, err := p.garlicSessions.DecryptGarlicMessage(encryptedData)
	if err != nil {
		return nil, [8]byte{}, oops.Wrapf(err, "failed to decrypt garlic message")
	}
	RecordExploratoryReplyStage(ExploratoryReplyStageGarlicDecryptSuccess)

	log.WithFields(logger.Fields{
		"msg_id":      msgID,
		"clove_count": len(decryptedCloves),
		"session_tag": fmt.Sprintf("%x", sessionTag[:]),
	}).Debug("Garlic message decrypted successfully")

	return decryptedCloves, sessionTag, nil
}

// parseAndLogGarlic parses the decrypted ECIES clove payload and logs the result.
func (p *MessageProcessor) parseAndLogGarlic(msgID int, decryptedData []byte, sessionTag [8]byte) (*Garlic, error) {
	garlic, err := parseECIESGarlicClove(decryptedData)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to parse decrypted ECIES garlic clove")
	}

	log.WithFields(logger.Fields{
		"msg_id":        msgID,
		"clove_count":   len(garlic.Cloves),
		"session_tag":   fmt.Sprintf("%x", sessionTag[:]),
		"delivery_flag": garlic.Cloves[0].DeliveryInstructions.Flag,
		"wrapped_type":  garlic.Cloves[0].Message.Type(),
	}).Debug("Processing decrypted ECIES garlic clove")

	return garlic, nil
}

// processGarlicCloves processes each clove in the garlic message.
// depth tracks the current nesting level of garlic LOCAL delivery cloves.
func (p *MessageProcessor) processGarlicCloves(cloves []GarlicClove, depth int) error {
	for i, clove := range cloves {
		if err := p.processSingleClove(i, clove, depth); err != nil {
			return err
		}
	}
	return nil
}

// processSingleClove processes a single garlic clove based on its delivery type.
// depth tracks the current nesting level of garlic LOCAL delivery cloves.
func (p *MessageProcessor) processSingleClove(index int, clove GarlicClove, depth int) error {
	deliveryType := (clove.DeliveryInstructions.Flag >> 5) & 0x03

	if clove.Message == nil {
		log.WithField("clove_index", index).Warn("Garlic clove contains nil I2NP message")
		return oops.Errorf("garlic clove %d contains nil I2NP message", index)
	}

	log.WithFields(logger.Fields{
		"clove_index":   index,
		"clove_id":      clove.CloveID,
		"delivery_type": deliveryType,
		"wrapped_type":  clove.Message.Type(),
	}).Debug("Processing garlic clove")

	return p.routeCloveByType(index, deliveryType, clove, depth)
}

// routeCloveByType routes a clove to its destination based on delivery type.
// depth tracks the current nesting level of garlic LOCAL delivery cloves.
func (p *MessageProcessor) routeCloveByType(index int, deliveryType byte, clove GarlicClove, depth int) error {
	switch deliveryType {
	case 0x00:
		return p.handleLocalDelivery(index, clove, depth)
	case 0x01:
		p.handleDestinationDelivery(index, clove)
		return nil
	case 0x02:
		p.handleRouterDelivery(index, clove)
		return nil
	case 0x03:
		p.handleTunnelDelivery(index, clove)
		return nil
	}
	return oops.Errorf("unsupported garlic clove delivery type %d at index %d", deliveryType, index)
}

// handleLocalDelivery processes a LOCAL delivery clove.
// Guards against infinite recursion from nested garlic messages by tracking depth
// as a per-call-stack parameter, not a global counter.
// depth is the current nesting level; it is incremented for each nested LOCAL clove.
func (p *MessageProcessor) handleLocalDelivery(index int, clove GarlicClove, depth int) error {
	// Use the same depth limit as the parse-time guard for consistency
	nextDepth := depth + 1

	if nextDepth > MaxGarlicNestingDepth {
		log.WithFields(logger.Fields{
			"clove_index":   index,
			"nesting_depth": nextDepth,
			"max_depth":     MaxGarlicNestingDepth,
		}).Error("Garlic nesting depth exceeded, dropping clove to prevent recursion bomb")
		return oops.Errorf("garlic nesting depth exceeded for clove %d at depth %d", index, nextDepth)
	}

	// H6 FIX: Pass nextDepth to processMessageWithDepth so nested garlic messages
	// continue tracking the nesting depth and can't bypass the recursion limit.
	if err := p.processMessageWithDepth(clove.Message, nextDepth); err != nil {
		log.WithFields(logger.Fields{
			"clove_index": index,
			"error":       err,
		}).Error("Failed to process LOCAL clove message")
		return oops.Wrapf(err, "failed to process LOCAL clove %d", index)
	}
	log.WithField("clove_index", index).Debug("Successfully processed LOCAL clove")
	return nil
}

// handleDestinationDelivery forwards a clove to a destination hash.
func (p *MessageProcessor) handleDestinationDelivery(index int, clove GarlicClove) {
	if p.cloveForwarder == nil {
		log.WithFields(logger.Fields{
			"clove_index": index,
			"dest_hash":   logutil.HashPrefix(clove.DeliveryInstructions.Hash),
		}).Warn("DESTINATION delivery requires clove forwarder")
		return
	}

	err := p.cloveForwarder.ForwardToDestination(
		clove.DeliveryInstructions.Hash,
		clove.Message,
	)
	if err != nil {
		log.WithFields(logger.Fields{
			"clove_index": index,
			"dest_hash":   logutil.HashPrefix(clove.DeliveryInstructions.Hash),
			"error":       err,
		}).Error("Failed to forward clove to destination")
		return
	}

	log.WithFields(logger.Fields{
		"clove_index": index,
		"dest_hash":   logutil.HashPrefix(clove.DeliveryInstructions.Hash),
	}).Debug("Successfully forwarded clove to destination")
}

// handleRouterDelivery forwards a clove to a router hash.
func (p *MessageProcessor) handleRouterDelivery(index int, clove GarlicClove) {
	if p.cloveForwarder == nil {
		log.WithFields(logger.Fields{
			"clove_index": index,
			"router_hash": logutil.HashPrefix(clove.DeliveryInstructions.Hash),
		}).Warn("ROUTER delivery requires clove forwarder")
		return
	}

	err := p.cloveForwarder.ForwardToRouter(
		clove.DeliveryInstructions.Hash,
		clove.Message,
	)
	if err != nil {
		log.WithFields(logger.Fields{
			"clove_index": index,
			"router_hash": logutil.HashPrefix(clove.DeliveryInstructions.Hash),
			"error":       err,
		}).Error("Failed to forward clove to router")
		return
	}

	log.WithFields(logger.Fields{
		"clove_index": index,
		"router_hash": logutil.HashPrefix(clove.DeliveryInstructions.Hash),
	}).Debug("Successfully forwarded clove to router")
}

// handleTunnelDelivery forwards a clove through a tunnel.
func (p *MessageProcessor) handleTunnelDelivery(index int, clove GarlicClove) {
	if p.cloveForwarder == nil {
		log.WithFields(logger.Fields{
			"clove_index":  index,
			"gateway_hash": logutil.HashPrefix(clove.DeliveryInstructions.Hash),
			"tunnel_id":    clove.DeliveryInstructions.TunnelID,
		}).Warn("TUNNEL delivery requires clove forwarder")
		return
	}

	err := p.cloveForwarder.ForwardThroughTunnel(
		clove.DeliveryInstructions.Hash,
		clove.DeliveryInstructions.TunnelID,
		clove.Message,
	)
	if err != nil {
		log.WithFields(logger.Fields{
			"clove_index":  index,
			"gateway_hash": logutil.HashPrefix(clove.DeliveryInstructions.Hash),
			"tunnel_id":    clove.DeliveryInstructions.TunnelID,
			"error":        err,
		}).Error("Failed to forward clove through tunnel")
		return
	}

	log.WithFields(logger.Fields{
		"clove_index":  index,
		"gateway_hash": logutil.HashPrefix(clove.DeliveryInstructions.Hash),
		"tunnel_id":    clove.DeliveryInstructions.TunnelID,
	}).Debug("Successfully forwarded clove through tunnel")
}

// processTunnelDataMessage processes tunnel data messages using TunnelCarrier interface.
// If a TunnelDataHandler is configured, the message is delegated for endpoint decryption
// and delivery to the owning I2CP session. Otherwise the message is validated and logged.
func (p *MessageProcessor) processTunnelDataMessage(msg Message) error {
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
