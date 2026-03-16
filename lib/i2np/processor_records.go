package i2np

import (
	"fmt"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/crypto/rand"
	"github.com/go-i2p/logger"
)

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
