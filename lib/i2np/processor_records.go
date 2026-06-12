package i2np

import (
	"fmt"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/crypto/rand"
	"github.com/go-i2p/go-i2p/lib/util/logutil"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
	"golang.org/x/crypto/chacha20poly1305"
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
func (p *MessageProcessor) processShortTunnelBuildMessage(msg Message) error {
	return p.processTunnelBuildRequest(msg, true)
}

// processVariableTunnelBuildMessage processes Variable Tunnel Build Messages (legacy format).
// This handles incoming requests using the older VTB format for backward compatibility.
func (p *MessageProcessor) processVariableTunnelBuildMessage(msg Message) error {
	return p.processTunnelBuildRequest(msg, false)
}

// processTunnelBuildMessage processes TunnelBuild (type 21) messages.
// TunnelBuild has a fixed format: exactly 8 records × 528 bytes = 4224 bytes,
// with NO count prefix byte (unlike VariableTunnelBuild type 23).
func (p *MessageProcessor) processTunnelBuildMessage(msg Message) error {
	return p.processFixedTunnelBuildRequest(msg)
}

// processFixedTunnelBuildRequest handles TunnelBuild (type 21) messages with
// fixed 8-record format. Unlike VTB/STBM, type 21 has no count prefix byte.
func (p *MessageProcessor) processFixedTunnelBuildRequest(msg Message) error {
	if err := p.validateParticipantManager(false, msg.Type()); err != nil {
		return err
	}

	data, err := p.extractBuildMessageData(msg)
	if err != nil {
		return err
	}

	records, err := p.parseFixedTunnelBuildRecords(data)
	if err != nil {
		return oops.Wrapf(err, "failed to parse fixed tunnel build records")
	}

	p.logParsedBuildRequest(msg.MessageID(), len(records), false)
	return p.processAllBuildRecords(msg.MessageID(), records, data, false)
}

// parseFixedTunnelBuildRecords parses TunnelBuild (type 21) records.
// Type 21 has exactly 8 records at 528 bytes each with no count prefix byte.
func (p *MessageProcessor) parseFixedTunnelBuildRecords(data []byte) ([]BuildRequestRecord, error) {
	const fixedRecordCount = 8
	const recordSize = 528                             // VTB record size
	const expectedSize = fixedRecordCount * recordSize // 4224 bytes

	if len(data) < expectedSize {
		return nil, oops.Errorf("insufficient data for TunnelBuild: have %d, need %d", len(data), expectedSize)
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
func (p *MessageProcessor) processTunnelBuildReplyMessage(msg Message) error {
	return p.processFixedBuildReply(msg)
}

// processFixedBuildReply handles TunnelBuildReply (type 22) with fixed 8-record format.
func (p *MessageProcessor) processFixedBuildReply(msg Message) error {
	if p.buildReplyProcessor == nil {
		log.WithFields(logger.Fields{
			"at":           "processFixedBuildReply",
			"message_type": msg.Type(),
			"message_id":   msg.MessageID(),
			"reason":       "no build reply processor configured",
		}).Warn("Tunnel build reply discarded - no TunnelBuildReplyProcessor set")
		return nil
	}

	data, err := extractBuildReplyData(msg)
	if err != nil {
		return err
	}

	const fixedRecordCount = 8
	const recordSize = 528
	const expectedSize = fixedRecordCount * recordSize

	if len(data) < expectedSize {
		return oops.Errorf("insufficient data for TunnelBuildReply: have %d, need %d", len(data), expectedSize)
	}

	records, rawRecords, err := parseFixedBuildRecords(data, fixedRecordCount, recordSize)
	if err != nil {
		return err
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

// extractBuildReplyData extracts the data payload from a build reply message.
func extractBuildReplyData(msg Message) ([]byte, error) {
	carrier, ok := msg.(DataCarrier)
	if !ok {
		return nil, oops.Errorf("tunnel build reply does not implement DataCarrier")
	}
	data := carrier.GetData()
	if len(data) == 0 {
		return nil, oops.Errorf("tunnel build reply contains no data")
	}
	return data, nil
}

// parseResponseRecords reads count response records of recordSize bytes each from data,
// starting at startOffset. It returns the parsed records, a raw byte copy of each record,
// and any parse error. The caller is responsible for bounds-checking data before calling.
func parseResponseRecords(data []byte, count, recordSize, startOffset int, isShortBuild bool) ([]BuildResponseRecord, [][]byte, error) {
	records := make([]BuildResponseRecord, count)
	rawRecords := make([][]byte, count)
	offset := startOffset
	for i := 0; i < count; i++ {
		recordData := data[offset : offset+recordSize]
		rawCopy := make([]byte, recordSize)
		copy(rawCopy, recordData)
		rawRecords[i] = rawCopy
		if isShortBuild {
			// Type-26 short replies carry 218-byte encrypted slots. They are
			// decrypted later in ReplyProcessor using pending build keys, so
			// populate a conservative placeholder record here and preserve raw
			// ciphertext in rawRecords for deferred decryption.
			records[i] = BuildResponseRecord{Reply: TunnelBuildReplyReject}
			offset += recordSize
			continue
		}
		record, err := ReadBuildResponseRecord(recordData)
		if err != nil {
			return nil, nil, oops.Wrapf(err, "failed to parse response record %d", i)
		}
		records[i] = record
		offset += recordSize
	}
	return records, rawRecords, nil
}

// parseFixedBuildRecords parses a fixed number of build response records from data.
func parseFixedBuildRecords(data []byte, count, recordSize int) ([8]BuildResponseRecord, [][]byte, error) {
	var records [8]BuildResponseRecord
	sliceRecords, rawRecords, err := parseResponseRecords(data, count, recordSize, 0, false)
	if err != nil {
		return records, nil, err
	}
	copy(records[:], sliceRecords)
	return records, rawRecords, nil
}

// processVariableTunnelBuildReplyMessage processes VariableTunnelBuildReply (type 24) messages.
// The reply contains a variable number of BuildResponseRecords.
func (p *MessageProcessor) processVariableTunnelBuildReplyMessage(msg Message) error {
	return p.processBuildReplyCommon(msg, false)
}

// processShortTunnelBuildReplyMessage processes ShortTunnelBuildReply (type 26) messages.
// Uses the newer short tunnel build format (v0.9.51+).
func (p *MessageProcessor) processShortTunnelBuildReplyMessage(msg Message) error {
	return p.processBuildReplyCommon(msg, true)
}

// processBuildReplyCommon is the common handler for all tunnel build reply message types.
// It extracts the response records from the raw message data, wraps them in the
// appropriate TunnelReplyHandler, and delegates to the configured TunnelBuildReplyProcessor.
func (p *MessageProcessor) processBuildReplyCommon(msg Message, isShortBuild bool) error {
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
		return oops.Errorf("tunnel build reply does not implement DataCarrier")
	}

	data := carrier.GetData()
	if len(data) == 0 {
		return oops.Errorf("tunnel build reply contains no data")
	}

	records, rawRecords, err := p.parseBuildResponseRecords(data, isShortBuild)
	if err != nil {
		return oops.Wrapf(err, "failed to parse build reply records")
	}

	// Wrap parsed records in a TunnelReplyHandler
	var handler TunnelReplyHandler
	if isShortBuild {
		RecordExploratoryReplyStage(ExploratoryReplyStageShortReplyDispatched)
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
		return nil, nil, oops.Errorf("insufficient data for record count")
	}

	recordCount := int(data[0])
	if recordCount < 1 || recordCount > 8 {
		return nil, nil, oops.Errorf("invalid record count: %d (must be 1-8)", recordCount)
	}

	recordSize := p.getRecordSize(isShortBuild)
	expectedLen := 1 + recordCount*recordSize
	if len(data) < expectedLen {
		return nil, nil, oops.Errorf("insufficient data for %d records: have %d, need %d", recordCount, len(data), expectedLen)
	}

	return parseResponseRecords(data, recordCount, recordSize, 1, isShortBuild)
}

// processTunnelBuildRequest is the common handler for both STBM and VTB messages.
// It extracts the build records, validates the request, and generates a reply.
//
// Parameters:
// - msg: The incoming I2NP tunnel build message
// - isShortBuild: True for STBM format, false for VTB format
func (p *MessageProcessor) processTunnelBuildRequest(msg Message, isShortBuild bool) error {
	if err := p.validateParticipantManager(isShortBuild, msg.Type()); err != nil {
		return err
	}

	data, err := p.extractBuildMessageData(msg)
	if err != nil {
		return err
	}

	records, err := p.parseTunnelBuildRecords(data, isShortBuild)
	if err != nil {
		return oops.Wrapf(err, "failed to parse tunnel build records")
	}

	p.logParsedBuildRequest(msg.MessageID(), len(records), isShortBuild)
	return p.processAllBuildRecords(msg.MessageID(), records, data, isShortBuild)
}

// validateParticipantManager checks if the participant manager is configured.
func (p *MessageProcessor) validateParticipantManager(isShortBuild bool, msgType int) error {
	if p.participantManager == nil {
		log.WithFields(logger.Fields{
			"at":             "processTunnelBuildRequest",
			"message_type":   msgType,
			"is_short_build": isShortBuild,
		}).Warn("participant manager not configured - rejecting tunnel build request")
		return oops.Errorf("participant manager not configured - cannot process tunnel build requests")
	}
	return nil
}

// extractBuildMessageData extracts raw data from the tunnel build message.
func (p *MessageProcessor) extractBuildMessageData(msg Message) ([]byte, error) {
	carrier, ok := msg.(DataCarrier)
	if !ok {
		return nil, oops.Errorf("tunnel build message does not implement DataCarrier")
	}

	data := carrier.GetData()
	if len(data) == 0 {
		return nil, oops.Errorf("tunnel build message contains no data")
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
func (p *MessageProcessor) processAllBuildRecords(messageID int, records []BuildRequestRecord, rawData []byte, isShortBuild bool) error {
	var zeroHash common.Hash
	if p.ourRouterHash == zeroHash {
		log.WithFields(logger.Fields{
			"at":         "processAllBuildRecords",
			"message_id": messageID,
		}).Warn("Router hash not set (zero) — skipping all build records. Call SetOurRouterHash first.")
		return oops.Errorf("router hash not set: call SetOurRouterHash before processing tunnel build messages")
	}

	for i, record := range records {
		if record.OurIdent != p.ourRouterHash {
			log.WithFields(logger.Fields{
				"at":           "processAllBuildRecords",
				"message_id":   messageID,
				"record_index": i,
				"record_ident": logutil.HashPrefix(record.OurIdent),
			}).Debug("Skipping build record not destined for us")
			continue
		}
		p.processSingleBuildRecord(messageID, i, record, rawData, isShortBuild)
	}
	return nil
}

// processSingleBuildRecord validates and processes a single build request record.
// After validating and accepting/rejecting the request, it generates an encrypted
// BuildResponseRecord and forwards it to the next hop.
func (p *MessageProcessor) processSingleBuildRecord(messageID, index int, record BuildRequestRecord, rawData []byte, isShortBuild bool) {
	accepted, rejectCode, reason := p.participantManager.ProcessBuildRequest(record.OurIdent)

	if accepted {
		if err := p.handleAcceptedBuildRecord(messageID, index, record); err != nil {
			// Registration failed — send a rejection reply so the tunnel builder
			// knows this hop is non-functional instead of a phantom success.
			rejectCode = TunnelBuildReplyReject
			p.handleRejectedBuildRecord(messageID, index, record, rejectCode,
				fmt.Sprintf("participant registration failed: %v", err))
		} else {
			rejectCode = TunnelBuildReplySuccess
		}
	} else {
		p.handleRejectedBuildRecord(messageID, index, record, rejectCode, reason)
	}

	// Generate and send build reply message
	if err := p.generateAndSendBuildReply(messageID, index, record, rejectCode, rawData, isShortBuild); err != nil {
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
//
// For STBM (isShortBuild=true) the wire format differs from VTB:
//   - Reply record: 218 bytes, ChaCha20 stream XOR (no Poly1305 tag)
//   - Our reply slot is written at position 'index' in the full N-slot message
//   - All other slots carry the original (opaque) build-request bytes so the
//     reply message has the correct wire size: 1 byte count + N × 218 bytes
//
// For VTB (isShortBuild=false) the original AEAD path is unchanged:
//   - 528-byte cleartext → ChaCha20-Poly1305 AEAD → 544-byte ciphertext
func (p *MessageProcessor) generateAndSendBuildReply(messageID, index int, record BuildRequestRecord, replyCode byte, rawData []byte, isShortBuild bool) error {
	encryptedReply, err := p.encryptBuildReply(index, record, replyCode, rawData, isShortBuild)
	if err != nil {
		return err
	}

	if err := p.forwardBuildReply(messageID, record, encryptedReply, isShortBuild); err != nil {
		return oops.Wrapf(err, "failed to forward build reply")
	}

	p.logBuildReplySuccess(messageID, index, replyCode, int(record.NextTunnel), len(encryptedReply), isShortBuild)
	return nil
}

// encryptBuildReply encrypts a build reply using the appropriate encryption path.
func (p *MessageProcessor) encryptBuildReply(index int, record BuildRequestRecord, replyCode byte, rawData []byte, isShortBuild bool) ([]byte, error) {
	if isShortBuild {
		return p.encryptSTBMReply(index, replyCode, rawData)
	}
	return p.encryptVTBReply(index, record, replyCode)
}

// encryptSTBMReply encrypts a short tunnel build reply.
func (p *MessageProcessor) encryptSTBMReply(index int, replyCode byte, rawData []byte) ([]byte, error) {
	var crypto stbmSlotCrypto
	if p.stbmSlotCrypto != nil {
		crypto = p.stbmSlotCrypto[index]
	}

	encryptedReply, err := p.buildSTBMReplyMessage(rawData, index, crypto, replyCode)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to build STBM reply message")
	}
	return encryptedReply, nil
}

// encryptVTBReply encrypts a variable tunnel build reply.
func (p *MessageProcessor) encryptVTBReply(index int, record BuildRequestRecord, replyCode byte) ([]byte, error) {
	var randomData [495]byte
	if _, err := rand.Read(randomData[:]); err != nil {
		return nil, oops.Wrapf(err, "failed to generate random data for VTB reply")
	}

	responseRecord := CreateBuildResponseRecord(replyCode, randomData)

	if p.buildRecordCrypto == nil {
		log.WithFields(logger.Fields{
			"at":           "generateAndSendBuildReply",
			"record_index": index,
		}).Warn("build record crypto not initialized - cannot encrypt reply")
		return nil, oops.Errorf("build record crypto not initialized")
	}

	encryptedReply, err := p.buildRecordCrypto.EncryptReplyRecord(
		responseRecord,
		record.ReplyKey,
		record.ReplyIV,
	)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to encrypt VTB build response record")
	}

	return encryptedReply, nil
}

// logBuildReplySuccess logs successful build reply generation and sending.
func (p *MessageProcessor) logBuildReplySuccess(messageID, index int, replyCode byte, nextTunnel, encryptedLen int, isShortBuild bool) {
	log.WithFields(logger.Fields{
		"at":             "generateAndSendBuildReply",
		"message_id":     messageID,
		"record_index":   index,
		"reply_code":     replyCode,
		"next_tunnel":    nextTunnel,
		"encrypted_len":  encryptedLen,
		"is_short_build": isShortBuild,
	}).Debug("generated and sent build reply successfully")
}

// buildSTBMReplyMessage assembles the ShortTunnelBuildReply body (type 26):
//
//	[count:1][slot_0:218][slot_1:218]...[slot_N-1:218]
//
// Our slot (ourIndex) is encrypted with ChaCha20-Poly1305 AEAD using the Noise-derived
// replyKey and noiseHash as AD. All other slots are ChaCha20-XOR'd with the same replyKey.
// Matches i2pd I2NPProtocol.cpp transit-hop reply construction.
func (p *MessageProcessor) buildSTBMReplyMessage(rawData []byte, ourIndex int, crypto stbmSlotCrypto, replyCode byte) ([]byte, error) {
	count, expected, err := p.validateSTBMReplyParams(rawData, ourIndex)
	if err != nil {
		return nil, err
	}

	replyData := p.initializeSTBMReply(rawData, expected, count)

	if err := p.encryptSTBMSlots(replyData, count, ourIndex, crypto, replyCode); err != nil {
		return nil, err
	}

	log.WithFields(logger.Fields{
		"at":         "buildSTBMReplyMessage",
		"slot_count": count,
		"our_index":  ourIndex,
		"reply_code": replyCode,
	}).Debug("assembled STBM reply message")

	return replyData, nil
}

// validateSTBMReplyParams validates the STBM reply parameters and returns count and expected size.
func (p *MessageProcessor) validateSTBMReplyParams(rawData []byte, ourIndex int) (int, int, error) {
	if len(rawData) < 1 {
		return 0, 0, oops.Errorf("STBM rawData empty")
	}
	count := int(rawData[0])
	if count < 1 || count > 8 {
		return 0, 0, oops.Errorf("STBM invalid record count: %d (want 1-8)", count)
	}
	expected := 1 + count*ShortBuildRecordSize
	if len(rawData) < expected {
		return 0, 0, oops.Errorf("STBM rawData too short: have %d, need %d", len(rawData), expected)
	}
	if ourIndex < 0 || ourIndex >= count {
		return 0, 0, oops.Errorf("STBM slot index %d out of range [0, %d)", ourIndex, count)
	}
	return count, expected, nil
}

// initializeSTBMReply creates the reply data buffer with verbatim copy of build message.
func (p *MessageProcessor) initializeSTBMReply(rawData []byte, expected, count int) []byte {
	replyData := make([]byte, expected)
	replyData[0] = byte(count)
	copy(replyData[1:], rawData[1:expected])
	return replyData
}

// encryptSTBMSlots encrypts all slots: AEAD for our slot, ChaCha20 XOR for others.
func (p *MessageProcessor) encryptSTBMSlots(replyData []byte, count, ourIndex int, crypto stbmSlotCrypto, replyCode byte) error {
	var nonce [12]byte
	for j := 0; j < count; j++ {
		slotOffset := 1 + j*ShortBuildRecordSize
		nonce[4] = byte(j)
		if j == ourIndex {
			if err := p.encryptOwnSTBMSlot(replyData, slotOffset, nonce, crypto, replyCode); err != nil {
				return err
			}
		} else {
			if err := p.xorOtherSTBMSlot(replyData, slotOffset, j, crypto.replyKey); err != nil {
				return err
			}
		}
	}
	return nil
}

// encryptOwnSTBMSlot AEAD-encrypts our slot with the reply code.
func (p *MessageProcessor) encryptOwnSTBMSlot(replyData []byte, slotOffset int, nonce [12]byte, crypto stbmSlotCrypto, replyCode byte) error {
	cleartext := p.prepareSTBMSlotCleartext(replyCode)
	aead, err := chacha20poly1305.New(crypto.replyKey[:])
	if err != nil {
		return oops.Wrapf(err, "ChaCha20-Poly1305 init failed")
	}
	ciphertext := aead.Seal(nil, nonce[:], cleartext[:], crypto.noiseHash[:])
	copy(replyData[slotOffset:], ciphertext[:ShortBuildRecordSize])
	return nil
}

// prepareSTBMSlotCleartext prepares 202-byte cleartext: zero options, random padding, retCode at [201].
func (p *MessageProcessor) prepareSTBMSlotCleartext(replyCode byte) [ShortBuildRecordSize - 16]byte {
	var cleartext [ShortBuildRecordSize - 16]byte // 202 bytes
	cleartext[0] = 0x00                           // options high byte
	cleartext[1] = 0x00                           // options low byte
	rand.Read(cleartext[2:201])                   // padding (error ignored, acceptable for padding)
	cleartext[201] = replyCode
	return cleartext
}

// xorOtherSTBMSlot ChaCha20-XORs other slots so the next hop can peel our layer.
func (p *MessageProcessor) xorOtherSTBMSlot(replyData []byte, slotOffset, slotIndex int, replyKey [32]byte) error {
	var slot [ShortBuildRecordSize]byte
	copy(slot[:], replyData[slotOffset:slotOffset+ShortBuildRecordSize])
	if err := chacha20XORRecord(&slot, replyKey, slotIndex); err != nil {
		return oops.Wrapf(err, "ChaCha20 XOR failed for STBM reply slot %d", slotIndex)
	}
	copy(replyData[slotOffset:slotOffset+ShortBuildRecordSize], slot[:])
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
			"next_ident":  logutil.HashPrefix(record.NextIdent),
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
		"target_hash":    logutil.HashPrefix(record.OurIdent),
	}).Info("accepting tunnel build request")

	expiry := time.Now().Add(10 * time.Minute) // Tunnel lifetime per I2P spec
	err := p.participantManager.RegisterParticipant(
		record.ReceiveTunnel,
		record.OurIdent,
		expiry,
		record.LayerKey,
		record.IVKey,
		record.NextIdent,
		record.NextTunnel,
	)
	if err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"at":             "processTunnelBuildRequest",
			"receive_tunnel": record.ReceiveTunnel,
		}).Error("failed to register participant after acceptance")
		return oops.Wrapf(err, "RegisterParticipant failed for tunnel %d", record.ReceiveTunnel)
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
		return 0, oops.Errorf("insufficient data for record count")
	}

	recordCount := int(data[0])
	if recordCount < 1 || recordCount > 8 {
		return 0, oops.Errorf("invalid record count: %d (must be 1-8)", recordCount)
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
			return nil, oops.Errorf("insufficient data for record %d: have %d, need %d", i, len(data)-offset, recordSize)
		}

		recordData := data[offset : offset+recordSize]
		p.tryParseAndAppendRecord(&records, recordData, i, isShortBuild)
		offset += recordSize
	}

	return records, nil
}

// tryParseAndAppendRecord attempts to parse a single build request record.
// For standard (VTB) 528-byte records it checks the first 16 bytes (toPeer)
// against our router identity hash. If the record is destined for us and a
// BuildRequestDecryptor + private key are configured, the record is decrypted
// via ECIES-X25519-AEAD before parsing. Records not destined for us are still
// appended so that processAllBuildRecords can forward them to other hops.
// When no decryptor is configured the record is parsed as cleartext (testing mode).
func (p *MessageProcessor) tryParseAndAppendRecord(records *[]BuildRequestRecord, recordData []byte, index int, isShortBuild bool) {
	if isShortBuild && len(recordData) >= ShortBuildRecordSize {
		p.tryParseShortRecord(records, recordData, index)
	} else if !isShortBuild && len(recordData) >= StandardBuildRecordSize {
		p.tryParseStandardRecord(records, recordData, index)
	}
}

// tryParseShortRecord handles STBM 218-byte encrypted records (ECIES).
// When an identity and decryptor are configured it attempts ECIES decryption;
// otherwise it falls back to cleartext parsing (test/introspection mode).
// CRITICAL: If the record is destined for us but decryption fails, we must not
// fall back to cleartext parsing, as that could allow forged build records.
func (p *MessageProcessor) tryParseShortRecord(records *[]BuildRequestRecord, recordData []byte, index int) {
	if p.isRecordForUs(recordData) && p.buildRequestDecryptor != nil && len(p.ourPrivateKey) > 0 {
		record, err := p.decryptShortRecord(recordData, index)
		if err == nil {
			*records = append(*records, record)
			return
		}
		// Record is destined for us but decryption failed; fail-closed by not
		// appending. Do not parse as cleartext to prevent forged participant registration.
		log.WithError(err).WithField("record_index", index).Warn("STBM ECIES decryption failed; rejecting record destined for us")
		return
	}
	// Record is not destined for us, or no decryptor is configured (test mode).
	// Parse as cleartext for forward/introspection.
	record, err := ReadBuildRequestRecord(recordData)
	if err != nil {
		log.WithError(err).WithField("record_index", index).Warn("failed to parse STBM build request record")
	} else {
		*records = append(*records, record)
	}
}

// decryptShortRecord decrypts a 218-byte STBM record using ECIES-X25519-AEAD.
// As a side effect it populates p.stbmSlotCrypto[index] with the Noise-derived
// reply key and transcript hash that are needed to build the AEAD reply.
func (p *MessageProcessor) decryptShortRecord(recordData []byte, index int) (BuildRequestRecord, error) {
	var encrypted [218]byte
	copy(encrypted[:], recordData[:218])
	ck, noiseHash, err := DecryptSTBMRecordReturningChainingKeyAndHash(encrypted, p.ourPrivateKey)
	if err != nil {
		return BuildRequestRecord{}, err
	}
	replyKey, _, err := DeriveSTBMReplyKey(ck)
	if err != nil {
		return BuildRequestRecord{}, oops.Wrapf(err, "failed to derive STBM reply key for slot %d", index)
	}
	if p.stbmSlotCrypto == nil {
		p.stbmSlotCrypto = make(map[int]stbmSlotCrypto)
	}
	p.stbmSlotCrypto[index] = stbmSlotCrypto{replyKey: replyKey, noiseHash: noiseHash}
	return DecryptShortBuildRequestRecord(encrypted, p.ourPrivateKey)
}

// tryParseStandardRecord handles VTB 528-byte records. It checks the toPeer
// prefix, attempts ECIES decryption when a decryptor is available, and fails
// closed on decryption failure to prevent forged build records.
func (p *MessageProcessor) tryParseStandardRecord(records *[]BuildRequestRecord, recordData []byte, index int) {
	if p.isRecordForUs(recordData) && p.buildRequestDecryptor != nil && len(p.ourPrivateKey) > 0 {
		record, err := p.decryptStandardRecord(recordData, index)
		if err == nil {
			*records = append(*records, record)
			return
		}
		// Record is destined for us but decryption failed; fail-closed by not
		// appending. Do not parse as cleartext to prevent forged participant registration.
		log.WithError(err).WithField("record_index", index).Warn("ECIES decryption failed; rejecting record destined for us")
		return
	}
	// Record is not destined for us, or no decryptor is configured (test mode).
	// Parse as cleartext for forward/introspection.
	record, err := ReadBuildRequestRecord(recordData)
	if err != nil {
		log.WithError(err).WithField("record_index", index).Warn("failed to parse VTB build request record")
	} else {
		*records = append(*records, record)
	}
}

// isRecordForUs checks whether the first 16 bytes of the encrypted record
// (the toPeer field) match the first 16 bytes of our router identity hash.
func (p *MessageProcessor) isRecordForUs(recordData []byte) bool {
	var zeroHash common.Hash
	if p.ourRouterHash == zeroHash || len(recordData) < 16 {
		return false
	}
	for i := 0; i < 16; i++ {
		if recordData[i] != p.ourRouterHash[i] {
			return false
		}
	}
	return true
}

// decryptStandardRecord decrypts a 528-byte VTB record using ECIES-X25519-AEAD.
func (p *MessageProcessor) decryptStandardRecord(recordData []byte, index int) (BuildRequestRecord, error) {
	var encrypted [528]byte
	copy(encrypted[:], recordData[:528])
	return p.buildRequestDecryptor.DecryptRecord(encrypted, p.ourPrivateKey)
}
