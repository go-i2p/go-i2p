package i2np

import (
	"fmt"
	"strconv"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/crypto/rand"
	i2ptunnel "github.com/go-i2p/crypto/tunnel"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/go-i2p/go-i2p/lib/util/logutil"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
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
	return newBuildRequestProcessor(p, msg).process()
}

// parseResponseRecords reads count 218-byte short response records from data,
// starting at startOffset. It returns placeholder records plus a raw byte copy
// of each record. Type-26 short replies carry encrypted slots that are
// decrypted later in ReplyProcessor using pending build keys, so the actual
// ciphertext is preserved in rawRecords for that deferred decryption. The
// Reply field is set to an internal "pending decryption" sentinel so
// pre-decryption consumers cannot mistake it for a real wire rejection code.
// The caller is responsible for bounds-checking data before calling.
func parseResponseRecords(data []byte, count, recordSize, startOffset int) ([]BuildResponseRecord, [][]byte, error) {
	records := make([]BuildResponseRecord, count)
	rawRecords := make([][]byte, count)
	offset := startOffset
	for i := 0; i < count; i++ {
		recordData := data[offset : offset+recordSize]
		rawCopy := make([]byte, recordSize)
		copy(rawCopy, recordData)
		rawRecords[i] = rawCopy
		records[i] = BuildResponseRecord{Reply: TunnelBuildReplyPendingDecryption}
		offset += recordSize
	}
	return records, rawRecords, nil
}

// processShortTunnelBuildReplyMessage processes ShortTunnelBuildReply (type 26)
// messages, the current short tunnel build reply format (v0.9.51+).
func (p *MessageProcessor) processShortTunnelBuildReplyMessage(msg Message) error {
	return p.processBuildReplyCommon(msg)
}

// processBuildReplyCommon is the common handler for all tunnel build reply message types.
// It extracts the response records from the raw message data, wraps them in the
// appropriate TunnelReplyHandler, and delegates to the configured TunnelBuildReplyProcessor.
func (p *MessageProcessor) processBuildReplyCommon(msg Message) error {
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

	records, rawRecords, err := p.parseBuildResponseRecords(data)
	if err != nil {
		return oops.Wrapf(err, "failed to parse build reply records")
	}

	RecordExploratoryReplyStage(ExploratoryReplyStageShortReplyDispatched)
	handler := &ShortTunnelBuildReply{
		Count:                len(records),
		BuildResponseRecords: records,
		RawRecordData:        rawRecords,
	}

	log.WithFields(logger.Fields{
		"at":           "processBuildReplyCommon",
		"message_id":   msg.MessageID(),
		"record_count": len(records),
	}).Debug("Dispatching tunnel build reply to processor")

	return p.buildReplyProcessor.ProcessTunnelBuildReply(handler, msg.MessageID())
}

// parseBuildResponseRecords parses short build response records from raw
// message data. The format is: 1 byte record count followed by N 218-byte
// records. Returns both placeholder records and the raw encrypted bytes for
// each record, since re-serializing parsed records corrupts the original
// ciphertext needed for decryption.
func (p *MessageProcessor) parseBuildResponseRecords(data []byte) ([]BuildResponseRecord, [][]byte, error) {
	if len(data) < 1 {
		return nil, nil, oops.Errorf("insufficient data for record count")
	}

	recordCount := int(data[0])
	if recordCount < 1 || recordCount > 8 {
		return nil, nil, oops.Errorf("invalid record count: %d (must be 1-8)", recordCount)
	}

	recordSize := ShortBuildRecordSize
	expectedLen := 1 + recordCount*recordSize
	if len(data) < expectedLen {
		return nil, nil, oops.Errorf("insufficient data for %d records: have %d, need %d", recordCount, len(data), expectedLen)
	}

	return parseResponseRecords(data, recordCount, recordSize, 1)
}

// buildRequestProcessor centralizes the common extract → validate → parse → log → dispatch flow.
type buildRequestProcessor struct {
	processor        *MessageProcessor
	msg              Message
	inputMessageType int
	parse            func([]byte) ([]BuildRequestRecord, []int, error)
}

func newBuildRequestProcessor(p *MessageProcessor, msg Message) buildRequestProcessor {
	return buildRequestProcessor{
		processor:        p,
		msg:              msg,
		inputMessageType: msg.Type(),
		parse: func(data []byte) ([]BuildRequestRecord, []int, error) {
			return p.parseTunnelBuildRecords(data)
		},
	}
}

func (b buildRequestProcessor) process() error {
	if err := b.processor.validateParticipantManager(b.msg.Type()); err != nil {
		return err
	}

	data, err := b.processor.extractBuildMessageData(b.msg)
	if err != nil {
		return err
	}

	// A ShortTunnelBuild addressed to us may be the completed reply set of an
	// inbound tunnel we are building (see tryCompleteInboundBuild); check that
	// before treating the message as a request to participate in a build.
	if handled, err := b.processor.tryCompleteInboundBuild(b.msg.MessageID(), data); handled {
		return err
	}

	records, slotIndices, err := b.parse(data)
	if err != nil {
		return oops.Wrapf(err, "failed to parse tunnel build records")
	}

	b.processor.logParsedBuildRequest(b.msg.MessageID(), len(records))
	return b.processor.processAllBuildRecords(b.msg.MessageID(), records, slotIndices, data, b.inputMessageType)
}

// pendingInboundBuildMatcher is optionally implemented by a
// TunnelBuildReplyProcessor that can say whether an inbound tunnel build it
// started is still awaiting its reply set under a given I2NP message ID.
// Implemented by *TunnelManager.
type pendingInboundBuildMatcher interface {
	HasPendingInboundBuild(messageID int) bool
}

// tryCompleteInboundBuild recognises the final leg of an inbound tunnel build
// that this router created.
//
// Inbound builds have no OBEP hop: the creator is the tunnel's endpoint, so
// every peer relays the transformed message (type 25) to the previous hop and
// the inbound gateway sends the finished message - whose body is now the
// complete reply set, [count][N x 218] - straight back to the creator. The
// I2NP message ID is the correlation ID the creator put in the last record's
// "next message ID" field.
//
// This mirrors the reference behaviour of checking for a pending inbound tunnel
// by reply message ID before doing any transit processing (i2pd
// Tunnel::HandleShortTunnelBuildMsg -> GetPendingInboundTunnel). When the ID
// matches, the body is handed to the reply processor, which peels the per-hop
// ChaCha20 layers and AEAD-decrypts each reply slot, establishing the tunnel.
//
// It returns handled=true when the message was consumed as our own inbound
// build reply (err reports the outcome) and handled=false when normal build
// request processing should continue.
func (p *MessageProcessor) tryCompleteInboundBuild(messageID int, data []byte) (bool, error) {
	if p.buildReplyProcessor == nil {
		return false, nil
	}
	matcher, ok := p.buildReplyProcessor.(pendingInboundBuildMatcher)
	if !ok || !matcher.HasPendingInboundBuild(messageID) {
		return false, nil
	}

	records, rawRecords, err := p.parseBuildResponseRecords(data)
	if err != nil {
		log.WithFields(logger.Fields{
			"at":          "tryCompleteInboundBuild",
			"message_id":  messageID,
			"record_size": len(data),
			"error":       err,
		}).Warn("Inbound build reply set could not be parsed - falling back to build request processing")
		return false, nil
	}

	handler := &ShortTunnelBuildReply{
		Count:                len(records),
		BuildResponseRecords: records,
		RawRecordData:        rawRecords,
	}

	RecordExploratoryReplyStage(ExploratoryReplyStageShortReplyDispatched)
	log.WithFields(logger.Fields{
		"at":           "tryCompleteInboundBuild",
		"message_id":   messageID,
		"record_count": len(records),
	}).Debug("Completed inbound tunnel build from relayed ShortTunnelBuild")

	if err := p.buildReplyProcessor.ProcessTunnelBuildReply(handler, messageID); err != nil {
		return true, oops.Wrapf(err, "failed to process inbound build reply set")
	}
	return true, nil
}

// validateParticipantManager checks if the participant manager is configured.
func (p *MessageProcessor) validateParticipantManager(msgType int) error {
	if p.participantManager == nil {
		log.WithFields(logger.Fields{
			"at":           "processTunnelBuildRequest",
			"message_type": msgType,
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
func (p *MessageProcessor) logParsedBuildRequest(messageID, recordCount int) {
	log.WithFields(logger.Fields{
		"at":           "processTunnelBuildRequest",
		"message_id":   messageID,
		"record_count": recordCount,
	}).Debug("parsed tunnel build request")
}

// processAllBuildRecords processes each build record destined for us.
//
// Every record in the list was already decrypted by tryParseAndAppendRecord: a
// short build record carries no OurIdent (it is zero), so successful decryption
// with our static key is the sole proof that the record is ours. Records we could
// not decrypt are never added to the list. slotIndices[i] is the position record
// i occupied in the message - the reply/forward transform must use it, not the
// index within this filtered list.
//
// Per tunnel-creation-ecies.rst, a hop sends the ShortTunnelBuildReply (type 26)
// only if it is the outbound endpoint (request record flag bit 6); every other
// hop forwards the transformed build message (type 25) to the next hop. The
// total record count from rawData determines whether our slot is the last one.
//
// inputMessageType is preserved so the reply type maps correctly (type 25
// ShortTunnelBuild -> type 26 ShortTunnelBuildReply).
//
// IMPORTANT: If our router hash has not been set (is zero), NO records are
// added to the list by tryParseAndAppendRecord, so this function will be called with an
// empty list. Callers must call SetOurRouterHash before processing any tunnel
// build messages.
func (p *MessageProcessor) processAllBuildRecords(messageID int, records []BuildRequestRecord, slotIndices []int, rawData []byte, inputMessageType int) error {
	var zeroHash common.Hash
	if p.ourRouterHash == zeroHash {
		log.WithFields(logger.Fields{
			"at":         "processAllBuildRecords",
			"message_id": messageID,
		}).Warn("Router hash not set (zero) — skipping all build records. Call SetOurRouterHash first.")
		return oops.Errorf("router hash not set: call SetOurRouterHash before processing tunnel build messages")
	}

	for i, record := range records {
		slot := i
		if i < len(slotIndices) {
			slot = slotIndices[i]
		}
		p.processSingleBuildRecord(messageID, slot, record, rawData, inputMessageType)
	}
	return nil
}

// processSingleBuildRecord validates and processes a single build request record.
// After validating and accepting/rejecting the request, it generates an encrypted
// BuildResponseRecord and forwards it to the next hop.
// inputMessageType is passed to generateAndSendBuildReply for correct reply type mapping.
func (p *MessageProcessor) processSingleBuildRecord(messageID, index int, record BuildRequestRecord, rawData []byte, inputMessageType int) {
	accepted, rejectCode, reason := p.participantManager.ProcessBuildRequest(record.OurIdent)

	// availableBW is the bandwidth (KB/s) advertised back to the tunnel creator
	// in the reply's "b" option. It stays 0 unless the request is accepted and
	// the bandwidth policy computes a non-zero offer.
	var availableBW uint32

	if accepted {
		// Apply the transit-tunnel bandwidth policy (i2pd TransitTunnel build
		// handling): a non-zero reject code overrides acceptance with code 30.
		bwReject, avail := p.participantManager.EvaluateBuildBandwidth(record.MinBandwidthKBps, record.RequestedBandwidthKBps)
		if bwReject != 0 {
			rejectCode = bwReject
			p.handleRejectedBuildRecord(messageID, index, record, rejectCode,
				"insufficient transit bandwidth")
		} else if err := p.handleAcceptedBuildRecord(messageID, index, record); err != nil {
			// Registration failed — send a rejection reply so the tunnel builder
			// knows this hop is non-functional instead of a phantom success.
			// Use the spec-sanctioned bandwidth rejection (0x03): 0x01 is a
			// deprecated receive-only code and must never be transmitted.
			rejectCode = TunnelBuildReplyBandwidth
			p.handleRejectedBuildRecord(messageID, index, record, rejectCode,
				fmt.Sprintf("participant registration failed: %v", err))
		} else {
			rejectCode = TunnelBuildReplySuccess
			availableBW = avail
		}
	} else {
		p.handleRejectedBuildRecord(messageID, index, record, rejectCode, reason)
	}

	// Generate and send build reply message
	if err := p.generateAndSendBuildReply(messageID, index, record, rejectCode, availableBW, rawData, inputMessageType); err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"at":             "processSingleBuildRecord",
			"message_id":     messageID,
			"record_index":   index,
			"receive_tunnel": record.ReceiveTunnel,
		}).Error("failed to generate and send build reply")
	}
}

// generateAndSendBuildReply applies this hop's symmetric transform to the build
// message and sends it on. The transform is the same for every hop
// (tunnel-creation-ecies.rst "Symmetric Encryption of Records"): our own slot is
// replaced with our AEAD-encrypted reply, and every other slot is ChaCha20-XOR'd
// with our reply key (which peels the layer the creator pre-applied to the still
// opaque request slots, or adds a layer to the replies of earlier hops).
//
// What differs is where the transformed message goes, decided by our record's
// OBEP flag bit (bit 6, tunnel.FlagOBEP), exactly as the I2P reference (i2pd
// TransitTunnels::HandleShortTransitTunnelBuildMsg) branches on
// TUNNEL_BUILD_RECORD_ENDPOINT_FLAG:
//   - OBEP set (we are the outbound endpoint): send it back toward the creator
//     as a ShortTunnelBuildReply (type 26) through the reply routing in our
//     record (NextIdent/NextTunnel = the reply tunnel gateway).
//   - OBEP clear (a transit/inbound hop): forward the SAME transformed body to
//     the next hop as a ShortTunnelBuild (type 25) message, so the next hop can
//     process its record. For the final hop of an inbound build this delivers
//     the completed reply set back to the creator.
//
// The reply/forward body has wire size 1 byte count + N × 218 bytes.
// See [I2P Spec: Tunnel Creation ECIES](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/tunnel-creation-ecies.rst) "Message Flow" and "Symmetric Encryption of Records".
func (p *MessageProcessor) generateAndSendBuildReply(messageID, index int, record BuildRequestRecord, replyCode byte, availableBW uint32, rawData []byte, inputMessageType int) error {
	transformed, err := p.encryptBuildReply(index, replyCode, availableBW, rawData)
	if err != nil {
		return err
	}

	// The outgoing I2NP message ID is the "next message ID" carried in our own
	// request record (spec field bytes 52-55), NOT the ID the message arrived
	// with. i2pd uses SHORT_REQUEST_RECORD_SEND_MSG_ID_OFFSET for both the
	// type-26 reply and the type-25 relay; a conforming creator sets the final
	// hop's value to its own correlation ID and randomizes the rest, so echoing
	// the incoming ID would break reply correlation against real peers.
	outgoingID := record.SendMessageID

	// Flag bit 6 (OBEP) marks the outbound endpoint: it is the only hop that
	// emits a ShortTunnelBuildReply. Every other hop relays the build request.
	if record.Flag&tunnel.FlagOBEP != 0 {
		if err := p.forwardBuildReply(outgoingID, record, transformed, inputMessageType); err != nil {
			return oops.Wrapf(err, "failed to forward build reply")
		}
		p.logBuildReplySuccess(outgoingID, index, replyCode, int(record.NextTunnel), len(transformed))
		return nil
	}

	// Transit / inbound hop: relay the build message to the next hop as a type-25 STBM.
	if err := p.forwardBuildRequest(outgoingID, record, transformed, inputMessageType); err != nil {
		return oops.Wrapf(err, "failed to forward build request to next hop")
	}
	p.logBuildRequestForward(outgoingID, index, record)
	return nil
}

// forwardBuildRequest relays the transformed build message to the next hop as a
// ShortTunnelBuild (type 25) over a direct transport session to the next hop's
// identity (NextIdent). A build request is always sent hop-to-hop directly: the
// NextTunnel field carries the next hop's receive tunnel ID as record data, not a
// routing tunnel, so - unlike the build reply - it is never wrapped in a
// TunnelGateway here.
func (p *MessageProcessor) forwardBuildRequest(messageID int, record BuildRequestRecord, body []byte, inputMessageType int) error {
	if p.buildReplyForwarder == nil {
		log.WithFields(logger.Fields{
			"at":         "forwardBuildRequest",
			"message_id": messageID,
			"next_ident": logutil.HashPrefix(record.NextIdent),
		}).Warn("build forwarder not configured - build request not relayed")
		return nil // Not an error - forwarder is optional
	}

	// A build request is only ever relayed for ShortTunnelBuild (type 25).
	if inputMessageType != I2NPMessageTypeShortTunnelBuild {
		log.WithFields(logger.Fields{
			"at":           "forwardBuildRequest",
			"message_id":   messageID,
			"message_type": inputMessageType,
		}).Warn("refusing to relay non-STBM build request")
		return nil
	}

	return p.buildReplyForwarder.ForwardBuildRequestToRouter(record.NextIdent, messageID, body)
}

// logBuildRequestForward logs a successful transit-hop relaying of the build
// message to the next hop.
func (p *MessageProcessor) logBuildRequestForward(messageID, index int, record BuildRequestRecord) {
	log.WithFields(logger.Fields{
		"at":           "forwardBuildRequest",
		"message_id":   messageID,
		"record_index": index,
		"next_ident":   logutil.HashPrefix(record.NextIdent),
		"next_tunnel":  record.NextTunnel,
	}).Debug("relayed STBM build request to next hop")
}

// encryptBuildReply encrypts a short tunnel build reply.
func (p *MessageProcessor) encryptBuildReply(index int, replyCode byte, availableBW uint32, rawData []byte) ([]byte, error) {
	var crypto stbmSlotCrypto
	if p.stbmSlotCrypto != nil {
		crypto = p.stbmSlotCrypto[index]
	}

	encryptedReply, err := p.buildSTBMReplyMessage(rawData, index, crypto, replyCode, availableBW)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to build STBM reply message")
	}
	return encryptedReply, nil
}

// logBuildReplySuccess logs successful build reply generation and sending.
func (p *MessageProcessor) logBuildReplySuccess(messageID, index int, replyCode byte, nextTunnel, encryptedLen int) {
	log.WithFields(logger.Fields{
		"at":            "generateAndSendBuildReply",
		"message_id":    messageID,
		"record_index":  index,
		"reply_code":    replyCode,
		"next_tunnel":   nextTunnel,
		"encrypted_len": encryptedLen,
	}).Debug("generated and sent build reply successfully")
}

// buildSTBMReplyMessage assembles the ShortTunnelBuildReply body (type 26):
//
//	[count:1][slot_0:218][slot_1:218]...[slot_N-1:218]
//
// Our slot (ourIndex) is encrypted with ChaCha20-Poly1305 AEAD using the Noise-derived
// replyKey and noiseHash as AD. All other slots are ChaCha20-XOR'd with the same replyKey.
// Matches i2pd I2NPProtocol.cpp transit-hop reply construction.
func (p *MessageProcessor) buildSTBMReplyMessage(rawData []byte, ourIndex int, crypto stbmSlotCrypto, replyCode byte, availableBW uint32) ([]byte, error) {
	count, expected, err := p.validateSTBMReplyParams(rawData, ourIndex)
	if err != nil {
		return nil, err
	}

	replyData := p.initializeSTBMReply(rawData, expected, count)

	if err := p.encryptSTBMSlots(replyData, count, ourIndex, crypto, replyCode, availableBW); err != nil {
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
//
// The per-slot primitives are the upstream ones (crypto/tunnel), so the reply
// records we emit are byte-identical to what a conforming router expects:
// our slot is ChaCha20-Poly1305 under our reply key with the build-request
// handshake hash as AD and the record number as the nonce; the other slots are
// raw ChaCha20-XORed with the same reply key so the next hop can peel our layer.
func (p *MessageProcessor) encryptSTBMSlots(replyData []byte, count, ourIndex int, crypto stbmSlotCrypto, replyCode byte, availableBW uint32) error {
	for j := 0; j < count; j++ {
		slotOffset := 1 + j*ShortBuildRecordSize
		if j == ourIndex {
			if err := p.encryptOwnSTBMSlot(replyData, slotOffset, byte(j), crypto, replyCode, availableBW); err != nil {
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
func (p *MessageProcessor) encryptOwnSTBMSlot(replyData []byte, slotOffset int, recordNumber byte, crypto stbmSlotCrypto, replyCode byte, availableBW uint32) error {
	cleartext := p.prepareSTBMSlotCleartext(replyCode, availableBW)
	ciphertext, err := i2ptunnel.EncryptOwnBuildReply(crypto.replyKey, crypto.noiseHash, recordNumber, cleartext[:])
	if err != nil {
		return oops.Wrapf(err, "failed to AEAD-encrypt STBM reply slot %d", recordNumber)
	}
	copy(replyData[slotOffset:], ciphertext[:ShortBuildRecordSize])
	return nil
}

// prepareSTBMSlotCleartext prepares 202-byte cleartext: options mapping in
// [0:201], retCode at [201]. When availableBW is non-zero, the reply advertises
// the available transit bandwidth (KB/s) via the "b" option mapping (i2pd
// TransitTunnel reply); otherwise the options field is empty (0x0000) and the
// remaining bytes are random padding.
func (p *MessageProcessor) prepareSTBMSlotCleartext(replyCode byte, availableBW uint32) [ShortBuildRecordSize - 16]byte {
	var cleartext [ShortBuildRecordSize - 16]byte // 202 bytes

	optionBytes := encodeBuildReplyOptions(availableBW)
	if len(optionBytes) > 0 && len(optionBytes) <= 201 {
		// Write the serialized options mapping at the front, random-pad the rest.
		copy(cleartext[0:], optionBytes)
		_, _ = rand.Read(cleartext[len(optionBytes):201]) // padding (error ignored)
	} else {
		cleartext[0] = 0x00                   // options high byte (empty mapping)
		cleartext[1] = 0x00                   // options low byte
		_, err := rand.Read(cleartext[2:201]) // padding (error ignored, acceptable for padding)
		if err != nil {
			log.WithFields(logger.Fields{
				"at": "prepareSTBMSlotCleartext",
			}).Warn("Error in padding generation", err)
		}
	}
	cleartext[201] = replyCode
	return cleartext
}

// encodeBuildReplyOptions serializes the short build reply options mapping. When
// availableBW > 0 it emits a single "b" entry carrying the available transit
// bandwidth in KB/s as a decimal string (matching i2pd). When availableBW == 0
// it returns nil so the caller emits an empty options field, preserving the
// previous default reply layout.
func encodeBuildReplyOptions(availableBW uint32) []byte {
	if availableBW == 0 {
		return nil
	}
	mapping, err := common.GoMapToMapping(map[string]string{
		"b": strconv.FormatUint(uint64(availableBW), 10),
	})
	if err != nil {
		return nil
	}
	data, err := mapping.DataSafe()
	if err != nil {
		return nil
	}
	return data
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
// inputMessageType determines the output reply type: type 25 ShortTunnelBuild → type 26 reply.
func (p *MessageProcessor) forwardBuildReply(messageID int, record BuildRequestRecord, encryptedReply []byte, inputMessageType int) error {
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
			inputMessageType,
		)
	}

	// Tunnel forwarding
	return p.buildReplyForwarder.ForwardBuildReplyThroughTunnel(
		record.NextIdent,
		record.NextTunnel,
		messageID,
		encryptedReply,
		inputMessageType,
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
	}).Debug("accepting tunnel build request")

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
	}).Debug("rejecting tunnel build request")
}

// parseTunnelBuildRecords parses the short build request records from message
// data. Returns the parsed records (in slot order) together with the slot index
// each record occupied in the message. Only records that decrypt with our static
// key are returned; the slot index is needed downstream because a relay hop's
// own slot is NOT necessarily position 0 of the filtered list, and the reply /
// forward transform must write and obfuscate by the true slot index.
func (p *MessageProcessor) parseTunnelBuildRecords(data []byte) ([]BuildRequestRecord, []int, error) {
	recordCount, err := p.validateAndGetRecordCount(data)
	if err != nil {
		return nil, nil, err
	}

	return p.parseRecordsFromData(data, recordCount, ShortBuildRecordSize)
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

// parseRecordsFromData iterates through the data and parses each record,
// recording the slot index of each record that decrypts to us.
func (p *MessageProcessor) parseRecordsFromData(data []byte, recordCount, recordSize int) ([]BuildRequestRecord, []int, error) {
	records := make([]BuildRequestRecord, 0, recordCount)
	slotIndices := make([]int, 0, recordCount)
	offset := 1

	for i := 0; i < recordCount; i++ {
		if len(data)-offset < recordSize {
			return nil, nil, oops.Errorf("insufficient data for record %d: have %d, need %d", i, len(data)-offset, recordSize)
		}

		recordData := data[offset : offset+recordSize]
		before := len(records)
		p.tryParseAndAppendRecord(&records, recordData, i)
		if len(records) > before {
			slotIndices = append(slotIndices, i)
		}
		offset += recordSize
	}

	return records, slotIndices, nil
}

// tryParseAndAppendRecord attempts to decrypt a single 218-byte short build
// request record destined for us and, on success, appends the parsed record.
//
// A record is only ever accepted if it authenticates under our static X25519
// key. Records that are not addressed to us, or that fail to decrypt, are
// dropped: the ECIES tunnel-creation spec requires unencrypted/foreign build
// records to be detected and rejected, and accepting a cleartext record on the
// strength of its OurIdent field alone would let any peer register a transit
// tunnel with attacker-chosen layer, IV and reply keys.
func (p *MessageProcessor) tryParseAndAppendRecord(records *[]BuildRequestRecord, recordData []byte, index int) {
	if len(recordData) < ShortBuildRecordSize {
		return
	}
	if !p.isRecordForUs(recordData) {
		return
	}
	if len(p.ourPrivateKey) == 0 {
		log.WithField("record_index", index).
			Warn("STBM record addressed to us but no static private key configured; rejecting")
		return
	}

	record, err := p.decryptShortRecord(recordData, index)
	if err != nil {
		log.WithError(err).WithField("record_index", index).
			Warn("STBM ECIES decryption failed; rejecting record destined for us")
		return
	}
	*records = append(*records, record)
}

// decryptShortRecord decrypts a 218-byte STBM record using ECIES-X25519-AEAD.
// As a side effect it populates p.stbmSlotCrypto[index] with the Noise-derived
// reply key and transcript hash that are needed to build the AEAD reply.
//
// The short record format does not carry layer/IV keys in its cleartext, so the
// transit hop and the tunnel creator must derive them from the Noise chaining
// key via the spec KDF (deriveSTBMHopKeys -> upstream
// crypto/tunnel.DeriveBuildReplyKeysFromChain). That chain is OBEP-dependent:
// the outbound endpoint runs an extra TunnelLayerIVKey step while every other
// hop uses the left half of the layer-key output as its IV key
// (tunnel-creation-ecies.rst "Reply keys"). The hop learns which branch applies
// from its own decrypted record's Flag bit 6. We populate record.LayerKey and
// record.IVKey here so handleAcceptedBuildRecord registers real (non-zero) keys.
func (p *MessageProcessor) decryptShortRecord(recordData []byte, index int) (BuildRequestRecord, error) {
	var encrypted [218]byte
	copy(encrypted[:], recordData[:218])
	record, preReplyCK, noiseHash, err := decryptSTBMRecord(encrypted, p.ourPrivateKey)
	if err != nil {
		return BuildRequestRecord{}, err
	}

	isOBEP := record.Flag&tunnel.FlagOBEP != 0
	keys, err := deriveSTBMHopKeys(preReplyCK, isOBEP)
	if err != nil {
		return BuildRequestRecord{}, oops.Wrapf(err, "failed to derive STBM reply/layer keys for slot %d", index)
	}

	if p.stbmSlotCrypto == nil {
		p.stbmSlotCrypto = make(map[int]stbmSlotCrypto)
	}
	p.stbmSlotCrypto[index] = stbmSlotCrypto{replyKey: keys.ReplyKey, noiseHash: noiseHash}

	copy(record.LayerKey[:], keys.LayerKey[:])
	copy(record.IVKey[:], keys.IVKey[:])

	return record, nil
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
