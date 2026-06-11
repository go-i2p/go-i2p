package i2np

import (
	"encoding/binary"
	"fmt"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/common/session_key"
	"github.com/go-i2p/crypto/rand"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
	"github.com/go-i2p/go-i2p/lib/util/logutil"
)

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
	if err := tm.validateBuildRequest(req); err != nil {
		return 0, nil, err
	}

	// Zero-hop inbound short-circuit: no remote hop, no build message,
	// no pending-build tracking. Register the tunnel directly as Active.
	if req.HopCount == 0 && req.IsInbound {
		return tm.buildZeroHopInbound(req)
	}

	if err := tm.handleOutboundReplyTunnel(&req); err != nil {
		return 0, nil, err
	}

	result, messageID, peerHashes, err := tm.prepareAndSendBuild(req)
	if err != nil {
		return 0, peerHashes, err
	}

	if err := tm.finalizePendingBuild(result, messageID, req); err != nil {
		return 0, peerHashes, err
	}

	tm.logBuildRequestSent(result, messageID, req.ReplyTunnelID, req.IsInbound)
	return result.TunnelID, peerHashes, nil
}

// validateBuildRequest validates the build request parameters.
func (tm *TunnelManager) validateBuildRequest(req tunnel.BuildTunnelRequest) error {
	var zeroHash common.Hash
	if req.OurIdentity == zeroHash {
		return oops.Errorf("invalid build request: router identity is unset")
	}
	if req.IsInbound && req.ReplyGateway == zeroHash {
		return oops.Errorf("invalid build request: reply gateway is unset for inbound tunnel")
	}
	return nil
}

// handleOutboundReplyTunnel injects a reply tunnel ID for outbound builds.
func (tm *TunnelManager) handleOutboundReplyTunnel(req *tunnel.BuildTunnelRequest) error {
	if req.IsInbound || req.ReplyTunnelID != 0 {
		return nil
	}

	inbound := tm.inboundPool.SelectTunnel()
	if inbound == nil {
		return oops.Errorf("outbound build requires active inbound tunnel for reply routing")
	}

	req.ReplyTunnelID = inbound.ID
	log.WithFields(logger.Fields{
		"at":              "BuildTunnelFromRequest",
		"reply_tunnel_id": inbound.ID,
	}).Debug("injected inbound tunnel ID into outbound build request for OBEP reply routing")
	return nil
}

// prepareAndSendBuild creates the build request, sends the message, and returns the result.
func (tm *TunnelManager) prepareAndSendBuild(req tunnel.BuildTunnelRequest) (*tunnel.TunnelBuildResult, int, []common.Hash, error) {
	result, messageID, err := tm.createBuildRequestAndID(req)
	if err != nil {
		return nil, 0, nil, err
	}

	peerHashes := tm.extractPeerHashes(result)
	tunnelState := tm.createTunnelStateFromResult(result)
	pool := tm.getPoolForTunnel(req.IsInbound)
	pool.AddTunnel(tunnelState)
	tm.trackPendingBuild(result, messageID, req.IsClientTunnel, req.ReplyTunnelID)

	// Send the build message first. For STBM, createShortTunnelBuildMessage
	// overwrites result.ReplyKeys with the HKDF-derived keys that the remote
	// hops will actually use to encrypt their reply slots. Registration must
	// happen after send so it captures the correct keys.
	//
	// IMPORTANT: sendBuildMessage may block for tens of seconds while
	// sessionProvider.GetSessionByHash performs a NetDB RouterInfo lookup
	// (up to 30s) plus the outbound NTCP2/SSU2 dial and Noise handshake.
	err = tm.sendBuildMessage(result, messageID)
	if err != nil {
		tm.cleanupFailedBuild(result.TunnelID, messageID, req.IsInbound)
		return nil, 0, peerHashes, oops.Wrapf(err, "failed to send build request")
	}

	return result, messageID, peerHashes, nil
}

// finalizePendingBuild updates crypto context, arms the expiration timer, and registers with ReplyProcessor.
func (tm *TunnelManager) finalizePendingBuild(result *tunnel.TunnelBuildResult, messageID int, req tunnel.BuildTunnelRequest) error {
	// STBM message construction updates result.ReplyKeys/NoiseHashes to the
	// final HKDF-derived values used for reply decryption. Persist the final
	// crypto context so late uncorrelated replies can be best-effort decrypted.
	tm.updatePendingBuildReplyCrypto(messageID, result.ReplyKeys, result.ReplyIVs, result.NoiseHashes)

	// Anchor the 90-second expiration window to the moment the build message
	// actually left this router, then arm cleanup at that horizon.
	// BUG-5 fix: arm the timer at buildTimeout + buildExpireGrace (200ms) so
	// replies that arrive on the boundary do not race the cleanup goroutine.
	tm.resetPendingBuildCreatedAt(messageID)
	time.AfterFunc(90*time.Second+buildExpireGrace, func() {
		tm.cleanupExpiredBuildByID(messageID)
	})

	// Register with ReplyProcessor now that result.ReplyKeys holds the
	// HKDF-derived reply keys written by createShortTunnelBuildMessage.
	if regErr := tm.replyProcessor.RegisterPendingBuild(
		result.TunnelID,
		result.ReplyKeys,
		result.ReplyIVs,
		req.IsInbound,
		len(result.Hops),
	); regErr != nil {
		tm.cleanupFailedBuild(result.TunnelID, messageID, req.IsInbound)
		return oops.Wrapf(regErr, "failed to register pending build")
	}

	// Store Noise transcript hashes for STBM reply AEAD decryption.
	if len(result.NoiseHashes) > 0 {
		if setErr := tm.replyProcessor.SetPendingBuildNoiseHashes(result.TunnelID, result.NoiseHashes); setErr != nil {
			log.WithError(setErr).WithField("tunnel_id", result.TunnelID).Warn("Failed to set STBM noise hashes")
		}
	}

	return nil
}

// buildZeroHopInbound registers a zero-hop inbound tunnel directly into the
// inbound pool as Active. No peer is selected, no STBM is emitted, and no
// pending build is tracked: we are simultaneously the inbound gateway and
// inbound endpoint, so the tunnel is operational the moment its ID is
// allocated. Returns the tunnel ID and a nil peer-hash slice.
func (tm *TunnelManager) buildZeroHopInbound(req tunnel.BuildTunnelRequest) (tunnel.TunnelID, []common.Hash, error) {
	builder, err := tunnel.NewTunnelBuilder(tm.peerSelector)
	if err != nil {
		return 0, nil, oops.Wrapf(err, "failed to create tunnel builder for zero-hop inbound")
	}
	result, err := builder.CreateBuildRequest(req)
	if err != nil {
		return 0, nil, oops.Wrapf(err, "failed to create zero-hop inbound build request")
	}
	state := &tunnel.TunnelState{
		ID:        result.TunnelID,
		Hops:      nil,
		State:     tunnel.TunnelReady,
		CreatedAt: time.Now(),
		Responses: nil,
		IsInbound: true,
	}
	tm.inboundPool.AddTunnel(state)
	log.WithFields(logger.Fields{
		"at":               "BuildTunnelFromRequest",
		"tunnel_id":        result.TunnelID,
		"is_inbound":       true,
		"hop_count":        0,
		"is_client_tunnel": req.IsClientTunnel,
		"reason":           "zero-hop inbound tunnel registered as active without build message",
	}).Info("Zero-hop inbound tunnel built")
	return result.TunnelID, nil, nil
}

// createBuildRequestAndID validates prerequisites and creates the build request with message ID
func (tm *TunnelManager) createBuildRequestAndID(req tunnel.BuildTunnelRequest) (*tunnel.TunnelBuildResult, int, error) {
	if tm.peerSelector == nil {
		return nil, 0, oops.Errorf("no peer selector configured")
	}

	builder, err := tunnel.NewTunnelBuilder(tm.peerSelector)
	if err != nil {
		return nil, 0, oops.Wrapf(err, "failed to create tunnel builder")
	}

	result, err := builder.CreateBuildRequest(req)
	if err != nil {
		return nil, 0, oops.Wrapf(err, "failed to create build request")
	}

	messageID, err := tm.generateMessageID()
	if err != nil {
		return nil, 0, oops.Wrapf(err, "failed to generate message ID")
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

// trackPendingBuild records the pending build request for reply correlation.
// isClientTunnel indicates whether the build originated from an I2CP client session pool.
func (tm *TunnelManager) trackPendingBuild(result *tunnel.TunnelBuildResult, messageID int, isClientTunnel bool, replyTunnelID tunnel.TunnelID) {
	// Lazily start the cleanup goroutine on the first build request
	tm.ensureCleanupStarted()

	tm.buildMutex.Lock()
	defer tm.buildMutex.Unlock()

	tm.pendingBuilds[messageID] = &buildRequest{
		tunnelID:       result.TunnelID,
		messageID:      messageID,
		replyTunnelID:  replyTunnelID,
		hopCount:       len(result.Hops),
		replyKeys:      result.ReplyKeys,
		replyIVs:       result.ReplyIVs,
		noiseHashes:    result.NoiseHashes,
		createdAt:      time.Now(),
		retryCount:     0,
		useShortBuild:  result.UseShortBuild,
		isInbound:      result.IsInbound,
		isClientTunnel: isClientTunnel,
	}
}

// updatePendingBuildReplyCrypto refreshes the pending build's reply-decryption
// context after message creation has finalized STBM-derived keys and hashes.
func (tm *TunnelManager) updatePendingBuildReplyCrypto(messageID int, replyKeys []session_key.SessionKey, replyIVs [][16]byte, noiseHashes [][32]byte) {
	tm.buildMutex.Lock()
	defer tm.buildMutex.Unlock()
	req, ok := tm.pendingBuilds[messageID]
	if !ok {
		return
	}
	req.replyKeys = replyKeys
	req.replyIVs = replyIVs
	req.noiseHashes = noiseHashes
}

// resetPendingBuildCreatedAt re-anchors the createdAt timestamp of a tracked
// pending build to time.Now(). Called immediately after the build message has
// actually been queued onto the gateway session, so that the 90-second I2P
// build expiration window is measured from when the message left the
// originator rather than from in-process struct creation. Without this, slow
// outbound dials (RouterInfo lookup up to 30s + NTCP2/SSU2 handshake) eat
// most of the window before the message is even sent, causing replies to
// arrive after expiration cleanup has already fired.
func (tm *TunnelManager) resetPendingBuildCreatedAt(messageID int) {
	tm.buildMutex.Lock()
	defer tm.buildMutex.Unlock()
	if req, ok := tm.pendingBuilds[messageID]; ok {
		req.createdAt = time.Now()
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
func (tm *TunnelManager) logBuildRequestSent(result *tunnel.TunnelBuildResult, messageID int, replyTunnelID tunnel.TunnelID, isInbound bool) {
	log.WithFields(logger.Fields{
		"tunnel_id":        result.TunnelID,
		"message_id":       messageID,
		"hop_count":        len(result.Hops),
		"use_stbm":         result.UseShortBuild,
		"is_inbound_build": isInbound,
		"reply_tunnel_id":  replyTunnelID,
	}).Info("Tunnel build request sent")
}

// sendBuildMessage sends a tunnel build message (STBM or VTB) based on the result.
func (tm *TunnelManager) sendBuildMessage(result *tunnel.TunnelBuildResult, messageID int) error {
	if tm.buildSessionProv == nil {
		return oops.Errorf("no session provider available")
	}
	if tm.messageFactory == nil {
		return oops.Errorf("no message factory available")
	}

	firstHop, err := validateTunnelBuild(result)
	if err != nil {
		return err
	}

	peerHash, err := firstHop.IdentHash()
	if err != nil {
		return oops.Wrapf(err, "failed to get first hop identity")
	}

	session, err := tm.buildSessionProv.GetSessionByHash(peerHash)
	if err != nil {
		return oops.Wrapf(err, "failed to get session for gateway %x", peerHash[:8])
	}

	serialized, err := tm.createSerializedBuildMessage(result, messageID)
	if err != nil {
		return oops.Wrapf(err, "failed to create build message")
	}

	if err := session.Send(serialized); err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"message_id":   messageID,
			"gateway_hash": logutil.HashPrefixPlain(peerHash),
			"use_stbm":     result.UseShortBuild,
		}).Warn("Failed to send tunnel build message")
		return oops.Wrapf(err, "failed to send tunnel build message to gateway %x", peerHash[:8])
	}

	log.WithFields(logger.Fields{
		"message_id":   messageID,
		"gateway_hash": logutil.HashPrefixPlain(peerHash),
		"use_stbm":     result.UseShortBuild,
	}).Debug("Sent tunnel build message")
	return nil
}

// validateTunnelBuild validates the tunnel build result has required hops.
func validateTunnelBuild(result *tunnel.TunnelBuildResult) (router_info.RouterInfo, error) {
	if len(result.Hops) == 0 {
		return router_info.RouterInfo{}, oops.Errorf("no hops in tunnel build result")
	}
	return result.Hops[0], nil
}

// createSerializedBuildMessage creates and serializes the appropriate build message.
func (tm *TunnelManager) createSerializedBuildMessage(result *tunnel.TunnelBuildResult, messageID int) ([]byte, error) {
	if result.UseShortBuild {
		return tm.createSerializedShortTunnelBuildMessage(result, messageID)
	}
	return tm.createSerializedTunnelBuildMessage(result, messageID)
}

// createSerializedShortTunnelBuildMessage creates a Short Tunnel Build Message (STBM).
// Each build record is encrypted with the corresponding hop's X25519 public key
// using the STBM-format ECIES-X25519-AEAD encryption (zero nonce, ephemeral key
// as AD) before being placed into the message.
//
// Per the I2P tunnel-creation-ECIES specification (proposal 152), STBM records
// are 218 bytes each on the wire. Using the long-format 528-byte records here
// causes peers to reject the entire message (silent EOF after the NTCP2
// handshake), since the count byte is interpreted against the wrong stride.
func (tm *TunnelManager) createSerializedShortTunnelBuildMessage(result *tunnel.TunnelBuildResult, messageID int) ([]byte, error) {
	i2npRecords := tm.convertAndOverrideMessageID(result.Records, messageID)

	encryptedRecords, replyKeys, noiseHashes, postReplyCKs, err := tm.encryptRecordsAndDeriveKeys(i2npRecords, result.Hops)
	if err != nil {
		return nil, err
	}

	tm.updateReplyKeysWithHKDF(result, replyKeys, noiseHashes)

	if err := tm.registerGarlicReplyKeys(noiseHashes, postReplyCKs, messageID, result.TunnelID); err != nil {
		return nil, err
	}

	if err := tm.applyChaCha20LayerObfuscation(encryptedRecords, replyKeys); err != nil {
		return nil, err
	}

	// Convert [][218]byte to [][]byte for factory
	records := make([][]byte, len(encryptedRecords))
	for i := range encryptedRecords {
		records[i] = encryptedRecords[i][:]
	}

	serialized, err := tm.messageFactory.CreateShortTunnelBuildMessage(records, messageID)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to create Short Tunnel Build message")
	}
	return serialized, nil
}

// convertAndOverrideMessageID converts tunnel records to I2NP format and overrides SendMessageID
// for STBM reply correlation. The remote OBEP reads sendMessageID from its decrypted record
// and uses it as the I2NP message ID of the ShortTunnelBuildReply it sends back.
func (tm *TunnelManager) convertAndOverrideMessageID(records []tunnel.BuildRequestRecord, messageID int) []BuildRequestRecord {
	i2npRecords := make([]BuildRequestRecord, len(records))
	for i, rec := range records {
		i2npRecords[i] = rec
		i2npRecords[i].SendMessageID = messageID
	}
	return i2npRecords
}

// encryptRecordsAndDeriveKeys encrypts each STBM record and derives cryptographic keys.
// Each encrypted STBM record is exactly 218 bytes. Returns encrypted records, reply keys,
// Noise transcript hashes, and post-reply chaining keys needed for STBM protocol.
func (tm *TunnelManager) encryptRecordsAndDeriveKeys(i2npRecords []BuildRequestRecord, hops []router_info.RouterInfo) (
	encryptedRecords [][ShortBuildRecordSize]byte,
	replyKeys [][32]byte,
	noiseHashes [][32]byte,
	postReplyCKs [][32]byte,
	err error,
) {
	encryptedRecords = make([][ShortBuildRecordSize]byte, len(i2npRecords))
	replyKeys = make([][32]byte, len(i2npRecords))
	noiseHashes = make([][32]byte, len(i2npRecords))
	postReplyCKs = make([][32]byte, len(i2npRecords))

	for i, record := range i2npRecords {
		if i >= len(hops) {
			return nil, nil, nil, nil, oops.Errorf("record %d has no corresponding hop RouterInfo", i)
		}
		encrypted, ck, nh, encErr := EncryptShortBuildRequestRecordWithChain(record, hops[i])
		if encErr != nil {
			return nil, nil, nil, nil, oops.Wrapf(encErr, "failed to encrypt short build record %d", i)
		}
		encryptedRecords[i] = encrypted
		noiseHashes[i] = nh

		rk, newCK, keyErr := DeriveSTBMReplyKey(ck)
		if keyErr != nil {
			return nil, nil, nil, nil, oops.Wrapf(keyErr, "failed to derive reply key for hop %d", i)
		}
		replyKeys[i] = rk
		postReplyCKs[i] = newCK
	}

	return encryptedRecords, replyKeys, noiseHashes, postReplyCKs, nil
}

// updateReplyKeysWithHKDF overwrites result.ReplyKeys with HKDF-derived keys.
// Per STBM spec (proposal 152), the ReplyKey field is absent from the 154-byte cleartext.
// Each hop derives its reply key via HKDF(ck, "", "SMTunnelReplyKey", 64).
func (tm *TunnelManager) updateReplyKeysWithHKDF(result *tunnel.TunnelBuildResult, replyKeys, noiseHashes [][32]byte) {
	result.ReplyKeys = make([]session_key.SessionKey, len(replyKeys))
	for i, rk := range replyKeys {
		result.ReplyKeys[i] = session_key.SessionKey(rk)
	}
	result.NoiseHashes = noiseHashes
}

// registerGarlicReplyKeys derives and registers the one-time garlic key for OBEP reply decryption.
// Uses the spec-compliant i2pd derivation path: SMTunnelLayerKey → TunnelLayerIVKey → RGarlicKeyAndTag.
// This matches TransitTunnel.cpp::HandleShortTransitTunnelBuildMsg.
func (tm *TunnelManager) registerGarlicReplyKeys(noiseHashes, postReplyCKs [][32]byte, messageID int, tunnelID tunnel.TunnelID) error {
	if tm.garlicKeyRegistrar == nil || len(postReplyCKs) == 0 {
		return nil
	}

	lastHop := len(postReplyCKs) - 1
	obepKey, obepTag, obepErr := DeriveSTBMOBEPGarlicKeyAndTag(postReplyCKs[lastHop])
	if obepErr != nil {
		return oops.Wrapf(obepErr, "failed to derive OBEP garlic reply key")
	}
	tm.garlicKeyRegistrar.RegisterOneTimeGarlicKey(obepTag, obepKey)
	log.WithFields(logger.Fields{
		"at":         "registerGarlicReplyKeys",
		"tag":        fmt.Sprintf("%x", obepTag),
		"last_hop":   lastHop,
		"tag_source": "obep_rgarlickey",
		"message_id": messageID,
		"tunnel_id":  tunnelID,
	}).Debug("Registered one-time garlic reply key for STBM build")

	return nil
}

// applyChaCha20LayerObfuscation applies chained ChaCha20 stream-cipher layer obfuscation
// to STBM records. For each hop i (second-to-last down to first), XOR every record at
// index j > i with ChaCha20(key=replyKeys[i], nonce[4]=j). This ensures each hop can
// decrypt its record and peel its layer off subsequent records.
func (tm *TunnelManager) applyChaCha20LayerObfuscation(encryptedRecords [][ShortBuildRecordSize]byte, replyKeys [][32]byte) error {
	if len(encryptedRecords) < 2 {
		return nil
	}

	for i := len(encryptedRecords) - 2; i >= 0; i-- {
		for j := i + 1; j < len(encryptedRecords); j++ {
			if err := chacha20XORRecord(&encryptedRecords[j], replyKeys[i], j); err != nil {
				return oops.Wrapf(err, "ChaCha20 layer obfuscation failed at hop %d record %d", i, j)
			}
		}
	}

	return nil
}

// createSerializedTunnelBuildMessage creates a TunnelBuild (type 21) message.
// Type 21 has exactly 8 records at 528 bytes each with NO count prefix byte.
// Each build record is encrypted with the corresponding hop's X25519 public key
// using ECIES-X25519-AEAD encryption before being placed into the message.
func (tm *TunnelManager) createSerializedTunnelBuildMessage(result *tunnel.TunnelBuildResult, messageID int) ([]byte, error) {
	encryptedData, err := encryptBuildRecords(result)
	if err != nil {
		return nil, err
	}

	// Convert [8][528]byte to [][]byte for factory
	records := make([][]byte, 8)
	for i := range encryptedData {
		records[i] = encryptedData[i][:]
	}

	serialized, err := tm.messageFactory.CreateTunnelBuildMessage(records, messageID)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to create Tunnel Build message")
	}
	return serialized, nil
}

// encryptBuildRecords encrypts each build request record with its corresponding
// hop's X25519 public key using ECIES-X25519-AEAD encryption.
func encryptBuildRecords(result *tunnel.TunnelBuildResult) ([8][528]byte, error) {
	var encryptedData [8][528]byte
	for i := 0; i < 8 && i < len(result.Records); i++ {
		i2npRecord := result.Records[i]

		if i >= len(result.Hops) {
			return encryptedData, oops.Errorf("record %d has no corresponding hop RouterInfo", i)
		}
		encrypted, err := EncryptBuildRequestRecord(i2npRecord, result.Hops[i])
		if err != nil {
			return encryptedData, oops.Wrapf(err, "failed to encrypt build record %d", i)
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
				return nil, oops.Wrapf(err, "failed to generate random padding for unused slot %d", i)
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
		return 0, oops.Wrapf(err, "failed to generate random message ID")
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
		return oops.Wrapf(err, "failed to generate tunnel ID")
	}
	tunnelState := tm.createTunnelState(tunnelID, count, peers)
	// BuildTunnelWithBuilder is legacy interface, defaults to outbound tunnels
	tm.outboundPool.AddTunnel(tunnelState)

	return tm.sendTunnelBuildRequests(records, peers[:count], tunnelID)
}

// validateTunnelBuilder checks if the tunnel manager and builder are properly configured.
func (tm *TunnelManager) validateTunnelBuilder(builder TunnelBuilder) error {
	if tm.peerSelector == nil {
		return oops.Errorf("no peer selector configured")
	}

	if builder.GetRecordCount() == 0 {
		return oops.Errorf("no build records provided")
	}

	return nil
}

// selectTunnelPeers selects the required number of peers for tunnel construction.
func (tm *TunnelManager) selectTunnelPeers(count int) ([]router_info.RouterInfo, error) {
	peers, err := tm.peerSelector.SelectPeers(count, nil)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to select peers for tunnel")
	}

	if len(peers) < count {
		return nil, oops.Errorf("insufficient peers available: need %d, got %d", count, len(peers))
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
		return 0, oops.Wrapf(err, "failed to generate random tunnel ID")
	}
	return tunnel.TunnelID(binary.BigEndian.Uint32(buf[:])), nil
}

// sendTunnelBuildRequests builds a single TunnelBuild message containing all
// encrypted hop records and sends it to the first hop (gateway) only.
// Per the I2P tunnel creation specification, the gateway forwards the message
// through the partially-built tunnel; each hop peels its layer and forwards
// to the next. Sending directly to each hop would break tunnel anonymity.
func (tm *TunnelManager) sendTunnelBuildRequests(records []BuildRequestRecord, peers []router_info.RouterInfo, tunnelID tunnel.TunnelID) error {
	if err := tm.validateSendRequest(peers); err != nil {
		return err
	}

	tm.logSendingBuildRequests(tunnelID, len(peers))

	messageID := tm.registerPendingBuild(tunnelID, len(records))

	msg, err := tm.createCombinedBuildMessage(records, peers, tunnelID)
	if err != nil {
		tm.removePendingBuildRequest(messageID)
		return oops.Wrapf(err, "failed to create combined tunnel build message")
	}

	if err := tm.sendToFirstHop(peers[0], msg, messageID); err != nil {
		return err
	}

	tm.logBuildRequestsCompleted(tunnelID)
	return nil
}

// validateSendRequest validates that the tunnel manager and peers are ready.
func (tm *TunnelManager) validateSendRequest(peers []router_info.RouterInfo) error {
	if tm.sessionProvider == nil {
		return oops.Errorf("no session provider available for sending tunnel build requests")
	}
	if len(peers) == 0 {
		return oops.Errorf("no peers provided for tunnel build")
	}
	return nil
}

// registerPendingBuild registers a pending build request and schedules cleanup.
func (tm *TunnelManager) registerPendingBuild(tunnelID tunnel.TunnelID, hopCount int) int {
	// GAP-5 fix: For type-21 TunnelBuild, the reply message ID equals the
	// tunnelID (not a random message ID).  Register a pendingBuilds entry
	// keyed by int(tunnelID) so ProcessTunnelReply can correlate the reply.
	messageID := int(tunnelID)
	tm.buildMutex.Lock()
	tm.pendingBuilds[messageID] = &buildRequest{
		tunnelID:  tunnelID,
		messageID: messageID,
		hopCount:  hopCount,
		createdAt: time.Now(),
		isInbound: false,
	}
	tm.buildMutex.Unlock()
	time.AfterFunc(90*time.Second+buildExpireGrace, func() {
		tm.cleanupExpiredBuildByID(messageID)
	})
	return messageID
}

// sendToFirstHop sends the build message to the first hop (gateway).
func (tm *TunnelManager) sendToFirstHop(firstPeer router_info.RouterInfo, msg *TunnelBuildMessage, messageID int) error {
	firstPeerHash, err := firstPeer.IdentHash()
	if err != nil {
		tm.removePendingBuildRequest(messageID)
		return oops.Wrapf(err, "failed to get first hop hash")
	}
	session, err := tm.getSessionForPeer(firstPeerHash)
	if err != nil {
		tm.removePendingBuildRequest(messageID)
		return oops.Wrapf(err, "failed to get session for gateway")
	}
	if err := session.QueueSendI2NP(msg); err != nil {
		tm.removePendingBuildRequest(messageID)
		return oops.Wrapf(err, "failed to queue build message")
	}
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
				return nil, oops.Wrapf(err, "failed to encrypt record for hop %d", i)
			}
			copy(data[slotStart:slotEnd], encrypted[:])
		} else {
			if _, err := rand.Read(data[slotStart:slotEnd]); err != nil {
				return nil, oops.Wrapf(err, "failed to generate random padding for slot %d", i)
			}
		}
	}

	msg := &TunnelBuildMessage{
		BaseI2NPMessage: NewBaseI2NPMessage(I2NPMessageTypeTunnelBuild),
		encrypted:       true,
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

// getSessionForPeer retrieves a transport session for the specified peer.
func (tm *TunnelManager) getSessionForPeer(peerHash common.Hash) (I2NPTransportSession, error) {
	session, err := tm.sessionProvider.GetSessionByHash(peerHash)
	if err != nil {
		log.WithFields(logger.Fields{
			"peer_hash": logutil.HashPrefixPlain(peerHash),
			"error":     err,
		}).Warn("Failed to get session for peer")
		return nil, err
	}
	return session, nil
}

// logBuildRequestsCompleted logs completion of all build request transmissions.
func (tm *TunnelManager) logBuildRequestsCompleted(tunnelID tunnel.TunnelID) {
	log.WithField("tunnel_id", tunnelID).Debug("Tunnel build requests sent")
}
