package i2np

import (
	"encoding/binary"
	"fmt"
	"sync"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/common/session_key"
	"github.com/go-i2p/crypto/rand"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/go-i2p/logger"
)

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
	cleanupOnce     sync.Once             // Ensures cleanup goroutine starts at most once
	stopOnce        sync.Once             // Ensures Stop() is idempotent (no double-close panic)
	replyProcessor  *ReplyProcessor       // Handles reply decryption and processing
}

// NewTunnelManager creates a new tunnel manager with build request tracking.
// The background cleanup goroutine is started lazily on the first build request,
// avoiding resource leaks if the TunnelManager is created but never used.
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
	tm.replyProcessor.SetRetryCallback(tm.retryTunnelBuild)

	log.WithFields(logger.Fields{
		"at":     "NewTunnelManager",
		"phase":  "initialization",
		"reason": "retry callback configured for automatic tunnel build retry",
	}).Debug("tunnel manager initialized with retry callback")

	// Cleanup goroutine is started lazily via ensureCleanupStarted()
	// to avoid resource leaks when TunnelManager is created but never used.

	log.WithFields(logger.Fields{
		"at":     "NewTunnelManager",
		"phase":  "initialization",
		"reason": "tunnel manager initialized with separate inbound/outbound pools",
	}).Debug("tunnel manager created")

	return tm
}

// ensureCleanupStarted lazily starts the background cleanup goroutine.
// Safe to call multiple times; the goroutine is started at most once.
func (tm *TunnelManager) ensureCleanupStarted() {
	tm.cleanupOnce.Do(func() {
		tm.cleanupTicker = time.NewTicker(30 * time.Second)
		go tm.cleanupExpiredBuilds()
		log.Debug("Tunnel manager cleanup goroutine started (lazy)")
	})
}

// Stop gracefully stops the tunnel manager and cleans up resources.
// Safe to call multiple times — subsequent calls are no-ops.
// Should be called when shutting down the router.
func (tm *TunnelManager) Stop() {
	tm.stopOnce.Do(func() {
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
	})
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
	result, messageID, err := tm.createBuildRequestAndID(req)
	if err != nil {
		return 0, nil, err
	}

	// Extract peer hashes from the build result for caller tracking
	peerHashes := tm.extractPeerHashes(result)

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
		return 0, peerHashes, fmt.Errorf("failed to register pending build: %w", regErr)
	}

	// Schedule immediate cleanup on timeout (90 seconds per I2P spec)
	// This prevents memory leaks from failed/timeout builds between periodic cleanups
	time.AfterFunc(90*time.Second, func() {
		tm.cleanupExpiredBuildByID(messageID)
	})

	err = tm.sendBuildMessage(result, messageID)
	if err != nil {
		tm.cleanupFailedBuild(result.TunnelID, messageID, req.IsInbound)
		return 0, peerHashes, fmt.Errorf("failed to send build request: %w", err)
	}

	tm.logBuildRequestSent(result, messageID)
	return result.TunnelID, peerHashes, nil
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

	messageID, err := tm.generateMessageID()
	if err != nil {
		return nil, 0, fmt.Errorf("failed to generate message ID: %w", err)
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

// trackPendingBuild records the pending build request for reply correlation
func (tm *TunnelManager) trackPendingBuild(result *tunnel.TunnelBuildResult, messageID int) {
	// Lazily start the cleanup goroutine on the first build request
	tm.ensureCleanupStarted()

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

	buildMsg, err := tm.selectBuildMessage(result, messageID)
	if err != nil {
		return fmt.Errorf("failed to create build message: %w", err)
	}
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
// Each build record is encrypted with the corresponding hop's public encryption key
// using ECIES-X25519-AEAD before being placed into the message.
func (tm *TunnelManager) selectBuildMessage(result *tunnel.TunnelBuildResult, messageID int) (I2NPMessage, error) {
	if result.UseShortBuild {
		// Use Short Tunnel Build Message (modern)
		return tm.createShortTunnelBuildMessage(result, messageID)
	}
	// Use TunnelBuild (type 21): fixed 8 records, no count prefix
	return tm.createTunnelBuildMessage(result, messageID)
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
// Each build record is encrypted with the corresponding hop's X25519 public key
// using ECIES-X25519-AEAD encryption before being placed into the message.
func (tm *TunnelManager) createShortTunnelBuildMessage(result *tunnel.TunnelBuildResult, messageID int) (I2NPMessage, error) {
	// Convert tunnel.BuildRequestRecord to i2np.BuildRequestRecord
	i2npRecords := make([]BuildRequestRecord, len(result.Records))
	for i, rec := range result.Records {
		i2npRecords[i] = convertTunnelBuildRecord(rec)
	}

	// Encrypt each record with the corresponding hop's public key.
	// Each encrypted record is 528 bytes (16-byte identity hash prefix + 512 bytes ECIES ciphertext).
	encryptedRecords := make([][528]byte, len(i2npRecords))
	for i, record := range i2npRecords {
		if i >= len(result.Hops) {
			return nil, fmt.Errorf("record %d has no corresponding hop RouterInfo", i)
		}
		encrypted, err := EncryptBuildRequestRecord(record, result.Hops[i])
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt build record %d: %w", i, err)
		}
		encryptedRecords[i] = encrypted
	}

	// Serialize encrypted records: [count:1][encrypted_records...]
	// Each encrypted record is 528 bytes
	data := make([]byte, 1+len(encryptedRecords)*528)
	data[0] = byte(len(encryptedRecords))
	for i, enc := range encryptedRecords {
		copy(data[1+i*528:1+(i+1)*528], enc[:])
	}

	// Wrap in I2NP message
	msg := NewBaseI2NPMessage(I2NPMessageTypeShortTunnelBuild)
	msg.SetMessageID(messageID)
	msg.SetData(data)

	log.WithFields(logger.Fields{
		"at":           "createShortTunnelBuildMessage",
		"record_count": len(encryptedRecords),
		"data_size":    len(data),
		"encrypted":    true,
	}).Debug("Created encrypted Short Tunnel Build message")

	return msg, nil
}

// createTunnelBuildMessage creates a TunnelBuild (type 21) message.
// Type 21 has exactly 8 records at 528 bytes each with NO count prefix byte.
// Each build record is encrypted with the corresponding hop's X25519 public key
// using ECIES-X25519-AEAD encryption before being placed into the message.
func (tm *TunnelManager) createTunnelBuildMessage(result *tunnel.TunnelBuildResult, messageID int) (I2NPMessage, error) {
	encryptedData, err := encryptBuildRecords(result)
	if err != nil {
		return nil, err
	}

	data, err := serializeBuildRecords(encryptedData, len(result.Records))
	if err != nil {
		return nil, err
	}

	msg := NewBaseI2NPMessage(I2NPMessageTypeTunnelBuild)
	msg.SetMessageID(messageID)
	msg.SetData(data)

	log.WithFields(logger.Fields{
		"at":           "createTunnelBuildMessage",
		"record_count": len(result.Records),
		"data_size":    len(data),
		"encrypted":    true,
	}).Debug("Created encrypted TunnelBuild (type 21) message")

	return msg, nil
}

// createVariableTunnelBuildMessage creates a VariableTunnelBuild (type 23) message.
// Type 23 has a 1-byte count prefix followed by N records at 528 bytes each.
// This is the variable-length format that allows 1-8 records.
func (tm *TunnelManager) createVariableTunnelBuildMessage(result *tunnel.TunnelBuildResult, messageID int) (I2NPMessage, error) {
	encryptedData, err := encryptBuildRecords(result)
	if err != nil {
		return nil, err
	}

	data := serializeVariableBuildRecords(encryptedData, len(result.Records))

	msg := NewBaseI2NPMessage(I2NPMessageTypeVariableTunnelBuild)
	msg.SetMessageID(messageID)
	msg.SetData(data)

	log.WithFields(logger.Fields{
		"at":           "createVariableTunnelBuildMessage",
		"record_count": len(result.Records),
		"data_size":    len(data),
		"encrypted":    true,
	}).Debug("Created encrypted VariableTunnelBuild (type 23) message")

	return msg, nil
}

// convertTunnelBuildRecord converts a tunnel.BuildRequestRecord to an i2np.BuildRequestRecord.
// This avoids duplicating the field-by-field copy in multiple functions.
func convertTunnelBuildRecord(rec tunnel.BuildRequestRecord) BuildRequestRecord {
	return BuildRequestRecord{
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

// encryptBuildRecords encrypts each build request record with its corresponding
// hop's X25519 public key using ECIES-X25519-AEAD encryption.
func encryptBuildRecords(result *tunnel.TunnelBuildResult) ([8][528]byte, error) {
	var encryptedData [8][528]byte
	for i := 0; i < 8 && i < len(result.Records); i++ {
		i2npRecord := convertTunnelBuildRecord(result.Records[i])

		if i >= len(result.Hops) {
			return encryptedData, fmt.Errorf("record %d has no corresponding hop RouterInfo", i)
		}
		encrypted, err := EncryptBuildRequestRecord(i2npRecord, result.Hops[i])
		if err != nil {
			return encryptedData, fmt.Errorf("failed to encrypt build record %d: %w", i, err)
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
				return nil, fmt.Errorf("failed to generate random padding for unused slot %d: %w", i, err)
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
		return 0, fmt.Errorf("failed to generate random message ID: %w", err)
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
		return fmt.Errorf("failed to generate tunnel ID: %w", err)
	}
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
func (tm *TunnelManager) generateTunnelID() (tunnel.TunnelID, error) {
	var buf [4]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return 0, fmt.Errorf("failed to generate random tunnel ID: %w", err)
	}
	return tunnel.TunnelID(binary.BigEndian.Uint32(buf[:])), nil
}

// sendTunnelBuildRequests builds a single TunnelBuild message containing all
// encrypted hop records and sends it to the first hop (gateway) only.
// Per the I2P tunnel creation specification, the gateway forwards the message
// through the partially-built tunnel; each hop peels its layer and forwards
// to the next. Sending directly to each hop would break tunnel anonymity.
func (tm *TunnelManager) sendTunnelBuildRequests(records []BuildRequestRecord, peers []router_info.RouterInfo, tunnelID tunnel.TunnelID) error {
	if tm.sessionProvider == nil {
		return fmt.Errorf("no session provider available for sending tunnel build requests")
	}
	if len(peers) == 0 {
		return fmt.Errorf("no peers provided for tunnel build")
	}

	tm.logSendingBuildRequests(tunnelID, len(peers))

	// Encrypt each record with the corresponding hop's public key and
	// assemble all records into a single 8-slot TunnelBuild message.
	msg, err := tm.createCombinedBuildMessage(records, peers, tunnelID)
	if err != nil {
		return fmt.Errorf("failed to create combined tunnel build message: %w", err)
	}

	// Send only to the first hop (gateway) — it will forward onion-style.
	firstPeerHash, err := peers[0].IdentHash()
	if err != nil {
		return fmt.Errorf("failed to get first hop hash: %w", err)
	}
	session, err := tm.getSessionForPeer(firstPeerHash)
	if err != nil {
		return fmt.Errorf("failed to get session for gateway: %w", err)
	}
	session.QueueSendI2NP(msg)

	tm.logBuildRequestsCompleted(tunnelID)
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
				return nil, fmt.Errorf("failed to encrypt record for hop %d: %w", i, err)
			}
			copy(data[slotStart:slotEnd], encrypted[:])
		} else {
			if _, err := rand.Read(data[slotStart:slotEnd]); err != nil {
				return nil, fmt.Errorf("failed to generate random padding for slot %d: %w", i, err)
			}
		}
	}

	msg := &TunnelBuildMessage{
		BaseI2NPMessage: NewBaseI2NPMessage(I2NPMessageTypeTunnelBuild),
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

	tm.cleanupFailedTunnel(matchingTunnel.ID, matchingTunnel.IsInbound)
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

// cleanupFailedTunnel schedules removal of a failed tunnel from the pool after a delay.
// Uses time.AfterFunc instead of time.Sleep to avoid blocking a goroutine.
func (tm *TunnelManager) cleanupFailedTunnel(tunnelID tunnel.TunnelID, isInbound bool) {
	time.AfterFunc(1*time.Second, func() {
		pool := tm.getPoolForTunnel(isInbound)
		if pool != nil {
			pool.RemoveTunnel(tunnelID)
			log.WithField("tunnel_id", tunnelID).Debug("Cleaned up failed tunnel")
		}
	})
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

	tm.cleanupFailedTunnel(req.tunnelID, req.isInbound)
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
			tm.cleanupFailedTunnel(req.tunnelID, req.isInbound)
		}

		log.WithFields(logger.Fields{
			"message_id": messageID,
			"tunnel_id":  req.tunnelID,
			"age":        time.Since(req.createdAt),
		}).Debug("Cleaned up expired tunnel build via timeout")
	}
}
