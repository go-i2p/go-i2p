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
	"github.com/samber/oops"
	"golang.org/x/crypto/chacha20"
)

// buildExpireGrace is the extra window added to the cleanup timer and expiry
// threshold to close the race between a late-arriving reply and the
// time.AfterFunc cleanup goroutine (BUG-5 fix).
const buildExpireGrace = 200 * time.Millisecond

// buildRequest tracks a pending tunnel build request for correlation with replies.
// This enables matching build replies to the original request and managing timeouts.
type buildRequest struct {
	tunnelID       tunnel.TunnelID          // Unique tunnel ID for this request
	messageID      int                      // I2NP message ID for correlation
	replyTunnelID  tunnel.TunnelID          // Reply tunnel ID selected for outbound build replies
	hopCount       int                      // Number of hops in the tunnel
	replyKeys      []session_key.SessionKey // Reply decryption keys for each hop
	replyIVs       [][16]byte               // Reply IVs for each hop
	noiseHashes    [][32]byte               // STBM per-hop Noise transcript hashes for reply AEAD decryption
	createdAt      time.Time                // When the request was created
	retryCount     int                      // Number of retry attempts
	useShortBuild  bool                     // True if using STBM, false for legacy VTB
	isInbound      bool                     // True if this is an inbound tunnel
	isClientTunnel bool                     // True if this tunnel belongs to an I2CP client session
}

// expiredBuild tracks a recently expired build request for late-reply accounting.
// Entries are retained briefly so uncorrelated late replies can be attributed to
// their original build origin (exploratory vs client) for metrics correction.
type expiredBuild struct {
	req       *buildRequest
	expiredAt time.Time
}

// TunnelManager coordinates tunnel building and management
type TunnelManager struct {
	inboundPool     *tunnel.Pool
	outboundPool    *tunnel.Pool
	sessionProvider SessionProvider
	peerSelector    tunnel.PeerSelector
	pendingBuilds   map[int]*buildRequest // Track pending builds by message ID
	expiredBuilds   map[int]expiredBuild  // Recently expired builds retained for late-reply accounting
	buildMutex      sync.RWMutex          // Protect pending builds map
	cleanupTicker   *time.Ticker          // Periodic cleanup of expired requests
	cleanupStop     chan struct{}         // Signal to stop cleanup goroutine
	cleanupOnce     sync.Once             // Ensures cleanup goroutine starts at most once
	stopOnce        sync.Once             // Ensures Stop() is idempotent (no double-close panic)
	replyProcessor  *ReplyProcessor       // Handles reply decryption and processing
	// garlicKeyRegistrar receives one-time garlic keys derived from STBM Noise
	// transcript hashes so that incoming ShortTunnelBuildReply garlic messages
	// can be decrypted. Set via SetGarlicKeyRegistrar after construction.
	garlicKeyRegistrar GarlicKeyRegistrar

	// Build event windows for period-aware statistics (retained for 2 hours).
	// These track tunnel build outcomes so GetRate("tunnel.buildExploratorySuccess", period)
	// can return the count of successful builds within the requested time window.
	buildSuccessWindow       *buildEventWindow // successful exploratory tunnel builds
	buildRejectWindow        *buildEventWindow // explicitly rejected tunnel builds
	buildExpireWindow        *buildEventWindow // timed-out tunnel builds
	buildTimeWindow          *buildEventWindow // build duration in milliseconds
	clientBuildSuccessWindow *buildEventWindow // successful I2CP client session tunnel builds
	clientBuildRejectWindow  *buildEventWindow // rejected I2CP client session tunnel builds
	clientBuildExpireWindow  *buildEventWindow // timed-out I2CP client session tunnel builds
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

	const buildWindowMaxAge = 2 * time.Hour
	tm := &TunnelManager{
		inboundPool:              inboundPool,
		outboundPool:             outboundPool,
		peerSelector:             peerSelector,
		pendingBuilds:            make(map[int]*buildRequest),
		expiredBuilds:            make(map[int]expiredBuild),
		cleanupStop:              make(chan struct{}),
		buildSuccessWindow:       newBuildEventWindow(buildWindowMaxAge),
		buildRejectWindow:        newBuildEventWindow(buildWindowMaxAge),
		buildExpireWindow:        newBuildEventWindow(buildWindowMaxAge),
		buildTimeWindow:          newBuildEventWindow(buildWindowMaxAge),
		clientBuildSuccessWindow: newBuildEventWindow(buildWindowMaxAge),
		clientBuildRejectWindow:  newBuildEventWindow(buildWindowMaxAge),
		clientBuildExpireWindow:  newBuildEventWindow(buildWindowMaxAge),
	}

	// Initialize ReplyProcessor with default config for reply decryption
	tm.replyProcessor = NewReplyProcessor(DefaultReplyProcessorConfig(), tm)
	replyTunnelProvider := func() (tunnel.TunnelID, bool) {
		if tm.inboundPool == nil {
			return 0, false
		}
		if inbound := tm.inboundPool.SelectTunnel(); inbound != nil {
			return inbound.ID, true
		}
		return 0, false
	}
	tm.inboundPool.SetReplyTunnelProvider(replyTunnelProvider)
	tm.outboundPool.SetReplyTunnelProvider(replyTunnelProvider)

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
		log.WithFields(logger.Fields{"at": "ensureCleanupStarted"}).Debug("Tunnel manager cleanup goroutine started (lazy)")
	})
}

// SetGarlicKeyRegistrar wires the GarlicKeyRegistrar so that one-time garlic
// reply keys derived from STBM builds can be registered for later decryption.
// Must be called before the first tunnel build is initiated.
func (tm *TunnelManager) SetGarlicKeyRegistrar(r GarlicKeyRegistrar) {
	tm.garlicKeyRegistrar = r
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

		log.WithFields(logger.Fields{"at": "Stop"}).Debug("Tunnel manager stopped")
	})
}

// SetSessionProvider sets the session provider for sending tunnel build messages
func (tm *TunnelManager) SetSessionProvider(provider SessionProvider) {
	tm.sessionProvider = provider
}

// SetOurRouterHash propagates our router's identity hash to both tunnel pools
// so they can populate the ReplyGateway field in build requests. Without this,
// the last hop in every tunnel build sends its reply to an all-zeros peer and
// the reply is never received.
func (tm *TunnelManager) SetOurRouterHash(hash common.Hash) {
	if tm.inboundPool != nil {
		tm.inboundPool.SetRouterHash(hash)
	}
	if tm.outboundPool != nil {
		tm.outboundPool.SetRouterHash(hash)
	}
}

// GetPool returns the outbound tunnel pool for backward compatibility.
// Deprecated: Use GetInboundPool() or GetOutboundPool() for specific pools. Will be removed in v0.2.0.
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
		return oops.Errorf("pool not initialized for isInbound=%v", isInbound)
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
	tm.logExpectedReplyTagCandidates(result, messageID, req.ReplyTunnelID, req.IsInbound)
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

// logExpectedReplyTagCandidates logs expected one-time garlic tag candidates for
// outbound STBM builds so fresh logs can be correlated against incoming type-11
// decrypt attempts on reply_tunnel_id.
func (tm *TunnelManager) logExpectedReplyTagCandidates(result *tunnel.TunnelBuildResult, messageID int, replyTunnelID tunnel.TunnelID, isInbound bool) {
	if !tm.shouldLogExpectedTags(isInbound, replyTunnelID, result.UseShortBuild) {
		return
	}

	tags := tm.collectExpectedTags(result)
	if len(tags) == 0 {
		return
	}

	tm.logExpectedTags(messageID, result.TunnelID, replyTunnelID, tags)
}

// shouldLogExpectedTags checks if we should log expected tags for this build.
func (tm *TunnelManager) shouldLogExpectedTags(isInbound bool, replyTunnelID tunnel.TunnelID, useShortBuild bool) bool {
	return !isInbound && replyTunnelID != 0 && useShortBuild
}

// collectExpectedTags collects all expected reply tag candidates from the build result.
func (tm *TunnelManager) collectExpectedTags(result *tunnel.TunnelBuildResult) []string {
	tags := []string{}
	seen := map[[8]byte]struct{}{}

	appendTag := func(source string, tag [8]byte) {
		if _, ok := seen[tag]; ok {
			return
		}
		seen[tag] = struct{}{}
		tags = append(tags, fmt.Sprintf("%s:%x", source, tag))
	}

	tm.collectNoiseHashTags(result, appendTag)
	tm.collectReplyKeyTags(result, appendTag)

	return tags
}

// collectNoiseHashTags collects tags derived from noise hashes.
func (tm *TunnelManager) collectNoiseHashTags(result *tunnel.TunnelBuildResult, appendTag func(string, [8]byte)) {
	if len(result.NoiseHashes) == 0 {
		return
	}

	lastHop := len(result.NoiseHashes) - 1
	if key, tag, err := DeriveSTBMGarlicKey(result.NoiseHashes[lastHop]); err == nil {
		_ = key
		appendTag("noise_hash", tag)
	}
}

// collectReplyKeyTags collects tags derived from reply keys.
func (tm *TunnelManager) collectReplyKeyTags(result *tunnel.TunnelBuildResult, appendTag func(string, [8]byte)) {
	if len(result.ReplyKeys) == 0 {
		return
	}

	lastHop := len(result.ReplyKeys) - 1
	var rawReplyKey [32]byte
	copy(rawReplyKey[:], result.ReplyKeys[lastHop][:])

	var rawTag [8]byte
	copy(rawTag[:], rawReplyKey[24:32])
	appendTag("raw_reply_key", rawTag)

	if key, tag, err := DeriveSTBMGarlicKeyFromChainingKey(rawReplyKey); err == nil {
		_ = key
		appendTag("reply_key_attachlayer", tag)
	}
}

// logExpectedTags logs the expected tag candidates.
func (tm *TunnelManager) logExpectedTags(messageID int, tunnelID, replyTunnelID tunnel.TunnelID, tags []string) {
	log.WithFields(logger.Fields{
		"at":                 "BuildTunnelFromRequest",
		"message_id":         messageID,
		"tunnel_id":          tunnelID,
		"reply_tunnel_id":    replyTunnelID,
		"expected_tag_count": len(tags),
		"expected_tags":      tags,
	}).Debug("Computed expected one-time garlic tag candidates for outbound STBM build")
}

// sendBuildMessage sends a tunnel build message (STBM or VTB) based on the result.
func (tm *TunnelManager) sendBuildMessage(result *tunnel.TunnelBuildResult, messageID int) error {
	if tm.sessionProvider == nil {
		return oops.Errorf("no session provider available")
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
		return oops.Wrapf(err, "failed to create build message")
	}
	if err := tm.queueBuildMessageToGateway(session, buildMsg, messageID, peerHash, result.UseShortBuild); err != nil {
		return err
	}

	return nil
}

// validateTunnelBuild validates the tunnel build result has required hops.
func validateTunnelBuild(result *tunnel.TunnelBuildResult) (router_info.RouterInfo, error) {
	if len(result.Hops) == 0 {
		return router_info.RouterInfo{}, oops.Errorf("no hops in tunnel build result")
	}
	return result.Hops[0], nil
}

// getGatewaySession retrieves the transport session for the gateway router.
func (tm *TunnelManager) getGatewaySession(firstHop router_info.RouterInfo) (I2NPTransportSession, [32]byte, error) {
	peerHash, err := firstHop.IdentHash()
	if err != nil {
		return nil, [32]byte{}, oops.Wrapf(err, "failed to get first hop identity")
	}

	session, err := tm.sessionProvider.GetSessionByHash(peerHash)
	if err != nil {
		return nil, [32]byte{}, oops.Wrapf(err, "failed to get session for gateway %x", peerHash[:8])
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
// Returns an error when QueueSendI2NP fails (e.g. session was closed by the
// peer between getGatewaySession and now): without this, the caller would
// register a pending build entry whose message never actually leaves and the
// build would silently expire 90s later. Propagating the error lets
// BuildTunnelFromRequest run cleanupFailedBuild immediately and free the
// tunnel/pending-build slots.
func (tm *TunnelManager) queueBuildMessageToGateway(session I2NPTransportSession, buildMsg I2NPMessage, messageID int, peerHash [32]byte, useShortBuild bool) error {
	if err := session.QueueSendI2NP(buildMsg); err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"message_id":   messageID,
			"gateway_hash": fmt.Sprintf("%x", peerHash[:8]),
			"message_type": buildMsg.Type(),
			"use_stbm":     useShortBuild,
		}).Warn("Failed to queue tunnel build message")
		return oops.Wrapf(err, "failed to queue tunnel build message to gateway %x", peerHash[:8])
	}

	log.WithFields(logger.Fields{
		"message_id":   messageID,
		"gateway_hash": fmt.Sprintf("%x", peerHash[:8]),
		"message_type": buildMsg.Type(),
		"use_stbm":     useShortBuild,
	}).Debug("Queued tunnel build message")
	return nil
}

// createShortTunnelBuildMessage creates a Short Tunnel Build Message (STBM).
// Each build record is encrypted with the corresponding hop's X25519 public key
// using the STBM-format ECIES-X25519-AEAD encryption (zero nonce, ephemeral key
// as AD) before being placed into the message.
//
// Per the I2P tunnel-creation-ECIES specification (proposal 152), STBM records
// are 218 bytes each on the wire. Using the long-format 528-byte records here
// causes peers to reject the entire message (silent EOF after the NTCP2
// handshake), since the count byte is interpreted against the wrong stride.
func (tm *TunnelManager) createShortTunnelBuildMessage(result *tunnel.TunnelBuildResult, messageID int) (I2NPMessage, error) {
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

	return tm.serializeSTBM(encryptedRecords, messageID), nil
}

// convertAndOverrideMessageID converts tunnel records to I2NP format and overrides SendMessageID
// for STBM reply correlation. The remote OBEP reads sendMessageID from its decrypted record
// and uses it as the I2NP message ID of the ShortTunnelBuildReply it sends back.
func (tm *TunnelManager) convertAndOverrideMessageID(records []tunnel.BuildRequestRecord, messageID int) []BuildRequestRecord {
	i2npRecords := make([]BuildRequestRecord, len(records))
	for i, rec := range records {
		i2npRecords[i] = convertTunnelBuildRecord(rec)
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
func (tm *TunnelManager) updateReplyKeysWithHKDF(result *tunnel.TunnelBuildResult, replyKeys [][32]byte, noiseHashes [][32]byte) {
	result.ReplyKeys = make([]session_key.SessionKey, len(replyKeys))
	for i, rk := range replyKeys {
		result.ReplyKeys[i] = session_key.SessionKey(rk)
	}
	result.NoiseHashes = noiseHashes
}

// registerGarlicReplyKeys derives and registers one-time garlic keys for OBEP reply decryption.
// Registers both compatibility keys (from Noise transcript hash) and exact OBEP keys
// (from post-reply chaining key) to ensure interoperability with different implementations.
func (tm *TunnelManager) registerGarlicReplyKeys(noiseHashes [][32]byte, postReplyCKs [][32]byte, messageID int, tunnelID tunnel.TunnelID) error {
	if tm.garlicKeyRegistrar == nil || len(postReplyCKs) == 0 {
		return nil
	}

	lastHop := len(postReplyCKs) - 1
	if len(noiseHashes) > lastHop {
		compatKey, compatTag, compatErr := DeriveSTBMGarlicKey(noiseHashes[lastHop])
		if compatErr != nil {
			return oops.Wrapf(compatErr, "failed to derive compatibility garlic reply key")
		}
		tm.garlicKeyRegistrar.RegisterOneTimeGarlicKey(compatTag, compatKey)
	}

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

// serializeSTBM serializes encrypted STBM records and wraps them in an I2NP message.
// Format: [count:1][encrypted_records...] where each record is 218 bytes.
func (tm *TunnelManager) serializeSTBM(encryptedRecords [][ShortBuildRecordSize]byte, messageID int) I2NPMessage {
	data := make([]byte, 1+len(encryptedRecords)*ShortBuildRecordSize)
	data[0] = byte(len(encryptedRecords))
	for i, enc := range encryptedRecords {
		copy(data[1+i*ShortBuildRecordSize:1+(i+1)*ShortBuildRecordSize], enc[:])
	}

	msg := NewBaseI2NPMessage(I2NPMessageTypeShortTunnelBuild)
	msg.SetMessageID(messageID)
	msg.SetData(data)

	log.WithFields(logger.Fields{
		"at":           "serializeSTBM",
		"record_count": len(encryptedRecords),
		"data_size":    len(data),
		"record_size":  ShortBuildRecordSize,
		"encrypted":    true,
	}).Debug("Created encrypted Short Tunnel Build message")

	return msg
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

// ProcessTunnelBuildReply satisfies the TunnelBuildReplyProcessor interface used by
// MessageProcessor. It delegates to ProcessTunnelReply so that the single pendingBuilds
// map is consulted for reply correlation (A4 fix).
func (tm *TunnelManager) ProcessTunnelBuildReply(handler TunnelReplyHandler, messageID int) error {
	return tm.ProcessTunnelReply(handler, messageID)
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
	RecordExploratoryReplyStage(ExploratoryReplyStageShortReplyUncorrelated)
	log.WithField("message_id", messageID).Warn("No pending build request found for reply - processing without correlation")

	expired, foundExpired := tm.consumeExpiredBuildForLateReply(messageID)

	if tm.processLateShortBuildReply(messageID, &expired, foundExpired, handler) {
		return nil // Late reply was skipped
	}

	err := handler.ProcessReply()
	if foundExpired {
		tm.reclassifyExpiredBuildFromLateReply(messageID, expired, err)
	}

	if shouldPropagateError := err != nil && !foundExpired; shouldPropagateError {
		return err
	}

	if foundExpired {
		return nil
	}

	tm.updateTunnelStatesIfPossible(messageID, records)
	return nil
}

// processLateShortBuildReply handles late short-build replies if applicable.
// Returns true if the reply was skipped due to decryption failure.
func (tm *TunnelManager) processLateShortBuildReply(messageID int, expired *expiredBuild, foundExpired bool, handler TunnelReplyHandler) bool {
	if !foundExpired || !expired.req.useShortBuild {
		return false
	}

	if decryptErr := tm.tryDecryptLateShortBuildReply(handler, expired.req); decryptErr != nil {
		RecordExploratoryReplyStage(ExploratoryReplyStageLateReplyShortSkipped)
		log.WithFields(logger.Fields{
			"message_id":       messageID,
			"tunnel_id":        expired.req.tunnelID,
			"is_client_tunnel": expired.req.isClientTunnel,
			"error":            decryptErr,
			"reason":           "late short-build reply missing/invalid decrypt context",
		}).Warn("Ignoring late uncorrelated STBM reply for reclassification")
		return true
	}

	return false
}

// updateTunnelStatesIfPossible updates tunnel states if pools are available.
func (tm *TunnelManager) updateTunnelStatesIfPossible(messageID int, records []BuildResponseRecord) {
	if tm.inboundPool != nil || tm.outboundPool != nil {
		tm.updateTunnelStatesFromReply(messageID, records, nil)
	}
}

// tryDecryptLateShortBuildReply performs a best-effort STBM reply decrypt using
// decryption material retained from the original build request.
func (tm *TunnelManager) tryDecryptLateShortBuildReply(handler TunnelReplyHandler, req *buildRequest) error {
	if req == nil {
		return oops.Errorf("missing expired build context")
	}
	if len(req.replyKeys) == 0 || len(req.noiseHashes) == 0 {
		return oops.Errorf("missing STBM decryption keys/noise hashes")
	}
	pending := &PendingBuildRequest{
		ReplyKeys:   req.replyKeys,
		ReplyIVs:    req.replyIVs,
		NoiseHashes: req.noiseHashes,
	}
	if tm.replyProcessor == nil {
		return oops.Errorf("reply processor unavailable")
	}
	return tm.replyProcessor.decryptReplyRecords(handler, pending)
}

// consumeExpiredBuildForLateReply retrieves and removes a recently expired build
// entry for one-time late-reply reclassification.
func (tm *TunnelManager) consumeExpiredBuildForLateReply(messageID int) (expiredBuild, bool) {
	tm.buildMutex.Lock()
	defer tm.buildMutex.Unlock()
	entry, ok := tm.expiredBuilds[messageID]
	if !ok {
		return expiredBuild{}, false
	}
	delete(tm.expiredBuilds, messageID)
	return entry, true
}

// rememberExpiredBuild records an expired build for a short retention period so
// a late uncorrelated reply can update outcome accounting.
func (tm *TunnelManager) rememberExpiredBuild(messageID int, req *buildRequest) {
	tm.expiredBuilds[messageID] = expiredBuild{
		req:       req,
		expiredAt: time.Now(),
	}
}

// pruneExpiredBuildCacheLocked removes stale expired-build entries.
// Caller must hold tm.buildMutex.
func (tm *TunnelManager) pruneExpiredBuildCacheLocked(now time.Time) {
	const keep = 2 * time.Minute
	cutoff := now.Add(-keep)
	for msgID, entry := range tm.expiredBuilds {
		if entry.expiredAt.Before(cutoff) {
			delete(tm.expiredBuilds, msgID)
		}
	}
}

// reclassifyExpiredBuildFromLateReply compensates one previously-recorded
// expiration event with a late reply outcome.
func (tm *TunnelManager) reclassifyExpiredBuildFromLateReply(messageID int, expired expiredBuild, replyErr error) {
	req := expired.req
	if req == nil {
		return
	}

	if req.isClientTunnel {
		tm.clientBuildExpireWindow.recordValue(-1)
		if replyErr == nil {
			RecordExploratoryReplyStage(ExploratoryReplyStageLateReplyReclassedOK)
			tm.clientBuildSuccessWindow.recordEvent()
		} else {
			RecordExploratoryReplyStage(ExploratoryReplyStageLateReplyReclassedFail)
			tm.clientBuildRejectWindow.recordEvent()
		}
	} else {
		tm.buildExpireWindow.recordValue(-1)
		if replyErr == nil {
			RecordExploratoryReplyStage(ExploratoryReplyStageLateReplyReclassedOK)
			tm.buildSuccessWindow.recordEvent()
		} else {
			RecordExploratoryReplyStage(ExploratoryReplyStageLateReplyReclassedFail)
			tm.buildRejectWindow.recordEvent()
		}
	}

	fields := logger.Fields{
		"message_id":       messageID,
		"tunnel_id":        req.tunnelID,
		"is_client_tunnel": req.isClientTunnel,
		"late_age":         time.Since(expired.expiredAt),
	}
	if replyErr == nil {
		log.WithFields(fields).Info("Late reply reclassified prior expiration as success")
		return
	}
	fields["error"] = replyErr
	log.WithFields(fields).Info("Late reply reclassified prior expiration as reject")
}

// processCorrelatedReply handles replies with a pending build request.
func (tm *TunnelManager) processCorrelatedReply(handler TunnelReplyHandler, req *buildRequest, messageID int, records []BuildResponseRecord) error {
	RecordExploratoryReplyStage(ExploratoryReplyStageShortReplyCorrelated)
	// Use ReplyProcessor to decrypt and process the reply with proper key handling
	err := tm.replyProcessor.ProcessBuildReply(handler, req.tunnelID)

	// Update tunnel state based on reply processing results
	if tm.inboundPool != nil || tm.outboundPool != nil {
		tm.updateTunnelStatesFromReply(messageID, records, err)
	} else {
		log.WithFields(logger.Fields{"at": "processCorrelatedReply"}).Warn("No tunnel pool available for state updates")
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
	tm.buildMutex.RLock()
	req, reqExists := tm.pendingBuilds[messageID]
	tm.buildMutex.RUnlock()

	matchingTunnel := tm.findMatchingBuildingTunnel(messageID)

	if matchingTunnel == nil {
		tm.logNoMatchingTunnel(messageID, len(records))
		if reqExists {
			tm.accountCorrelatedReplyWithoutTunnelState(req, messageID, replyErr)
		}
		return
	}

	tm.logTunnelUpdate(matchingTunnel.ID, messageID, len(records), replyErr == nil)

	responses := tm.createBuildResponses(records)
	tm.updateTunnelBasedOnReply(matchingTunnel, messageID, responses, replyErr)
}

func (tm *TunnelManager) accountCorrelatedReplyWithoutTunnelState(req *buildRequest, messageID int, replyErr error) {
	if req == nil {
		return
	}

	if replyErr == nil {
		if req.isClientTunnel {
			tm.clientBuildSuccessWindow.recordEvent()
		} else {
			tm.buildSuccessWindow.recordEvent()
		}
		buildTimeMs := float64(time.Since(req.createdAt).Milliseconds())
		tm.buildTimeWindow.recordDuration(buildTimeMs)
		log.WithFields(logger.Fields{
			"tunnel_id":        req.tunnelID,
			"message_id":       messageID,
			"build_time_ms":    buildTimeMs,
			"is_client_tunnel": req.isClientTunnel,
		}).Warn("Counted successful tunnel build reply without tunnel state in pool")
		return
	}

	if req.isClientTunnel {
		tm.clientBuildRejectWindow.recordEvent()
	} else {
		tm.buildRejectWindow.recordEvent()
	}
	log.WithFields(logger.Fields{
		"tunnel_id":        req.tunnelID,
		"message_id":       messageID,
		"error":            replyErr,
		"is_client_tunnel": req.isClientTunnel,
	}).Warn("Counted failed tunnel build reply without tunnel state in pool")
	tm.cleanupFailedTunnel(req.tunnelID, req.isInbound)
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
			Success:  record.Reply == TunnelBuildReplySuccess,
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
	buildTimeMs := float64(time.Since(matchingTunnel.CreatedAt).Milliseconds())
	matchingTunnel.State = tunnel.TunnelReady

	// Route the build success event to the appropriate window based on tunnel origin.
	// Client tunnels (I2CP session pools) are tracked separately from exploratory tunnels.
	tm.buildMutex.RLock()
	req, known := tm.pendingBuilds[messageID]
	tm.buildMutex.RUnlock()
	if known && req.isClientTunnel {
		tm.clientBuildSuccessWindow.recordEvent()
	} else {
		tm.buildSuccessWindow.recordEvent()
	}
	tm.buildTimeWindow.recordDuration(buildTimeMs)

	log.WithFields(logger.Fields{
		"tunnel_id":        matchingTunnel.ID,
		"message_id":       messageID,
		"build_time_ms":    buildTimeMs,
		"is_client_tunnel": known && req.isClientTunnel,
	}).Info("Tunnel build completed successfully")
}

// handleFailedBuild processes a failed tunnel build and schedules cleanup.
func (tm *TunnelManager) handleFailedBuild(matchingTunnel *tunnel.TunnelState, messageID int, replyErr error) {
	matchingTunnel.State = tunnel.TunnelFailed

	// Keep exploratory and I2CP client build outcomes in separate windows.
	// This prevents client failures from skewing exploratory reject statistics.
	tm.buildMutex.RLock()
	req, known := tm.pendingBuilds[messageID]
	tm.buildMutex.RUnlock()
	if known && req.isClientTunnel {
		tm.clientBuildRejectWindow.recordEvent()
	} else {
		tm.buildRejectWindow.recordEvent()
	}

	log.WithFields(logger.Fields{
		"tunnel_id":        matchingTunnel.ID,
		"message_id":       messageID,
		"error":            replyErr,
		"is_client_tunnel": known && req.isClientTunnel,
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
// Build requests timeout after 90 seconds (implementation convention; no specific spec value).
func (tm *TunnelManager) cleanupExpiredBuilds() {
	for {
		select {
		case <-tm.cleanupTicker.C:
			tm.logExploratoryReplyFunnelSummary()
			tm.removeExpiredBuildRequests()
		case <-tm.cleanupStop:
			return
		}
	}
}

func safeRatio(numerator, denominator uint64) float64 {
	if denominator == 0 {
		return 0
	}
	return float64(numerator) / float64(denominator)
}

// logExploratoryReplyFunnelSummary emits a periodic stage-level summary for
// exploratory reply processing. It runs on the 30-second cleanup ticker.
func (tm *TunnelManager) logExploratoryReplyFunnelSummary() {
	counters := SnapshotExploratoryReplyStages()
	inbound := counters[ExploratoryReplyStageInboundI2NPReceived]
	parsed := counters[ExploratoryReplyStageTunnelGatewayParsed]
	decryptAttempt := counters[ExploratoryReplyStageGarlicDecryptAttempt]
	decryptSuccess := counters[ExploratoryReplyStageGarlicDecryptSuccess]
	dispatched := counters[ExploratoryReplyStageShortReplyDispatched]
	correlated := counters[ExploratoryReplyStageShortReplyCorrelated]
	uncorrelated := counters[ExploratoryReplyStageShortReplyUncorrelated]
	lateReclassedSuccess := counters[ExploratoryReplyStageLateReplyReclassedOK]
	lateReclassedReject := counters[ExploratoryReplyStageLateReplyReclassedFail]
	lateShortSkipped := counters[ExploratoryReplyStageLateReplyShortSkipped]

	log.WithFields(logger.Fields{
		"interval_sec":                     30,
		"inbound_i2np_received":            inbound,
		"tunnel_gateway_inner_parsed":      parsed,
		"garlic_decrypt_attempted":         decryptAttempt,
		"garlic_decrypt_succeeded":         decryptSuccess,
		"short_build_reply_dispatched":     dispatched,
		"short_build_reply_correlated":     correlated,
		"short_build_reply_uncorrelated":   uncorrelated,
		"late_reply_reclassified_success":  lateReclassedSuccess,
		"late_reply_reclassified_reject":   lateReclassedReject,
		"late_reply_short_build_skipped":   lateShortSkipped,
		"gateway_parse_ratio":              safeRatio(parsed, inbound),
		"garlic_decrypt_success_ratio":     safeRatio(decryptSuccess, decryptAttempt),
		"short_reply_correlation_ratio":    safeRatio(correlated, correlated+uncorrelated),
		"short_reply_dispatch_correlation": safeRatio(correlated, dispatched),
	}).Info("Exploratory reply funnel summary")
}

// removeExpiredBuildRequests removes build requests older than 90 seconds.
// Also marks corresponding tunnels as failed and removes them from the pool.
func (tm *TunnelManager) removeExpiredBuildRequests() {
	tm.buildMutex.Lock()
	defer tm.buildMutex.Unlock()

	tm.pruneExpiredBuildCacheLocked(time.Now())
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
	if req.isClientTunnel {
		tm.clientBuildExpireWindow.recordEvent()
	} else {
		tm.buildExpireWindow.recordEvent()
	}
	if req.isInbound {
		pool.RecordInboundBuildTimeout()
	} else {
		pool.RecordOutboundBuildTimeout()
	}
	log.WithFields(logger.Fields{
		"message_id":       msgID,
		"tunnel_id":        req.tunnelID,
		"reply_tunnel_id":  req.replyTunnelID,
		"is_inbound_build": req.isInbound,
		"is_client_tunnel": req.isClientTunnel,
		"elapsed":          now.Sub(req.createdAt),
	}).Warn("Tunnel build timed out")

	tm.rememberExpiredBuild(msgID, req)

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

	// BUG-5 fix: include a grace window in the expiry check to match the
	// deferred AfterFunc firing time (buildTimeout + buildExpireGrace).
	// This ensures a reply that races the cleanup goroutine on the 90s
	// boundary still wins and the entry survives until the timer fires.
	const buildTimeout = 90 * time.Second
	if time.Since(req.createdAt) > buildTimeout+buildExpireGrace {
		tm.processExpiredBuild(messageID, req)
	}
}

// processExpiredBuild handles the expiration of a tunnel build request.
func (tm *TunnelManager) processExpiredBuild(messageID int, req *buildRequest) {
	tm.rememberExpiredBuild(messageID, req)
	delete(tm.pendingBuilds, messageID)

	tm.markTunnelAsFailed(req)

	log.WithFields(logger.Fields{
		"message_id":       messageID,
		"tunnel_id":        req.tunnelID,
		"reply_tunnel_id":  req.replyTunnelID,
		"is_inbound_build": req.isInbound,
		"is_client_tunnel": req.isClientTunnel,
		"elapsed":          time.Since(req.createdAt),
	}).Debug("Cleaned up expired tunnel build via timeout")
}

// markTunnelAsFailed marks a tunnel as failed and schedules cleanup.
func (tm *TunnelManager) markTunnelAsFailed(req *buildRequest) {
	pool := tm.getPoolForTunnel(req.isInbound)
	tunnelState, exists := pool.GetTunnel(req.tunnelID)
	if !exists {
		return
	}

	tunnelState.State = tunnel.TunnelFailed

	tm.recordBuildTimeoutMetrics(req)

	if req.isInbound {
		pool.RecordInboundBuildTimeout()
	} else {
		pool.RecordOutboundBuildTimeout()
	}

	tm.cleanupFailedTunnel(req.tunnelID, req.isInbound)
}

// recordBuildTimeoutMetrics records timeout events to the appropriate time window.
func (tm *TunnelManager) recordBuildTimeoutMetrics(req *buildRequest) {
	if req.isClientTunnel {
		tm.clientBuildExpireWindow.recordEvent()
	} else {
		tm.buildExpireWindow.recordEvent()
	}
}

// GetBuildSuccessCount returns the number of successful tunnel builds within windowMs milliseconds.
// Maps to the Java I2P stat "tunnel.buildExploratorySuccess".
func (tm *TunnelManager) GetBuildSuccessCount(windowMs int64) float64 {
	return tm.buildSuccessWindow.countInWindow(windowMs)
}

// GetBuildRejectCount returns the number of explicitly rejected tunnel builds within windowMs milliseconds.
// Maps to the Java I2P stat "tunnel.buildExploratoryReject".
func (tm *TunnelManager) GetBuildRejectCount(windowMs int64) float64 {
	return tm.buildRejectWindow.countInWindow(windowMs)
}

// GetBuildExpireCount returns the number of timed-out tunnel builds within windowMs milliseconds.
// Maps to the Java I2P stat "tunnel.buildExploratoryExpire".
func (tm *TunnelManager) GetBuildExpireCount(windowMs int64) float64 {
	return tm.buildExpireWindow.countInWindow(windowMs)
}

// GetBuildAvgTimeMs returns the average tunnel build time in milliseconds for builds completed
// within windowMs milliseconds. Maps to the Java I2P stat "tunnel.buildRequestTime".
// Returns 0 if no successful builds have been recorded in the window.
func (tm *TunnelManager) GetBuildAvgTimeMs(windowMs int64) float64 {
	return tm.buildTimeWindow.avgInWindow(windowMs)
}

// GetClientBuildSuccessCount returns the number of successful I2CP client session tunnel builds
// within windowMs milliseconds. Maps to the Java I2P stat "tunnel.buildClientSuccess".
func (tm *TunnelManager) GetClientBuildSuccessCount(windowMs int64) float64 {
	return tm.clientBuildSuccessWindow.countInWindow(windowMs)
}

// GetClientBuildRejectCount returns the number of explicitly rejected I2CP client session
// tunnel builds within windowMs milliseconds.
func (tm *TunnelManager) GetClientBuildRejectCount(windowMs int64) float64 {
	return tm.clientBuildRejectWindow.countInWindow(windowMs)
}

// GetClientBuildExpireCount returns the number of timed-out I2CP client session tunnel
// builds within windowMs milliseconds.
func (tm *TunnelManager) GetClientBuildExpireCount(windowMs int64) float64 {
	return tm.clientBuildExpireWindow.countInWindow(windowMs)
}

// chacha20XORRecord applies the I2P short-tunnel-build chained layer
// obfuscation to a single 218-byte STBM record using ChaCha20 as a raw
// stream cipher (no Poly1305). The nonce is 12 zero bytes with nonce[4]
// set to the record's index in the message — matching i2pd's
// ShortECIESTunnelHopConfig::DecryptRecord. Because ChaCha20 is a stream
// cipher, the same operation both applies and removes the layer.
func chacha20XORRecord(record *[ShortBuildRecordSize]byte, key [32]byte, index int) error {
	var nonce [12]byte
	nonce[4] = byte(index)
	c, err := chacha20.NewUnauthenticatedCipher(key[:], nonce[:])
	if err != nil {
		return oops.Wrapf(err, "ChaCha20 init failed")
	}
	c.XORKeyStream(record[:], record[:])
	return nil
}
