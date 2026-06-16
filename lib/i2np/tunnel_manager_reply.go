package i2np

import (
	"time"

	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

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
			tm.recordBuildSuccess(true)
		} else {
			RecordExploratoryReplyStage(ExploratoryReplyStageLateReplyReclassedFail)
			tm.recordBuildReject(true)
		}
	} else {
		tm.buildExpireWindow.recordValue(-1)
		if replyErr == nil {
			RecordExploratoryReplyStage(ExploratoryReplyStageLateReplyReclassedOK)
			tm.recordBuildSuccess(false)
		} else {
			RecordExploratoryReplyStage(ExploratoryReplyStageLateReplyReclassedFail)
			tm.recordBuildReject(false)
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

// recordBuildSuccess records a successful tunnel build in the appropriate window
// (client or exploratory) based on the tunnel type.
func (tm *TunnelManager) recordBuildSuccess(isClientTunnel bool) {
	if isClientTunnel {
		tm.clientBuildSuccessWindow.recordEvent()
	} else {
		tm.buildSuccessWindow.recordEvent()
	}
}

// recordBuildReject records a rejected tunnel build in the appropriate window
// (client or exploratory) based on the tunnel type.
func (tm *TunnelManager) recordBuildReject(isClientTunnel bool) {
	if isClientTunnel {
		tm.clientBuildRejectWindow.recordEvent()
	} else {
		tm.buildRejectWindow.recordEvent()
	}
}

// recordBuildExpire records an expired tunnel build in the appropriate window
// (client or exploratory) based on the tunnel type.
func (tm *TunnelManager) recordBuildExpire(isClientTunnel bool) {
	if isClientTunnel {
		tm.clientBuildExpireWindow.recordEvent()
	} else {
		tm.buildExpireWindow.recordEvent()
	}
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
		tm.recordBuildSuccess(req.isClientTunnel)
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

	tm.recordBuildReject(req.isClientTunnel)
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
	tm.recordBuildSuccess(known && req.isClientTunnel)
	tm.buildTimeWindow.recordDuration(buildTimeMs)

	log.WithFields(logger.Fields{
		"tunnel_id":        matchingTunnel.ID,
		"message_id":       messageID,
		"build_time_ms":    buildTimeMs,
		"is_client_tunnel": known && req.isClientTunnel,
	}).Info("Tunnel build completed successfully")

	// C-1 fix: register inbound exploratory tunnels as control-plane endpoints so
	// that TunnelData messages addressed to this tunnel ID (build replies forwarded
	// in TUNNEL delivery mode by a remote OBEP) reach ProcessMessage instead of
	// being silently dropped by lookupTunnelEntry.
	if matchingTunnel.IsInbound && tm.inboundHandler != nil {
		if err := tm.inboundHandler.RegisterExploratoryTunnel(matchingTunnel.ID); err != nil {
			log.WithError(err).WithFields(logger.Fields{
				"at":        "handleSuccessfulBuild",
				"tunnel_id": matchingTunnel.ID,
			}).Warn("failed to register inbound tunnel as exploratory endpoint")
		}
	}
}

// handleFailedBuild processes a failed tunnel build and schedules cleanup.
func (tm *TunnelManager) handleFailedBuild(matchingTunnel *tunnel.TunnelState, messageID int, replyErr error) {
	matchingTunnel.State = tunnel.TunnelFailed

	// Keep exploratory and I2CP client build outcomes in separate windows.
	// This prevents client failures from skewing exploratory reject statistics.
	tm.buildMutex.RLock()
	req, known := tm.pendingBuilds[messageID]
	tm.buildMutex.RUnlock()
	tm.recordBuildReject(known && req.isClientTunnel)

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
	inbound := counters["inbound_i2np_received"]
	parsed := counters["tunnel_gateway_inner_parsed"]
	decryptAttempt := counters["garlic_decrypt_attempted"]
	decryptSuccess := counters["garlic_decrypt_succeeded"]
	dispatched := counters["short_build_reply_dispatched"]
	correlated := counters["short_build_reply_correlated"]
	uncorrelated := counters["short_build_reply_uncorrelated"]
	lateReclassedSuccess := counters["late_reply_reclassified_success"]
	lateReclassedReject := counters["late_reply_reclassified_reject"]
	lateShortSkipped := counters["late_reply_short_build_skipped"]

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
	tm.recordBuildExpire(req.isClientTunnel)
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
	tm.recordBuildExpire(req.isClientTunnel)
}
