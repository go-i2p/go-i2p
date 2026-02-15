package i2np

import (
	"fmt"
	"sync"
	"time"

	"github.com/go-i2p/common/session_key"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/go-i2p/logger"
)

// ReplyProcessorConfig configures tunnel reply processing behavior.
type ReplyProcessorConfig struct {
	// BuildTimeout is the maximum time to wait for a tunnel build reply.
	// Default: 90 seconds (I2P spec recommendation).
	BuildTimeout time.Duration

	// MaxRetries is the maximum number of build retries for failed tunnels.
	// Default: 3 retries per tunnel.
	MaxRetries int

	// RetryBackoff is the delay between retry attempts.
	// Default: 5 seconds with exponential backoff.
	RetryBackoff time.Duration

	// EnableDecryption enables ECIES-X25519-AEAD (ChaCha20/Poly1305) decryption of encrypted build reply records.
	// This is the modern I2P standard (spec 0.9.44+), replacing legacy AES-256-CBC.
	// Default: true (required for production).
	EnableDecryption bool
}

// DefaultReplyProcessorConfig returns the default configuration.
func DefaultReplyProcessorConfig() ReplyProcessorConfig {
	return ReplyProcessorConfig{
		BuildTimeout:     90 * time.Second,
		MaxRetries:       3,
		RetryBackoff:     5 * time.Second,
		EnableDecryption: true,
	}
}

// PendingBuildRequest tracks an in-progress tunnel build request.
type PendingBuildRequest struct {
	TunnelID     tunnel.TunnelID
	RequestedAt  time.Time
	ReplyKeys    []session_key.SessionKey // ECIES-X25519-AEAD keys for decrypting each hop's reply
	ReplyIVs     [][16]byte               // Nonces/IVs for AEAD decryption
	Retries      int                      // Number of retry attempts
	IsInbound    bool                     // True for inbound tunnel, false for outbound
	HopCount     int                      // Number of hops in tunnel
	TimeoutTimer *time.Timer              // Timeout timer for this build
}

// ReplyProcessor handles tunnel build reply processing with timeout and retry logic.
// It manages pending build requests, decrypts encrypted reply records, and coordinates
// tunnel state transitions based on build success or failure.
type ReplyProcessor struct {
	config ReplyProcessorConfig

	// pendingBuilds tracks all in-progress tunnel builds keyed by tunnel ID.
	pendingBuilds map[tunnel.TunnelID]*PendingBuildRequest
	mutex         sync.RWMutex

	// stopped indicates the processor has been shut down.
	// Retry timer callbacks check this flag before executing to prevent
	// operations on torn-down resources after Stop() is called.
	stopped bool

	// pendingTimers tracks all active retry timers so they can be
	// cancelled during shutdown, preventing goroutine leaks.
	pendingTimers []*time.Timer

	// tunnelManager handles tunnel state management and coordination.
	tunnelManager *TunnelManager

	// retryCallback is invoked when a build fails and should be retried.
	retryCallback func(tunnelID tunnel.TunnelID, isInbound bool, hopCount int) error
}

// NewReplyProcessor creates a new reply processor with the given configuration.
func NewReplyProcessor(config ReplyProcessorConfig, tm *TunnelManager) *ReplyProcessor {
	return &ReplyProcessor{
		config:        config,
		pendingBuilds: make(map[tunnel.TunnelID]*PendingBuildRequest),
		tunnelManager: tm,
	}
}

// SetRetryCallback sets the callback function for retrying failed builds.
// The callback receives the tunnel ID, tunnel direction, and hop count.
func (rp *ReplyProcessor) SetRetryCallback(callback func(tunnel.TunnelID, bool, int) error) {
	rp.retryCallback = callback
}

// RegisterPendingBuild registers a new tunnel build request for reply tracking.
// This must be called before sending the build request to enable proper correlation.
//
// Parameters:
//   - tunnelID: Unique identifier for this tunnel build
//   - replyKeys: ECIES-X25519-AEAD decryption keys for each hop's reply record
//   - replyIVs: Nonces/initialization vectors for AEAD decryption
//   - isInbound: Tunnel direction (true=inbound, false=outbound)
//   - hopCount: Number of hops in the tunnel
func (rp *ReplyProcessor) RegisterPendingBuild(
	tunnelID tunnel.TunnelID,
	replyKeys []session_key.SessionKey,
	replyIVs [][16]byte,
	isInbound bool,
	hopCount int,
) error {
	if len(replyKeys) != hopCount || len(replyIVs) != hopCount {
		return fmt.Errorf("reply key/IV count mismatch: got %d keys, %d IVs, expected %d",
			len(replyKeys), len(replyIVs), hopCount)
	}

	rp.mutex.Lock()
	defer rp.mutex.Unlock()

	// Create pending build request
	pending := &PendingBuildRequest{
		TunnelID:    tunnelID,
		RequestedAt: time.Now(),
		ReplyKeys:   replyKeys,
		ReplyIVs:    replyIVs,
		Retries:     0,
		IsInbound:   isInbound,
		HopCount:    hopCount,
	}

	// Set up timeout timer
	pending.TimeoutTimer = time.AfterFunc(rp.config.BuildTimeout, func() {
		rp.handleBuildTimeout(tunnelID)
	})

	rp.pendingBuilds[tunnelID] = pending

	log.WithFields(logger.Fields{
		"tunnel_id":    tunnelID,
		"is_inbound":   isInbound,
		"hop_count":    hopCount,
		"timeout_secs": rp.config.BuildTimeout.Seconds(),
	}).Debug("Registered pending tunnel build")

	return nil
}

// ProcessBuildReply processes a tunnel build reply message.
// It decrypts encrypted reply records, validates responses, and updates tunnel state.
//
// The handler parameter should be one of:
//   - *TunnelBuildReply (8 hops)
//   - *VariableTunnelBuildReply (1-8 hops)
//   - *ShortTunnelBuildReply (1-8 hops, modern STBM format)
//
// Returns nil on successful build, error otherwise.
func (rp *ReplyProcessor) ProcessBuildReply(handler TunnelReplyHandler, tunnelID tunnel.TunnelID) error {
	pending, err := rp.retrieveAndRemovePendingBuild(tunnelID)
	if err != nil {
		return err
	}

	rp.logReplyProcessing(tunnelID, pending)

	if err := rp.decryptReplyIfEnabled(handler, tunnelID, pending); err != nil {
		return err
	}

	if err := rp.processReplyWithHandler(handler, tunnelID, pending); err != nil {
		return err
	}

	return rp.handleBuildSuccess(tunnelID, pending)
}

func (rp *ReplyProcessor) retrieveAndRemovePendingBuild(tunnelID tunnel.TunnelID) (*PendingBuildRequest, error) {
	rp.mutex.Lock()
	defer rp.mutex.Unlock()

	pending, exists := rp.pendingBuilds[tunnelID]
	if !exists {
		log.WithField("tunnel_id", tunnelID).Warn("Received reply for unknown tunnel build")
		return nil, fmt.Errorf("no pending build for tunnel %d", tunnelID)
	}

	if pending.TimeoutTimer != nil {
		pending.TimeoutTimer.Stop()
	}

	delete(rp.pendingBuilds, tunnelID)
	return pending, nil
}

func (rp *ReplyProcessor) logReplyProcessing(tunnelID tunnel.TunnelID, pending *PendingBuildRequest) {
	log.WithFields(logger.Fields{
		"tunnel_id":  tunnelID,
		"latency_ms": time.Since(pending.RequestedAt).Milliseconds(),
	}).Debug("Processing tunnel build reply")
}

func (rp *ReplyProcessor) decryptReplyIfEnabled(handler TunnelReplyHandler, tunnelID tunnel.TunnelID, pending *PendingBuildRequest) error {
	if !rp.config.EnableDecryption {
		return nil
	}

	if err := rp.decryptReplyRecords(handler, pending); err != nil {
		log.WithFields(logger.Fields{
			"tunnel_id": tunnelID,
			"error":     err,
		}).Error("Failed to decrypt reply records")
		return rp.handleBuildFailure(tunnelID, pending, err)
	}
	return nil
}

func (rp *ReplyProcessor) processReplyWithHandler(handler TunnelReplyHandler, tunnelID tunnel.TunnelID, pending *PendingBuildRequest) error {
	if err := handler.ProcessReply(); err != nil {
		log.WithFields(logger.Fields{
			"tunnel_id": tunnelID,
			"error":     err,
		}).Warn("Tunnel build failed")
		return rp.handleBuildFailure(tunnelID, pending, err)
	}
	return nil
}

// decryptReplyRecords decrypts encrypted build reply records using the stored reply keys.
// Each hop's reply is encrypted with ECIES-X25519-AEAD (ChaCha20/Poly1305) using the reply key
// from the build request. This is the modern I2P standard, replacing legacy AES-256-CBC.
//
// Uses raw encrypted bytes from GetRawReplyRecords() instead of re-serializing parsed records,
// because round-tripping through parse/serialize corrupts the original ciphertext.
func (rp *ReplyProcessor) decryptReplyRecords(handler TunnelReplyHandler, pending *PendingBuildRequest) error {
	records := handler.GetReplyRecords()
	rawRecords := handler.GetRawReplyRecords()

	if len(records) != len(pending.ReplyKeys) {
		return fmt.Errorf("record count mismatch: got %d records, expected %d",
			len(records), len(pending.ReplyKeys))
	}

	if len(rawRecords) != len(records) {
		return fmt.Errorf("raw record count mismatch: got %d raw records, expected %d",
			len(rawRecords), len(records))
	}

	for i := range records {
		// Decrypt this hop's reply record using the raw encrypted bytes
		decrypted, err := rp.decryptRecord(rawRecords[i], pending.ReplyKeys[i], pending.ReplyIVs[i])
		if err != nil {
			return fmt.Errorf("failed to decrypt record %d: %w", i, err)
		}

		// Parse decrypted data into BuildResponseRecord
		decryptedRecord, err := ReadBuildResponseRecord(decrypted)
		if err != nil {
			return fmt.Errorf("failed to parse decrypted record %d: %w", i, err)
		}

		// Update the record in-place (this modifies the handler's records)
		records[i] = decryptedRecord
	}

	log.WithField("record_count", len(records)).Debug("Decrypted all reply records using ChaCha20/Poly1305 AEAD")
	return nil
}

// decryptRecord decrypts a single encrypted build response record from raw bytes.
// Uses ChaCha20-Poly1305 AEAD (modern mode, I2P 0.9.44+) or AES-256-CBC (legacy).
//
// The encrypted parameter must be the original wire bytes, NOT re-serialized from
// a parsed record, as round-tripping through parse/serialize would corrupt the ciphertext.
func (rp *ReplyProcessor) decryptRecord(
	encrypted []byte,
	replyKey session_key.SessionKey,
	replyIV [16]byte,
) ([]byte, error) {
	crypto := NewBuildRecordCrypto()

	// Perform actual ChaCha20-Poly1305 AEAD decryption.
	// DecryptReplyRecord expects 544 bytes (528 ciphertext + 16 auth tag).
	// If the record data is only 528 bytes (legacy AES-256-CBC format where
	// no auth tag is appended), we cannot use ChaCha20-Poly1305 and must
	// fall back to treating the data as AES-encrypted.
	if len(encrypted) == 544 {
		// Modern path: ChaCha20-Poly1305 AEAD with 16-byte auth tag
		decryptedRecord, err := crypto.DecryptReplyRecord(encrypted, replyKey, replyIV)
		if err != nil {
			return nil, fmt.Errorf("ChaCha20-Poly1305 decryption failed: %w", err)
		}

		cleartext, err := crypto.serializeResponseRecord(decryptedRecord)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize decrypted record: %w", err)
		}

		log.WithFields(logger.Fields{
			"encryption": "ChaCha20-Poly1305",
			"size":       len(cleartext),
		}).Debug("Decrypted tunnel build reply record")

		return cleartext, nil
	}

	if len(encrypted) == 528 {
		// Legacy path: AES-256-CBC decryption (528-byte records, no auth tag).
		cleartext, err := crypto.decryptAES256CBC(encrypted, replyKey, replyIV)
		if err != nil {
			return nil, fmt.Errorf("AES-256-CBC decryption failed: %w", err)
		}

		log.WithFields(logger.Fields{
			"encryption": "AES-256-CBC",
			"size":       len(cleartext),
		}).Debug("Decrypted tunnel build reply record (legacy)")

		return cleartext, nil
	}

	return nil, fmt.Errorf("unexpected encrypted record size: %d (expected 528 or 544)", len(encrypted))
}

// handleBuildSuccess handles successful tunnel build completion.
func (rp *ReplyProcessor) handleBuildSuccess(tunnelID tunnel.TunnelID, pending *PendingBuildRequest) error {
	log.WithFields(logger.Fields{
		"tunnel_id":   tunnelID,
		"is_inbound":  pending.IsInbound,
		"build_time":  time.Since(pending.RequestedAt).Seconds(),
		"retry_count": pending.Retries,
	}).Info("Tunnel build completed successfully")

	// Note: tunnelManager is available for future enhancements.
	// Currently, tunnel state management happens in ProcessTunnelReply in processor.go
	// Future: Implement direct tunnel manager integration here if needed
	_ = rp.tunnelManager // Explicitly mark as intentionally unused for now

	return nil
}

// handleBuildFailure handles failed tunnel builds with retry logic.
func (rp *ReplyProcessor) handleBuildFailure(
	tunnelID tunnel.TunnelID,
	pending *PendingBuildRequest,
	buildErr error,
) error {
	log.WithFields(logger.Fields{
		"tunnel_id":   tunnelID,
		"error":       buildErr,
		"retry_count": pending.Retries,
		"max_retries": rp.config.MaxRetries,
	}).Warn("Tunnel build failed")

	// Check if we should retry
	if pending.Retries < rp.config.MaxRetries {
		return rp.retryBuild(tunnelID, pending)
	}

	// Exceeded retry limit - fail permanently
	log.WithFields(logger.Fields{
		"tunnel_id":   tunnelID,
		"retry_count": pending.Retries,
	}).Error("Tunnel build failed permanently after all retries")

	return fmt.Errorf("tunnel build failed after %d retries: %w", pending.Retries, buildErr)
}

// retryBuild attempts to retry a failed tunnel build with exponential backoff.
func (rp *ReplyProcessor) retryBuild(tunnelID tunnel.TunnelID, pending *PendingBuildRequest) error {
	if rp.retryCallback == nil {
		log.Warn("No retry callback configured, cannot retry tunnel build")
		return fmt.Errorf("retry not available")
	}

	// Calculate backoff delay with exponential increase
	backoffDelay := rp.config.RetryBackoff * time.Duration(1<<pending.Retries)

	log.WithFields(logger.Fields{
		"tunnel_id":     tunnelID,
		"retry_count":   pending.Retries + 1,
		"backoff_delay": backoffDelay.Seconds(),
	}).Info("Scheduling tunnel build retry")

	// Schedule retry after backoff delay.
	// The callback checks rp.stopped to avoid operating on torn-down resources
	// if Stop() was called while this timer was pending.
	timer := time.AfterFunc(backoffDelay, func() {
		rp.mutex.RLock()
		stopped := rp.stopped
		rp.mutex.RUnlock()
		if stopped {
			log.WithField("tunnel_id", tunnelID).Debug("Skipping retry callback: processor stopped")
			return
		}
		if err := rp.retryCallback(tunnelID, pending.IsInbound, pending.HopCount); err != nil {
			log.WithFields(logger.Fields{
				"tunnel_id": tunnelID,
				"error":     err,
			}).Error("Tunnel build retry failed")
		}
	})

	// Track the timer so it can be cancelled during shutdown
	rp.mutex.Lock()
	rp.pendingTimers = append(rp.pendingTimers, timer)
	rp.mutex.Unlock()

	return fmt.Errorf("tunnel build failed, retry scheduled")
}

// handleBuildTimeout handles tunnel build timeout events.
func (rp *ReplyProcessor) handleBuildTimeout(tunnelID tunnel.TunnelID) {
	rp.mutex.Lock()
	pending, exists := rp.pendingBuilds[tunnelID]
	if !exists {
		rp.mutex.Unlock()
		return // Already processed
	}

	// Remove from pending builds
	delete(rp.pendingBuilds, tunnelID)
	rp.mutex.Unlock()

	log.WithFields(logger.Fields{
		"tunnel_id":    tunnelID,
		"elapsed_secs": time.Since(pending.RequestedAt).Seconds(),
	}).Warn("Tunnel build timed out")

	// Attempt retry if within limit
	if pending.Retries < rp.config.MaxRetries {
		if err := rp.retryBuild(tunnelID, pending); err != nil {
			log.WithError(err).WithField("tunnel_id", tunnelID).Error("Failed to schedule tunnel build retry after timeout")
		}
	} else {
		log.WithField("tunnel_id", tunnelID).Error("Tunnel build timed out after all retries")
	}
}

// CleanupExpiredBuilds removes pending builds that have exceeded their timeout.
// This is a maintenance function that should be called periodically.
func (rp *ReplyProcessor) CleanupExpiredBuilds() int {
	rp.mutex.Lock()
	defer rp.mutex.Unlock()

	now := time.Now()
	maxAge := rp.config.BuildTimeout + (rp.config.RetryBackoff * time.Duration(rp.config.MaxRetries+1))
	var expired []tunnel.TunnelID

	for id, pending := range rp.pendingBuilds {
		if now.Sub(pending.RequestedAt) > maxAge {
			expired = append(expired, id)
			if pending.TimeoutTimer != nil {
				pending.TimeoutTimer.Stop()
			}
		}
	}

	for _, id := range expired {
		delete(rp.pendingBuilds, id)
	}

	if len(expired) > 0 {
		log.WithField("expired_count", len(expired)).Warn("Cleaned up expired tunnel builds")
	}

	return len(expired)
}

// GetPendingBuildCount returns the number of currently pending tunnel builds.
func (rp *ReplyProcessor) GetPendingBuildCount() int {
	rp.mutex.RLock()
	defer rp.mutex.RUnlock()
	return len(rp.pendingBuilds)
}

// GetPendingBuildInfo returns information about a specific pending build.
// Returns nil if the build is not found.
func (rp *ReplyProcessor) GetPendingBuildInfo(tunnelID tunnel.TunnelID) *PendingBuildRequest {
	rp.mutex.RLock()
	defer rp.mutex.RUnlock()
	return rp.pendingBuilds[tunnelID]
}

// Stop shuts down the reply processor, cancelling all pending timers and
// setting the stopped flag to prevent retry callbacks from executing.
// This prevents goroutine leaks from fire-and-forget time.AfterFunc timers
// that would otherwise continue running after the processor is torn down.
func (rp *ReplyProcessor) Stop() {
	rp.mutex.Lock()
	defer rp.mutex.Unlock()

	rp.stopped = true

	// Cancel all pending retry timers
	for _, timer := range rp.pendingTimers {
		timer.Stop()
	}
	rp.pendingTimers = nil

	// Cancel all pending build timeout timers
	for id, pending := range rp.pendingBuilds {
		if pending.TimeoutTimer != nil {
			pending.TimeoutTimer.Stop()
		}
		delete(rp.pendingBuilds, id)
	}

	log.Debug("ReplyProcessor stopped, all pending timers cancelled")
}
