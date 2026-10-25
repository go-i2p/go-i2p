package i2np

import (
	"sync"
	"time"

	"github.com/go-i2p/common/session_key"
	i2ptunnel "github.com/go-i2p/crypto/tunnel"
	"github.com/go-i2p/go-i2p/lib/tunnel/buildrecord"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// ReplyProcessorConfig configures tunnel reply processing behavior.
// It holds the timeout, retry, and decryption settings that a ReplyProcessor
// uses to track builds and recover from failed hops.
// See also [ReplyProcessor].
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
	// This is the I2P standard (spec 0.9.44+).
	// Default: true (required for production).
	EnableDecryption bool
}

// DefaultReplyProcessorConfig returns the default configuration.
// The defaults follow the I2P spec recommendation for build timeouts and
// enable ECIES decryption, which is required for production use.
// See also [ReplyProcessorConfig].
func DefaultReplyProcessorConfig() ReplyProcessorConfig {
	return ReplyProcessorConfig{
		BuildTimeout:     90 * time.Second,
		MaxRetries:       3,
		RetryBackoff:     5 * time.Second,
		EnableDecryption: true,
	}
}

// PendingBuildRequest tracks an in-progress tunnel build request.
// It holds the reply keys, IVs, and retry state needed to decrypt and
// correlate the reply for a specific tunnel once it arrives.
// See also [ReplyProcessor].
type PendingBuildRequest struct {
	TunnelID     buildrecord.TunnelID
	RequestedAt  time.Time
	ReplyKeys    []session_key.SessionKey // ECIES-X25519-AEAD keys for decrypting each hop's reply
	ReplyIVs     [][16]byte               // Nonces/IVs for AEAD decryption
	NoiseHashes  [][32]byte               // Per-hop Noise transcript hash (m_H) used as AEAD AD for STBM reply decryption
	Retries      int                      // Number of retry attempts
	IsInbound    bool                     // True for inbound tunnel, false for outbound
	HopCount     int                      // Number of hops in tunnel
	TimeoutTimer *time.Timer              // Timeout timer for this build

	// RecordSlots maps hop path index -> wire slot index for the build request
	// we sent. Build record order is randomized (tunnel-creation-ecies.rst
	// "Build Records"), and every per-slot nonce on both the build and reply
	// paths is the WIRE slot number, so reply decryption must address hop i's
	// record at RecordSlots[i] rather than at i. Nil means the identity.
	RecordSlots []int
}

// ReplyProcessor handles tunnel build reply processing with timeout and retry logic.
// It manages pending build requests, decrypts encrypted reply records, and coordinates
// tunnel state transitions based on build success or failure.
type ReplyProcessor struct {
	config ReplyProcessorConfig

	// pendingBuilds tracks all in-progress tunnel builds keyed by tunnel ID.
	pendingBuilds map[buildrecord.TunnelID]*PendingBuildRequest
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
	retryCallback func(tunnelID buildrecord.TunnelID, isInbound bool, hopCount int) error
}

// NewReplyProcessor creates a new reply processor with the given configuration.
// The processor is the component that matches incoming build replies to the
// builds that were sent, so it must be wired to the same TunnelManager that
// initiates those builds.
// See also [ReplyProcessor].
func NewReplyProcessor(config ReplyProcessorConfig, tm *TunnelManager) *ReplyProcessor {
	return &ReplyProcessor{
		config:        config,
		pendingBuilds: make(map[buildrecord.TunnelID]*PendingBuildRequest),
		tunnelManager: tm,
	}
}

// SetRetryCallback sets the callback function for retrying failed builds.
// The callback receives the tunnel ID, tunnel direction, and hop count.
func (rp *ReplyProcessor) SetRetryCallback(callback func(buildrecord.TunnelID, bool, int) error) {
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
	tunnelID buildrecord.TunnelID,
	replyKeys []session_key.SessionKey,
	replyIVs [][16]byte,
	isInbound bool,
	hopCount int,
) error {
	if len(replyKeys) != hopCount || len(replyIVs) != hopCount {
		return oops.Errorf("reply key/IV count mismatch: got %d keys, %d IVs, expected %d",
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

// SetPendingBuildNoiseHashes stores the per-hop Noise transcript hashes for an
// in-progress STBM build. These are the m_H values (Noise handshake hash after
// EncryptAndHash) needed as AEAD associated data when decrypting each hop's
// ShortTunnelBuildReply record. Must be called immediately after RegisterPendingBuild.
func (rp *ReplyProcessor) SetPendingBuildNoiseHashes(tunnelID buildrecord.TunnelID, noiseHashes [][32]byte) error {
	rp.mutex.Lock()
	defer rp.mutex.Unlock()

	pending, exists := rp.pendingBuilds[tunnelID]
	if !exists {
		return oops.Errorf("no pending build for tunnel %d when setting noise hashes", tunnelID)
	}
	pending.NoiseHashes = noiseHashes
	return nil
}

// SetPendingBuildRecordSlots stores the build-record permutation used for an
// in-progress STBM build. Build record order is randomized so middle hops cannot
// learn their tunnel position (tunnel-creation-ecies.rst "Build Records"); the
// creator must remember it to address each hop's reply slot correctly, because
// every per-slot nonce on the reply path is the wire slot number. Must be called
// immediately after RegisterPendingBuild.
func (rp *ReplyProcessor) SetPendingBuildRecordSlots(tunnelID buildrecord.TunnelID, recordSlots []int) error {
	rp.mutex.Lock()
	defer rp.mutex.Unlock()

	pending, exists := rp.pendingBuilds[tunnelID]
	if !exists {
		return oops.Errorf("no pending build for tunnel %d when setting record slots", tunnelID)
	}
	pending.RecordSlots = recordSlots
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
func (rp *ReplyProcessor) ProcessBuildReply(handler TunnelReplyHandler, tunnelID buildrecord.TunnelID) error {
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

func (rp *ReplyProcessor) retrieveAndRemovePendingBuild(tunnelID buildrecord.TunnelID) (*PendingBuildRequest, error) {
	rp.mutex.Lock()
	defer rp.mutex.Unlock()

	pending, exists := rp.pendingBuilds[tunnelID]
	if !exists {
		log.WithField("tunnel_id", tunnelID).Warn("Received reply for unknown tunnel build")
		return nil, oops.Errorf("no pending build for tunnel %d", tunnelID)
	}

	if pending.TimeoutTimer != nil {
		pending.TimeoutTimer.Stop()
	}

	delete(rp.pendingBuilds, tunnelID)
	return pending, nil
}

func (rp *ReplyProcessor) logReplyProcessing(tunnelID buildrecord.TunnelID, pending *PendingBuildRequest) {
	log.WithFields(logger.Fields{
		"tunnel_id":  tunnelID,
		"latency_ms": time.Since(pending.RequestedAt).Milliseconds(),
	}).Debug("Processing tunnel build reply")
}

func (rp *ReplyProcessor) decryptReplyIfEnabled(handler TunnelReplyHandler, tunnelID buildrecord.TunnelID, pending *PendingBuildRequest) error {
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

func (rp *ReplyProcessor) processReplyWithHandler(handler TunnelReplyHandler, tunnelID buildrecord.TunnelID, pending *PendingBuildRequest) error {
	if err := handler.ProcessReply(); err != nil {
		log.WithFields(logger.Fields{
			"tunnel_id": tunnelID,
			"error":     err,
		}).Warn("Tunnel build failed")
		return rp.handleBuildFailure(tunnelID, pending, err)
	}
	return nil
}

// decryptReplyRecords decrypts encrypted short (STBM) build reply records using
// the stored reply keys.
//
// STBM format (218-byte records, ShortBuildRecordSize): multi-pass ChaCha20
// layer peel followed by ChaCha20-Poly1305 AEAD decrypt; the ret code is at
// plaintext[201]. The 544-byte VTB reply format was removed along with the
// deprecated 528-byte long records ("NOTE: Deprecated, obsolete. Use the Short
// Record format specified below").
//
// Uses raw encrypted bytes from GetRawReplyRecords() instead of re-serializing parsed records,
// because round-tripping through parse/serialize corrupts the original ciphertext.
func (rp *ReplyProcessor) decryptReplyRecords(handler TunnelReplyHandler, pending *PendingBuildRequest) error {
	records := handler.GetReplyRecords()
	rawRecords := handler.GetRawReplyRecords()

	if err := rp.validateRecordCounts(records, rawRecords, pending); err != nil {
		return err
	}

	if len(rawRecords) == 0 {
		return nil
	}

	if len(rawRecords[0]) != ShortBuildRecordSize {
		return oops.Errorf("unexpected reply record size: %d (want %d-byte short records)",
			len(rawRecords[0]), ShortBuildRecordSize)
	}

	return rp.decryptSTBMReplyRecords(records, rawRecords, pending)
}

// validateRecordCounts ensures record counts match between parsed, raw, and expected keys.
func (rp *ReplyProcessor) validateRecordCounts(records []BuildResponseRecord, rawRecords [][]byte, pending *PendingBuildRequest) error {
	if len(records) != len(pending.ReplyKeys) {
		return oops.Errorf("record count mismatch: got %d records, expected %d",
			len(records), len(pending.ReplyKeys))
	}

	if len(rawRecords) != len(records) {
		return oops.Errorf("raw record count mismatch: got %d raw records, expected %d",
			len(rawRecords), len(records))
	}

	return nil
}

// decryptSTBMReplyRecords handles STBM reply decryption using i2pd-compatible 2-pass algorithm.
//
// Hops process the build message in path order 0..n-1, each replacing its own
// wire slot with its AEAD-encrypted reply and XOR-ing every other slot with its
// reply key, so after the last hop:
//
//	slot[perm[i]] = AEAD(hop_i_reply, key_i) XOR'd by all hops j > i
//
// where perm is the build-record permutation the creator chose (pending.RecordSlots).
// The creator decrypts from LAST hop to FIRST, peeling each hop's XOR layers off
// the other slots and then AEAD-decrypting that hop's slot. Both nonces are the
// WIRE slot number, not the path index; results are written back in path order
// so callers see records[i] for hop i regardless of the shuffle.
func (rp *ReplyProcessor) decryptSTBMReplyRecords(records []BuildResponseRecord, rawRecords [][]byte, pending *PendingBuildRequest) error {
	work, err := rp.prepareSTBMWorkBuffer(rawRecords)
	if err != nil {
		return err
	}

	n := len(work)
	for i := n - 1; i >= 0; i-- {
		var key [32]byte
		copy(key[:], pending.ReplyKeys[i][:])

		ourSlot := rp.slotForHop(pending, i, n)
		if err := rp.peelChaCha20Layers(work, key, ourSlot); err != nil {
			return err
		}

		retCode, err := rp.decryptSTBMSlot(work[ourSlot][:], key, pending.NoiseHashes, i, ourSlot)
		if err != nil {
			return err
		}

		records[i] = BuildResponseRecord{Reply: retCode}
	}

	log.WithField("record_count", n).Debug("Decrypted all STBM reply records")
	return nil
}

// slotForHop returns the wire slot carrying hop i's reply record. Falls back to
// the identity mapping when no permutation was recorded (or when it does not
// cover this hop, e.g. a legacy reply).
func (rp *ReplyProcessor) slotForHop(pending *PendingBuildRequest, hopIndex, recordCount int) int {
	if pending == nil || hopIndex < 0 || hopIndex >= len(pending.RecordSlots) {
		return hopIndex
	}
	slot := pending.RecordSlots[hopIndex]
	if slot < 0 || slot >= recordCount {
		return hopIndex
	}
	return slot
}

// prepareSTBMWorkBuffer copies raw records into a work buffer for in-place decryption.
func (rp *ReplyProcessor) prepareSTBMWorkBuffer(rawRecords [][]byte) ([][ShortBuildRecordSize]byte, error) {
	n := len(rawRecords)
	work := make([][ShortBuildRecordSize]byte, n)
	for i, raw := range rawRecords {
		if len(raw) < ShortBuildRecordSize {
			return nil, oops.Errorf("STBM record %d too short: %d bytes", i, len(raw))
		}
		copy(work[i][:], raw[:ShortBuildRecordSize])
	}
	return work, nil
}

// peelChaCha20Layers peels one hop's ChaCha20 layer from every wire slot except
// that hop's own. This mirrors the relay behavior exactly: a hop XORs all slots
// j != ourSlot using j as the nonce, so the initiator peels the same set with
// the same nonces.
func (rp *ReplyProcessor) peelChaCha20Layers(work [][ShortBuildRecordSize]byte, key [32]byte, ourSlot int) error {
	for j := 0; j < len(work); j++ {
		if j == ourSlot {
			continue // Skip the hop's own record (AEAD-decrypted separately)
		}
		if err := chacha20XORRecord(&work[j], key, j); err != nil {
			return oops.Wrapf(err, "ChaCha20 peel failed for slot %d record %d", ourSlot, j)
		}
	}
	return nil
}

// decryptSTBMSlot AEAD-decrypts hop hopIndex's own STBM reply record and extracts
// the ret code. The AEAD nonce is the record's WIRE slot number (spec: "n =
// record number 0-7"); the associated-data hash is looked up by path index,
// which stays in tunnel order.
func (rp *ReplyProcessor) decryptSTBMSlot(record []byte, key [32]byte, noiseHashes [][32]byte, hopIndex, slotIndex int) (byte, error) {
	var noiseHash [32]byte
	if hopIndex < len(noiseHashes) {
		noiseHash = noiseHashes[hopIndex]
	}
	cleartext, err := decryptSTBMReplySlot(record, key, noiseHash, slotIndex)
	if err != nil {
		return 0, oops.Wrapf(err, "STBM AEAD decrypt failed for hop %d (slot %d)", hopIndex, slotIndex)
	}
	return cleartext[201], nil
}

// decryptSTBMReplySlot AEAD-decrypts a single 218-byte STBM reply record slot.
//
// Delegates to the upstream primitive (crypto/tunnel.DecryptOwnBuildReply),
// which implements proposal 157 / i2pd ShortECIESTunnelHopConfig::
// DecryptBuildResponseRecord:
//   - Cipher: ChaCha20-Poly1305
//   - Key: 32-byte reply key (HKDF "SMTunnelReplyKey" output)
//   - Nonce: record number 0-7 in nonce byte 4
//   - AD: 32-byte Noise transcript hash (m_H after EncryptAndHash on creator side)
//   - Input: 218 bytes (202 ciphertext + 16 Poly1305 MAC)
//   - Output: 202 bytes plaintext; ret code at offset 201
func decryptSTBMReplySlot(encrypted []byte, key, noiseHash [32]byte, index int) ([]byte, error) {
	cleartext, err := i2ptunnel.DecryptOwnBuildReply(key, noiseHash, byte(index), encrypted[:min(len(encrypted), ShortBuildRecordSize)])
	if err != nil {
		return nil, oops.Wrapf(err, "ChaCha20-Poly1305 Open failed for STBM reply slot %d", index)
	}
	return cleartext, nil
}

// handleBuildSuccess handles successful tunnel build completion.
func (rp *ReplyProcessor) handleBuildSuccess(tunnelID buildrecord.TunnelID, pending *PendingBuildRequest) error {
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
	tunnelID buildrecord.TunnelID,
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
		if err := rp.retryBuild(tunnelID, pending); err != nil {
			return oops.Wrapf(buildErr, "tunnel build failed and retry scheduling failed: %v", err)
		}
		return oops.Wrapf(buildErr, "tunnel build failed; retry scheduled")
	}

	// Exceeded retry limit - fail permanently
	log.WithFields(logger.Fields{
		"tunnel_id":   tunnelID,
		"retry_count": pending.Retries,
	}).Error("Tunnel build failed permanently after all retries")

	return oops.Wrapf(buildErr, "tunnel build failed after %d retries", pending.Retries)
}

// retryBuild attempts to retry a failed tunnel build with exponential backoff.
func (rp *ReplyProcessor) retryBuild(tunnelID buildrecord.TunnelID, pending *PendingBuildRequest) error {
	if rp.retryCallback == nil {
		log.WithFields(logger.Fields{"at": "retryBuild"}).Warn("No retry callback configured, cannot retry tunnel build")
		return oops.Errorf("retry not available")
	}

	// Advance retry state before scheduling so max retry enforcement and
	// exponential backoff are based on actual attempt number.
	pending.Retries++
	retryAttempt := pending.Retries

	// Calculate backoff delay with exponential increase
	backoffDelay := rp.config.RetryBackoff * time.Duration(1<<(retryAttempt-1))

	log.WithFields(logger.Fields{
		"tunnel_id":     tunnelID,
		"retry_count":   retryAttempt,
		"backoff_delay": backoffDelay.Seconds(),
	}).Debug("Scheduling tunnel build retry")

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

	return nil
}

// handleBuildTimeout handles tunnel build timeout events.
func (rp *ReplyProcessor) handleBuildTimeout(tunnelID buildrecord.TunnelID) {
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

	expired := rp.collectExpiredBuilds(now, maxAge)
	rp.removeExpiredBuilds(expired)

	if len(expired) > 0 {
		log.WithField("expired_count", len(expired)).Warn("Cleaned up expired tunnel builds")
	}

	return len(expired)
}

// collectExpiredBuilds identifies builds that have exceeded the maximum age.
func (rp *ReplyProcessor) collectExpiredBuilds(now time.Time, maxAge time.Duration) []buildrecord.TunnelID {
	var expired []buildrecord.TunnelID

	for id, pending := range rp.pendingBuilds {
		if now.Sub(pending.RequestedAt) > maxAge {
			expired = append(expired, id)
			if pending.TimeoutTimer != nil {
				pending.TimeoutTimer.Stop()
			}
		}
	}

	return expired
}

// removeExpiredBuilds deletes expired builds from the pending builds map.
func (rp *ReplyProcessor) removeExpiredBuilds(expired []buildrecord.TunnelID) {
	for _, id := range expired {
		delete(rp.pendingBuilds, id)
	}
}

// GetPendingBuildCount returns the number of currently pending tunnel builds.
// It is useful for monitoring how many builds are in flight at once.
// See also [ReplyProcessor].
func (rp *ReplyProcessor) GetPendingBuildCount() int {
	rp.mutex.RLock()
	defer rp.mutex.RUnlock()
	return len(rp.pendingBuilds)
}

// GetPendingBuildInfo returns information about a specific pending build.
// It exposes the retry count and direction for a build so callers can
// inspect build state without triggering processing.
// Returns nil if the build is not found.
// See also [PendingBuildRequest].
func (rp *ReplyProcessor) GetPendingBuildInfo(tunnelID buildrecord.TunnelID) *PendingBuildRequest {
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

	log.WithFields(logger.Fields{"at": "Stop"}).Debug("ReplyProcessor stopped, all pending timers cancelled")
}
