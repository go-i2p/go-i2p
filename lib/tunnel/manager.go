package tunnel

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/session_key"
	"github.com/go-i2p/crypto/rand"
	"github.com/go-i2p/crypto/tunnel"
	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/go-i2p/logger"
)

// Build reply codes per I2P specification (TUNNEL-CREATION)
const (
	BuildReplyCodeAccepted            = 0  // Tunnel accepted
	BuildReplyCodeProbabilisticReject = 10 // Rejected: probabilistic reject
	BuildReplyCodeTransientOverload   = 20 // Rejected: transient overload
	BuildReplyCodeBandwidth           = 30 // Rejected: bandwidth limit (used for most rejections)
	BuildReplyCodeCritical            = 50 // Rejected: critical (router shutdown, etc.)
)

// Manager coordinates all tunnel operations including participant tracking.
// It manages the lifecycle of tunnels where this router acts as an intermediate hop.
//
// Design decisions:
// - Separate tracking for participants (where we relay) vs owned tunnels (where we originate)
// - Automatic cleanup of expired participant tunnels
// - Thread-safe concurrent access
// - Simple map-based storage for O(1) lookup
// - Configurable participation limits to protect against resource exhaustion
// - Per-source rate limiting to prevent single-source flooding
type Manager struct {
	// participants tracks tunnels where this router is an intermediate hop
	participants map[TunnelID]*Participant
	mu           sync.RWMutex

	// Participation limits (resource exhaustion protection)
	maxParticipants int  // Hard limit on participating tunnels
	limitsEnabled   bool // Whether limits are enforced

	// Per-source rate limiting
	sourceLimiter        *SourceLimiter // Rate limiter for per-source limiting
	sourceLimiterEnabled bool           // Whether per-source limiting is enabled

	// Rejection statistics (atomic for lock-free access)
	rejectCountTotal  uint64 // Total rejections due to limits
	rejectCountRecent uint64 // Recent rejections (reset periodically)

	// stopChan signals the cleanup goroutine to stop
	stopChan chan struct{}
	// stopOnce ensures Stop() is idempotent and safe to call multiple times
	stopOnce sync.Once
	// wg tracks background goroutines
	wg sync.WaitGroup
}

// NewManager creates a new tunnel manager with default configuration.
// Starts a background goroutine to clean up expired participants.
// For custom limits, use NewManagerWithConfig instead.
func NewManager() *Manager {
	return NewManagerWithConfig(config.Defaults().Tunnel)
}

// NewManagerWithConfig creates a new tunnel manager with the specified configuration.
// This allows customizing participation limits and other tunnel settings.
//
// Parameters:
// - cfg: TunnelDefaults containing limit configuration
//
// The manager will start a background cleanup goroutine automatically.
// If per-source rate limiting is enabled, a SourceLimiter will also be created.
func NewManagerWithConfig(cfg config.TunnelDefaults) *Manager {
	maxParticipants := cfg.MaxParticipatingTunnels
	if maxParticipants <= 0 {
		maxParticipants = 2000 // Sensible default if unset or zero
		log.WithField("default_max", maxParticipants).Info("MaxParticipatingTunnels was zero, using default")
	}
	m := &Manager{
		participants:         make(map[TunnelID]*Participant),
		maxParticipants:      maxParticipants,
		limitsEnabled:        cfg.ParticipatingLimitsEnabled,
		sourceLimiterEnabled: cfg.PerSourceRateLimitEnabled,
		stopChan:             make(chan struct{}),
	}

	// Initialize per-source rate limiter if enabled
	if cfg.PerSourceRateLimitEnabled {
		m.sourceLimiter = NewSourceLimiterWithConfig(cfg)
	}

	// Start background cleanup routine
	m.wg.Add(1)
	go m.cleanupLoop()

	log.WithFields(logger.Fields{
		"at":                     "NewManagerWithConfig",
		"phase":                  "tunnel_build",
		"reason":                 "tunnel manager initialized",
		"cleanup_interval":       "60s",
		"max_participants":       m.maxParticipants,
		"limits_enabled":         m.limitsEnabled,
		"soft_limit":             m.softLimit(),
		"source_limiter_enabled": m.sourceLimiterEnabled,
	}).Info("tunnel manager started")
	return m
}

// AddParticipant registers a new participant tunnel.
// This is called when this router accepts a tunnel build request
// and agrees to relay traffic as an intermediate hop.
//
// Parameters:
// - p: the participant tunnel to track
//
// Returns an error if the participant is nil or already exists.
func (m *Manager) AddParticipant(p *Participant) error {
	if p == nil {
		log.WithFields(logger.Fields{
			"at":     "Manager.AddParticipant",
			"phase":  "tunnel_build",
			"reason": "nil_participant_rejected",
		}).Error("cannot add nil participant")
		return fmt.Errorf("cannot add nil participant")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	tunnelID := p.TunnelID()
	if _, exists := m.participants[tunnelID]; exists {
		log.WithFields(logger.Fields{
			"at":        "Manager.AddParticipant",
			"phase":     "tunnel_build",
			"reason":    "duplicate_tunnel_id",
			"tunnel_id": tunnelID,
		}).Warn("participant already exists, rejecting duplicate")
		return fmt.Errorf("participant with tunnel ID %d already exists", tunnelID)
	}

	m.participants[tunnelID] = p
	log.WithFields(logger.Fields{
		"at":                "Manager.AddParticipant",
		"phase":             "tunnel_build",
		"reason":            "registered_for_relay",
		"tunnel_id":         tunnelID,
		"participant_count": len(m.participants),
	}).Debug("added participant tunnel")

	return nil
}

// RemoveParticipant removes a participant tunnel by its tunnel ID.
// This is called when a tunnel expires or is no longer needed.
//
// Returns true if the participant was found and removed, false otherwise.
func (m *Manager) RemoveParticipant(tunnelID TunnelID) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.participants[tunnelID]; exists {
		delete(m.participants, tunnelID)
		log.WithFields(logger.Fields{
			"at":        "Manager.RemoveParticipant",
			"reason":    "cleanup_or_expiry",
			"tunnel_id": tunnelID,
		}).Debug("removed participant tunnel")
		return true
	}

	log.WithFields(logger.Fields{
		"at":        "Manager.RemoveParticipant",
		"reason":    "not_found",
		"tunnel_id": tunnelID,
	}).Debug("participant tunnel not found for removal")
	return false
}

// GetParticipant retrieves a participant tunnel by its ID.
// Returns nil if no participant exists with the given ID.
//
// This is used when processing incoming TunnelData messages to find
// the appropriate participant to handle decryption and forwarding.
func (m *Manager) GetParticipant(tunnelID TunnelID) *Participant {
	m.mu.RLock()
	defer m.mu.RUnlock()

	participant := m.participants[tunnelID]
	if participant == nil {
		log.WithFields(logger.Fields{
			"at":        "Manager.GetParticipant",
			"reason":    "not_found",
			"tunnel_id": tunnelID,
		}).Debug("participant tunnel not found")
	}
	return participant
}

// ParticipantCount returns the current number of participant tunnels.
// This is useful for monitoring and statistics.
func (m *Manager) ParticipantCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return len(m.participants)
}

// MaxParticipants returns the maximum allowed number of participant tunnels.
// This is the hard limit used for congestion monitoring (PROP_162).
func (m *Manager) MaxParticipants() int {
	return m.maxParticipants
}

// softLimit returns 50% of maxParticipants.
// This is always derived, not independently configured.
// Probabilistic rejection starts at the soft limit.
func (m *Manager) softLimit() int {
	return m.maxParticipants / 2
}

// CanAcceptParticipant checks if we can accept a new participating tunnel.
// This implements a two-tier rejection system:
// 1. Soft limit (50% of max): probabilistic rejection starts, increasing toward hard limit
// 2. Hard limit (max): always reject
//
// The probabilistic rejection uses dynamic scaling:
// - From soft limit to critical threshold (last 100): 50% → 90% rejection
// - In critical zone (last 100 tunnels): 90% → 100% rejection
//
// Returns:
// - canAccept: true if the tunnel build request should be accepted
// - reason: human-readable reason if rejected (empty string if accepted)
func (m *Manager) CanAcceptParticipant() (bool, string) {
	if !m.limitsEnabled {
		return true, ""
	}

	m.mu.RLock()
	count := len(m.participants)
	m.mu.RUnlock()

	if rejected, reason := m.checkHardLimit(count); rejected {
		return false, reason
	}

	if rejected, reason := m.checkSoftLimit(count); rejected {
		return false, reason
	}

	return true, ""
}

// checkHardLimit verifies if we've reached the maximum participant count.
// Returns (rejected, reason) where rejected is true if at hard limit.
func (m *Manager) checkHardLimit(count int) (bool, string) {
	if count < m.maxParticipants {
		return false, ""
	}

	atomic.AddUint64(&m.rejectCountTotal, 1)
	atomic.AddUint64(&m.rejectCountRecent, 1)
	log.WithFields(logger.Fields{
		"at":                "Manager.CanAcceptParticipant",
		"phase":             "tunnel_build",
		"reason":            "hard_limit_reached",
		"participant_count": count,
		"max_participants":  m.maxParticipants,
	}).Debug("rejecting tunnel build: hard limit reached")
	return true, "hard_limit_reached"
}

// checkSoftLimit applies probabilistic rejection based on current load.
// Returns (rejected, reason) where rejected is true if probabilistically rejected.
func (m *Manager) checkSoftLimit(count int) (bool, string) {
	softLimitValue := m.softLimit()
	if count < softLimitValue {
		return false, ""
	}

	rejectProb := m.calculateRejectProbability(count, softLimitValue)

	if rand.Float64() < rejectProb {
		atomic.AddUint64(&m.rejectCountTotal, 1)
		atomic.AddUint64(&m.rejectCountRecent, 1)
		log.WithFields(logger.Fields{
			"at":                 "Manager.CanAcceptParticipant",
			"phase":              "tunnel_build",
			"reason":             "soft_limit_probabilistic_reject",
			"participant_count":  count,
			"soft_limit":         softLimitValue,
			"reject_probability": rejectProb,
		}).Debug("rejecting tunnel build: soft limit probabilistic rejection")
		return true, "soft_limit_probabilistic_reject"
	}

	return false, ""
}

// calculateRejectProbability computes the rejection probability based on load.
// Uses dynamic scaling with a critical zone for the last 100 tunnels.
func (m *Manager) calculateRejectProbability(count, softLimitValue int) float64 {
	criticalThreshold := m.maxParticipants - 100
	if criticalThreshold < softLimitValue {
		criticalThreshold = softLimitValue
	}

	if count >= criticalThreshold {
		return m.calculateCriticalZoneProbability(count, criticalThreshold)
	}
	return m.calculateNormalZoneProbability(count, softLimitValue, criticalThreshold)
}

// calculateCriticalZoneProbability returns rejection probability for critical zone (90% → 100%).
func (m *Manager) calculateCriticalZoneProbability(count, criticalThreshold int) float64 {
	criticalRange := float64(m.maxParticipants - criticalThreshold)
	if criticalRange > 0 {
		criticalRatio := float64(count-criticalThreshold) / criticalRange
		return 0.90 + (0.10 * criticalRatio)
	}
	return 0.95
}

// calculateNormalZoneProbability returns rejection probability for soft limit zone (50% → 90%).
func (m *Manager) calculateNormalZoneProbability(count, softLimitValue, criticalThreshold int) float64 {
	normalRange := float64(criticalThreshold - softLimitValue)
	if normalRange > 0 {
		normalRatio := float64(count-softLimitValue) / normalRange
		return 0.50 + (0.40 * normalRatio)
	}
	return 0.70
}

// GetRejectStats returns the current rejection statistics.
// Returns total rejections and recent rejections since last reset.
func (m *Manager) GetRejectStats() (total, recent uint64) {
	return atomic.LoadUint64(&m.rejectCountTotal), atomic.LoadUint64(&m.rejectCountRecent)
}

// ResetRecentRejectCount resets the recent rejection counter.
// This is typically called periodically for monitoring purposes.
func (m *Manager) ResetRecentRejectCount() {
	atomic.StoreUint64(&m.rejectCountRecent, 0)
}

// GetLimitConfig returns the current participation limit configuration.
// Returns maxParticipants, softLimit, and whether limits are enabled.
func (m *Manager) GetLimitConfig() (maxParticipants, softLimit int, limitsEnabled bool) {
	return m.maxParticipants, m.softLimit(), m.limitsEnabled
}

// ProcessBuildRequest validates a tunnel build request against all limits.
// This should be called before accepting any participating tunnel.
//
// Parameters:
// - sourceHash: The router hash of the requester (from BuildRequestRecord.OurIdent)
//
// Returns:
// - accepted: Whether the request should be accepted
// - rejectCode: I2P-compliant rejection code if not accepted (0 if accepted)
// - reason: Human-readable reason for logging (empty if accepted)
//
// Note: Per I2P specification, we use BuildReplyCodeBandwidth (30) for most
// rejections to hide the specific rejection reason from peers.
func (m *Manager) ProcessBuildRequest(sourceHash common.Hash) (accepted bool, rejectCode byte, reason string) {
	// Check 1: Global participating tunnel limit
	if canAccept, limitReason := m.CanAcceptParticipant(); !canAccept {
		log.WithFields(logger.Fields{
			"at":                "Manager.ProcessBuildRequest",
			"phase":             "tunnel_build",
			"source":            truncateHash(sourceHash),
			"reason":            limitReason,
			"action":            "reject_build_request",
			"participant_count": m.ParticipantCount(),
		}).Warn("rejecting tunnel build request due to global limit")

		// Use BANDWIDTH to hide specific rejection reason per I2P spec
		return false, BuildReplyCodeBandwidth, limitReason
	}

	// Check 2: Per-source rate limiting (if enabled)
	if m.sourceLimiter != nil && m.sourceLimiterEnabled {
		if allowed, rateReason := m.sourceLimiter.AllowRequest(sourceHash); !allowed {
			log.WithFields(logger.Fields{
				"at":     "Manager.ProcessBuildRequest",
				"phase":  "tunnel_build",
				"source": truncateHash(sourceHash),
				"reason": rateReason,
				"action": "reject_build_request",
			}).Warn("rejecting tunnel build request due to rate limit")

			// Use BANDWIDTH to hide specific rejection reason per I2P spec
			return false, BuildReplyCodeBandwidth, rateReason
		}
	}

	return true, 0, ""
}

// RegisterParticipant creates and registers a new participating tunnel.
// This is called after ProcessBuildRequest returns accepted=true.
//
// Parameters:
// - tunnelID: The tunnel ID for the participating tunnel
// - sourceHash: The router hash of the requester (used for tracking)
// - expiry: When the tunnel participation expires
//
// Returns an error if registration fails.
//
// The layerKey and ivKey are extracted from the BuildRequestRecord and used
// to create the AES encryptor for tunnel layer decryption.
func (m *Manager) RegisterParticipant(tunnelID TunnelID, sourceHash common.Hash, expiry time.Time, layerKey, ivKey session_key.SessionKey) error {
	// Calculate lifetime from expiry
	lifetime := time.Until(expiry)
	if lifetime <= 0 {
		return fmt.Errorf("tunnel expiry is in the past")
	}

	// Create the tunnel decryption using the layer and IV keys from the build request
	// Convert session_key.SessionKey to tunnel.TunnelKey (both are [32]byte)
	var tunnelLayerKey, tunnelIVKey tunnel.TunnelKey
	copy(tunnelLayerKey[:], layerKey[:])
	copy(tunnelIVKey[:], ivKey[:])

	decryption, err := tunnel.NewAESEncryptor(tunnelLayerKey, tunnelIVKey)
	if err != nil {
		return fmt.Errorf("failed to create tunnel decryption: %w", err)
	}

	// Create the participant with proper decryption
	participant := &Participant{
		tunnelID:     tunnelID,
		createdAt:    time.Now(),
		lifetime:     lifetime,
		lastActivity: time.Now(),
		idleTimeout:  DefaultIdleTimeout,
		decryption:   decryption,
	}

	// Add to tracking
	err = m.AddParticipant(participant)
	if err != nil {
		return fmt.Errorf("failed to add participant: %w", err)
	}

	log.WithFields(logger.Fields{
		"at":          "Manager.RegisterParticipant",
		"phase":       "tunnel_build",
		"tunnel_id":   tunnelID,
		"source_hash": fmt.Sprintf("%x", sourceHash[:8]),
		"lifetime":    lifetime,
	}).Info("registered participating tunnel")

	return nil
}

// GetSourceLimiterStats returns statistics about per-source rate limiting.
// Returns nil if source limiting is not enabled.
func (m *Manager) GetSourceLimiterStats() *SourceLimiterStats {
	if m.sourceLimiter == nil {
		return nil
	}
	stats := m.sourceLimiter.GetStats()
	return &stats
}

// TunnelLimitStats provides visibility into protection mechanisms.
type TunnelLimitStats struct {
	// Global limits
	CurrentParticipants    int
	MaxParticipants        int
	SoftLimitParticipants  int // Always 50% of MaxParticipants
	GlobalRejectionsTotal  uint64
	GlobalRejectionsRecent uint64

	// Per-source limits (nil if not enabled)
	SourceLimiter *SourceLimiterStats

	// Health indicators
	AtSoftLimit bool
	AtHardLimit bool
}

// GetLimitStats returns comprehensive statistics about all protection mechanisms.
func (m *Manager) GetLimitStats() TunnelLimitStats {
	current := m.ParticipantCount()
	total, recent := m.GetRejectStats()
	softLimit := m.softLimit()

	stats := TunnelLimitStats{
		CurrentParticipants:    current,
		MaxParticipants:        m.maxParticipants,
		SoftLimitParticipants:  softLimit,
		GlobalRejectionsTotal:  total,
		GlobalRejectionsRecent: recent,
		AtSoftLimit:            current >= softLimit,
		AtHardLimit:            current >= m.maxParticipants,
	}

	if m.sourceLimiter != nil {
		sourceLimiterStats := m.sourceLimiter.GetStats()
		stats.SourceLimiter = &sourceLimiterStats
	}

	return stats
}

// cleanupLoop runs in a background goroutine and periodically
// removes expired participant tunnels.
//
// Design decisions:
// - Runs every 60 seconds (tunnels typically last 10 minutes)
// - Logs statistics about cleaned up tunnels
// - Gracefully stops when stopChan is closed
func (m *Manager) cleanupLoop() {
	defer m.wg.Done()

	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopChan:
			log.WithFields(logger.Fields{
				"at":     "Manager.cleanupLoop",
				"reason": "shutdown_signal",
			}).Debug("tunnel manager cleanup loop stopping")
			return
		case <-ticker.C:
			m.cleanupExpiredParticipants()
		}
	}
}

// cleanupExpiredParticipants removes participant tunnels that have expired or are idle.
// Tunnels are considered expired after their configured lifetime (typically 10 minutes).
// Tunnels are considered idle if no data has been processed within the idle timeout (2 minutes).
// Dropping idle tunnels helps mitigate resource exhaustion attacks where attackers
// request excessive tunnels but send no data through them.
func (m *Manager) cleanupExpiredParticipants() {
	m.mu.Lock()
	defer m.mu.Unlock()

	expired, idle := m.categorizeParticipants()
	m.removeParticipants(expired, idle)
	m.logCleanupResults(expired, idle)
}

// categorizeParticipants separates participants into expired and idle lists.
func (m *Manager) categorizeParticipants() (expired, idle []TunnelID) {
	now := time.Now()
	for id, p := range m.participants {
		if p.IsExpired(now) {
			expired = append(expired, id)
		} else if p.IsIdle(now) {
			idle = append(idle, id)
		}
	}
	return expired, idle
}

// removeParticipants deletes the specified tunnel IDs from the participants map.
func (m *Manager) removeParticipants(expired, idle []TunnelID) {
	for _, id := range expired {
		delete(m.participants, id)
	}
	for _, id := range idle {
		delete(m.participants, id)
	}
}

// logCleanupResults logs information about cleaned up tunnels.
func (m *Manager) logCleanupResults(expired, idle []TunnelID) {
	if len(expired) > 0 {
		log.WithFields(logger.Fields{
			"at":        "Manager.cleanupExpiredParticipants",
			"phase":     "tunnel_build",
			"reason":    "expiry_maintenance",
			"count":     len(expired),
			"remaining": len(m.participants),
		}).Info("cleaned up expired participant tunnels")
	}

	if len(idle) > 0 {
		log.WithFields(logger.Fields{
			"at":        "Manager.cleanupExpiredParticipants",
			"phase":     "tunnel_build",
			"reason":    "idle_tunnel_dropped",
			"count":     len(idle),
			"remaining": len(m.participants),
		}).Warn("dropped idle participant tunnels (potential resource exhaustion attack mitigation)")
	}
}

// Stop gracefully stops the tunnel manager.
// Waits for background goroutines to finish.
// Also stops the source limiter if it was enabled.
//
// This should be called during router shutdown.
func (m *Manager) Stop() {
	log.WithFields(logger.Fields{
		"at":     "Manager.Stop",
		"reason": "shutdown_requested",
	}).Info("stopping tunnel manager")
	m.stopOnce.Do(func() {
		close(m.stopChan)
	})
	m.wg.Wait()

	// Stop the source limiter if it exists
	if m.sourceLimiter != nil {
		m.sourceLimiter.Stop()
	}

	m.mu.Lock()
	participantCount := len(m.participants)
	m.participants = make(map[TunnelID]*Participant)
	m.mu.Unlock()

	log.WithFields(logger.Fields{
		"at":                   "Manager.Stop",
		"reason":               "shutdown_complete",
		"cleared_participants": participantCount,
	}).Info("tunnel manager stopped")
}
