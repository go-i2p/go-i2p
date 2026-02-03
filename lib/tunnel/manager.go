package tunnel

import (
	"fmt"
	"sync"
	"time"

	"github.com/go-i2p/logger"
)

// Manager coordinates all tunnel operations including participant tracking.
// It manages the lifecycle of tunnels where this router acts as an intermediate hop.
//
// Design decisions:
// - Separate tracking for participants (where we relay) vs owned tunnels (where we originate)
// - Automatic cleanup of expired participant tunnels
// - Thread-safe concurrent access
// - Simple map-based storage for O(1) lookup
type Manager struct {
	// participants tracks tunnels where this router is an intermediate hop
	participants map[TunnelID]*Participant
	mu           sync.RWMutex

	// stopChan signals the cleanup goroutine to stop
	stopChan chan struct{}
	// wg tracks background goroutines
	wg sync.WaitGroup
}

// NewManager creates a new tunnel manager.
// Starts a background goroutine to clean up expired participants.
func NewManager() *Manager {
	m := &Manager{
		participants: make(map[TunnelID]*Participant),
		stopChan:     make(chan struct{}),
	}

	// Start background cleanup routine
	m.wg.Add(1)
	go m.cleanupLoop()

	log.WithFields(logger.Fields{
		"at":               "NewManager",
		"phase":            "tunnel_build",
		"reason":           "tunnel manager initialized",
		"cleanup_interval": "60s",
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
			"action":    "replacing",
		}).Warn("participant already exists, replacing")
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

	now := time.Now()
	var expired []TunnelID
	var idle []TunnelID

	for id, p := range m.participants {
		if p.IsExpired(now) {
			expired = append(expired, id)
		} else if p.IsIdle(now) {
			idle = append(idle, id)
		}
	}

	for _, id := range expired {
		delete(m.participants, id)
	}

	for _, id := range idle {
		delete(m.participants, id)
	}

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
//
// This should be called during router shutdown.
func (m *Manager) Stop() {
	log.WithFields(logger.Fields{
		"at":     "Manager.Stop",
		"reason": "shutdown_requested",
	}).Info("stopping tunnel manager")
	close(m.stopChan)
	m.wg.Wait()

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
