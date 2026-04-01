package i2cp

import (
	"sync"

	"github.com/go-i2p/common/destination"
	"github.com/go-i2p/crypto/rand"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// SessionManager manages all active I2CP sessions
type SessionManager struct {
	mu       sync.RWMutex
	sessions map[uint16]*Session // Session ID -> Session
}

// NewSessionManager creates a new session manager
func NewSessionManager() *SessionManager {
	return &SessionManager{
		sessions: make(map[uint16]*Session),
	}
}

// CreateSession creates a new session with the given destination and config.
// Optional private keys (signingPrivKey, encryptionPrivKey) can be provided
// to preserve the client's persistent identity across sessions.
func (sm *SessionManager) CreateSession(dest *destination.Destination, config *SessionConfig, privKeys ...interface{}) (*Session, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Allocate session ID
	sessionID, err := sm.allocateSessionID()
	if err != nil {
		log.WithFields(logger.Fields{
			"at":             "i2cp.SessionManager.CreateSession",
			"activeSessions": len(sm.sessions),
		}).Error("no_available_session_ids")
		return nil, err
	}

	// Create session with its own isolated in-memory NetDB
	session, err := NewSession(sessionID, dest, config, privKeys...)
	if err != nil {
		log.WithFields(logger.Fields{
			"at":        "i2cp.SessionManager.CreateSession",
			"sessionID": sessionID,
			"error":     err.Error(),
		}).Error("failed_to_create_session")
		return nil, err
	}

	// Register session
	sm.sessions[sessionID] = session

	log.WithFields(logger.Fields{
		"at":             "i2cp.SessionManager.CreateSession",
		"sessionID":      sessionID,
		"activeSessions": len(sm.sessions),
	}).Info("session_registered")

	return session, nil
}

// GetSession retrieves a session by ID
func (sm *SessionManager) GetSession(sessionID uint16) (*Session, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	session, ok := sm.sessions[sessionID]
	return session, ok
}

// DestroySession removes and stops a session
func (sm *SessionManager) DestroySession(sessionID uint16) error {
	sm.mu.Lock()
	session, ok := sm.sessions[sessionID]
	if !ok {
		sm.mu.Unlock()
		log.WithFields(logger.Fields{
			"at":        "i2cp.SessionManager.DestroySession",
			"sessionID": sessionID,
		}).Warn("session_not_found")
		return oops.Errorf("session %d not found", sessionID)
	}

	delete(sm.sessions, sessionID)
	remainingCount := len(sm.sessions)
	sm.mu.Unlock()

	log.WithFields(logger.Fields{
		"at":                "i2cp.SessionManager.DestroySession",
		"sessionID":         sessionID,
		"remainingSessions": remainingCount,
	}).Info("session_destroyed")

	// Stop session (outside lock to prevent deadlock)
	session.Stop()

	return nil
}

// SessionCount returns the number of active sessions
func (sm *SessionManager) SessionCount() int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return len(sm.sessions)
}

// GetAllSessions returns a copy of all active sessions
func (sm *SessionManager) GetAllSessions() []*Session {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	sessions := make([]*Session, 0, len(sm.sessions))
	for _, session := range sm.sessions {
		sessions = append(sessions, session)
	}
	return sessions
}

// RemoveSession removes a session from the manager without stopping it
func (sm *SessionManager) RemoveSession(sessionID uint16) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	delete(sm.sessions, sessionID)
}

// allocateSessionID finds the next available session ID using cryptographic randomness
// to prevent session ID prediction attacks. Must be called with sm.mu locked.
//
// For low occupancy (<90%), uses random probing (up to 100 attempts).
// For high occupancy (≥90%), falls back to sequential scan from a random offset
// to guarantee finding an available ID if one exists.
// allocateSessionID picks an unused session ID from the available space.
// Uses random probing under normal load, and sequential scanning
// when occupancy exceeds 90%.
func (sm *SessionManager) allocateSessionID() (uint16, error) {
	activeCount := len(sm.sessions)
	usableIDs := uint32(65536 - 2) // exclude the two reserved IDs

	if uint32(activeCount) >= usableIDs*9/10 {
		return sm.allocateSequentialScan(activeCount)
	}
	return sm.allocateRandomProbe(activeCount)
}

// allocateSequentialScan performs a linear scan from a random offset to find
// a free session ID. Used when occupancy is above 90% and random probing
// would be inefficient.
func (sm *SessionManager) allocateSequentialScan(activeCount int) (uint16, error) {
	startID, err := generateSecureSessionID()
	if err != nil {
		startID = uint16(activeCount) // fallback to deterministic offset
	}
	for offset := uint32(0); offset < 65536; offset++ {
		id := uint16((uint32(startID) + offset) % 65536)
		if id == SessionIDReservedControl || id == SessionIDReservedBroadcast {
			continue
		}
		if _, exists := sm.sessions[id]; !exists {
			return id, nil
		}
	}
	return 0, oops.Errorf("session ID space exhausted (%d active sessions)", activeCount)
}

// allocateRandomProbe picks a free session ID by generating random candidates.
// Used under normal load when collisions are unlikely.
func (sm *SessionManager) allocateRandomProbe(activeCount int) (uint16, error) {
	maxAttempts := 100
	for attempt := 0; attempt < maxAttempts; attempt++ {
		id, err := generateSecureSessionID()
		if err != nil {
			log.WithFields(logger.Fields{
				"at":      "allocateSessionID",
				"attempt": attempt,
				"error":   err.Error(),
			}).Warn("failed to generate random session ID")
			continue
		}
		if id == SessionIDReservedControl || id == SessionIDReservedBroadcast {
			continue
		}
		if _, exists := sm.sessions[id]; !exists {
			return id, nil
		}
	}

	log.WithFields(logger.Fields{
		"at":             "allocateSessionID",
		"activeSessions": activeCount,
		"maxAttempts":    maxAttempts,
	}).Error("failed to allocate session ID after maximum attempts")
	return 0, oops.Errorf("failed to allocate session ID after %d attempts (%d active sessions)", maxAttempts, activeCount)
}

// generateSecureSessionID generates a cryptographically random 16-bit session ID
func generateSecureSessionID() (uint16, error) {
	var buf [2]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return 0, oops.Errorf("failed to read random bytes: %w", err)
	}

	// Convert bytes to uint16 (big-endian)
	id := uint16(buf[0])<<8 | uint16(buf[1])
	return id, nil
}

// StopAll stops all active sessions
func (sm *SessionManager) StopAll() {
	sm.mu.Lock()
	sessions := make([]*Session, 0, len(sm.sessions))
	for _, session := range sm.sessions {
		sessions = append(sessions, session)
	}
	sm.sessions = make(map[uint16]*Session)
	sm.mu.Unlock()

	// Stop all sessions outside lock
	for _, session := range sessions {
		session.Stop()
	}
}
