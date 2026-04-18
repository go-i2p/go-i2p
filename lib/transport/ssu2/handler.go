package ssu2

import (
	"math"
	"sync"
	"time"

	ssu2noise "github.com/go-i2p/go-noise/ssu2"
)

// SSU2Handler defines callback hooks for injecting I2P-specific behaviour
// into the SSU2 transport layer. The go-noise/ssu2 library handles the
// low-level Noise protocol mechanics; this interface allows the router
// transport to add higher-level concerns: replay detection, timestamp
// validation, and termination.
type SSU2Handler interface {
	// CheckReplay checks whether an ephemeral key has been seen before.
	// Returns true if the key is a replay and the connection should be rejected.
	CheckReplay(ephemeralKey [32]byte) bool

	// ValidateTimestamp checks whether a peer's timestamp is within the
	// allowed clock skew tolerance. Returns a non-nil error if the skew
	// exceeds the tolerance.
	ValidateTimestamp(peerTime uint32) error

	// SendTermination sends a termination block through the SSU2 connection.
	SendTermination(conn *ssu2noise.SSU2Conn, reason byte) error
}

// DefaultHandler implements SSU2Handler with replay detection and clock skew
// validation suitable for production use. A background goroutine periodically
// evicts stale entries from the replay cache to prevent unbounded memory growth.
// Call Close() when the handler is no longer needed to stop the cleanup goroutine.
type DefaultHandler struct {
	mu      sync.Mutex
	seen    map[[32]byte]time.Time
	maxSkew time.Duration
	done    chan struct{}
}

// replayTTL is the time-to-live for replay cache entries (2× clock skew tolerance).
// Set to 60 s (2 × 30 s tolerance) to match the narrowed clock skew window.
const replayTTL = 60 * time.Second

// replayCleanupInterval is how often the background goroutine sweeps stale entries.
const replayCleanupInterval = 5 * time.Minute

// NewDefaultHandler creates a new DefaultHandler with ±60 second clock skew tolerance.
// We use ±30 s to narrow the post-restart replay window; see AUDIT.md.
// A background goroutine evicts replay cache entries older than 60 seconds every
// 5 minutes. Call Close() to stop it.
func NewDefaultHandler() *DefaultHandler {
	log.Debug("creating SSU2 default handler")
	h := &DefaultHandler{
		seen:    make(map[[32]byte]time.Time),
		maxSkew: 30 * time.Second,
		done:    make(chan struct{}),
	}
	go h.cleanupLoop()
	return h
}

// cleanupLoop periodically removes stale entries from the replay cache.
func (h *DefaultHandler) cleanupLoop() {
	ticker := time.NewTicker(replayCleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-h.done:
			return
		case <-ticker.C:
			h.evictStale()
		}
	}
}

// evictStale removes replay cache entries older than replayTTL.
func (h *DefaultHandler) evictStale() {
	cutoff := time.Now().Add(-replayTTL)
	h.mu.Lock()
	defer h.mu.Unlock()
	for k, ts := range h.seen {
		if ts.Before(cutoff) {
			delete(h.seen, k)
		}
	}
}

// CheckReplay checks whether an ephemeral key has been seen before.
// Returns true if the key is a duplicate (replay attack).
func (h *DefaultHandler) CheckReplay(ephemeralKey [32]byte) bool {
	h.mu.Lock()
	defer h.mu.Unlock()

	if _, exists := h.seen[ephemeralKey]; exists {
		log.Warn("SSU2 replay attack detected: duplicate ephemeral key")
		return true
	}

	h.seen[ephemeralKey] = time.Now()
	return false
}

// ValidateTimestamp checks whether a peer's timestamp is within ±60 seconds
// of the local clock.
func (h *DefaultHandler) ValidateTimestamp(peerTime uint32) error {
	now := uint32(time.Now().Unix())
	var diff uint32
	if now > peerTime {
		diff = now - peerTime
	} else {
		diff = peerTime - now
	}
	if diff > uint32(math.Round(h.maxSkew.Seconds())) {
		log.WithFields(map[string]interface{}{
			"peer_time":    peerTime,
			"local_time":   now,
			"diff_seconds": diff,
			"max_skew":     h.maxSkew.Seconds(),
		}).Warn("SSU2 peer clock skew exceeds tolerance")
		return WrapSSU2Error(
			ErrHandshakeFailed,
			"clock skew too large",
		)
	}
	return nil
}

// SendTermination sends a termination block through the SSU2 connection.
func (h *DefaultHandler) SendTermination(conn *ssu2noise.SSU2Conn, reason byte) error {
	log.WithField("reason", reason).Debug("sending SSU2 termination block")
	block := buildTerminationBlock(reason)
	_, err := conn.Write(block)
	if err != nil {
		log.WithError(err).WithField("reason", reason).Warn("failed to send SSU2 termination block")
	}
	return err
}

// buildTerminationBlock constructs a termination block payload for SSU2.
// Block type 6, 9 bytes of data per SSU2 spec.
func buildTerminationBlock(reason byte) []byte {
	// Block format: type (1) + length (2) + data (9)
	// Data: seconds connected (4) + padding (4) + reason (1)
	block := make([]byte, 12)
	block[0] = 6 // BlockTypeTermination
	block[1] = 0
	block[2] = 9 // 9 bytes data
	// Seconds connected (4 bytes) - zeroed for immediate termination
	// Padding (4 bytes) - zeroed
	block[11] = reason
	return block
}

// Close stops the background cleanup goroutine and resets the replay cache.
func (h *DefaultHandler) Close() {
	log.Debug("closing SSU2 handler replay cache")
	select {
	case <-h.done:
		// already closed
	default:
		close(h.done)
	}
	h.mu.Lock()
	h.seen = make(map[[32]byte]time.Time)
	h.mu.Unlock()
}

// ReplayCacheSize returns the current number of entries in the replay cache.
func (h *DefaultHandler) ReplayCacheSize() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.seen)
}
