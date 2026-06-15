package ssu2

import (
	"math"
	"time"

	"github.com/go-i2p/go-i2p/lib/transport"
	gonoise "github.com/go-i2p/go-noise/ntcp2"
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
// validation suitable for production use. The replay cache is managed by go-noise,
// which periodically evicts stale entries to prevent unbounded memory growth.
// Call Close() when the handler is no longer needed to stop the cleanup goroutine.
type DefaultHandler struct {
	replayCache *gonoise.ReplayCache
	maxSkew     time.Duration
}

// NewDefaultHandler creates a new DefaultHandler with ±30 second clock skew tolerance
// (shared with NTCP2 transport). We use ±30 s (narrower than the go-noise default of 60 s)
// to narrow the post-restart replay window; see AUDIT.md.
// The replay cache is managed by go-noise, which periodically evicts stale entries.
// Call Close() to clean up resources when the handler is no longer needed.
func NewDefaultHandler() *DefaultHandler {
	log.Debug("creating SSU2 default handler")
	return &DefaultHandler{
		replayCache: gonoise.NewReplayCache(),
		maxSkew:     transport.ClockSkewTolerance,
	}
}

// CheckReplay checks whether an ephemeral key has been seen before.
// Returns true if the key is a duplicate (replay attack).
func (h *DefaultHandler) CheckReplay(ephemeralKey [32]byte) bool {
	if h.replayCache.CheckAndAdd(ephemeralKey) {
		log.Warn("SSU2 replay attack detected: duplicate ephemeral key")
		return true
	}
	return false
}

// ValidateTimestamp checks whether a peer's timestamp is within the configured
// clock skew tolerance of the local clock. Returns nil if valid, or a wrapped
// SSU2Error if the clock skew is excessive.
func (h *DefaultHandler) ValidateTimestamp(peerTime uint32) error {
	if peerTime == 0 {
		// Timestamp not provided — skip validation.
		return nil
	}

	now := uint32(time.Now().Unix())
	skewSeconds := transport.CalculateTimestampSkew(peerTime, now)

	if !transport.IsTimestampWithinTolerance(peerTime, h.maxSkew) {
		log.WithFields(map[string]interface{}{
			"peer_time":    peerTime,
			"local_time":   now,
			"diff_seconds": math.Abs(float64(skewSeconds)),
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

// Close releases resources held by the handler (stops replay cache cleanup).
func (h *DefaultHandler) Close() {
	log.Debug("closing SSU2 handler replay cache")
	if h.replayCache != nil {
		h.replayCache.Close()
	}
}

// ReplayCacheSize returns the current number of entries in the replay cache.
// Useful for monitoring and diagnostics.
func (h *DefaultHandler) ReplayCacheSize() int {
	if h.replayCache == nil {
		return 0
	}
	return h.replayCache.Size()
}
