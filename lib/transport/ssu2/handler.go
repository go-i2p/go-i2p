package ssu2

import (
	"time"

	"github.com/go-i2p/go-i2p/lib/transport"
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
// validation suitable for production use. The replay cache is managed by the
// embedded BaseHandler. Call Close() when the handler is no longer needed to stop
// the cleanup goroutine.
type DefaultHandler struct {
	*transport.BaseHandler
	maxSkew time.Duration
}

// NewDefaultHandler creates a new DefaultHandler with the shared transport
// clock skew tolerance (currently ±60 seconds, matching NTCP2).
// The replay cache is managed by the embedded BaseHandler.
// Call Close() to clean up resources when the handler is no longer needed.
func NewDefaultHandler() *DefaultHandler {
	log.Debug("creating SSU2 default handler")
	return &DefaultHandler{
		BaseHandler: transport.NewBaseHandler(),
		maxSkew:     transport.ClockSkewTolerance,
	}
}

// ValidateTimestamp checks whether a peer's timestamp is within the configured
// clock skew tolerance of the local clock. Returns nil if valid, or a wrapped
// SSU2Error if the clock skew is excessive.
func (h *DefaultHandler) ValidateTimestamp(peerTime uint32) error {
	// H3 FIX: Reject peerTime=0. The I2P spec requires timestamps in handshake messages.
	// Treating zero as "not provided" creates a replay vulnerability.
	if peerTime == 0 {
		log.WithFields(map[string]interface{}{
			"at":            "(SSU2 DefaultHandler) ValidateTimestamp",
			"reason":        "peer_time_missing",
			"phase":         "handshake",
			"session_state": "pre_auth",
			"transport":     "ssu2",
		}).Warn("SSU2 handshake rejected: peerTime is zero (required by spec)")
		return WrapSSU2Error(
			ErrHandshakeFailed,
			"peerTime is zero (required by I2P spec)",
		)
	}

	return transport.ValidateTimestampAndLog(peerTime, h.validateClockSkew, func(peerTime uint32, _ error) {
		now := uint32(time.Now().Unix())
		skewSeconds := transport.CalculateTimestampSkew(peerTime, now)
		log.WithFields(map[string]interface{}{
			"at":            "(SSU2 DefaultHandler) ValidateTimestamp",
			"reason":        "clock_skew_exceeded",
			"phase":         "handshake",
			"session_state": "pre_auth",
			"transport":     "ssu2",
			"peer_time":     peerTime,
			"local_time":    now,
			"diff_seconds":  absInt64(skewSeconds),
			"max_skew":      h.maxSkew.Seconds(),
		}).Warn("SSU2 peer clock skew exceeds tolerance")
	})
}

func (h *DefaultHandler) validateClockSkew(peerTime uint32) error {
	if !transport.IsTimestampWithinTolerance(peerTime, h.maxSkew) {
		return WrapSSU2Error(
			ErrHandshakeFailed,
			"clock skew too large",
		)
	}
	return nil
}

func absInt64(v int64) float64 {
	if v < 0 {
		return float64(-v)
	}
	return float64(v)
}

// SendTermination sends a termination block through the SSU2 connection and
// closes it, so the peer learns why the connection is ending.
//
// The Termination block format (ssu2.rst §"Termination") is block type 6 with
// data = valid data packets received (8 bytes, big endian) + reason (1 byte) +
// optional additional data, carried inside an encrypted Data packet. That
// framing is owned by the upstream connection, so this delegates to
// (*SSU2Conn).CloseWithReason rather than assembling a block by hand.
//
// An earlier implementation here wrote a plaintext 12-byte
// type(1)+len(2)+seconds(4)+padding(4)+reason(1) buffer straight to the socket.
// That layout is SSU1's, not SSU2's, and it also skipped the Data-packet
// encryption entirely, so no peer could have parsed it.
func (h *DefaultHandler) SendTermination(conn *ssu2noise.SSU2Conn, reason byte) error {
	log.WithField("reason", reason).Debug("sending SSU2 termination block")
	err := conn.CloseWithReason(ssu2noise.TerminationReason(reason), nil)
	if err != nil {
		log.WithError(err).WithFields(map[string]interface{}{
			"at":             "(SSU2 DefaultHandler) SendTermination",
			"reason":         "termination_write_failed",
			"phase":          "teardown",
			"session_state":  "closing",
			"transport":      "ssu2",
			"termination_id": reason,
		}).Warn("failed to send SSU2 termination block")
	}
	return err
}
