package ntcp2

import (
	"net"

	"github.com/go-i2p/go-i2p/lib/transport"
)

// NTCP2Handler defines callback hooks for injecting I2P-specific behaviour
// into the NTCP2 transport layer. The go-noise library handles the low-level
// Noise protocol mechanics; this interface allows the router transport to add
// higher-level concerns: probing resistance, replay detection, timestamp
// validation, and encrypted termination.
//
// Implementations must be safe for concurrent use across multiple goroutines.
type NTCP2Handler interface {
	// OnHandshakeError is called when a Noise XK handshake fails (either as
	// initiator or responder). The implementation should apply probing
	// resistance (random delay + junk read) on the raw TCP connection before
	// the connection is closed.
	//
	// rawConn is the underlying TCP connection; it may be nil if extraction
	// failed. The error is the original handshake failure reason.
	OnHandshakeError(rawConn net.Conn, err error)

	// CheckReplay checks whether an ephemeral key (the first 32 bytes of
	// message 1) has been seen before. Returns true if the key is a replay
	// and the connection should be rejected.
	//
	// The replay cache must be shared across all listener goroutines within
	// a single router instance.
	CheckReplay(ephemeralKey [32]byte) bool

	// ValidateTimestamp checks whether a peer's timestamp (Unix epoch seconds)
	// is within the allowed clock skew tolerance. Returns a non-nil error if
	// the skew exceeds the tolerance.
	ValidateTimestamp(peerTime uint32) error
}

// DefaultHandler implements NTCP2Handler using the existing functions in this
// package. It is wired into the NTCP2Transport at construction time.
// The replay cache is managed by the embedded BaseHandler.
type DefaultHandler struct {
	*transport.BaseHandler
}

// NewDefaultHandler creates a new DefaultHandler with a fresh replay cache.
// Call Close() on the handler when it is no longer needed to stop the
// background cache cleanup goroutine.
func NewDefaultHandler() *DefaultHandler {
	log.Debug("creating NTCP2 default handler")
	return &DefaultHandler{
		BaseHandler: transport.NewBaseHandler(),
	}
}

// OnHandshakeError applies probing resistance (random delay + junk read) on the
// raw TCP connection. This makes handshake failures indistinguishable from a
// random TCP service to an active prober.
func (h *DefaultHandler) OnHandshakeError(rawConn net.Conn, err error) {
	log.WithError(err).Debug("NTCP2 handshake error, applying probing resistance")
	applyProbingResistance(rawConn)
}

// ValidateTimestamp checks whether a peer's timestamp is within ±60 seconds
// of the local clock. Returns a *ClockSkewError if the skew is excessive.
func (h *DefaultHandler) ValidateTimestamp(peerTime uint32) error {
	return transport.ValidateTimestampAndLog(peerTime, ValidateTimestamp, func(peerTime uint32, err error) {
		log.WithFields(map[string]interface{}{
			"at":            "(NTCP2 DefaultHandler) ValidateTimestamp",
			"reason":        "clock_skew_exceeded",
			"phase":         "handshake",
			"session_state": "pre_auth",
			"transport":     "ntcp2",
			"peer_time":     peerTime,
			"error":         err.Error(),
		}).Warn("NTCP2 peer clock skew exceeds tolerance")
	})
}
