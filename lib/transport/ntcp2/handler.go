package ntcp2

import (
	"net"

	gonoise "github.com/go-i2p/go-noise/ntcp2"
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

	// SendTermination sends an encrypted termination block through the NTCP2
	// connection's Noise cipher state. The block is encrypted and framed by
	// conn.Write, ensuring no plaintext termination data appears on the wire.
	//
	// For AEAD failure reasons (reason 4), this must NOT be called because
	// the cipher state may be corrupted. Use OnHandshakeError instead.
	SendTermination(conn *gonoise.NTCP2Conn, reason byte) error
}

// DefaultHandler implements NTCP2Handler using the existing functions in this
// package. It is wired into the NTCP2Transport at construction time.
type DefaultHandler struct {
	replayCache *ReplayCache
}

// NewDefaultHandler creates a new DefaultHandler with a fresh replay cache.
// Call Close() on the handler when it is no longer needed to stop the
// background cache cleanup goroutine.
func NewDefaultHandler() *DefaultHandler {
	return &DefaultHandler{
		replayCache: NewReplayCache(),
	}
}

// OnHandshakeError applies probing resistance (random delay + junk read) on the
// raw TCP connection. This makes handshake failures indistinguishable from a
// random TCP service to an active prober.
func (h *DefaultHandler) OnHandshakeError(rawConn net.Conn, err error) {
	applyProbingResistance(rawConn)
}

// CheckReplay checks whether an ephemeral key has been seen before using the
// shared replay cache. Returns true if the key is a duplicate (replay attack).
func (h *DefaultHandler) CheckReplay(ephemeralKey [32]byte) bool {
	return h.replayCache.CheckAndAdd(ephemeralKey)
}

// ValidateTimestamp checks whether a peer's timestamp is within ±60 seconds
// of the local clock. Returns a *ClockSkewError if the skew is excessive.
func (h *DefaultHandler) ValidateTimestamp(peerTime uint32) error {
	return ValidateTimestamp(peerTime)
}

// SendTermination constructs and sends an encrypted termination block through
// the NTCP2 connection's Noise cipher. The block is written via conn.Write,
// which applies AEAD encryption and SipHash length obfuscation.
func (h *DefaultHandler) SendTermination(conn *gonoise.NTCP2Conn, reason byte) error {
	block := BuildTerminationBlock(reason)
	_, err := conn.Write(block)
	return err
}

// Close releases resources held by the handler (stops replay cache cleanup).
func (h *DefaultHandler) Close() {
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
