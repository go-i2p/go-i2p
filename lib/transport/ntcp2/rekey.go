package ntcp2

import (
	"sync/atomic"
)

// RekeyThreshold is the number of messages (sent + received) after which
// a session should be rekeyed for forward secrecy. Per the NTCP2 specification,
// rekeying should occur periodically. 65535 messages is a conservative threshold
// (just under 2^16) that balances forward secrecy with performance.
const RekeyThreshold uint64 = 65535

// Rekeyer is an interface for connections that support cryptographic rekeying.
// This is a forward-compatible interface: the underlying go-noise library's
// NTCP2Conn or NoiseConn does not currently expose Rekey(), but when it does,
// this interface will allow automatic integration.
//
// Implementations must be safe for concurrent use.
type Rekeyer interface {
	// Rekey replaces the session's encryption key using the Noise protocol's
	// rekeying mechanism (encrypt 32 zero bytes with nonce 2^64-1, use first
	// 32 bytes as new key). Both send and receive cipher states should be rekeyed.
	Rekey() error
}

// rekeyState tracks message counts and rekeying state for an NTCP2 session.
type rekeyState struct {
	// messagesSent is the total number of messages sent since last rekey
	messagesSent uint64 // atomic
	// messagesReceived is the total number of messages received since last rekey
	messagesReceived uint64 // atomic
	// rekeyCount is the total number of rekeys performed on this session
	rekeyCount uint64 // atomic
}

// newRekeyState creates a new rekeying state tracker.
func newRekeyState() *rekeyState {
	return &rekeyState{}
}

// recordSent increments the sent message counter and returns the new total
// messages (sent + received) since last rekey.
func (rs *rekeyState) recordSent() uint64 {
	sent := atomic.AddUint64(&rs.messagesSent, 1)
	received := atomic.LoadUint64(&rs.messagesReceived)
	return sent + received
}

// recordReceived increments the received message counter and returns the new
// total messages (sent + received) since last rekey.
func (rs *rekeyState) recordReceived() uint64 {
	received := atomic.AddUint64(&rs.messagesReceived, 1)
	sent := atomic.LoadUint64(&rs.messagesSent)
	return sent + received
}

// resetCounters resets the message counters after a successful rekey.
func (rs *rekeyState) resetCounters() {
	atomic.StoreUint64(&rs.messagesSent, 0)
	atomic.StoreUint64(&rs.messagesReceived, 0)
	atomic.AddUint64(&rs.rekeyCount, 1)
}

// totalMessages returns the total messages (sent + received) since last rekey.
func (rs *rekeyState) totalMessages() uint64 {
	return atomic.LoadUint64(&rs.messagesSent) + atomic.LoadUint64(&rs.messagesReceived)
}

// getRekeyCount returns the total number of rekeys performed.
func (rs *rekeyState) getRekeyCount() uint64 {
	return atomic.LoadUint64(&rs.rekeyCount)
}

// needsRekey returns true if the message count has reached the rekey threshold.
func (rs *rekeyState) needsRekey() bool {
	return rs.totalMessages() >= RekeyThreshold
}

// attemptRekey tries to rekey the connection if it implements the Rekeyer interface.
// Returns true if rekeying was performed, false if the connection does not support it.
// If the connection does not implement Rekeyer, this is a no-op (forward-compatible:
// once go-noise exposes Rekey() on NTCP2Conn or NoiseConn, this will automatically work).
func attemptRekey(conn interface{}, rs *rekeyState, logger interface {
	WithField(string, interface{}) interface{ Debug(string) }
}) bool {
	rekeyer, ok := conn.(Rekeyer)
	if !ok {
		// Connection does not support rekeying yet.
		// This is expected until go-noise exposes the Rekey method.
		// Reset counters to avoid checking on every message.
		rs.resetCounters()
		return false
	}

	err := rekeyer.Rekey()
	if err != nil {
		// Log the error but don't fail the session — rekeying is best-effort.
		// The session remains usable with the current keys.
		log.WithField("error", err.Error()).Warn("NTCP2 session rekeying failed, continuing with current keys")
		rs.resetCounters()
		return false
	}

	rs.resetCounters()
	return true
}
