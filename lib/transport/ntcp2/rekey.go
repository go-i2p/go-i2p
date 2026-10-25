package ntcp2

import (
	"sync/atomic"
)

// RekeyThreshold is the number of messages (sent + received) after which a
// session is torn down and re-established with a fresh Noise handshake.
//
// NTCP2 defines NO in-band, mid-session symmetric rekey. The spec's "rekey"
// refers to rotating the router's static key / IV (a RouterInfo-level change
// at startup), not renegotiating the keys of a live data-phase session. See
// ntcp2.rst "Public Key and IV Rotation".
//
// The go-noise Conn.Rekey() helper only rotates the *local* cipher and does
// not reset the nonce counters or signal the peer, so calling it mid-session
// desynchronises the two peers and breaks AEAD. Its own documentation says a
// connection "near its nonce limit should be replaced with a new one".
//
// The compliant way to bound key/nonce lifetime is therefore to terminate the
// session once it has carried RekeyThreshold messages; the transport
// transparently re-dials (NTCP2Transport.GetSession re-establishes on demand).
// 65535 messages is a conservative threshold (just under 2^16) that balances
// forward secrecy against connection churn.
//
// The go-noise library exposes the authoritative signal for the same
// conclusion — Conn.NonceExhaustionImminent(), documented as "the right
// response is to open a new connection rather than keep using this one" — at
// MaxNonce-1000. This message-count bound is far stricter than that, so it
// always fires first and the nonce limit is never approached.
const RekeyThreshold uint64 = 65535

// rekeyState tracks per-session message counts and whether a threshold-based
// replacement has already been triggered. It replaces the previous in-band
// rekeying mechanism (the Rekeyer interface and attemptRekey), which was not
// spec-compliant for NTCP2.
//
// All counters are updated with atomics so the concurrent send and receive
// workers can record traffic without locking.
type rekeyState struct {
	// messagesSent is the number of messages sent over this session.
	messagesSent uint64 // atomic
	// messagesReceived is the number of messages received over this session.
	messagesReceived uint64 // atomic
	// replacementCount is the number of times the threshold triggered a
	// session replacement. Within a single session this is at most 1, but it
	// is tracked so stats callers can see that a replacement was requested.
	replacementCount uint64 // atomic
	// replacementTriggered is a 0/1 flag set via CAS so that, even if both
	// workers cross the threshold simultaneously, only one replacement (and
	// therefore one close) is scheduled.
	replacementTriggered uint64 // atomic
}

// newRekeyState creates a new message-count tracker.
func newRekeyState() *rekeyState {
	return &rekeyState{}
}

// recordSent increments the sent message counter and returns the new total
// messages (sent + received) for the session.
func (rs *rekeyState) recordSent() uint64 {
	sent := atomic.AddUint64(&rs.messagesSent, 1)
	received := atomic.LoadUint64(&rs.messagesReceived)
	return sent + received
}

// recordReceived increments the received message counter and returns the new
// total messages (sent + received) for the session.
func (rs *rekeyState) recordReceived() uint64 {
	received := atomic.AddUint64(&rs.messagesReceived, 1)
	sent := atomic.LoadUint64(&rs.messagesSent)
	return sent + received
}

// totalMessages returns the total messages (sent + received) for the session.
func (rs *rekeyState) totalMessages() uint64 {
	return atomic.LoadUint64(&rs.messagesSent) + atomic.LoadUint64(&rs.messagesReceived)
}

// getReplacementCount returns the number of threshold-triggered replacements.
func (rs *rekeyState) getReplacementCount() uint64 {
	return atomic.LoadUint64(&rs.replacementCount)
}

// needsReplacement returns true if the message count has reached the
// replacement threshold.
func (rs *rekeyState) needsReplacement() bool {
	return rs.totalMessages() >= RekeyThreshold
}

// tryTriggerReplacement atomically claims the one-shot replacement trigger.
// It returns true for the single caller that wins the race (and should
// therefore schedule the session teardown) and increments the replacement
// count. Concurrent callers that lose the race receive false and take no
// action, guaranteeing exactly one replacement per session.
func (rs *rekeyState) tryTriggerReplacement() bool {
	if !atomic.CompareAndSwapUint64(&rs.replacementTriggered, 0, 1) {
		return false
	}
	atomic.AddUint64(&rs.replacementCount, 1)
	return true
}
