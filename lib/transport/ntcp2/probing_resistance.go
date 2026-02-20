package ntcp2

import (
	"io"
	"math/big"
	"net"
	"time"

	"github.com/go-i2p/crypto/rand"
)

// Probing-resistance constants per the NTCP2 specification.
//
// Spec reference: https://geti2p.net/spec/ntcp2#probing-resistance
//
// When an AEAD failure occurs during the handshake phase, the responder (Bob)
// should set a random timeout and then read a random number of bytes before
// closing the socket. This prevents an active prober from distinguishing an
// NTCP2 listener from a random TCP service by timing how quickly the connection
// closes after sending a malformed message 1.
const (
	// probingResistanceMaxDelay is the maximum random delay (in milliseconds)
	// before closing a connection on handshake failure. Per spec, Bob should
	// "set a random timeout" — we use 0–2000ms.
	probingResistanceMaxDelay = 2000

	// probingResistanceMaxJunkBytes is the maximum number of random bytes to
	// read from the connection before closing. Per spec, Bob should "read a
	// random number of bytes" — we use 0–1024.
	probingResistanceMaxJunkBytes = 1024
)

// applyProbingResistance implements the NTCP2 probing-resistance behaviour for
// handshake-phase failures. It applies a random delay, then reads a random
// number of junk bytes from the connection before returning. The caller is
// responsible for closing the connection afterward.
//
// This MUST be called on both the responder (Bob) and initiator (Alice) side
// so that both sides are indistinguishable in their failure behaviour.
//
// The function is a no-op if rawConn is nil.
func applyProbingResistance(rawConn net.Conn) {
	if rawConn == nil {
		return
	}

	logger := log.WithField("component", "probing_resistance")

	// 1. Apply random delay (0 to probingResistanceMaxDelay ms)
	delay := randomDuration(probingResistanceMaxDelay)
	logger.WithField("delay_ms", delay.Milliseconds()).Debug("Applying probing resistance delay")
	time.Sleep(delay)

	// 2. Read random number of junk bytes (0 to probingResistanceMaxJunkBytes)
	junkSize := randomInt(probingResistanceMaxJunkBytes + 1)
	if junkSize > 0 {
		logger.WithField("junk_bytes", junkSize).Debug("Reading junk bytes for probing resistance")

		// Set a read deadline so we don't block indefinitely if the prober
		// has already closed their end of the connection.
		_ = rawConn.SetReadDeadline(time.Now().Add(delay + 500*time.Millisecond))

		junkBuf := make([]byte, junkSize)
		// io.ReadFull may return early if the peer closes; that's fine.
		_, _ = io.ReadFull(rawConn, junkBuf)
	}

	logger.Debug("Probing resistance applied")
}

// randomDuration returns a random duration between 0 and maxMs milliseconds.
func randomDuration(maxMs int) time.Duration {
	if maxMs <= 0 {
		return 0
	}
	ms := randomInt(maxMs + 1)
	return time.Duration(ms) * time.Millisecond
}

// randomInt returns a cryptographically random integer in [0, max).
// Falls back to 0 if crypto/rand fails (should never happen in practice).
func randomInt(max int) int {
	if max <= 0 {
		return 0
	}
	n, err := rand.CryptoInt(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		// crypto/rand failure is fatal in practice, but we degrade gracefully
		// here to avoid panicking in a network error handler.
		return 0
	}
	return int(n.Int64())
}

// extractRawConn extracts the raw TCP net.Conn from a net.Conn that may be
// wrapped by go-noise layers. It tries, in order:
//  1. If the conn has an Underlying() net.Conn method (noise.NoiseConn), call it.
//  2. Otherwise, use the conn directly.
//
// This is needed because after a failed handshake the Noise-layer conn may
// already be in an unusable state, but the raw TCP conn is still open and
// we need to perform the junk-read on it.
func extractRawConn(conn net.Conn) net.Conn {
	// Try to get the underlying raw TCP connection.
	// The go-noise library's NoiseConn has an Underlying() method.
	type underlying interface {
		Underlying() net.Conn
	}
	if u, ok := conn.(underlying); ok {
		return u.Underlying()
	}
	return conn
}
