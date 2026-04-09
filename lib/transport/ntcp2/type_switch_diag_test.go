package ntcp2

import (
	"testing"

	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/go-i2p/go-i2p/lib/transport"
)

// trackedSessionSim simulates the trackedSession wrapper from transport/multi.go.
// The real trackedSession is unexported, so we replicate its structure.
type trackedSessionSim struct {
	transport.TransportSession
}

func (t *trackedSessionSim) Unwrap() transport.TransportSession {
	return t.TransportSession
}

// TestDiag_RegisterNewSession_TypeSwitchWithoutUnwrap proves that without
// unwrapping, a *trackedSession wrapping an *NTCP2Session does NOT match
// case *NTCP2Session in a type switch.
func TestDiag_RegisterNewSession_TypeSwitchWithoutUnwrap(t *testing.T) {
	// We can't create a real NTCP2Session without a connection, but we can
	// test the type-switch mechanics using the actual NTCP2Session type.
	// Create a nil-valued *NTCP2Session — type switch tests dynamic type, not value.
	var realSession *NTCP2Session

	// Verify: bare *NTCP2Session matches the type switch
	var asI2NP i2np.I2NPTransportSession = realSession
	switch asI2NP.(type) {
	case *NTCP2Session:
		t.Log("PASS: bare *NTCP2Session matches type switch")
	default:
		t.Fatal("bare *NTCP2Session should match type switch")
	}

	// Now wrap it like TransportMuxer does
	wrapped := &trackedSessionSim{TransportSession: realSession}
	var wrappedI2NP i2np.I2NPTransportSession = wrapped

	// Test WITHOUT unwrapping (the pre-fix code path)
	switch wrappedI2NP.(type) {
	case *NTCP2Session:
		t.Fatal("UNEXPECTED: wrapped session should NOT match *NTCP2Session without unwrapping")
	default:
		t.Log("CONFIRMED BUG: type switch on wrapped session hits default (pre-fix behavior)")
		t.Logf("  concrete type: %T", wrappedI2NP)
	}

	// Test WITH unwrapping (the fix in HEAD commit bcd30b1cb)
	type unwrapper interface {
		Unwrap() transport.TransportSession
	}
	if uw, ok := wrappedI2NP.(unwrapper); ok {
		if inner, ok := uw.Unwrap().(i2np.I2NPTransportSession); ok {
			wrappedI2NP = inner
		}
	}

	switch wrappedI2NP.(type) {
	case *NTCP2Session:
		t.Log("FIX VERIFIED: after unwrapping, *NTCP2Session matches type switch")
	default:
		t.Fatalf("UNEXPECTED: unwrapped session should match, got %T", wrappedI2NP)
	}
}
