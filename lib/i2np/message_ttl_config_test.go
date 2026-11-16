package i2np

import (
	"testing"
	"time"
)

// TestSetOutboundMessageTTL_ReachesNewMessages is the C1 guard for
// router.message_expiration_time: the operator's TTL must be stamped on freshly
// created outbound I2NP messages. Before this fix every message used the
// hardcoded defaultI2NPMessageTTL constant and the knob was dead.
func TestSetOutboundMessageTTL_ReachesNewMessages(t *testing.T) {
	// Restore the package default after the test so other tests are unaffected.
	t.Cleanup(ResetOutboundMessageTTLForTest)

	const want = 7 * time.Second
	SetOutboundMessageTTL(want)

	if got := GetOutboundMessageTTL(); got != want {
		t.Fatalf("GetOutboundMessageTTL() = %v, want %v", got, want)
	}

	msg := NewBaseI2NPMessage(I2NPMessageTypeDatabaseStore)
	// The message expiration should be ~want from now. Allow a small slack for
	// scheduling, and assert it is clearly NOT the 60s default.
	delta := time.Until(msg.Expiration())
	if delta < want-time.Second || delta > want+2*time.Second {
		t.Fatalf("new message expiration delta = %v, want ~%v (knob did not reach message creation)", delta, want)
	}
	if delta > 30*time.Second {
		t.Fatalf("new message expiration delta = %v looks like the 60s default, not the configured %v", delta, want)
	}
}

// TestSetOutboundMessageTTL_ZeroKeepsDefault pins that a non-positive value
// (unset config) leaves the built-in default in effect, so a default-configured
// router is unchanged.
func TestSetOutboundMessageTTL_ZeroKeepsDefault(t *testing.T) {
	t.Cleanup(ResetOutboundMessageTTLForTest)

	SetOutboundMessageTTL(0)
	if got := GetOutboundMessageTTL(); got != defaultI2NPMessageTTL {
		t.Fatalf("zero TTL must keep the built-in default %v, got %v", defaultI2NPMessageTTL, got)
	}

	SetOutboundMessageTTL(-time.Second)
	if got := GetOutboundMessageTTL(); got != defaultI2NPMessageTTL {
		t.Fatalf("negative TTL must keep the built-in default %v, got %v", defaultI2NPMessageTTL, got)
	}
}
