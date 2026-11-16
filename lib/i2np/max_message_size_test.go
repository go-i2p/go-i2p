package i2np

import (
	"bytes"
	"testing"
)

// marshalWithPayload builds a valid standard-header I2NP message whose payload
// is exactly payloadLen bytes, so the declared size field equals payloadLen.
func marshalWithPayload(t *testing.T, payloadLen int) []byte {
	t.Helper()
	msg := NewBaseI2NPMessage(I2NPMessageTypeDatabaseStore)
	msg.SetData(bytes.Repeat([]byte{0xAB}, payloadLen))
	out, err := msg.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}
	return out
}

// TestMaxInboundMessageSize_RejectsOversized is the C1 guard for
// transport.max_message_size: an inbound I2NP message whose declared payload
// exceeds the configured cap must be rejected before allocation. Before this
// fix the knob was dead and any size up to the 16-bit field max was accepted.
func TestMaxInboundMessageSize_RejectsOversized(t *testing.T) {
	t.Cleanup(func() { SetMaxInboundMessageSize(0) })

	// 1000-byte payload, cap 500 → reject.
	wire := marshalWithPayload(t, 1000)
	SetMaxInboundMessageSize(500)

	var got BaseI2NPMessage
	if err := got.UnmarshalBinary(wire); err == nil {
		t.Fatal("oversized inbound message should be rejected when max_message_size is set")
	}
}

// TestMaxInboundMessageSize_AcceptsWithinLimit verifies a message at or below
// the cap still parses normally.
func TestMaxInboundMessageSize_AcceptsWithinLimit(t *testing.T) {
	t.Cleanup(func() { SetMaxInboundMessageSize(0) })

	wire := marshalWithPayload(t, 400)
	SetMaxInboundMessageSize(500)

	var got BaseI2NPMessage
	if err := got.UnmarshalBinary(wire); err != nil {
		t.Fatalf("within-limit message should parse, got error: %v", err)
	}
	if len(got.data) != 400 {
		t.Fatalf("payload length = %d, want 400", len(got.data))
	}
}

// TestMaxInboundMessageSize_ZeroMeansNoCap pins that a zero cap (unset config)
// accepts any size, so a default/unset router is unchanged.
func TestMaxInboundMessageSize_ZeroMeansNoCap(t *testing.T) {
	t.Cleanup(func() { SetMaxInboundMessageSize(0) })

	wire := marshalWithPayload(t, 2000)
	SetMaxInboundMessageSize(0)

	var got BaseI2NPMessage
	if err := got.UnmarshalBinary(wire); err != nil {
		t.Fatalf("zero cap must accept any size, got error: %v", err)
	}
}
