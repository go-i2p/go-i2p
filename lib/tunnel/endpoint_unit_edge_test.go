package tunnel

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestProcessInstructionLoop_ZeroLengthFragment verifies that a delivery
// instruction with FragmentSize()==0 does NOT cause an infinite loop.
// Before the fix, data = remainder[0:] would never advance, spinning forever.
func TestProcessInstructionLoop_ZeroLengthFragment(t *testing.T) {
	ep := &Endpoint{
		handler:         func(msgBytes []byte) error { return nil },
		fragments:       make(map[uint32]*fragmentAssembler),
		fragmentTimeout: 60 * time.Second,
	}

	// Construct a LOCAL first-fragment delivery instruction with fragmentSize == 0.
	// Byte layout for a LOCAL first fragment (no delay, not fragmented, no ext opts):
	//   byte 0: flag = 0x00  (bit7=0 → FIRST_FRAGMENT, bits6:5=00 → LOCAL)
	//   bytes 1-2: fragmentSize = 0x0000
	// Append extra bytes so remainder is non-empty, which would trigger the
	// infinite loop in the original code.
	data := []byte{
		0x00,       // flag: FIRST_FRAGMENT, DT_LOCAL, no delay/frag/ext
		0x00, 0x00, // fragmentSize = 0
		0xFF, 0xFF, 0xFF, // extra bytes (would cause infinite loop without fix)
	}

	// This should return an error, NOT spin forever.
	done := make(chan error, 1)
	go func() {
		done <- ep.processInstructionLoop(data)
	}()

	select {
	case err := <-done:
		require.Error(t, err, "should return error for zero-length fragment")
		assert.ErrorIs(t, err, ErrInvalidTunnelData)
	case <-time.After(2 * time.Second):
		t.Fatal("processInstructionLoop did not return within 2s — infinite loop detected")
	}
}

// TestProcessInstructionLoop_ValidFragment verifies that a valid non-zero
// fragment is processed normally (no false positives from the zero-length check).
func TestProcessInstructionLoop_ValidFragment(t *testing.T) {
	var delivered []byte
	ep := &Endpoint{
		handler: func(msgBytes []byte) error {
			delivered = append(delivered, msgBytes...)
			return nil
		},
		fragments:       make(map[uint32]*fragmentAssembler),
		fragmentTimeout: 60 * time.Second,
	}

	// Construct a LOCAL first-fragment delivery instruction with fragmentSize == 5.
	// Byte layout:
	//   byte 0:   flag = 0x00  (FIRST_FRAGMENT, DT_LOCAL)
	//   bytes 1-2: fragmentSize = 0x0005
	//   bytes 3-7: fragment data (5 bytes)
	data := []byte{
		0x00,       // flag
		0x00, 0x05, // fragmentSize = 5
		0x41, 0x42, 0x43, 0x44, 0x45, // fragment data: "ABCDE"
	}

	done := make(chan error, 1)
	go func() {
		done <- ep.processInstructionLoop(data)
	}()

	select {
	case err := <-done:
		assert.NoError(t, err)
		assert.Equal(t, []byte{0x41, 0x42, 0x43, 0x44, 0x45}, delivered,
			"handler should receive the 5-byte fragment")
	case <-time.After(2 * time.Second):
		t.Fatal("processInstructionLoop did not return within 2s")
	}
}
