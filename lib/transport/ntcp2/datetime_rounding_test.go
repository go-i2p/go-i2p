package ntcp2

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-i2p/go-i2p/lib/transport"
)

// TestNewDateTimeBlockRoundsToNearestSecond locks ntcp2.rst:1491 "Implementations
// must round to the nearest second to prevent clock bias in the network". The
// block must carry the rounded value, not the truncated one.
func TestNewDateTimeBlockRoundsToNearestSecond(t *testing.T) {
	before := time.Now()
	blk := NewDateTimeBlock()
	after := time.Now()

	require.Equal(t, BlockTypeDateTime, blk.Type)
	require.Len(t, blk.Data, 4, "ntcp2.rst:1487 DateTime block size = 4")

	got := binary.BigEndian.Uint32(blk.Data)

	// Whatever the clock's sub-second position, the emitted value must equal the
	// nearest-second rounding of some instant inside the measured window.
	lo := transport.RoundUnixSeconds(before)
	hi := transport.RoundUnixSeconds(after)
	assert.GreaterOrEqual(t, got, lo, "timestamp below the rounded lower bound")
	assert.LessOrEqual(t, got, hi, "timestamp above the rounded upper bound")

	// Direct proof that the block is not the truncated value when the clock sits
	// in the upper half of a second.
	if frac := float64(before.Nanosecond()) / float64(time.Second); frac >= 0.51 && frac <= 0.99 {
		assert.Equal(t, uint32(before.Unix())+1, got,
			"clock at %0.2f s into the second must round up", frac)
	}
}
