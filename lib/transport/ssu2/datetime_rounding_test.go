package ssu2

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-i2p/go-i2p/lib/transport"
)

// TestSSU2NewDateTimeBlockRoundsToNearestSecond locks ssu2.rst:2836 "Implementations
// must round to the nearest second to prevent clock bias in the network."
func TestSSU2NewDateTimeBlockRoundsToNearestSecond(t *testing.T) {
	before := time.Now()
	blk := NewDateTimeBlock()
	after := time.Now()
	require.NotNil(t, blk)
	require.Len(t, blk.Data, 4)

	got := binary.BigEndian.Uint32(blk.Data)
	assert.GreaterOrEqual(t, got, transport.RoundUnixSeconds(before))
	assert.LessOrEqual(t, got, transport.RoundUnixSeconds(after))
}
