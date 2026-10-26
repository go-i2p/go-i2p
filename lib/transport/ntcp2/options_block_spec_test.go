package ntcp2

import (
	"testing"
	"time"

	"github.com/go-i2p/go-i2p/lib/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A7: the data-phase Options block must be parsed and the spec's 12-byte
// minimum validated (ntcp2.rst:1515 "size of options to follow, 12 bytes
// minimum"). Before this, session.handleNonI2NPBlock logged the block and
// discarded its payload.

func TestA7_ParseOptionsBlock_Layout(t *testing.T) {
	// tmin=0x00 tmax=0x01 rmin=0x02 rmax=0x10 tdmy=1000 rdmy=2000 tdelay=3000 rdelay=4000
	data := []byte{0x00, 0x01, 0x02, 0x10, 0x03, 0xE8, 0x07, 0xD0, 0x0B, 0xB8, 0x0F, 0xA0}
	opts, err := ParseOptionsBlock(data)
	require.NoError(t, err)

	assert.Equal(t, byte(0x00), opts.TransmitMinRatio)
	assert.Equal(t, byte(0x01), opts.TransmitMaxRatio)
	assert.Equal(t, byte(0x02), opts.ReceiveMinRatio)
	assert.Equal(t, byte(0x10), opts.ReceiveMaxRatio)
	assert.Equal(t, uint16(1000), opts.TransmitDummy)
	assert.Equal(t, uint16(2000), opts.ReceiveDummy)
	assert.Equal(t, uint16(3000), opts.TransmitDelay)
	assert.Equal(t, uint16(4000), opts.ReceiveDelay)
	assert.Empty(t, opts.Extra)
}

func TestA7_ParseOptionsBlock_RejectsShortBlock(t *testing.T) {
	// ntcp2.rst:1515 requires 12 bytes minimum; 11 must be rejected.
	for _, size := range []int{0, 1, 8, 11} {
		_, err := ParseOptionsBlock(make([]byte, size))
		require.Error(t, err, "options data of %d bytes must be rejected", size)
	}
	_, err := ParseOptionsBlock(make([]byte, 12))
	require.NoError(t, err, "exactly 12 bytes is the spec minimum")
}

func TestA7_ParseOptionsBlock_PreservesMoreOptions(t *testing.T) {
	// "more_options :: Format TBD" (ntcp2.rst:1542) — preserved, not interpreted.
	data := append([]byte{0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0}, 0xAA, 0xBB)
	opts, err := ParseOptionsBlock(data)
	require.NoError(t, err)
	assert.Equal(t, []byte{0xAA, 0xBB}, opts.Extra)
}

// The 4.4 fixed-point ratio semantics (ntcp2.rst:1522-1528).
func TestA7_RatioToFloat(t *testing.T) {
	assert.InDelta(t, 0.0, RatioToFloat(0x00), 1e-9)    // no padding
	assert.InDelta(t, 0.0625, RatioToFloat(0x01), 1e-9) // ~6 percent
	assert.InDelta(t, 1.0, RatioToFloat(0x10), 1e-9)    // 100 percent
	assert.InDelta(t, 8.0, RatioToFloat(0x80), 1e-9)    // 800 percent
}

// The session receive path must record a valid Options block and survive a
// malformed one without closing the connection (the spec leaves the response
// to options violations implementation-dependent, ntcp2.rst:1530, :1773).
func TestA7_SessionRecordsPeerOptions(t *testing.T) {
	session := newTestSession(t)

	valid := []byte{0x00, 0x01, 0x02, 0x03, 0x00, 0x64, 0x00, 0xC8, 0x01, 0x2C, 0x01, 0x90}
	session.handleNonI2NPBlock(Block{Type: BlockTypeOptions, Data: valid})

	got := session.PeerOptions()
	require.NotNil(t, got, "a valid Options block must be recorded")
	assert.Equal(t, byte(0x01), got.TransmitMaxRatio)
	assert.Equal(t, uint16(100), got.TransmitDummy)

	// Malformed block must not overwrite the last valid options and must not
	// kill the session.
	session.handleNonI2NPBlock(Block{Type: BlockTypeOptions, Data: []byte{1, 2, 3}})
	after := session.PeerOptions()
	require.NotNil(t, after)
	assert.Equal(t, byte(0x01), after.TransmitMaxRatio, "malformed block must not clobber valid options")
}

// A9: the shared skew helper must reject a zero timestamp, matching both
// transports' explicit rejection and ssu2.rst:4036-4039 ("must contain
// DateTime blocks").
func TestA9_IsTimestampWithinToleranceRejectsZero(t *testing.T) {
	assert.False(t, transport.IsTimestampWithinTolerance(0, 60*time.Second),
		"zero timestamp is a missing required DateTime block, not an absent optional field")

	now := uint32(time.Now().Unix())
	assert.True(t, transport.IsTimestampWithinTolerance(now, 60*time.Second))
	assert.False(t, transport.IsTimestampWithinTolerance(now+3600, 60*time.Second))
}
