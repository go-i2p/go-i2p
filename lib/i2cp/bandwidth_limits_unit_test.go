package i2cp

import (
	"encoding/binary"
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fixedBandwidthProvider struct{ in, out uint32 }

func (p fixedBandwidthProvider) GetBandwidthLimits() (uint32, uint32) { return p.in, p.out }

// TestWBandwidthLimitsReportsKBps locks i2cp.rst:497-502, which labels the
// inbound and outbound limits "(KBps)". The provider reports bytes per second
// (lib/config/router.go:72), so a raw pass-through overstates every limit 1024x
// and clients derive a wildly optimistic throughput budget from it.
func TestBandwidthLimitsWireUnitIsKBps(t *testing.T) {
	server := newTestI2CPServer(t, "")
	const bytesPerSec = 3200 * 1024 // 3200 KBps
	server.SetBandwidthProvider(fixedBandwidthProvider{in: bytesPerSec, out: bytesPerSec})

	msg := &Message{Type: MessageTypeGetBandwidthLimits, SessionID: 7}
	resp, err := server.handleGetBandwidthLimits(msg)
	require.NoError(t, err, "handleGetBandwidthLimits() error")
	require.NotNil(t, resp)
	require.Len(t, resp.Payload, 64, "BandwidthLimits is 16 uint32 values")

	inbound := binary.BigEndian.Uint32(resp.Payload[0:4])
	outbound := binary.BigEndian.Uint32(resp.Payload[4:8])
	assert.Equal(t, uint32(3200), inbound, "bytes 0-3 must be the inbound limit in KBps")
	assert.Equal(t, uint32(3200), outbound, "bytes 4-7 must be the outbound limit in KBps")
	assert.NotEqual(t, uint32(bytesPerSec), inbound,
		"must not report the raw byte-per-second rate")

	// Undefined fields stay zero per i2cp.rst:504 "Nine 4-byte [Integer]_ (undefined)".
	for i := 8; i < 64; i++ {
		require.Equal(t, byte(0), resp.Payload[i], "byte %d must be zero-filled", i)
	}
}

// TestBandwidthLimitsUnlimitedSentinelSurvivesConversion checks that the
// provider's math.MaxUint32 "unlimited" marker is forwarded instead of divided
// into a large but finite-looking number.
func TestBandwidthLimitsUnlimitedSentinelSurvivesConversion(t *testing.T) {
	server := newTestI2CPServer(t, "")
	server.SetBandwidthProvider(fixedBandwidthProvider{in: math.MaxUint32, out: math.MaxUint32})

	resp, err := server.handleGetBandwidthLimits(&Message{Type: MessageTypeGetBandwidthLimits})
	require.NoError(t, err)
	assert.Equal(t, uint32(math.MaxUint32), binary.BigEndian.Uint32(resp.Payload[0:4]),
		"unlimited must not be divided down into a finite value")
	assert.Equal(t, uint32(math.MaxUint32), binary.BigEndian.Uint32(resp.Payload[4:8]))
}

// TestBytesPerSecToKBps covers the conversion boundary cases.
func TestBytesPerSecToKBps(t *testing.T) {
	cases := []struct{ in, want uint32 }{
		{0, 0},
		{1024, 1},
		{1535, 1}, // 1.499 KBps rounds down, not up
		{1536, 2}, // exactly half rounds up
		{2559, 2}, // 2.499 KBps rounds down
		{2048, 2},
		{math.MaxUint32, math.MaxUint32},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, bytesPerSecToKBps(tc.in), "bytesPerSec=%d", tc.in)
	}
}
