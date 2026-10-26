package transport

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRoundUnixSecondsRoundsToNearest locks the "must round to the nearest
// second" rule from ntcp2.rst:1491 and ssu2.rst:2836. Truncation with
// uint32(t.Unix()) always discards the sub-second remainder, biasing every
// timestamp we emit up to a full second into the past.
func TestRoundUnixSecondsRoundsToNearest(t *testing.T) {
	base := time.Date(2026, 3, 14, 7, 0, 0, 0, time.UTC)
	epoch := base.Unix()

	tests := []struct {
		name string
		sub  time.Duration
		want int64
	}{
		{"exact second", 0, 0},
		{"just under half", 499 * time.Millisecond, 0},
		{"exactly half rounds up", 500 * time.Millisecond, 1},
		{"three quarters", 750 * time.Millisecond, 1},
		{"just under next second", 999 * time.Millisecond, 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := RoundUnixSeconds(base.Add(tc.sub))
			require.Equal(t, uint64(epoch)+uint64(tc.want), uint64(got),
				"sub=%s must round to the nearest second", tc.sub)
		})
	}

	// The regression itself: a .75s timestamp must report the ceiling, which is
	// what uint32(Unix()) refuses to do.
	biased := base.Add(750 * time.Millisecond)
	assert.NotEqual(t, uint32(biased.Unix()), RoundUnixSeconds(biased),
		"rounding must differ from truncation for sub-second times")
	assert.Equal(t, uint32(biased.Unix())+1, RoundUnixSeconds(biased))
}

// TestRoundUnixSecondsHandlesNow sanity-checks the helper against wall-clock
// time in both directions of the half-second boundary.
func TestRoundUnixSecondsHandlesNow(t *testing.T) {
	now := time.Now()
	got := RoundUnixSeconds(now)
	want := uint32(now.Round(time.Second).Unix())
	assert.Equal(t, want, got)
	assert.LessOrEqual(t, int64(got)-int64(now.Unix()), int64(1),
		"rounded value may be at most one second ahead of the truncated value")
}
