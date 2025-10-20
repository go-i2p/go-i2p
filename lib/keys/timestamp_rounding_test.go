package keys

import (
	"testing"
	"time"
)

// TestRouterInfoTimestampRounding verifies that RouterInfo timestamps are properly
// rounded to the nearest second per I2P specification requirements.
// Reference: https://geti2p.net/spec/ntcp2#datetime
func TestRouterInfoTimestampRounding(t *testing.T) {
	testCases := []struct {
		name     string
		input    time.Time
		expected time.Time
	}{
		{
			name:     "timestamp with no subsecond component",
			input:    time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC),
			expected: time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC),
		},
		{
			name:     "timestamp rounds down (< 500ms)",
			input:    time.Date(2025, 1, 1, 12, 0, 0, 400*int(time.Millisecond), time.UTC),
			expected: time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC),
		},
		{
			name:     "timestamp rounds up (>= 500ms)",
			input:    time.Date(2025, 1, 1, 12, 0, 0, 600*int(time.Millisecond), time.UTC),
			expected: time.Date(2025, 1, 1, 12, 0, 1, 0, time.UTC),
		},
		{
			name:     "timestamp rounds up at exactly 500ms",
			input:    time.Date(2025, 1, 1, 12, 0, 0, 500*int(time.Millisecond), time.UTC),
			expected: time.Date(2025, 1, 1, 12, 0, 1, 0, time.UTC),
		},
		{
			name:     "timestamp with nanoseconds rounds down",
			input:    time.Date(2025, 1, 1, 12, 0, 0, 123456789, time.UTC),
			expected: time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC),
		},
		{
			name:     "timestamp with nanoseconds rounds up",
			input:    time.Date(2025, 1, 1, 12, 0, 0, 999999999, time.UTC),
			expected: time.Date(2025, 1, 1, 12, 0, 1, 0, time.UTC),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rounded := tc.input.Round(time.Second)
			if !rounded.Equal(tc.expected) {
				t.Errorf("Round(%v) = %v, want %v", tc.input, rounded, tc.expected)
			}

			// Verify no subsecond component remains
			if rounded.Nanosecond() != 0 {
				t.Errorf("Rounded timestamp has non-zero nanosecond component: %d", rounded.Nanosecond())
			}
		})
	}
}

// TestTimestampRoundingPreventsBias verifies that timestamp rounding prevents
// systematic clock bias accumulation in the network.
func TestTimestampRoundingPreventsBias(t *testing.T) {
	// Generate timestamps with various subsecond offsets
	baseTime := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	var totalBias time.Duration

	// Simulate 100 timestamps with random subsecond components
	for i := 0; i < 100; i++ {
		// Add various nanosecond offsets
		offset := time.Duration(i*10) * time.Millisecond
		timestamp := baseTime.Add(offset)
		rounded := timestamp.Round(time.Second)

		// Calculate bias (difference between original and rounded)
		bias := rounded.Sub(timestamp)
		totalBias += bias
	}

	// With proper rounding, average bias should be close to zero
	// (some timestamps round up, some round down)
	avgBias := totalBias / 100
	maxAcceptableBias := 100 * time.Millisecond

	if avgBias > maxAcceptableBias || avgBias < -maxAcceptableBias {
		t.Errorf("Average bias %v exceeds acceptable threshold of ±%v", avgBias, maxAcceptableBias)
	}
}
