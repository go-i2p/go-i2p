package ssu2

import (
	"math"
	"testing"
	"time"

	"github.com/go-i2p/go-i2p/lib/transport"
	"github.com/stretchr/testify/require"
)

// TestM5_IsTimestampWithinTolerance_Boundary
// M-5 FIX: Centralized timestamp validation.
// Verifies transport.IsTimestampWithinTolerance enforces symmetric ±tolerance bounds consistently.
func TestM5_IsTimestampWithinTolerance_Boundary(t *testing.T) {
	t.Parallel()

	tol := 60 * time.Second

	testCases := []struct {
		name      string
		offsetSec int32 // offset from now (can be negative)
		tolerance time.Duration
		expect    bool // expect within skew?
	}{
		{
			name:      "now exactly",
			offsetSec: 0,
			tolerance: tol,
			expect:    true,
		},
		{
			name:      "exactly +tol",
			offsetSec: int32(math.Round(tol.Seconds())),
			tolerance: tol,
			expect:    true, // boundary is inclusive
		},
		{
			name:      "exactly -tol",
			offsetSec: -int32(math.Round(tol.Seconds())),
			tolerance: tol,
			expect:    true, // boundary is inclusive
		},
		{
			name:      "+tol +1 second (outside)",
			offsetSec: int32(math.Round(tol.Seconds())) + 1,
			tolerance: tol,
			expect:    false,
		},
		{
			name:      "-tol -1 second (outside)",
			offsetSec: -int32(math.Round(tol.Seconds())) - 1,
			tolerance: tol,
			expect:    false,
		},
		{
			name:      "half tolerance future",
			offsetSec: int32(math.Round(tol.Seconds())) / 2,
			tolerance: tol,
			expect:    true,
		},
		{
			name:      "half tolerance past",
			offsetSec: -int32(math.Round(tol.Seconds())) / 2,
			tolerance: tol,
			expect:    true,
		},
	}

	now := uint32(time.Now().Unix())

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			peerTime := uint32(int32(now) + tc.offsetSec)
			result := transport.IsTimestampWithinTolerance(peerTime, tc.tolerance)
			require.Equal(t, tc.expect, result,
				"transport.IsTimestampWithinTolerance(%d, %v) = %v, expected %v",
				peerTime, tc.tolerance, result, tc.expect)
		})
	}
}

// TestM5_IsTimestampWithinTolerance_DifferentTolerances
// Verify transport.IsTimestampWithinTolerance respects custom tolerance values (not hardcoded to 60s).
// M-5 goal: single helper applied at every consumer with configurable skew window.
func TestM5_IsTimestampWithinTolerance_DifferentTolerances(t *testing.T) {
	t.Parallel()

	now := uint32(time.Now().Unix())
	testTimestamp := now + 100 // 100 seconds in the future

	testCases := []struct {
		name      string
		tolerance time.Duration
		expect    bool
	}{
		{
			name:      "60 second tolerance (default)",
			tolerance: 60 * time.Second,
			expect:    false, // 100s > 60s
		},
		{
			name:      "120 second tolerance",
			tolerance: 120 * time.Second,
			expect:    true, // 100s <= 120s
		},
		{
			name:      "30 second tolerance",
			tolerance: 30 * time.Second,
			expect:    false, // 100s > 30s
		},
		{
			name:      "100 second tolerance (exact match)",
			tolerance: 100 * time.Second,
			expect:    true, // 100s == 100s
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := transport.IsTimestampWithinTolerance(testTimestamp, tc.tolerance)
			require.Equal(t, tc.expect, result,
				"transport.IsTimestampWithinTolerance(%d, %v) = %v, expected %v",
				testTimestamp, tc.tolerance, result, tc.expect)
		})
	}
}

// TestM5_ValidateTimestamp_UsesConsistentSkew
// Verify DefaultHandler.ValidateTimestamp uses consistent skew tolerance (±30s).
// M-5: Establishes baseline that all consumers should follow.
func TestM5_ValidateTimestamp_UsesConsistentSkew(t *testing.T) {
	t.Parallel()

	h := NewDefaultHandler()
	defer h.Close()

	now := uint32(time.Now().Unix())

	testCases := []struct {
		name      string
		offsetSec int32
		expectErr bool
	}{
		{
			name:      "now",
			offsetSec: 0,
			expectErr: false,
		},
		{
			name:      "+29 seconds (within 30s tolerance)",
			offsetSec: 29,
			expectErr: false,
		},
		{
			name:      "-29 seconds (within 30s tolerance)",
			offsetSec: -29,
			expectErr: false,
		},
		{
			name:      "+31 seconds (outside 30s tolerance)",
			offsetSec: 31,
			expectErr: true,
		},
		{
			name:      "-31 seconds (outside 30s tolerance)",
			offsetSec: -31,
			expectErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			peerTime := uint32(int32(now) + tc.offsetSec)
			err := h.ValidateTimestamp(peerTime)
			if tc.expectErr {
				require.Error(t, err, "ValidateTimestamp should reject %s", tc.name)
			} else {
				require.NoError(t, err, "ValidateTimestamp should accept %s", tc.name)
			}
		})
	}
}

// TestM5_RaceDetectorValidatesTimestampAccess
// Concurrent timestamp validation calls should have no data races.
// M-5: Ensures transport.IsTimestampWithinTolerance is thread-safe (reads wall clock only).
func TestM5_RaceDetectorValidatesTimestampAccess(t *testing.T) {
	t.Parallel()

	now := uint32(time.Now().Unix())
	done := make(chan struct{})
	numGoroutines := 50

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 100; j++ {
				testTime := now + uint32(id*100+j)
				_ = transport.IsTimestampWithinTolerance(testTime, 60*time.Second)
			}
		}(i)
	}

	for i := 0; i < numGoroutines; i++ {
		<-done
	}
	// Race detector validates no unsynchronized accesses.
	t.Log("50 goroutines × 100 iterations completed with race detector clean")
}
