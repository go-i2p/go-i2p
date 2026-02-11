package router

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBandwidthTracker_DoubleStop verifies that calling Stop() twice does not
// panic with "close of closed channel". This was a critical bug where the
// stopChan was closed without a sync.Once guard.
func TestBandwidthTracker_DoubleStop(t *testing.T) {
	bt := NewBandwidthTracker()

	bt.Start(func() (uint64, uint64) {
		return 100, 200
	})

	// First stop should succeed normally
	bt.Stop()

	// Second stop must not panic
	require.NotPanics(t, func() {
		bt.Stop()
	}, "BandwidthTracker.Stop() must be idempotent and not panic on double-call")
}

// TestBandwidthTracker_TripleStop verifies that Stop() remains safe even with
// multiple redundant calls.
func TestBandwidthTracker_TripleStop(t *testing.T) {
	bt := NewBandwidthTracker()

	bt.Start(func() (uint64, uint64) {
		return 0, 0
	})

	require.NotPanics(t, func() {
		bt.Stop()
		bt.Stop()
		bt.Stop()
	}, "BandwidthTracker.Stop() must be safe to call any number of times")
}

// TestBandwidthTracker_StopWithoutStart verifies that Stop() does not panic
// when the tracker was never started. The stopChan is initialized in
// NewBandwidthTracker, so closing it should be safe even without Start().
func TestBandwidthTracker_StopWithoutStart(t *testing.T) {
	bt := NewBandwidthTracker()

	require.NotPanics(t, func() {
		bt.Stop()
	}, "Stop() without Start() should not panic")
}

// TestBandwidthTracker_ConcurrentStop verifies that concurrent calls to Stop()
// do not race or panic.
func TestBandwidthTracker_ConcurrentStop(t *testing.T) {
	bt := NewBandwidthTracker()

	bt.Start(func() (uint64, uint64) {
		return 50, 100
	})

	// Give it a moment to start the sampling loop
	time.Sleep(10 * time.Millisecond)

	done := make(chan struct{})
	for i := 0; i < 10; i++ {
		go func() {
			bt.Stop()
			done <- struct{}{}
		}()
	}

	for i := 0; i < 10; i++ {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("concurrent Stop() calls timed out")
		}
	}

	// Rates should still be accessible after stop
	inbound, outbound := bt.GetRates()
	assert.GreaterOrEqual(t, inbound+outbound, uint64(0), "Rates should be queryable after stop")
}
