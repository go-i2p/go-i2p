package router

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestBandwidthTracker_CounterResetUnderflow verifies that the bandwidth tracker
// handles counter resets (e.g., transport reconnect) gracefully without uint64 underflow.
func TestBandwidthTracker_CounterResetUnderflow(t *testing.T) {
	bt := NewBandwidthTracker()

	// Simulate initial state: counters at high values
	getBandwidth := func() (uint64, uint64) {
		return 1000, 2000
	}
	bt.takeSample(getBandwidth)

	// Simulate counter reset: new values lower than previous
	getBandwidthReset := func() (uint64, uint64) {
		return 100, 50 // lower than previous 1000, 2000
	}
	bt.takeSample(getBandwidthReset)

	// Verify no underflow: rates should be 0, not huge values
	bt.mu.Lock()
	defer bt.mu.Unlock()
	if len(bt.samples) >= 2 {
		lastSample := bt.samples[len(bt.samples)-1]
		assert.Equal(t, uint64(0), lastSample.bytesSent,
			"bytesSent should be 0 after counter reset, not underflowed")
		assert.Equal(t, uint64(0), lastSample.bytesReceived,
			"bytesReceived should be 0 after counter reset, not underflowed")
	}
}

// TestBandwidthTracker_NormalOperation verifies normal counter progression works.
func TestBandwidthTracker_NormalOperation(t *testing.T) {
	bt := NewBandwidthTracker()

	// First sample
	bt.takeSample(func() (uint64, uint64) { return 100, 200 })
	// Wait briefly to allow timestamp differentiation
	time.Sleep(10 * time.Millisecond)
	// Second sample: 50 more bytes sent, 100 more received
	bt.takeSample(func() (uint64, uint64) { return 150, 300 })

	bt.mu.Lock()
	defer bt.mu.Unlock()
	if len(bt.samples) >= 2 {
		lastSample := bt.samples[len(bt.samples)-1]
		assert.Equal(t, uint64(50), lastSample.bytesSent,
			"bytesSent should be delta between samples")
		assert.Equal(t, uint64(100), lastSample.bytesReceived,
			"bytesReceived should be delta between samples")
	}
}
