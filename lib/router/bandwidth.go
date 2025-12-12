package router

import (
	"sync"
	"sync/atomic"
	"time"
)

// BandwidthSample represents a single bandwidth measurement at a point in time.
type BandwidthSample struct {
	timestamp     time.Time
	bytesSent     uint64
	bytesReceived uint64
}

// BandwidthTracker tracks bandwidth usage over time and calculates rolling averages.
// It maintains samples for computing 1-second and 15-second rolling averages.
type BandwidthTracker struct {
	mu             sync.RWMutex
	samples        []BandwidthSample
	maxSamples     int           // Maximum samples to keep (15 for 15-second window with 1s sampling)
	sampleInterval time.Duration // How often to sample (1 second)
	lastSample     BandwidthSample

	// Cached rates (bytes per second)
	// Separate inbound and outbound tracking for I2PControl
	inboundRate1s   atomic.Uint64
	inboundRate15s  atomic.Uint64
	outboundRate1s  atomic.Uint64
	outboundRate15s atomic.Uint64

	stopChan chan struct{}
	wg       sync.WaitGroup
}

// NewBandwidthTracker creates a new bandwidth tracker with 1-second sampling.
func NewBandwidthTracker() *BandwidthTracker {
	return &BandwidthTracker{
		samples:        make([]BandwidthSample, 0, 15),
		maxSamples:     15, // Keep 15 samples for 15-second average
		sampleInterval: time.Second,
		stopChan:       make(chan struct{}),
	}
}

// Start begins the bandwidth tracking goroutine.
// The getBandwidth function should return current cumulative bytes sent/received.
func (bt *BandwidthTracker) Start(getBandwidth func() (sent, received uint64)) {
	bt.wg.Add(1)
	go bt.samplingLoop(getBandwidth)
}

// Stop stops the bandwidth tracking goroutine.
func (bt *BandwidthTracker) Stop() {
	close(bt.stopChan)
	bt.wg.Wait()
}

// samplingLoop periodically samples bandwidth and updates rolling averages.
func (bt *BandwidthTracker) samplingLoop(getBandwidth func() (sent, received uint64)) {
	defer bt.wg.Done()

	ticker := time.NewTicker(bt.sampleInterval)
	defer ticker.Stop()

	// Initialize with first sample
	sent, received := getBandwidth()
	bt.mu.Lock()
	bt.lastSample = BandwidthSample{
		timestamp:     time.Now(),
		bytesSent:     sent,
		bytesReceived: received,
	}
	bt.mu.Unlock()

	for {
		select {
		case <-ticker.C:
			bt.takeSample(getBandwidth)
		case <-bt.stopChan:
			return
		}
	}
}

// takeSample takes a new bandwidth sample and updates rolling averages.
func (bt *BandwidthTracker) takeSample(getBandwidth func() (sent, received uint64)) {
	now := time.Now()
	sent, received := getBandwidth()

	bt.mu.Lock()
	defer bt.mu.Unlock()

	// Calculate bytes transferred since last sample
	bytesSent := sent - bt.lastSample.bytesSent
	bytesReceived := received - bt.lastSample.bytesReceived

	// Store the new sample
	sample := BandwidthSample{
		timestamp:     now,
		bytesSent:     bytesSent,
		bytesReceived: bytesReceived,
	}

	bt.samples = append(bt.samples, sample)

	// Keep only the most recent maxSamples
	if len(bt.samples) > bt.maxSamples {
		bt.samples = bt.samples[1:]
	}

	// Update last sample for next delta calculation
	bt.lastSample.bytesSent = sent
	bt.lastSample.bytesReceived = received
	bt.lastSample.timestamp = now

	// Calculate and cache rolling averages
	bt.updateRates()
}

// updateRates calculates 1-second and 15-second rolling averages from samples.
// Must be called with bt.mu held.
func (bt *BandwidthTracker) updateRates() {
	if len(bt.samples) == 0 {
		bt.inboundRate1s.Store(0)
		bt.inboundRate15s.Store(0)
		bt.outboundRate1s.Store(0)
		bt.outboundRate15s.Store(0)
		return
	}

	now := time.Now()

	// Calculate 1-second rates (most recent sample)
	if len(bt.samples) >= 1 {
		lastSample := bt.samples[len(bt.samples)-1]
		// Rates are bytes per second (we sample every second)
		bt.inboundRate1s.Store(lastSample.bytesReceived)
		bt.outboundRate1s.Store(lastSample.bytesSent)
	}

	// Calculate 15-second rates (average of all samples in 15s window)
	var totalSent, totalReceived uint64
	var count int
	for i := len(bt.samples) - 1; i >= 0; i-- {
		sample := bt.samples[i]
		// Only include samples within 15 seconds
		if now.Sub(sample.timestamp) > 15*time.Second {
			break
		}
		totalSent += sample.bytesSent
		totalReceived += sample.bytesReceived
		count++
	}

	if count > 0 {
		// Average bytes per sample (samples are 1 second apart)
		bt.inboundRate15s.Store(totalReceived / uint64(count))
		bt.outboundRate15s.Store(totalSent / uint64(count))
	} else {
		bt.inboundRate15s.Store(0)
		bt.outboundRate15s.Store(0)
	}
}

// GetRates returns the 15-second inbound and outbound bandwidth rates in bytes per second.
func (bt *BandwidthTracker) GetRates() (inbound, outbound uint64) {
	return bt.inboundRate15s.Load(), bt.outboundRate15s.Load()
}

// GetRate1s returns the 1-second inbound and outbound bandwidth rates in bytes per second.
func (bt *BandwidthTracker) GetRate1s() (inbound, outbound uint64) {
	return bt.inboundRate1s.Load(), bt.outboundRate1s.Load()
}

// GetRate15s returns the 15-second inbound and outbound bandwidth rates in bytes per second.
func (bt *BandwidthTracker) GetRate15s() (inbound, outbound uint64) {
	return bt.inboundRate15s.Load(), bt.outboundRate15s.Load()
}
