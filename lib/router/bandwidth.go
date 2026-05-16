package router

import (
	"math"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-i2p/go-i2p/lib/config"
	ntcp "github.com/go-i2p/go-i2p/lib/transport/ntcp2"
	ssu2 "github.com/go-i2p/go-i2p/lib/transport/ssu2"
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
	stopOnce sync.Once // guards stopChan close to prevent double-close panics
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
	log.WithField("sample_interval", bt.sampleInterval).Debug("starting bandwidth tracker")
	bt.wg.Add(1)
	go bt.samplingLoop(getBandwidth)
}

// Stop stops the bandwidth tracking goroutine.
// It is safe to call Stop multiple times; only the first call closes the channel.
func (bt *BandwidthTracker) Stop() {
	log.Debug("stopping bandwidth tracker")
	bt.stopOnce.Do(func() {
		close(bt.stopChan)
	})
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
	// Guard against underflow: if counters were reset (reconnect, transport swap),
	// the current value may be less than the last sample.
	var bytesSent, bytesReceived uint64
	if sent >= bt.lastSample.bytesSent {
		bytesSent = sent - bt.lastSample.bytesSent
	}
	if received >= bt.lastSample.bytesReceived {
		bytesReceived = received - bt.lastSample.bytesReceived
	}

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
		bt.clearAllRates()
		return
	}

	bt.calculateOneSecondRates()
	bt.calculateFifteenSecondRates()
}

// clearAllRates resets all rate counters to zero.
// Must be called with bt.mu held.
func (bt *BandwidthTracker) clearAllRates() {
	bt.inboundRate1s.Store(0)
	bt.inboundRate15s.Store(0)
	bt.outboundRate1s.Store(0)
	bt.outboundRate15s.Store(0)
}

// calculateOneSecondRates sets 1-second rates from the most recent sample.
// Must be called with bt.mu held.
func (bt *BandwidthTracker) calculateOneSecondRates() {
	lastSample := bt.samples[len(bt.samples)-1]
	bt.inboundRate1s.Store(lastSample.bytesReceived)
	bt.outboundRate1s.Store(lastSample.bytesSent)
}

// calculateFifteenSecondRates computes 15-second average rates from recent samples.
// Uses actual elapsed time rather than sample count for accuracy.
// Must be called with bt.mu held.
func (bt *BandwidthTracker) calculateFifteenSecondRates() {
	now := time.Now()
	var totalSent, totalReceived uint64
	var oldestTimestamp time.Time
	var count int

	for i := len(bt.samples) - 1; i >= 0; i-- {
		sample := bt.samples[i]
		if now.Sub(sample.timestamp) > 15*time.Second {
			break
		}
		totalSent += sample.bytesSent
		totalReceived += sample.bytesReceived
		if count == 0 || sample.timestamp.Before(oldestTimestamp) {
			oldestTimestamp = sample.timestamp
		}
		count++
	}

	if count == 0 {
		bt.inboundRate15s.Store(0)
		bt.outboundRate15s.Store(0)
		return
	}

	elapsedSecs := bt.computeElapsedSeconds(now, oldestTimestamp)
	bt.inboundRate15s.Store(totalReceived / elapsedSecs)
	bt.outboundRate15s.Store(totalSent / elapsedSecs)
}

// computeElapsedSeconds returns the number of whole seconds between two timestamps,
// clamped to a minimum of 1 to avoid division by zero.
func (bt *BandwidthTracker) computeElapsedSeconds(now, oldest time.Time) uint64 {
	elapsed := now.Sub(oldest)
	if elapsed < time.Second {
		return 1
	}
	secs := uint64(elapsed / time.Second)
	if secs == 0 {
		return 1
	}
	return secs
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

// getTotalBandwidth returns the total bytes sent and received from all transports.
// This method is used by the bandwidth tracker to sample bandwidth usage.
func (r *Router) getTotalBandwidth() (sent, received uint64) {
	// Capture TransportMuxer locally to avoid TOCTOU race:
	// the field could be set to nil by concurrent shutdown between
	// the nil check and the method call.
	muxer := r.transports
	if muxer == nil {
		return 0, 0
	}

	// Get all transports from the muxer
	for _, t := range muxer.GetTransports() {
		switch tr := t.(type) {
		case *ntcp.NTCP2Transport:
			s, rcv := tr.GetTotalBandwidth()
			sent += s
			received += rcv
		case *ssu2.SSU2Transport:
			s, rcv := tr.GetTotalBandwidth()
			sent += s
			received += rcv
		}
	}
	return sent, received
}

// GetBandwidthRates returns the current 15-second inbound and outbound bandwidth rates.
// Returns rates in bytes per second.
func (r *Router) GetBandwidthRates() (inbound, outbound uint64) {
	if r.bandwidthTracker == nil {
		return 0, 0
	}
	return r.bandwidthTracker.GetRates()
}

// GetBandwidthRates1s returns the most recent 1-second inbound and outbound bandwidth rates.
// Returns rates in bytes per second.
func (r *Router) GetBandwidthRates1s() (inbound, outbound uint64) {
	if r.bandwidthTracker == nil {
		return 0, 0
	}
	return r.bandwidthTracker.GetRate1s()
}

// routerBandwidthProvider adapts the router config to the I2CP bandwidth
// limits interface so the I2CP server returns the real configured limit
// instead of a hardcoded value.
type routerBandwidthProvider struct {
	cfg *config.RouterConfig
}

// GetBandwidthLimits returns the router's configured MaxBandwidth for both
// inbound and outbound directions. If MaxBandwidth is 0 (unlimited) or
// exceeds uint32 range, it clamps to math.MaxUint32.
func (bp *routerBandwidthProvider) GetBandwidthLimits() (inbound, outbound uint32) {
	bw := bp.cfg.MaxBandwidth
	if bw == 0 || bw > uint64(math.MaxUint32) {
		return math.MaxUint32, math.MaxUint32 // unlimited
	}
	limit := uint32(bw)
	return limit, limit
}
