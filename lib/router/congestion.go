package router

import (
	"sync"
	"time"

	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/go-i2p/logger"
)

// CongestionStateProvider provides access to local router congestion state.
// This interface is used by RouterInfo construction to determine which
// congestion flag (D/E/G or none) should be advertised.
type CongestionStateProvider interface {
	// GetCongestionFlag returns the current congestion flag ("D", "E", "G", or "")
	GetCongestionFlag() config.CongestionFlag

	// GetCongestionLevel returns a numeric congestion level (0=none, 1=D, 2=E, 3=G)
	GetCongestionLevel() int

	// ShouldAdvertiseCongestion returns true if any congestion flag should be advertised
	ShouldAdvertiseCongestion() bool
}

// CongestionMetricsCollector gathers metrics used to determine congestion state.
// Implementations collect data from tunnel manager, bandwidth tracker, and transports.
type CongestionMetricsCollector interface {
	// GetParticipatingTunnelRatio returns current/max participating tunnels ratio
	GetParticipatingTunnelRatio() float64

	// GetBandwidthUtilization returns current bandwidth usage ratio (0.0-1.0)
	GetBandwidthUtilization() float64

	// GetConnectionUtilization returns connection count / max connections ratio
	GetConnectionUtilization() float64

	// IsAcceptingTunnels returns false if router is configured to reject all tunnels
	IsAcceptingTunnels() bool
}

// CongestionSample represents a single congestion measurement at a point in time.
type CongestionSample struct {
	Timestamp                time.Time
	ParticipatingTunnelRatio float64
	BandwidthUtilization     float64
	ConnectionUtilization    float64
}

// CongestionMonitor tracks local router congestion and determines the appropriate
// congestion flag (D/E/G) to advertise in RouterInfo caps.
//
// Design decisions:
// - Uses rolling average over configurable window (default 5 minutes per spec)
// - Implements hysteresis to prevent flag flapping at threshold boundaries
// - Thread-safe for concurrent access from RouterInfo publisher
// - State machine: None → D → E → G with hysteresis thresholds for downgrades
type CongestionMonitor struct {
	mu sync.RWMutex

	// Configuration
	cfg config.CongestionDefaults

	// Metrics source
	collector CongestionMetricsCollector

	// Rolling average samples
	samples    []CongestionSample
	maxSamples int

	// Current state
	currentFlag config.CongestionFlag
	forcedFlag  bool // Set by ForceFlag; prevents updateState from overwriting

	// Startup grace period - don't advertise congestion at startup
	startupTime     time.Time
	startupGraceSec int

	// Background sampling
	stopChan chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
}

// NewCongestionMonitor creates a new congestion monitor with the given configuration.
// The collector parameter provides metrics; if nil, a no-op collector is used.
func NewCongestionMonitor(cfg config.CongestionDefaults, collector CongestionMetricsCollector) *CongestionMonitor {
	// Default to 1-second sampling, calculate max samples from averaging window
	sampleInterval := time.Second
	maxSamples := int(cfg.AveragingWindow / sampleInterval)
	if maxSamples < 10 {
		maxSamples = 10 // Minimum 10 samples
	}

	m := &CongestionMonitor{
		cfg:             cfg,
		collector:       collector,
		samples:         make([]CongestionSample, 0, maxSamples),
		maxSamples:      maxSamples,
		currentFlag:     config.CongestionFlagNone,
		startupTime:     time.Now(),
		startupGraceSec: 60, // 60 second startup grace period
		stopChan:        make(chan struct{}),
	}

	// Use no-op collector if none provided
	if m.collector == nil {
		m.collector = &noopMetricsCollector{}
	}

	return m
}

// Start begins the background congestion sampling goroutine.
func (m *CongestionMonitor) Start() {
	m.wg.Add(1)
	go m.samplingLoop()

	log.WithFields(logger.Fields{
		"at":               "CongestionMonitor.Start",
		"reason":           "congestion monitoring started",
		"averaging_window": m.cfg.AveragingWindow,
		"max_samples":      m.maxSamples,
	}).Debug("congestion monitor started")
}

// Stop stops the background sampling goroutine.
// Safe to call multiple times; only the first call has effect.
func (m *CongestionMonitor) Stop() {
	m.stopOnce.Do(func() {
		close(m.stopChan)
		m.wg.Wait()

		log.WithFields(logger.Fields{
			"at":     "CongestionMonitor.Stop",
			"reason": "congestion monitoring stopped",
		}).Debug("congestion monitor stopped")
	})
}

// samplingLoop periodically samples congestion metrics and updates state.
func (m *CongestionMonitor) samplingLoop() {
	defer m.wg.Done()

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.takeSample()
		case <-m.stopChan:
			return
		}
	}
}

// takeSample takes a new congestion sample and updates the state.
func (m *CongestionMonitor) takeSample() {
	sample := CongestionSample{
		Timestamp:                time.Now(),
		ParticipatingTunnelRatio: m.collector.GetParticipatingTunnelRatio(),
		BandwidthUtilization:     m.collector.GetBandwidthUtilization(),
		ConnectionUtilization:    m.collector.GetConnectionUtilization(),
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Add sample to rolling window
	m.samples = append(m.samples, sample)
	if len(m.samples) > m.maxSamples {
		m.samples = m.samples[1:]
	}

	// Update congestion state based on rolling average
	m.updateState()
}

// updateState calculates the rolling average and updates the congestion flag.
// Must be called with m.mu held.
// Skips updates when the flag has been manually forced via ForceFlag().
func (m *CongestionMonitor) updateState() {
	if m.forcedFlag {
		return
	}

	if len(m.samples) == 0 {
		return
	}

	avgRatio := m.calculateAverageRatio()
	newFlag := m.determineFlag(avgRatio)

	if newFlag != m.currentFlag {
		log.WithFields(logger.Fields{
			"at":            "CongestionMonitor.updateState",
			"reason":        "congestion state changed",
			"old_flag":      m.currentFlag.String(),
			"new_flag":      newFlag.String(),
			"average_ratio": avgRatio,
		}).Info("congestion flag changed")

		m.currentFlag = newFlag
	}
}

// calculateAverageRatio computes the weighted average congestion ratio.
// Incorporates participating tunnel ratio, bandwidth utilization, and connection
// utilization per PROP_162.  The weights reflect the relative importance of each
// metric: tunnel participation is the primary signal, while bandwidth and
// connection saturation act as secondary indicators.
// Must be called with m.mu held.
func (m *CongestionMonitor) calculateAverageRatio() float64 {
	if len(m.samples) == 0 {
		return 0
	}

	// Weights for the three congestion dimensions.
	// Participating tunnel ratio is the primary metric (weight 0.5).
	// Bandwidth and connection utilization each contribute 0.25.
	const (
		tunnelWeight     = 0.50
		bandwidthWeight  = 0.25
		connectionWeight = 0.25
	)

	var sum float64
	for _, s := range m.samples {
		weighted := s.ParticipatingTunnelRatio*tunnelWeight +
			s.BandwidthUtilization*bandwidthWeight +
			s.ConnectionUtilization*connectionWeight
		sum += weighted
	}

	return sum / float64(len(m.samples))
}

// determineFlag determines the appropriate congestion flag based on the ratio.
// Implements hysteresis to prevent flag flapping.
// Must be called with m.mu held.
func (m *CongestionMonitor) determineFlag(ratio float64) config.CongestionFlag {
	if !m.collector.IsAcceptingTunnels() {
		return config.CongestionFlagG
	}

	switch m.currentFlag {
	case config.CongestionFlagG:
		return m.transitionFromGFlag(ratio)
	case config.CongestionFlagE:
		return m.transitionFromEFlag(ratio)
	case config.CongestionFlagD:
		return m.transitionFromDFlag(ratio)
	default:
		return m.transitionFromNoFlag(ratio)
	}
}

// transitionFromGFlag handles state transitions when currently at G flag.
// Implements hysteresis: stays at G unless ratio drops below clear threshold.
func (m *CongestionMonitor) transitionFromGFlag(ratio float64) config.CongestionFlag {
	if ratio >= m.cfg.ClearGFlagThreshold {
		return config.CongestionFlagG
	}
	return m.determineFlagByRatio(ratio)
}

// transitionFromEFlag handles state transitions when currently at E flag.
// Checks for upgrade to G, or downgrade with hysteresis.
func (m *CongestionMonitor) transitionFromEFlag(ratio float64) config.CongestionFlag {
	if ratio >= m.cfg.GFlagThreshold {
		return config.CongestionFlagG
	}
	if ratio >= m.cfg.ClearEFlagThreshold {
		return config.CongestionFlagE
	}
	return m.determineFlagByRatioForD(ratio)
}

// transitionFromDFlag handles state transitions when currently at D flag.
// Checks for upgrades to E/G, or downgrade with hysteresis.
func (m *CongestionMonitor) transitionFromDFlag(ratio float64) config.CongestionFlag {
	if ratio >= m.cfg.GFlagThreshold {
		return config.CongestionFlagG
	}
	if ratio >= m.cfg.EFlagThreshold {
		return config.CongestionFlagE
	}
	if ratio >= m.cfg.ClearDFlagThreshold {
		return config.CongestionFlagD
	}
	return config.CongestionFlagNone
}

// transitionFromNoFlag handles state transitions from no congestion state.
// Only checks for upgrades to D/E/G flags.
func (m *CongestionMonitor) transitionFromNoFlag(ratio float64) config.CongestionFlag {
	return m.determineFlagByRatio(ratio)
}

// determineFlagByRatio returns the appropriate flag based on ratio thresholds.
// Used when transitioning down from G or up from None.
func (m *CongestionMonitor) determineFlagByRatio(ratio float64) config.CongestionFlag {
	if ratio >= m.cfg.GFlagThreshold {
		return config.CongestionFlagG
	}
	if ratio >= m.cfg.EFlagThreshold {
		return config.CongestionFlagE
	}
	if ratio >= m.cfg.DFlagThreshold {
		return config.CongestionFlagD
	}
	return config.CongestionFlagNone
}

// determineFlagByRatioForD returns D or None based on ratio.
// Used when downgrading from E flag.
func (m *CongestionMonitor) determineFlagByRatioForD(ratio float64) config.CongestionFlag {
	if ratio >= m.cfg.DFlagThreshold {
		return config.CongestionFlagD
	}
	return config.CongestionFlagNone
}

// GetCongestionFlag returns the current congestion flag.
// Returns empty string during startup grace period per spec (prevents restart detection).
func (m *CongestionMonitor) GetCongestionFlag() config.CongestionFlag {
	// Check startup grace period
	if time.Since(m.startupTime) < time.Duration(m.startupGraceSec)*time.Second {
		return config.CongestionFlagNone
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.currentFlag
}

// GetCongestionLevel returns the numeric congestion level (0=none, 1=D, 2=E, 3=G).
func (m *CongestionMonitor) GetCongestionLevel() int {
	return m.GetCongestionFlag().CongestionLevel()
}

// ShouldAdvertiseCongestion returns true if any congestion flag should be advertised.
func (m *CongestionMonitor) ShouldAdvertiseCongestion() bool {
	return m.GetCongestionFlag() != config.CongestionFlagNone
}

// GetCurrentRatio returns the current rolling average congestion ratio.
// Useful for debugging and monitoring.
func (m *CongestionMonitor) GetCurrentRatio() float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.calculateAverageRatio()
}

// GetSampleCount returns the current number of samples in the rolling window.
func (m *CongestionMonitor) GetSampleCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return len(m.samples)
}

// ForceFlag allows manually setting the congestion flag for testing or emergency use.
// This bypasses the normal state machine logic. The forced flag persists until
// ClearForceFlag() is called, preventing updateState() from overwriting it.
func (m *CongestionMonitor) ForceFlag(flag config.CongestionFlag) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.currentFlag = flag
	m.forcedFlag = true

	log.WithFields(logger.Fields{
		"at":     "CongestionMonitor.ForceFlag",
		"reason": "congestion flag manually set",
		"flag":   flag.String(),
	}).Warn("congestion flag manually forced")
}

// ClearForceFlag clears a previously forced congestion flag, allowing the
// normal state machine logic to resume determining the flag from samples.
func (m *CongestionMonitor) ClearForceFlag() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.forcedFlag = false

	log.WithFields(logger.Fields{
		"at":     "CongestionMonitor.ClearForceFlag",
		"reason": "forced congestion flag cleared",
	}).Info("forced congestion flag cleared, resuming automatic monitoring")
}

// noopMetricsCollector is a no-op implementation for when no collector is provided.
type noopMetricsCollector struct{}

func (n *noopMetricsCollector) GetParticipatingTunnelRatio() float64 { return 0 }
func (n *noopMetricsCollector) GetBandwidthUtilization() float64     { return 0 }
func (n *noopMetricsCollector) GetConnectionUtilization() float64    { return 0 }
func (n *noopMetricsCollector) IsAcceptingTunnels() bool             { return true }

// Ensure interfaces are implemented
var (
	_ CongestionStateProvider    = (*CongestionMonitor)(nil)
	_ CongestionMetricsCollector = (*noopMetricsCollector)(nil)
)

// RouterMetricsCollector collects congestion metrics from router subsystems.
// This is the production implementation of CongestionMetricsCollector.
type RouterMetricsCollector struct {
	// participantCountFunc returns current participating tunnel count
	participantCountFunc func() int
	// maxParticipantsFunc returns max participating tunnel limit
	maxParticipantsFunc func() int
	// bandwidthRatesFunc returns current inbound/outbound bandwidth in bytes/sec
	bandwidthRatesFunc func() (inbound, outbound uint64)
	// maxBandwidthFunc returns configured max bandwidth in bytes/sec (0 = unlimited)
	maxBandwidthFunc func() uint64
	// connectionCountFunc returns current transport connection count
	connectionCountFunc func() int
	// maxConnectionsFunc returns max transport connections
	maxConnectionsFunc func() int
	// acceptingTunnelsFunc returns whether router is accepting tunnels
	acceptingTunnelsFunc func() bool
}

// NewRouterMetricsCollector creates a RouterMetricsCollector with the provided functions.
// Any nil function will use a safe default that returns zero or true.
func NewRouterMetricsCollector(opts ...RouterMetricsOption) *RouterMetricsCollector {
	c := &RouterMetricsCollector{
		participantCountFunc: func() int { return 0 },
		maxParticipantsFunc:  func() int { return 15000 },
		bandwidthRatesFunc:   func() (uint64, uint64) { return 0, 0 },
		maxBandwidthFunc:     func() uint64 { return 0 },
		connectionCountFunc:  func() int { return 0 },
		maxConnectionsFunc:   func() int { return 200 },
		acceptingTunnelsFunc: func() bool { return true },
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// RouterMetricsOption configures a RouterMetricsCollector.
type RouterMetricsOption func(*RouterMetricsCollector)

// WithParticipantCount sets the function to get current participant count.
func WithParticipantCount(f func() int) RouterMetricsOption {
	return func(c *RouterMetricsCollector) {
		if f != nil {
			c.participantCountFunc = f
		}
	}
}

// WithMaxParticipants sets the function to get max participants.
func WithMaxParticipants(f func() int) RouterMetricsOption {
	return func(c *RouterMetricsCollector) {
		if f != nil {
			c.maxParticipantsFunc = f
		}
	}
}

// WithBandwidthRates sets the function to get bandwidth rates.
func WithBandwidthRates(f func() (inbound, outbound uint64)) RouterMetricsOption {
	return func(c *RouterMetricsCollector) {
		if f != nil {
			c.bandwidthRatesFunc = f
		}
	}
}

// WithMaxBandwidth sets the function to get max bandwidth.
func WithMaxBandwidth(f func() uint64) RouterMetricsOption {
	return func(c *RouterMetricsCollector) {
		if f != nil {
			c.maxBandwidthFunc = f
		}
	}
}

// WithConnectionCount sets the function to get connection count.
func WithConnectionCount(f func() int) RouterMetricsOption {
	return func(c *RouterMetricsCollector) {
		if f != nil {
			c.connectionCountFunc = f
		}
	}
}

// WithMaxConnections sets the function to get max connections.
func WithMaxConnections(f func() int) RouterMetricsOption {
	return func(c *RouterMetricsCollector) {
		if f != nil {
			c.maxConnectionsFunc = f
		}
	}
}

// WithAcceptingTunnels sets the function to check if accepting tunnels.
func WithAcceptingTunnels(f func() bool) RouterMetricsOption {
	return func(c *RouterMetricsCollector) {
		if f != nil {
			c.acceptingTunnelsFunc = f
		}
	}
}

// GetParticipatingTunnelRatio returns current/max participating tunnels ratio.
func (c *RouterMetricsCollector) GetParticipatingTunnelRatio() float64 {
	count := c.participantCountFunc()
	max := c.maxParticipantsFunc()

	if max <= 0 {
		return 0
	}

	ratio := float64(count) / float64(max)
	if ratio > 1.0 {
		ratio = 1.0
	}
	return ratio
}

// GetBandwidthUtilization returns current bandwidth usage ratio.
func (c *RouterMetricsCollector) GetBandwidthUtilization() float64 {
	inbound, outbound := c.bandwidthRatesFunc()
	maxBandwidth := c.maxBandwidthFunc()

	if maxBandwidth == 0 {
		return 0 // Unlimited bandwidth
	}

	// Use the higher of inbound or outbound
	current := inbound
	if outbound > current {
		current = outbound
	}

	ratio := float64(current) / float64(maxBandwidth)
	if ratio > 1.0 {
		ratio = 1.0
	}
	return ratio
}

// GetConnectionUtilization returns connection count / max connections ratio.
func (c *RouterMetricsCollector) GetConnectionUtilization() float64 {
	count := c.connectionCountFunc()
	max := c.maxConnectionsFunc()

	if max <= 0 {
		return 0
	}

	ratio := float64(count) / float64(max)
	if ratio > 1.0 {
		ratio = 1.0
	}
	return ratio
}

// IsAcceptingTunnels returns whether the router is accepting tunnel participation.
func (c *RouterMetricsCollector) IsAcceptingTunnels() bool {
	return c.acceptingTunnelsFunc()
}

// Ensure RouterMetricsCollector implements CongestionMetricsCollector
var _ CongestionMetricsCollector = (*RouterMetricsCollector)(nil)
