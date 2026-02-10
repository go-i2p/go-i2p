package router

import (
	"sync"
	"testing"
	"time"

	"github.com/go-i2p/go-i2p/lib/config"
)

// mockMetricsCollector is a mock implementation for testing
type mockMetricsCollector struct {
	mu                       sync.Mutex
	participatingTunnelRatio float64
	bandwidthUtilization     float64
	connectionUtilization    float64
	acceptingTunnels         bool
}

func newMockCollector() *mockMetricsCollector {
	return &mockMetricsCollector{
		acceptingTunnels: true,
	}
}

func (m *mockMetricsCollector) GetParticipatingTunnelRatio() float64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.participatingTunnelRatio
}

func (m *mockMetricsCollector) GetBandwidthUtilization() float64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.bandwidthUtilization
}

func (m *mockMetricsCollector) GetConnectionUtilization() float64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.connectionUtilization
}

func (m *mockMetricsCollector) IsAcceptingTunnels() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.acceptingTunnels
}

// SetRatio sets all three congestion metrics to the same value so that the
// weighted average equals this value regardless of weight distribution.
func (m *mockMetricsCollector) SetRatio(ratio float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.participatingTunnelRatio = ratio
	m.bandwidthUtilization = ratio
	m.connectionUtilization = ratio
}

// SetAllMetrics sets all three congestion metrics at once.
func (m *mockMetricsCollector) SetAllMetrics(tunnel, bandwidth, connection float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.participatingTunnelRatio = tunnel
	m.bandwidthUtilization = bandwidth
	m.connectionUtilization = connection
}

func (m *mockMetricsCollector) SetAcceptingTunnels(accepting bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.acceptingTunnels = accepting
}

// TestNewCongestionMonitor verifies monitor creation with defaults
func TestNewCongestionMonitor(t *testing.T) {
	cfg := config.Defaults().Congestion
	monitor := NewCongestionMonitor(cfg, nil)

	if monitor == nil {
		t.Fatal("NewCongestionMonitor returned nil")
	}

	// Verify initial state
	if monitor.currentFlag != config.CongestionFlagNone {
		t.Errorf("initial flag = %v, want %v", monitor.currentFlag, config.CongestionFlagNone)
	}

	if monitor.maxSamples < 10 {
		t.Errorf("maxSamples = %d, want >= 10", monitor.maxSamples)
	}

	// Verify no-op collector is used when nil provided
	if monitor.collector == nil {
		t.Error("collector should not be nil")
	}
}

// TestCongestionMonitor_StartStop verifies start/stop lifecycle
func TestCongestionMonitor_StartStop(t *testing.T) {
	cfg := config.Defaults().Congestion
	collector := newMockCollector()
	monitor := NewCongestionMonitor(cfg, collector)

	// Start should not block
	monitor.Start()

	// Give sampling time to run
	time.Sleep(100 * time.Millisecond)

	// Stop should not block
	monitor.Stop()
}

// TestCongestionMonitor_NoFlagDuringStartup verifies startup grace period
func TestCongestionMonitor_NoFlagDuringStartup(t *testing.T) {
	cfg := config.Defaults().Congestion
	collector := newMockCollector()
	collector.SetRatio(0.90) // High ratio that would normally trigger E flag

	monitor := NewCongestionMonitor(cfg, collector)
	monitor.startupGraceSec = 2 // Short grace period for testing

	// Manually take samples to build state
	for i := 0; i < 10; i++ {
		monitor.takeSample()
	}

	// During grace period, should return no flag despite high congestion
	flag := monitor.GetCongestionFlag()
	if flag != config.CongestionFlagNone {
		t.Errorf("during startup grace, flag = %v, want %v", flag, config.CongestionFlagNone)
	}

	// Wait for grace period to expire
	time.Sleep(2100 * time.Millisecond)

	// Now should return actual flag
	flag = monitor.GetCongestionFlag()
	if flag == config.CongestionFlagNone {
		t.Errorf("after startup grace, flag = %v, want non-empty", flag)
	}
}

// TestCongestionMonitor_DFlagThreshold verifies D flag is set at correct threshold
func TestCongestionMonitor_DFlagThreshold(t *testing.T) {
	cfg := config.Defaults().Congestion
	collector := newMockCollector()
	monitor := NewCongestionMonitor(cfg, collector)
	monitor.startupGraceSec = 0 // Disable grace period for testing

	tests := []struct {
		name     string
		ratio    float64
		wantFlag config.CongestionFlag
	}{
		{"below D threshold", 0.65, config.CongestionFlagNone},
		{"at D threshold", 0.70, config.CongestionFlagD},
		{"above D threshold", 0.75, config.CongestionFlagD},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset monitor state
			monitor.mu.Lock()
			monitor.samples = nil
			monitor.currentFlag = config.CongestionFlagNone
			monitor.mu.Unlock()

			collector.SetRatio(tt.ratio)

			// Take enough samples to establish average
			for i := 0; i < 10; i++ {
				monitor.takeSample()
			}

			flag := monitor.GetCongestionFlag()
			if flag != tt.wantFlag {
				t.Errorf("ratio=%.2f: flag = %v, want %v", tt.ratio, flag, tt.wantFlag)
			}
		})
	}
}

// TestCongestionMonitor_EFlagThreshold verifies E flag is set at correct threshold
func TestCongestionMonitor_EFlagThreshold(t *testing.T) {
	cfg := config.Defaults().Congestion
	collector := newMockCollector()
	monitor := NewCongestionMonitor(cfg, collector)
	monitor.startupGraceSec = 0

	tests := []struct {
		name     string
		ratio    float64
		wantFlag config.CongestionFlag
	}{
		{"below E threshold", 0.80, config.CongestionFlagD},
		{"above E threshold", 0.86, config.CongestionFlagE},
		{"well above E threshold", 0.90, config.CongestionFlagE},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset monitor state
			monitor.mu.Lock()
			monitor.samples = nil
			monitor.currentFlag = config.CongestionFlagNone
			monitor.mu.Unlock()

			collector.SetRatio(tt.ratio)

			for i := 0; i < 10; i++ {
				monitor.takeSample()
			}

			flag := monitor.GetCongestionFlag()
			if flag != tt.wantFlag {
				t.Errorf("ratio=%.2f: flag = %v, want %v", tt.ratio, flag, tt.wantFlag)
			}
		})
	}
}

// TestCongestionMonitor_GFlagThreshold verifies G flag is set at correct threshold
func TestCongestionMonitor_GFlagThreshold(t *testing.T) {
	cfg := config.Defaults().Congestion
	collector := newMockCollector()
	monitor := NewCongestionMonitor(cfg, collector)
	monitor.startupGraceSec = 0

	tests := []struct {
		name     string
		ratio    float64
		wantFlag config.CongestionFlag
	}{
		{"below G threshold", 0.95, config.CongestionFlagE},
		{"at G threshold", 1.00, config.CongestionFlagG},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset monitor state
			monitor.mu.Lock()
			monitor.samples = nil
			monitor.currentFlag = config.CongestionFlagNone
			monitor.mu.Unlock()

			collector.SetRatio(tt.ratio)

			for i := 0; i < 10; i++ {
				monitor.takeSample()
			}

			flag := monitor.GetCongestionFlag()
			if flag != tt.wantFlag {
				t.Errorf("ratio=%.2f: flag = %v, want %v", tt.ratio, flag, tt.wantFlag)
			}
		})
	}
}

// TestCongestionMonitor_Hysteresis verifies hysteresis prevents flag flapping
func TestCongestionMonitor_Hysteresis(t *testing.T) {
	cfg := config.Defaults().Congestion
	collector := newMockCollector()
	monitor := NewCongestionMonitor(cfg, collector)
	monitor.startupGraceSec = 0
	monitor.maxSamples = 5 // Small window for faster test transitions

	// Start with D flag (ratio = 0.72)
	collector.SetRatio(0.72)
	for i := 0; i < 10; i++ {
		monitor.takeSample()
	}
	if flag := monitor.GetCongestionFlag(); flag != config.CongestionFlagD {
		t.Fatalf("setup: flag = %v, want D", flag)
	}

	// Drop to 0.65 - still above ClearDFlagThreshold (0.60), should stay D
	collector.SetRatio(0.65)
	for i := 0; i < 10; i++ {
		monitor.takeSample()
	}
	if flag := monitor.GetCongestionFlag(); flag != config.CongestionFlagD {
		t.Errorf("hysteresis test: at 0.65 flag = %v, want D (hysteresis should keep D)", flag)
	}

	// Drop to 0.55 - below ClearDFlagThreshold, should clear to None
	collector.SetRatio(0.55)
	for i := 0; i < 10; i++ {
		monitor.takeSample()
	}
	if flag := monitor.GetCongestionFlag(); flag != config.CongestionFlagNone {
		t.Errorf("hysteresis test: at 0.55 flag = %v, want None", flag)
	}
}

// TestCongestionMonitor_HysteresisGToE verifies G → E transition with hysteresis
func TestCongestionMonitor_HysteresisGToE(t *testing.T) {
	cfg := config.Defaults().Congestion
	collector := newMockCollector()
	monitor := NewCongestionMonitor(cfg, collector)
	monitor.startupGraceSec = 0
	monitor.maxSamples = 5 // Small window for faster test transitions

	// Start with G flag (ratio = 1.0)
	collector.SetRatio(1.0)
	for i := 0; i < 10; i++ {
		monitor.takeSample()
	}
	if flag := monitor.GetCongestionFlag(); flag != config.CongestionFlagG {
		t.Fatalf("setup: flag = %v, want G", flag)
	}

	// Drop to 0.97 - still above ClearGFlagThreshold (0.95), should stay G
	collector.SetRatio(0.97)
	for i := 0; i < 10; i++ {
		monitor.takeSample()
	}
	if flag := monitor.GetCongestionFlag(); flag != config.CongestionFlagG {
		t.Errorf("at 0.97 flag = %v, want G (hysteresis)", flag)
	}

	// Drop to 0.90 - below ClearGFlagThreshold, should drop to E
	collector.SetRatio(0.90)
	for i := 0; i < 10; i++ {
		monitor.takeSample()
	}
	if flag := monitor.GetCongestionFlag(); flag != config.CongestionFlagE {
		t.Errorf("at 0.90 flag = %v, want E", flag)
	}
}

// TestCongestionMonitor_NotAcceptingTunnels verifies G flag when not accepting tunnels
func TestCongestionMonitor_NotAcceptingTunnels(t *testing.T) {
	cfg := config.Defaults().Congestion
	collector := newMockCollector()
	monitor := NewCongestionMonitor(cfg, collector)
	monitor.startupGraceSec = 0

	// Low ratio but not accepting tunnels
	collector.SetRatio(0.10)
	collector.SetAcceptingTunnels(false)

	for i := 0; i < 10; i++ {
		monitor.takeSample()
	}

	flag := monitor.GetCongestionFlag()
	if flag != config.CongestionFlagG {
		t.Errorf("when not accepting tunnels: flag = %v, want G", flag)
	}
}

// TestCongestionMonitor_GetCongestionLevel verifies level calculation
func TestCongestionMonitor_GetCongestionLevel(t *testing.T) {
	cfg := config.Defaults().Congestion
	collector := newMockCollector()
	monitor := NewCongestionMonitor(cfg, collector)
	monitor.startupGraceSec = 0

	tests := []struct {
		ratio     float64
		wantLevel int
	}{
		{0.50, 0}, // None
		{0.72, 1}, // D
		{0.87, 2}, // E
		{1.00, 3}, // G
	}

	for _, tt := range tests {
		monitor.mu.Lock()
		monitor.samples = nil
		monitor.currentFlag = config.CongestionFlagNone
		monitor.mu.Unlock()

		collector.SetRatio(tt.ratio)
		for i := 0; i < 10; i++ {
			monitor.takeSample()
		}

		level := monitor.GetCongestionLevel()
		if level != tt.wantLevel {
			t.Errorf("ratio=%.2f: level = %d, want %d", tt.ratio, level, tt.wantLevel)
		}
	}
}

// TestCongestionMonitor_ShouldAdvertiseCongestion verifies advertisement logic
func TestCongestionMonitor_ShouldAdvertiseCongestion(t *testing.T) {
	cfg := config.Defaults().Congestion
	collector := newMockCollector()
	monitor := NewCongestionMonitor(cfg, collector)
	monitor.startupGraceSec = 0

	// No congestion - should not advertise
	collector.SetRatio(0.50)
	for i := 0; i < 10; i++ {
		monitor.takeSample()
	}
	if monitor.ShouldAdvertiseCongestion() {
		t.Error("at 0.50 ratio, ShouldAdvertiseCongestion() = true, want false")
	}

	// With congestion - should advertise
	monitor.mu.Lock()
	monitor.samples = nil
	monitor.currentFlag = config.CongestionFlagNone
	monitor.mu.Unlock()

	collector.SetRatio(0.80)
	for i := 0; i < 10; i++ {
		monitor.takeSample()
	}
	if !monitor.ShouldAdvertiseCongestion() {
		t.Error("at 0.80 ratio, ShouldAdvertiseCongestion() = false, want true")
	}
}

// TestCongestionMonitor_ForceFlag verifies manual flag override
func TestCongestionMonitor_ForceFlag(t *testing.T) {
	cfg := config.Defaults().Congestion
	collector := newMockCollector()
	monitor := NewCongestionMonitor(cfg, collector)
	monitor.startupGraceSec = 0

	// Low ratio - should be None
	collector.SetRatio(0.30)
	for i := 0; i < 10; i++ {
		monitor.takeSample()
	}
	if flag := monitor.GetCongestionFlag(); flag != config.CongestionFlagNone {
		t.Fatalf("setup: flag = %v, want None", flag)
	}

	// Force to G
	monitor.ForceFlag(config.CongestionFlagG)
	if flag := monitor.GetCongestionFlag(); flag != config.CongestionFlagG {
		t.Errorf("after ForceFlag(G): flag = %v, want G", flag)
	}
}

// TestCongestionMonitor_GetCurrentRatio verifies ratio calculation
func TestCongestionMonitor_GetCurrentRatio(t *testing.T) {
	cfg := config.Defaults().Congestion
	collector := newMockCollector()
	monitor := NewCongestionMonitor(cfg, collector)

	// With no samples, ratio should be 0
	ratio := monitor.GetCurrentRatio()
	if ratio != 0 {
		t.Errorf("with no samples, GetCurrentRatio() = %v, want 0", ratio)
	}

	// Add samples and verify average
	collector.SetRatio(0.50)
	for i := 0; i < 10; i++ {
		monitor.takeSample()
	}

	ratio = monitor.GetCurrentRatio()
	if ratio < 0.49 || ratio > 0.51 {
		t.Errorf("GetCurrentRatio() = %v, want ~0.50", ratio)
	}
}

// TestCongestionMonitor_ConcurrentAccess verifies thread safety
func TestCongestionMonitor_ConcurrentAccess(t *testing.T) {
	cfg := config.Defaults().Congestion
	collector := newMockCollector()
	monitor := NewCongestionMonitor(cfg, collector)
	monitor.startupGraceSec = 0

	var wg sync.WaitGroup
	done := make(chan struct{})

	// Writer goroutines - update ratio
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for {
				select {
				case <-done:
					return
				default:
					ratio := float64(id+1) * 0.25
					collector.SetRatio(ratio)
					time.Sleep(time.Millisecond)
				}
			}
		}(i)
	}

	// Sampler goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			default:
				monitor.takeSample()
				time.Sleep(time.Millisecond)
			}
		}
	}()

	// Reader goroutines
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-done:
					return
				default:
					_ = monitor.GetCongestionFlag()
					_ = monitor.GetCongestionLevel()
					_ = monitor.GetCurrentRatio()
					_ = monitor.GetSampleCount()
					time.Sleep(time.Millisecond)
				}
			}
		}()
	}

	// Run for a short duration
	time.Sleep(100 * time.Millisecond)
	close(done)
	wg.Wait()
}

// TestRouterMetricsCollector verifies the production metrics collector
func TestRouterMetricsCollector(t *testing.T) {
	participantCount := 1000
	maxParticipants := 10000

	collector := NewRouterMetricsCollector(
		WithParticipantCount(func() int { return participantCount }),
		WithMaxParticipants(func() int { return maxParticipants }),
	)

	ratio := collector.GetParticipatingTunnelRatio()
	expectedRatio := float64(participantCount) / float64(maxParticipants)
	if ratio != expectedRatio {
		t.Errorf("GetParticipatingTunnelRatio() = %v, want %v", ratio, expectedRatio)
	}

	// Test bandwidth utilization
	collector2 := NewRouterMetricsCollector(
		WithBandwidthRates(func() (uint64, uint64) { return 500, 1000 }),
		WithMaxBandwidth(func() uint64 { return 2000 }),
	)

	bwUtil := collector2.GetBandwidthUtilization()
	if bwUtil != 0.5 {
		t.Errorf("GetBandwidthUtilization() = %v, want 0.5", bwUtil)
	}

	// Test connection utilization
	collector3 := NewRouterMetricsCollector(
		WithConnectionCount(func() int { return 100 }),
		WithMaxConnections(func() int { return 200 }),
	)

	connUtil := collector3.GetConnectionUtilization()
	if connUtil != 0.5 {
		t.Errorf("GetConnectionUtilization() = %v, want 0.5", connUtil)
	}
}

// TestRouterMetricsCollector_EdgeCases verifies edge case handling
func TestRouterMetricsCollector_EdgeCases(t *testing.T) {
	t.Run("zero max participants", func(t *testing.T) {
		collector := NewRouterMetricsCollector(
			WithParticipantCount(func() int { return 100 }),
			WithMaxParticipants(func() int { return 0 }),
		)
		ratio := collector.GetParticipatingTunnelRatio()
		if ratio != 0 {
			t.Errorf("with zero max, ratio = %v, want 0", ratio)
		}
	})

	t.Run("ratio capped at 1.0", func(t *testing.T) {
		collector := NewRouterMetricsCollector(
			WithParticipantCount(func() int { return 200 }),
			WithMaxParticipants(func() int { return 100 }),
		)
		ratio := collector.GetParticipatingTunnelRatio()
		if ratio != 1.0 {
			t.Errorf("over limit, ratio = %v, want 1.0", ratio)
		}
	})

	t.Run("unlimited bandwidth", func(t *testing.T) {
		collector := NewRouterMetricsCollector(
			WithBandwidthRates(func() (uint64, uint64) { return 1000000, 1000000 }),
			WithMaxBandwidth(func() uint64 { return 0 }), // 0 = unlimited
		)
		util := collector.GetBandwidthUtilization()
		if util != 0 {
			t.Errorf("unlimited bandwidth, util = %v, want 0", util)
		}
	})

	t.Run("accepting tunnels default", func(t *testing.T) {
		collector := NewRouterMetricsCollector()
		if !collector.IsAcceptingTunnels() {
			t.Error("default should accept tunnels")
		}
	})
}

// TestCongestionMonitor_RollingAverage verifies rolling average calculation
func TestCongestionMonitor_RollingAverage(t *testing.T) {
	cfg := config.Defaults().Congestion
	collector := newMockCollector()
	monitor := NewCongestionMonitor(cfg, collector)
	monitor.maxSamples = 5 // Small window for testing

	// Add samples at 0.50
	collector.SetRatio(0.50)
	for i := 0; i < 5; i++ {
		monitor.takeSample()
	}
	if ratio := monitor.GetCurrentRatio(); ratio < 0.49 || ratio > 0.51 {
		t.Errorf("after 5 samples at 0.50, ratio = %v, want ~0.50", ratio)
	}

	// Add samples at 0.90, old samples should roll out
	collector.SetRatio(0.90)
	for i := 0; i < 5; i++ {
		monitor.takeSample()
	}
	if ratio := monitor.GetCurrentRatio(); ratio < 0.89 || ratio > 0.91 {
		t.Errorf("after 5 more samples at 0.90, ratio = %v, want ~0.90", ratio)
	}
}

// TestCongestionMonitor_BandwidthSaturationTriggersCongestion verifies that
// high bandwidth utilization alone can trigger congestion flags even when
// participating tunnel ratio is low (the bug fixed by incorporating all metrics).
func TestCongestionMonitor_BandwidthSaturationTriggersCongestion(t *testing.T) {
	cfg := config.Defaults().Congestion
	collector := newMockCollector()
	monitor := NewCongestionMonitor(cfg, collector)
	monitor.startupGraceSec = 0

	// Low tunnel ratio but fully saturated bandwidth and connections
	collector.SetAllMetrics(0.10, 1.0, 1.0)

	for i := 0; i < 10; i++ {
		monitor.takeSample()
	}

	// Expected weighted ratio: 0.10*0.50 + 1.0*0.25 + 1.0*0.25 = 0.55
	ratio := monitor.GetCurrentRatio()
	if ratio < 0.54 || ratio > 0.56 {
		t.Errorf("bandwidth-saturated ratio = %v, want ~0.55", ratio)
	}

	// With zero tunnels but full bandwidth/connections:
	// ratio should still be non-zero (0.50), showing bandwidth impact
	collector.SetAllMetrics(0.0, 1.0, 1.0)
	monitor.mu.Lock()
	monitor.samples = nil
	monitor.currentFlag = config.CongestionFlagNone
	monitor.mu.Unlock()

	for i := 0; i < 10; i++ {
		monitor.takeSample()
	}
	ratio = monitor.GetCurrentRatio()
	if ratio < 0.49 || ratio > 0.51 {
		t.Errorf("zero-tunnel but saturated ratio = %v, want ~0.50", ratio)
	}
}
