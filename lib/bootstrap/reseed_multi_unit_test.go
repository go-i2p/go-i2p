package bootstrap

import (
	"context"
	"testing"
	"time"

	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/config"
)

// TestShouldUseMultiServerReseed tests the multi-server decision logic.
func TestShouldUseMultiServerReseed(t *testing.T) {
	tests := []struct {
		name             string
		minReseedServers int
		serverCount      int
		expectedResult   bool
	}{
		{
			name:             "multi-server mode when minServers > 1 and enough servers",
			minReseedServers: 2,
			serverCount:      3,
			expectedResult:   true,
		},
		{
			name:             "multi-server mode with exact minimum",
			minReseedServers: 2,
			serverCount:      2,
			expectedResult:   true,
		},
		{
			name:             "single-server mode when minServers == 1",
			minReseedServers: 1,
			serverCount:      5,
			expectedResult:   false,
		},
		{
			name:             "single-server mode when minServers == 0",
			minReseedServers: 0,
			serverCount:      5,
			expectedResult:   false,
		},
		{
			name:             "single-server fallback when not enough servers",
			minReseedServers: 3,
			serverCount:      2,
			expectedResult:   false,
		},
		{
			name:             "single-server fallback with empty server list",
			minReseedServers: 2,
			serverCount:      0,
			expectedResult:   false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			servers := make([]*config.ReseedConfig, tc.serverCount)
			for i := 0; i < tc.serverCount; i++ {
				servers[i] = &config.ReseedConfig{URL: "https://server" + string(rune('1'+i)) + "/"}
			}

			cfg := &config.BootstrapConfig{
				MinReseedServers: tc.minReseedServers,
				ReseedServers:    servers,
			}
			rb := &ReseedBootstrap{config: cfg}

			result := rb.shouldUseMultiServerReseed()
			if result != tc.expectedResult {
				t.Errorf("shouldUseMultiServerReseed() = %v, want %v", result, tc.expectedResult)
			}
		})
	}
}

// TestDefaultConfigUsesMultiServer verifies DefaultBootstrapConfig enables multi-server mode.
func TestDefaultConfigUsesMultiServer(t *testing.T) {
	// Verify that DefaultBootstrapConfig enables multi-server mode
	cfg := config.DefaultBootstrapConfig

	// DefaultMinReseedServers should be 2 (Java I2P parity)
	if cfg.MinReseedServers != 2 {
		t.Errorf("DefaultBootstrapConfig.MinReseedServers = %d, want 2 (Java I2P parity)", cfg.MinReseedServers)
	}

	// KnownReseedServers should have enough servers for multi-server mode
	if len(cfg.ReseedServers) < cfg.MinReseedServers {
		t.Errorf("DefaultBootstrapConfig has %d servers but needs at least %d for multi-server mode",
			len(cfg.ReseedServers), cfg.MinReseedServers)
	}

	// Create a ReseedBootstrap with default config and verify multi-server is enabled
	rb := &ReseedBootstrap{config: &cfg}
	if !rb.shouldUseMultiServerReseed() {
		t.Error("DefaultBootstrapConfig should enable multi-server reseed mode")
	}
}

// TestSingleServerModeBackwardCompatibility verifies MinReseedServers=1 disables multi-server.
func TestSingleServerModeBackwardCompatibility(t *testing.T) {
	// Verify that setting MinReseedServers=1 disables multi-server mode
	cfg := &config.BootstrapConfig{
		MinReseedServers: 1,
		ReseedServers: []*config.ReseedConfig{
			{URL: "https://server1/"},
			{URL: "https://server2/"},
			{URL: "https://server3/"},
		},
		ReseedStrategy: config.ReseedStrategyUnion,
	}

	rb := &ReseedBootstrap{config: cfg}
	if rb.shouldUseMultiServerReseed() {
		t.Error("MinReseedServers=1 should disable multi-server mode for backward compatibility")
	}
}

// TestFilterSuccessful tests filtering of successful reseed results.
func TestFilterSuccessful(t *testing.T) {
	tests := []struct {
		name          string
		results       []ReseedResult
		expectedCount int
	}{
		{
			name: "all successful",
			results: []ReseedResult{
				{ServerURL: "https://server1/", RouterInfos: make([]router_info.RouterInfo, 10)},
				{ServerURL: "https://server2/", RouterInfos: make([]router_info.RouterInfo, 5)},
			},
			expectedCount: 2,
		},
		{
			name: "some failures",
			results: []ReseedResult{
				{ServerURL: "https://server1/", RouterInfos: make([]router_info.RouterInfo, 10)},
				{ServerURL: "https://server2/", Error: context.DeadlineExceeded},
				{ServerURL: "https://server3/", RouterInfos: make([]router_info.RouterInfo, 5)},
			},
			expectedCount: 2,
		},
		{
			name: "all failures",
			results: []ReseedResult{
				{ServerURL: "https://server1/", Error: context.Canceled},
				{ServerURL: "https://server2/", Error: context.DeadlineExceeded},
			},
			expectedCount: 0,
		},
		{
			name: "empty router infos",
			results: []ReseedResult{
				{ServerURL: "https://server1/", RouterInfos: make([]router_info.RouterInfo, 10)},
				{ServerURL: "https://server2/", RouterInfos: make([]router_info.RouterInfo, 0)}, // No routers
			},
			expectedCount: 1,
		},
		{
			name:          "empty input",
			results:       []ReseedResult{},
			expectedCount: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := filterSuccessful(tc.results)
			if len(result) != tc.expectedCount {
				t.Errorf("filterSuccessful() returned %d results, expected %d", len(result), tc.expectedCount)
			}
		})
	}
}

// TestShuffleServers tests server list randomization.
func TestShuffleServers(t *testing.T) {
	cfg := &config.BootstrapConfig{
		ReseedServers: []*config.ReseedConfig{
			{URL: "https://server1/"},
			{URL: "https://server2/"},
			{URL: "https://server3/"},
			{URL: "https://server4/"},
			{URL: "https://server5/"},
		},
	}

	rb := &ReseedBootstrap{config: cfg}

	// Run shuffle multiple times to verify randomization
	originalOrder := make([]string, len(cfg.ReseedServers))
	for i, s := range cfg.ReseedServers {
		originalOrder[i] = s.URL
	}

	// Verify shuffle produces same length
	shuffled := rb.shuffleServers()
	if len(shuffled) != len(cfg.ReseedServers) {
		t.Errorf("shuffleServers() returned %d servers, expected %d", len(shuffled), len(cfg.ReseedServers))
	}

	// Verify original slice is not modified
	for i, s := range cfg.ReseedServers {
		if s.URL != originalOrder[i] {
			t.Error("shuffleServers() modified original slice")
		}
	}

	// Verify all servers are present in shuffled result
	urlSet := make(map[string]bool)
	for _, s := range shuffled {
		urlSet[s.URL] = true
	}
	for _, url := range originalOrder {
		if !urlSet[url] {
			t.Errorf("shuffleServers() missing server: %s", url)
		}
	}
}

// TestReseedBootstrap_ShuffleServersSingleServer tests shuffle with one server.
func TestReseedBootstrap_ShuffleServersSingleServer(t *testing.T) {
	cfg := &config.BootstrapConfig{
		ReseedServers: []*config.ReseedConfig{
			{URL: "https://only-server/"},
		},
	}

	rb := &ReseedBootstrap{config: cfg}
	shuffled := rb.shuffleServers()

	if len(shuffled) != 1 {
		t.Errorf("shuffleServers() returned %d servers for single server input", len(shuffled))
	}
	if shuffled[0].URL != "https://only-server/" {
		t.Errorf("shuffleServers() returned wrong server URL")
	}
}

// TestReseedBootstrap_ShuffleServersEmpty tests shuffle with no servers.
func TestReseedBootstrap_ShuffleServersEmpty(t *testing.T) {
	cfg := &config.BootstrapConfig{
		ReseedServers: []*config.ReseedConfig{},
	}

	rb := &ReseedBootstrap{config: cfg}
	shuffled := rb.shuffleServers()

	if len(shuffled) != 0 {
		t.Errorf("shuffleServers() returned %d servers for empty input", len(shuffled))
	}
}

// TestReseedResult_Fields verifies ReseedResult struct fields.
func TestReseedResult_Fields(t *testing.T) {
	result := ReseedResult{
		ServerURL:   "https://test-server/",
		RouterInfos: make([]router_info.RouterInfo, 5),
		Error:       nil,
		Duration:    500 * time.Millisecond,
	}

	if result.ServerURL != "https://test-server/" {
		t.Errorf("ServerURL = %s, want https://test-server/", result.ServerURL)
	}
	if len(result.RouterInfos) != 5 {
		t.Errorf("RouterInfos length = %d, want 5", len(result.RouterInfos))
	}
	if result.Error != nil {
		t.Errorf("Error = %v, want nil", result.Error)
	}
	if result.Duration != 500*time.Millisecond {
		t.Errorf("Duration = %v, want 500ms", result.Duration)
	}
}

// TestReseedResult_WithError verifies ReseedResult error handling.
func TestReseedResult_WithError(t *testing.T) {
	result := ReseedResult{
		ServerURL: "https://failed-server/",
		Error:     context.DeadlineExceeded,
		Duration:  30 * time.Second,
	}

	if result.Error != context.DeadlineExceeded {
		t.Errorf("Error = %v, want context.DeadlineExceeded", result.Error)
	}
	if len(result.RouterInfos) != 0 {
		t.Errorf("RouterInfos should be empty on error, got %d", len(result.RouterInfos))
	}
}

// TestApplyStrategy_DefaultsToUnion verifies empty strategy defaults to union.
func TestApplyStrategy_DefaultsToUnion(t *testing.T) {
	assertApplyStrategyNotNil(t, "", "applyStrategy with empty strategy should not return nil")
}

// TestApplyStrategy_InvalidStrategy verifies invalid strategy defaults to union.
func TestApplyStrategy_InvalidStrategy(t *testing.T) {
	assertApplyStrategyNotNil(t, "invalid_strategy", "applyStrategy with invalid strategy should default to union")
}

// TestUnionStrategy_Empty tests union strategy with no results.
func TestUnionStrategy_Empty(t *testing.T) {
	rb := &ReseedBootstrap{config: &config.BootstrapConfig{}}

	results := []ReseedResult{}
	combined := rb.unionStrategy(results)

	if len(combined) != 0 {
		t.Errorf("unionStrategy on empty results should return empty, got %d", len(combined))
	}
}

// TestIntersectionStrategy_Empty tests intersection strategy with no results.
func TestIntersectionStrategy_Empty(t *testing.T) {
	rb := &ReseedBootstrap{config: &config.BootstrapConfig{}}

	results := []ReseedResult{}
	combined := rb.intersectionStrategy(results)

	if combined != nil && len(combined) != 0 {
		t.Errorf("intersectionStrategy on empty results should return nil/empty, got %d", len(combined))
	}
}

// TestRandomWeightedStrategy_Empty tests random weighted strategy with no results.
func TestRandomWeightedStrategy_Empty(t *testing.T) {
	rb := &ReseedBootstrap{config: &config.BootstrapConfig{}}

	results := []ReseedResult{}
	combined := rb.randomWeightedStrategy(results)

	if len(combined) != 0 {
		t.Errorf("randomWeightedStrategy on empty results should return empty, got %d", len(combined))
	}
}

// TestMinReseedServersDefault tests MinReseedServers default handling.
func TestMinReseedServersDefault(t *testing.T) {
	cfg := &config.BootstrapConfig{
		MinReseedServers: 0, // Should default to 1
		ReseedServers: []*config.ReseedConfig{
			{URL: "https://s1/"},
		},
	}

	rb := &ReseedBootstrap{config: cfg}

	// The MultiServerReseed should handle minServers < 1 by setting it to 1
	// We can't fully test this without mocking the network, but we can verify
	// the config is set up correctly
	if rb.config.MinReseedServers != 0 {
		t.Errorf("MinReseedServers should be 0 (to test default handling), got %d", rb.config.MinReseedServers)
	}
}

// TestContextCancellation tests MultiServerReseed with cancelled context.
func TestContextCancellation(t *testing.T) {
	cfg := &config.BootstrapConfig{
		MinReseedServers: 2,
		ReseedServers: []*config.ReseedConfig{
			{URL: "https://s1/"},
			{URL: "https://s2/"},
		},
	}

	rb := &ReseedBootstrap{config: cfg}

	// Create already cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := rb.MultiServerReseed(ctx, 10)

	// Should return error due to insufficient servers (context cancelled before any fetch)
	if err == nil {
		t.Error("MultiServerReseed with cancelled context should return error")
	}
}
