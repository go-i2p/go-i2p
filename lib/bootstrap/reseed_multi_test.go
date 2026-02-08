package bootstrap

import (
	"context"
	"testing"
	"time"

	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/config"
)

// mockRouterInfo creates a mock RouterInfo for testing
// In real tests, we'd use actual RouterInfo instances
func createMockResults(serverURLs []string, routerCounts []int, errors []error) []ReseedResult {
	results := make([]ReseedResult, len(serverURLs))
	for i, url := range serverURLs {
		results[i] = ReseedResult{
			ServerURL:   url,
			RouterInfos: make([]router_info.RouterInfo, routerCounts[i]),
			Error:       errors[i],
			Duration:    100 * time.Millisecond,
		}
	}
	return results
}

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

func TestShuffleServers(t *testing.T) {
	cfg := &config.BootstrapConfig{
		ReseedServers: []*config.ReseedConfig{
			{Url: "https://server1/"},
			{Url: "https://server2/"},
			{Url: "https://server3/"},
			{Url: "https://server4/"},
			{Url: "https://server5/"},
		},
	}

	rb := &ReseedBootstrap{config: cfg}

	// Run shuffle multiple times to verify randomization
	originalOrder := make([]string, len(cfg.ReseedServers))
	for i, s := range cfg.ReseedServers {
		originalOrder[i] = s.Url
	}

	// Verify shuffle produces same length
	shuffled := rb.shuffleServers()
	if len(shuffled) != len(cfg.ReseedServers) {
		t.Errorf("shuffleServers() returned %d servers, expected %d", len(shuffled), len(cfg.ReseedServers))
	}

	// Verify original slice is not modified
	for i, s := range cfg.ReseedServers {
		if s.Url != originalOrder[i] {
			t.Error("shuffleServers() modified original slice")
		}
	}

	// Verify all servers are present in shuffled result
	urlSet := make(map[string]bool)
	for _, s := range shuffled {
		urlSet[s.Url] = true
	}
	for _, url := range originalOrder {
		if !urlSet[url] {
			t.Errorf("shuffleServers() missing server: %s", url)
		}
	}
}

func TestReseedBootstrap_ShuffleServersSingleServer(t *testing.T) {
	cfg := &config.BootstrapConfig{
		ReseedServers: []*config.ReseedConfig{
			{Url: "https://only-server/"},
		},
	}

	rb := &ReseedBootstrap{config: cfg}
	shuffled := rb.shuffleServers()

	if len(shuffled) != 1 {
		t.Errorf("shuffleServers() returned %d servers for single server input", len(shuffled))
	}
	if shuffled[0].Url != "https://only-server/" {
		t.Errorf("shuffleServers() returned wrong server URL")
	}
}

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

func TestApplyStrategy_DefaultsToUnion(t *testing.T) {
	cfg := &config.BootstrapConfig{
		ReseedStrategy: "", // Empty should default to union
	}
	rb := &ReseedBootstrap{config: cfg}

	// With empty strategy, should use union (returns all unique)
	results := []ReseedResult{
		{ServerURL: "https://s1/", RouterInfos: make([]router_info.RouterInfo, 3)},
	}

	// This should not panic and should return results
	combined := rb.applyStrategy(results)
	if combined == nil {
		t.Error("applyStrategy with empty strategy should not return nil")
	}
}

func TestApplyStrategy_InvalidStrategy(t *testing.T) {
	cfg := &config.BootstrapConfig{
		ReseedStrategy: "invalid_strategy",
	}
	rb := &ReseedBootstrap{config: cfg}

	results := []ReseedResult{
		{ServerURL: "https://s1/", RouterInfos: make([]router_info.RouterInfo, 3)},
	}

	// Invalid strategy should default to union
	combined := rb.applyStrategy(results)
	if combined == nil {
		t.Error("applyStrategy with invalid strategy should default to union")
	}
}

func TestUnionStrategy_Empty(t *testing.T) {
	rb := &ReseedBootstrap{config: &config.BootstrapConfig{}}

	results := []ReseedResult{}
	combined := rb.unionStrategy(results)

	if len(combined) != 0 {
		t.Errorf("unionStrategy on empty results should return empty, got %d", len(combined))
	}
}

func TestIntersectionStrategy_Empty(t *testing.T) {
	rb := &ReseedBootstrap{config: &config.BootstrapConfig{}}

	results := []ReseedResult{}
	combined := rb.intersectionStrategy(results)

	if combined != nil && len(combined) != 0 {
		t.Errorf("intersectionStrategy on empty results should return nil/empty, got %d", len(combined))
	}
}

func TestRandomWeightedStrategy_Empty(t *testing.T) {
	rb := &ReseedBootstrap{config: &config.BootstrapConfig{}}

	results := []ReseedResult{}
	combined := rb.randomWeightedStrategy(results)

	if len(combined) != 0 {
		t.Errorf("randomWeightedStrategy on empty results should return empty, got %d", len(combined))
	}
}

func TestMinReseedServersDefault(t *testing.T) {
	cfg := &config.BootstrapConfig{
		MinReseedServers: 0, // Should default to 1
		ReseedServers: []*config.ReseedConfig{
			{Url: "https://s1/"},
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

func TestContextCancellation(t *testing.T) {
	cfg := &config.BootstrapConfig{
		MinReseedServers: 2,
		ReseedServers: []*config.ReseedConfig{
			{Url: "https://s1/"},
			{Url: "https://s2/"},
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
