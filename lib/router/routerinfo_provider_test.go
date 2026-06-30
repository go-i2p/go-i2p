package router

import (
	"testing"
	"time"

	"github.com/go-i2p/common/router_address"
	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockCongestionStateProvider implements CongestionStateProvider for testing
type mockCongestionStateProviderRI struct {
	flag      config.CongestionFlag
	level     int
	shouldAdv bool
	callCount int
}

func (m *mockCongestionStateProviderRI) GetCongestionFlag() config.CongestionFlag {
	m.callCount++
	return m.flag
}

func (m *mockCongestionStateProviderRI) GetCongestionLevel() int {
	return m.level
}

func (m *mockCongestionStateProviderRI) ShouldAdvertiseCongestion() bool {
	return m.shouldAdv
}

// newTestRouterInfoProvider creates a router + keystore + provider for testing.
// Reduces repeated setup across routerinfo_provider tests.
func newTestRouterInfoProvider(t *testing.T) *routerInfoProvider {
	t.Helper()
	tempDir := t.TempDir()
	cfg := &config.RouterConfig{
		WorkingDir: tempDir,
	}
	router, err := FromConfig(cfg)
	require.NoError(t, err)
	require.NotNil(t, router)
	err = initializeRouterKeystore(router, cfg)
	require.NoError(t, err)
	provider := newRouterInfoProvider(router)
	require.NotNil(t, provider)
	return provider
}

// TestRouterInfoProvider_GetRouterInfo tests retrieving RouterInfo from the provider
func TestRouterInfoProvider_GetRouterInfo(t *testing.T) {
	provider := newTestRouterInfoProvider(t)

	ri, err := provider.GetRouterInfo()

	require.NoError(t, err)
	require.NotNil(t, ri)
	assert.NotNil(t, ri, "RouterInfo should be constructed")
}

// TestRouterInfoProvider_InterfaceCompliance tests interface implementation
func TestRouterInfoProvider_InterfaceCompliance(t *testing.T) {
	provider := newTestRouterInfoProvider(t)
	assert.NotNil(t, provider)
}

// TestRouterInfoProvider_MultipleCallsReturnValid tests calling GetRouterInfo multiple times
func TestRouterInfoProvider_MultipleCallsReturnValid(t *testing.T) {
	provider := newTestRouterInfoProvider(t)

	for i := 0; i < 3; i++ {
		ri, err := provider.GetRouterInfo()
		require.NoError(t, err)
		require.NotNil(t, ri)
	}
}

// TestRouterInfoProvider_BuildRouterInfoOptions tests options building with congestion
func TestRouterInfoProvider_BuildRouterInfoOptions(t *testing.T) {
	tests := []struct {
		name         string
		monitor      CongestionStateProvider
		expectedFlag string
	}{
		{
			name:         "nil monitor - empty flag",
			monitor:      nil,
			expectedFlag: "",
		},
		{
			name: "no congestion",
			monitor: &mockCongestionStateProviderRI{
				flag: config.CongestionFlagNone,
			},
			expectedFlag: "",
		},
		{
			name: "D flag",
			monitor: &mockCongestionStateProviderRI{
				flag: config.CongestionFlagD,
			},
			expectedFlag: "D",
		},
		{
			name: "E flag",
			monitor: &mockCongestionStateProviderRI{
				flag: config.CongestionFlagE,
			},
			expectedFlag: "E",
		},
		{
			name: "G flag",
			monitor: &mockCongestionStateProviderRI{
				flag: config.CongestionFlagG,
			},
			expectedFlag: "G",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := &routerInfoProvider{
				router:            nil, // Not needed for this test
				congestionMonitor: tt.monitor,
			}

			opts := provider.buildRouterInfoOptions()

			if opts.CongestionFlag != tt.expectedFlag {
				t.Errorf("CongestionFlag = %q, want %q", opts.CongestionFlag, tt.expectedFlag)
			}
		})
	}
}

// TestRouterInfoProvider_GetCongestionFlag tests the GetCongestionFlag helper method
func TestRouterInfoProvider_GetCongestionFlag(t *testing.T) {
	tests := []struct {
		name         string
		monitor      CongestionStateProvider
		expectedFlag string
	}{
		{
			name:         "nil monitor",
			monitor:      nil,
			expectedFlag: "",
		},
		{
			name: "D flag",
			monitor: &mockCongestionStateProviderRI{
				flag: config.CongestionFlagD,
			},
			expectedFlag: "D",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := &routerInfoProvider{
				congestionMonitor: tt.monitor,
			}

			flag := provider.GetCongestionFlag()

			if flag != tt.expectedFlag {
				t.Errorf("GetCongestionFlag() = %q, want %q", flag, tt.expectedFlag)
			}
		})
	}
}

// TestRouterInfoProvider_SetCongestionMonitor tests setting the congestion monitor
func TestRouterInfoProvider_SetCongestionMonitor(t *testing.T) {
	provider := &routerInfoProvider{}

	if provider.congestionMonitor != nil {
		t.Error("Initial congestion monitor should be nil")
	}

	monitor := &mockCongestionStateProviderRI{
		flag: config.CongestionFlagE,
	}

	provider.SetCongestionMonitor(monitor)

	if provider.congestionMonitor == nil {
		t.Error("Congestion monitor should be set")
	}

	if provider.GetCongestionFlag() != "E" {
		t.Errorf("Expected flag 'E', got %q", provider.GetCongestionFlag())
	}
}

// TestRouterInfoProvider_CongestionFlagChangeTracking tests that flag changes are tracked
func TestRouterInfoProvider_CongestionFlagChangeTracking(t *testing.T) {
	monitor := &mockCongestionStateProviderRI{
		flag: config.CongestionFlagNone,
	}

	provider := &routerInfoProvider{
		congestionMonitor: monitor,
	}

	// First call - should set lastCongestionFlag
	opts := provider.buildRouterInfoOptions()
	if opts.CongestionFlag != "" {
		t.Errorf("First call: expected empty flag, got %q", opts.CongestionFlag)
	}
	if flag, _ := provider.lastCongestionFlag.Load().(string); flag != "" {
		t.Errorf("First call: lastCongestionFlag should be empty, got %q", flag)
	}

	// Change the flag
	monitor.flag = config.CongestionFlagD

	// Second call - should update lastCongestionFlag
	opts = provider.buildRouterInfoOptions()
	if opts.CongestionFlag != "D" {
		t.Errorf("Second call: expected 'D', got %q", opts.CongestionFlag)
	}
	if flag, _ := provider.lastCongestionFlag.Load().(string); flag != "D" {
		t.Errorf("Second call: lastCongestionFlag should be 'D', got %q", flag)
	}

	// Change to E
	monitor.flag = config.CongestionFlagE

	// Third call - should detect change from D to E
	opts = provider.buildRouterInfoOptions()
	if opts.CongestionFlag != "E" {
		t.Errorf("Third call: expected 'E', got %q", opts.CongestionFlag)
	}
	if flag, _ := provider.lastCongestionFlag.Load().(string); flag != "E" {
		t.Errorf("Third call: lastCongestionFlag should be 'E', got %q", flag)
	}
}

// TestRouterInfoProvider_WithCongestionIntegration tests full integration with congestion monitor
func TestRouterInfoProvider_WithCongestionIntegration(t *testing.T) {
	provider := newTestRouterInfoProvider(t)

	// Set a mock congestion monitor with D flag
	monitor := &mockCongestionStateProviderRI{
		flag: config.CongestionFlagD,
	}
	provider.SetCongestionMonitor(monitor)

	// Get RouterInfo - should include congestion flag
	ri, err := provider.GetRouterInfo()
	require.NoError(t, err)
	require.NotNil(t, ri)

	// Check that the caps include the D flag
	// RouterCapabilities may include I2P length prefix, so use Contains
	caps := ri.RouterCapabilities()
	assert.Contains(t, caps, "D", "RouterInfo caps should contain D flag")
	assert.Contains(t, caps, "LU", "RouterInfo caps should contain base caps LU")
}

// TestRouterInfoProvider_CongestionFlagTransitions tests RouterInfo with changing congestion
func TestRouterInfoProvider_CongestionFlagTransitions(t *testing.T) {
	provider := newTestRouterInfoProvider(t)
	monitor := &mockCongestionStateProviderRI{
		flag: config.CongestionFlagNone,
	}
	provider.SetCongestionMonitor(monitor)

	// Test None -> D -> E -> G transitions
	flagTests := []struct {
		flag         config.CongestionFlag
		expectedCaps string
	}{
		{config.CongestionFlagNone, "LU"},
		{config.CongestionFlagD, "LUD"},
		{config.CongestionFlagE, "LUE"},
		{config.CongestionFlagG, "LUG"},
		{config.CongestionFlagNone, "LU"}, // Back to none
	}

	for _, tt := range flagTests {
		monitor.flag = tt.flag

		ri, err := provider.GetRouterInfo()
		require.NoError(t, err)

		// RouterCapabilities may include I2P length prefix, so use Contains
		caps := ri.RouterCapabilities()
		assert.Contains(t, caps, tt.expectedCaps, "Caps should contain %q for flag %q", tt.expectedCaps, tt.flag)
	}
}

func TestIsPubliclyRoutableHost(t *testing.T) {
	tests := []struct {
		name string
		host string
		want bool
	}{
		{name: "empty", host: "", want: false},
		{name: "hostname", host: "example.com", want: false},
		{name: "private ipv4", host: "192.168.1.10", want: false},
		{name: "loopback ipv4", host: "127.0.0.1", want: false},
		{name: "link local ipv4", host: "169.254.1.1", want: false},
		{name: "loopback ipv6", host: "::1", want: false},
		{name: "link local ipv6", host: "fe80::1", want: false},
		{name: "unique local ipv6", host: "fc00::1", want: false},
		{name: "cgnat ipv4", host: "100.64.1.1", want: false},
		{name: "test-net-1 ipv4", host: "192.0.2.10", want: false},
		{name: "test-net-2 ipv4", host: "198.51.100.10", want: false},
		{name: "test-net-3 ipv4", host: "203.0.113.10", want: false},
		{name: "public ipv4", host: "8.8.8.8", want: true},
		{name: "public ipv6", host: "2001:4860:4860::8888", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isPubliclyRoutableHost(tt.host))
		})
	}
}

func TestHasReachableAddress_UsesPublicRoutableHostPolicy(t *testing.T) {
	makeAddr := func(host string) *router_address.RouterAddress {
		opts := map[string]string{
			router_address.PORT_OPTION_KEY: "12345",
		}
		if host != "" {
			opts[router_address.HOST_OPTION_KEY] = host
		}
		addr, err := router_address.NewRouterAddress(10, time.Time{}, "NTCP2", opts)
		require.NoError(t, err)
		return addr
	}

	tests := []struct {
		name  string
		hosts []string
		want  bool
	}{
		{name: "nil address list", hosts: nil, want: false},
		{name: "no host option", hosts: []string{""}, want: false},
		{name: "private only", hosts: []string{"10.0.0.3", "192.168.1.2"}, want: false},
		{name: "loopback only", hosts: []string{"127.0.0.1", "::1"}, want: false},
		{name: "link local only", hosts: []string{"169.254.2.2", "fe80::2"}, want: false},
		{name: "special-use only", hosts: []string{"100.64.5.5", "192.0.2.7", "198.51.100.8", "203.0.113.9"}, want: false},
		{name: "public ipv4 present", hosts: []string{"10.0.0.3", "8.8.8.8"}, want: true},
		{name: "public ipv6 present", hosts: []string{"fc00::2", "2001:4860:4860::8888"}, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addresses := make([]*router_address.RouterAddress, 0, len(tt.hosts)+1)
			addresses = append(addresses, nil) // Ensure nil entries are ignored.
			for _, host := range tt.hosts {
				addresses = append(addresses, makeAddr(host))
			}
			assert.Equal(t, tt.want, hasReachableAddress(addresses))
		})
	}
}
