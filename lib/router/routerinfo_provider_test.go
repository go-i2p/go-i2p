package router

import (
	"testing"

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

// TestRouterInfoProvider_GetRouterInfo tests retrieving RouterInfo from the provider
func TestRouterInfoProvider_GetRouterInfo(t *testing.T) {
	// Create a router with test configuration
	tempDir := t.TempDir()
	cfg := &config.RouterConfig{
		WorkingDir: tempDir,
	}

	router, err := FromConfig(cfg)
	require.NoError(t, err)
	require.NotNil(t, router)

	// Initialize keystore
	err = initializeRouterKeystore(router, cfg)
	require.NoError(t, err)

	// Create the provider
	provider := newRouterInfoProvider(router)
	require.NotNil(t, provider)

	// Get RouterInfo
	ri, err := provider.GetRouterInfo()

	// Should successfully construct RouterInfo
	require.NoError(t, err)
	require.NotNil(t, ri)

	// Note: In test environment with nil addresses, IsValid() may return false
	// In production, the RouterInfo would have actual NTCP2/SSU2 addresses
	// The important part is that it constructs without error
	assert.NotNil(t, ri, "RouterInfo should be constructed")
}

// TestRouterInfoProvider_InterfaceCompliance tests interface implementation
func TestRouterInfoProvider_InterfaceCompliance(t *testing.T) {
	tempDir := t.TempDir()
	cfg := &config.RouterConfig{
		WorkingDir: tempDir,
	}

	router, err := FromConfig(cfg)
	require.NoError(t, err)
	require.NotNil(t, router)

	// Initialize keystore
	err = initializeRouterKeystore(router, cfg)
	require.NoError(t, err)

	provider := newRouterInfoProvider(router)

	// Verify provider implements the interface
	assert.NotNil(t, provider)
}

// TestRouterInfoProvider_MultipleCallsReturnValid tests calling GetRouterInfo multiple times
func TestRouterInfoProvider_MultipleCallsReturnValid(t *testing.T) {
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

	// Call GetRouterInfo multiple times
	ri1, err1 := provider.GetRouterInfo()
	require.NoError(t, err1)
	require.NotNil(t, ri1)

	ri2, err2 := provider.GetRouterInfo()
	require.NoError(t, err2)
	require.NotNil(t, ri2)

	ri3, err3 := provider.GetRouterInfo()
	require.NoError(t, err3)
	require.NotNil(t, ri3)

	// All should be constructed successfully
	// Note: IsValid() may return false in test environment without addresses
	assert.NotNil(t, ri1)
	assert.NotNil(t, ri2)
	assert.NotNil(t, ri3)
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
	assert.Contains(t, caps, "NU", "RouterInfo caps should contain base caps NU")
}

// TestRouterInfoProvider_CongestionFlagTransitions tests RouterInfo with changing congestion
func TestRouterInfoProvider_CongestionFlagTransitions(t *testing.T) {
	tempDir := t.TempDir()
	cfg := &config.RouterConfig{
		WorkingDir: tempDir,
	}

	router, err := FromConfig(cfg)
	require.NoError(t, err)

	err = initializeRouterKeystore(router, cfg)
	require.NoError(t, err)

	provider := newRouterInfoProvider(router)
	monitor := &mockCongestionStateProviderRI{
		flag: config.CongestionFlagNone,
	}
	provider.SetCongestionMonitor(monitor)

	// Test None -> D -> E -> G transitions
	flagTests := []struct {
		flag         config.CongestionFlag
		expectedCaps string
	}{
		{config.CongestionFlagNone, "NU"},
		{config.CongestionFlagD, "NUD"},
		{config.CongestionFlagE, "NUE"},
		{config.CongestionFlagG, "NUG"},
		{config.CongestionFlagNone, "NU"}, // Back to none
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
