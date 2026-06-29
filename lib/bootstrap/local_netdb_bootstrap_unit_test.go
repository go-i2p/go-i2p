package bootstrap

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/go-i2p/go-i2p/lib/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLocalNetDBBootstrap_GetDefaultSearchPaths verifies default search paths are populated.
func TestLocalNetDBBootstrap_GetDefaultSearchPaths(t *testing.T) {
	paths := getDefaultNetDBSearchPaths()
	assert.NotEmpty(t, paths, "Default search paths should not be empty")

	// All paths should be absolute or contain home directory references
	for _, path := range paths {
		assert.True(t, filepath.IsAbs(path) || path[0] == '~',
			"Path should be absolute or start with ~: %s", path)
	}
}

// TestLocalNetDBBootstrap_ExpandPath verifies tilde and absolute path expansion.
func TestLocalNetDBBootstrap_ExpandPath(t *testing.T) {
	homeDir, err := os.UserHomeDir()
	require.NoError(t, err)

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Tilde expansion",
			input:    "~/.i2p/netDb",
			expected: filepath.Join(homeDir, ".i2p/netDb"),
		},
		{
			name:     "Absolute path unchanged",
			input:    "/var/lib/i2p/netDb",
			expected: "/var/lib/i2p/netDb",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := expandPath(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestLocalNetDBBootstrap_IsValidNetDbDirectory tests netDb directory validation.
func TestLocalNetDBBootstrap_IsValidNetDbDirectory(t *testing.T) {
	// Create a temporary test directory structure
	tmpDir := t.TempDir()

	tests := []struct {
		name      string
		setupFunc func() string
		expected  bool
	}{
		{
			name: "Valid Java I2P style netDb",
			setupFunc: func() string {
				path := filepath.Join(tmpDir, "java-i2p")
				os.MkdirAll(filepath.Join(path, "r0"), 0o755)
				os.MkdirAll(filepath.Join(path, "ra"), 0o755)
				return path
			},
			expected: true,
		},
		{
			name: "Valid i2pd style netDb",
			setupFunc: func() string {
				path := filepath.Join(tmpDir, "i2pd")
				os.MkdirAll(path, 0o755)
				// Create a dummy routerInfo file
				f, _ := os.Create(filepath.Join(path, "routerInfo-test.dat"))
				f.Close()
				return path
			},
			expected: true,
		},
		{
			name: "Empty directory",
			setupFunc: func() string {
				path := filepath.Join(tmpDir, "empty")
				os.MkdirAll(path, 0o755)
				return path
			},
			expected: false,
		},
		{
			name: "Non-existent directory",
			setupFunc: func() string {
				return filepath.Join(tmpDir, "non-existent")
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := tt.setupFunc()
			lb := &LocalNetDBBootstrap{}
			result := lb.isValidNetDBDirectory(path)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestLocalNetDBBootstrap_GetPeers_NoNetDb verifies error when no netDb is found.
func TestLocalNetDBBootstrap_GetPeers_NoNetDb(t *testing.T) {
	// Create bootstrap with non-existent paths
	lb := NewLocalNetDBBootstrapWithPaths([]string{testNonExistentNetDBPath})

	ctx := context.Background()
	peers, err := lb.GetPeers(ctx, 10)

	assert.Error(t, err)
	assert.Nil(t, peers)
	assert.Contains(t, err.Error(), "no local netDb found")
}

// TestNewLocalNetDBBootstrap_UsesDefaultPaths verifies default path population.
func TestNewLocalNetDBBootstrap_UsesDefaultPaths(t *testing.T) {
	cfg := &config.BootstrapConfig{
		LowPeerThreshold: testLowPeerThreshold,
	}

	lb := NewLocalNetDBBootstrap(cfg)

	assert.NotNil(t, lb)
	assert.NotEmpty(t, lb.searchPaths, "Search paths should be populated with defaults")
}

// TestNewLocalNetDBBootstrap_UsesCustomPaths verifies custom paths are prepended.
func TestNewLocalNetDBBootstrap_UsesCustomPaths(t *testing.T) {
	customPaths := []string{"/custom/path/1", "/custom/path/2"}
	cfg := &config.BootstrapConfig{
		LowPeerThreshold: testLowPeerThreshold,
		LocalNetDBPaths:  customPaths,
	}

	lb := NewLocalNetDBBootstrap(cfg)

	assert.NotNil(t, lb)
	// Custom paths should be prepended to default paths
	assert.GreaterOrEqual(t, len(lb.searchPaths), len(customPaths),
		"Should have at least custom paths")
	// First paths should be the custom ones
	assert.Equal(t, customPaths[0], lb.searchPaths[0])
	assert.Equal(t, customPaths[1], lb.searchPaths[1])
}

// TestLocalNetDBBootstrap_ContextCancellation verifies context cancellation is respected.
func TestLocalNetDBBootstrap_ContextCancellation(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a directory with many dummy files to make reading slow
	netDbPath := filepath.Join(tmpDir, "netDb")
	os.MkdirAll(filepath.Join(netDbPath, "r0"), 0o755)

	// Create some dummy files (not valid RouterInfos, just for testing cancellation)
	for i := 0; i < 100; i++ {
		f, _ := os.Create(filepath.Join(netDbPath, "r0", "routerInfo-dummy.dat"))
		f.Write([]byte("invalid data"))
		f.Close()
	}

	lb := NewLocalNetDBBootstrapWithPaths([]string{netDbPath})

	// Create a context that cancels immediately
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	peers, err := lb.GetPeers(ctx, 10)

	// Should get a context cancellation error
	assert.Error(t, err)
	assert.Nil(t, peers)
}

func TestLocalNetDBBootstrap_GetPeersAggregatesMultipleDirectories(t *testing.T) {
	tmpDir := t.TempDir()
	javaPath := filepath.Join(tmpDir, "java-netDb")
	i2pdPath := filepath.Join(tmpDir, "i2pd-netDb")
	require.NoError(t, os.MkdirAll(filepath.Join(javaPath, "rA"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(i2pdPath, "rB"), 0o755))

	addrCfg1 := testutil.DefaultRouterAddressConfig()
	addrCfg1.Options = map[string]string{"host": testHost, "port": testPort}
	ri1 := testutil.CreateSignedTestRouterInfo(t, map[string]string{"router.version": "0.9.67"}, &addrCfg1)
	ri1Bytes, err := ri1.Bytes()
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(javaPath, "rA", "routerInfo-java.dat"), ri1Bytes, 0o644))

	addrCfg2 := testutil.DefaultRouterAddressConfig()
	addrCfg2.Options = map[string]string{"host": testHost, "port": "12346"}
	ri2 := testutil.CreateSignedTestRouterInfo(t, map[string]string{"router.version": "0.9.68"}, &addrCfg2)
	ri2Bytes, err := ri2.Bytes()
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(i2pdPath, "rB", "routerInfo-i2pd.dat"), ri2Bytes, 0o644))

	lb := NewLocalNetDBBootstrapWithPaths([]string{javaPath, i2pdPath})
	peers, err := lb.GetPeers(context.Background(), 0)
	require.NoError(t, err)
	require.Len(t, peers, 2)
}
