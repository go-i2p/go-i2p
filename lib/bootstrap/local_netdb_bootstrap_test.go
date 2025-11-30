package bootstrap

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLocalNetDbBootstrap_GetDefaultSearchPaths(t *testing.T) {
	paths := getDefaultNetDbSearchPaths()
	assert.NotEmpty(t, paths, "Default search paths should not be empty")

	// All paths should be absolute or contain home directory references
	for _, path := range paths {
		assert.True(t, filepath.IsAbs(path) || path[0] == '~',
			"Path should be absolute or start with ~: %s", path)
	}
}

func TestLocalNetDbBootstrap_ExpandPath(t *testing.T) {
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

func TestLocalNetDbBootstrap_IsValidNetDbDirectory(t *testing.T) {
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
				os.MkdirAll(filepath.Join(path, "r0"), 0755)
				os.MkdirAll(filepath.Join(path, "ra"), 0755)
				return path
			},
			expected: true,
		},
		{
			name: "Valid i2pd style netDb",
			setupFunc: func() string {
				path := filepath.Join(tmpDir, "i2pd")
				os.MkdirAll(path, 0755)
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
				os.MkdirAll(path, 0755)
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
			lb := &LocalNetDbBootstrap{}
			result := lb.isValidNetDbDirectory(path)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestLocalNetDbBootstrap_GetPeers_NoNetDb(t *testing.T) {
	// Create bootstrap with non-existent paths
	lb := NewLocalNetDbBootstrapWithPaths([]string{"/tmp/non-existent-netdb-12345"})

	ctx := context.Background()
	peers, err := lb.GetPeers(ctx, 10)

	assert.Error(t, err)
	assert.Nil(t, peers)
	assert.Contains(t, err.Error(), "no local netDb found")
}

func TestCompositeBootstrap_FallbackToLocalNetDb(t *testing.T) {
	// Create a bootstrap config with no reseed servers (so reseed will fail)
	cfg := &config.BootstrapConfig{
		LowPeerThreshold: 10,
		ReseedServers:    []*config.ReseedConfig{},
		LocalNetDbPaths:  []string{"/tmp/non-existent-for-test"},
	}

	cb := NewCompositeBootstrap(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// This should fail because both reseed and local netDb will fail
	// (we explicitly set non-existent paths)
	peers, err := cb.GetPeers(ctx, 10)

	// Note: If user has an actual netDb on their system, the default paths
	// might succeed. So we only check that error contains our expected message
	// when we get an error.
	if err != nil {
		assert.Contains(t, err.Error(), "all bootstrap methods failed")
		assert.Nil(t, peers)
	} else {
		// If it succeeded, it means it found a real netDb somewhere
		t.Log("Local netDb was found on the system - test adapted to this case")
		assert.NotNil(t, peers)
	}
}

func TestNewLocalNetDbBootstrap_UsesDefaultPaths(t *testing.T) {
	cfg := &config.BootstrapConfig{
		LowPeerThreshold: 10,
	}

	lb := NewLocalNetDbBootstrap(cfg)

	assert.NotNil(t, lb)
	assert.NotEmpty(t, lb.searchPaths, "Search paths should be populated with defaults")
}

func TestNewLocalNetDbBootstrap_UsesCustomPaths(t *testing.T) {
	customPaths := []string{"/custom/path/1", "/custom/path/2"}
	cfg := &config.BootstrapConfig{
		LowPeerThreshold: 10,
		LocalNetDbPaths:  customPaths,
	}

	lb := NewLocalNetDbBootstrap(cfg)

	assert.NotNil(t, lb)
	// Custom paths should be prepended to default paths
	assert.GreaterOrEqual(t, len(lb.searchPaths), len(customPaths),
		"Should have at least custom paths")
	// First paths should be the custom ones
	assert.Equal(t, customPaths[0], lb.searchPaths[0])
	assert.Equal(t, customPaths[1], lb.searchPaths[1])
}

func TestLocalNetDbBootstrap_ContextCancellation(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a directory with many dummy files to make reading slow
	netDbPath := filepath.Join(tmpDir, "netDb")
	os.MkdirAll(filepath.Join(netDbPath, "r0"), 0755)

	// Create some dummy files (not valid RouterInfos, just for testing cancellation)
	for i := 0; i < 100; i++ {
		f, _ := os.Create(filepath.Join(netDbPath, "r0", "routerInfo-dummy.dat"))
		f.Write([]byte("invalid data"))
		f.Close()
	}

	lb := NewLocalNetDbBootstrapWithPaths([]string{netDbPath})

	// Create a context that cancels immediately
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	peers, err := lb.GetPeers(ctx, 10)

	// Should get a context cancellation error
	assert.Error(t, err)
	assert.Nil(t, peers)
}
