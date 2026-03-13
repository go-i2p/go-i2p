package config

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// requireSubsystemConfigsNotNil asserts that all four subsystem config
// pointers (Tunnel, Transport, Performance, Congestion) in cfg are non-nil.
func requireSubsystemConfigsNotNil(t *testing.T, cfg *RouterConfig) {
	t.Helper()
	require.NotNil(t, cfg.Tunnel, "Tunnel config is nil")
	require.NotNil(t, cfg.Transport, "Transport config is nil")
	require.NotNil(t, cfg.Performance, "Performance config is nil")
	require.NotNil(t, cfg.Congestion, "Congestion config is nil")
}

// assertDirectoryCreatedWithPerm stats path and asserts it exists and is a
// directory. If wantPerm is provided, it also checks the directory permissions.
func assertDirectoryCreatedWithPerm(t *testing.T, path string, wantPerm ...os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	require.NoError(t, err, "path %s was not created", path)
	assert.True(t, info.IsDir(), "path %s is not a directory", path)
	if len(wantPerm) > 0 {
		assert.Equal(t, wantPerm[0], info.Mode().Perm(), "directory permissions for %s", path)
	}
}

// initConfigAndNewFromViper calls InitConfig and NewRouterConfigFromViper,
// failing the test on InitConfig error, and returns the resulting RouterConfig.
func initConfigAndNewFromViper(t *testing.T) *RouterConfig {
	t.Helper()
	require.NoError(t, InitConfig(), "InitConfig failed")
	return NewRouterConfigFromViper()
}

// initConfigAndUpdate calls InitConfig and UpdateRouterConfig, failing the
// test on InitConfig error.
func initConfigAndUpdate(t *testing.T) {
	t.Helper()
	require.NoError(t, InitConfig(), "InitConfig failed")
	UpdateRouterConfig()
}
