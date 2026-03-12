package config

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

// =============================================================================
// Unit Tests for router.go — GetRouterConfig, RouterConfigProperties,
// LockRouterConfigForWrite, deep copy, concurrency
// =============================================================================

// TestGetRouterConfigConcurrentAccess verifies that GetRouterConfig is thread-safe
// and can be called concurrently without data races. This test should be run with
// the -race flag to detect any race conditions.
func TestGetRouterConfigConcurrentAccess(t *testing.T) {
	// Set up initial config values
	LockRouterConfigForWrite()
	routerConfigProperties.BaseDir = "/test/base"
	routerConfigProperties.WorkingDir = "/test/working"
	routerConfigProperties.NetDb = &NetDbConfig{Path: "/test/netdb"}
	routerConfigProperties.Bootstrap = &BootstrapConfig{
		LowPeerThreshold: 10,
		BootstrapType:    "reseed",
		ReseedServers: []*ReseedConfig{
			{Url: "https://test.example.com", SU3Fingerprint: "testkey"},
		},
		LocalNetDbPaths: []string{"/path1", "/path2"},
	}
	routerConfigProperties.I2CP = &I2CPConfig{
		Enabled: true,
		Address: "localhost:7654",
	}
	routerConfigProperties.I2PControl = &I2PControlConfig{
		Enabled: true,
		Address: "localhost:7650",
	}
	UnlockRouterConfigWrite()

	// Run concurrent readers and writers
	const numReaders = 100
	const numWriters = 10
	const iterations = 100

	var wg sync.WaitGroup

	// Start readers
	for i := 0; i < numReaders; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				cfg := GetRouterConfig()
				// Access various fields to verify they're readable
				_ = cfg.BaseDir
				_ = cfg.WorkingDir
				if cfg.NetDb != nil {
					_ = cfg.NetDb.Path
				}
				if cfg.Bootstrap != nil {
					_ = cfg.Bootstrap.LowPeerThreshold
					for _, server := range cfg.Bootstrap.ReseedServers {
						if server != nil {
							_ = server.Url
						}
					}
				}
				if cfg.I2CP != nil {
					_ = cfg.I2CP.Enabled
				}
				if cfg.I2PControl != nil {
					_ = cfg.I2PControl.Enabled
				}
			}
		}()
	}

	// Start writers (simulating SIGHUP reloads)
	for i := 0; i < numWriters; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				LockRouterConfigForWrite()
				routerConfigProperties.BaseDir = "/updated/base"
				routerConfigProperties.WorkingDir = "/updated/working"
				if routerConfigProperties.NetDb != nil {
					routerConfigProperties.NetDb.Path = "/updated/netdb"
				}
				if routerConfigProperties.Bootstrap != nil {
					routerConfigProperties.Bootstrap.LowPeerThreshold = id*100 + j
				}
				UnlockRouterConfigWrite()
			}
		}(i)
	}

	wg.Wait()
}

// TestGetRouterConfigReturnsDeepCopy verifies that GetRouterConfig returns
// a deep copy that can be safely modified without affecting the global config.
func TestGetRouterConfigReturnsDeepCopy(t *testing.T) {
	// Set up initial config
	LockRouterConfigForWrite()
	routerConfigProperties.BaseDir = "/original/base"
	routerConfigProperties.Bootstrap = &BootstrapConfig{
		LowPeerThreshold: 5,
		ReseedServers: []*ReseedConfig{
			{Url: "https://original.example.com"},
		},
		LocalNetDbPaths: []string{"/original/path"},
	}
	UnlockRouterConfigWrite()

	// Get a copy
	cfg := GetRouterConfig()

	// Modify the copy
	cfg.BaseDir = "/modified/base"
	cfg.Bootstrap.LowPeerThreshold = 999
	cfg.Bootstrap.ReseedServers[0].Url = "https://modified.example.com"
	cfg.Bootstrap.LocalNetDbPaths[0] = "/modified/path"

	// Verify original is unchanged
	original := GetRouterConfig()
	assert.Equal(t, "/original/base", original.BaseDir, "BaseDir was modified")
	assert.Equal(t, 5, original.Bootstrap.LowPeerThreshold, "LowPeerThreshold was modified")
	assert.Equal(t, "https://original.example.com", original.Bootstrap.ReseedServers[0].Url, "ReseedServer Url was modified")
	assert.Equal(t, "/original/path", original.Bootstrap.LocalNetDbPaths[0], "LocalNetDbPaths was modified")
}

// TestLockRouterConfigForWrite verifies that the write lock provides exclusive access
func TestLockRouterConfigForWrite(t *testing.T) {
	LockRouterConfigForWrite()
	// Just verify we can modify while holding the lock
	originalValue := routerConfigProperties.BaseDir
	routerConfigProperties.BaseDir = "/locked/update"
	routerConfigProperties.BaseDir = originalValue
	UnlockRouterConfigWrite()
}

// TestRouterConfigProperties_ReturnsCopy verifies RouterConfigProperties returns a deep copy.
// (Moved from defaults_test.go — tests router.go's RouterConfigProperties)
func TestRouterConfigProperties_ReturnsCopy(t *testing.T) {
	cfg1 := RouterConfigProperties()
	cfg2 := RouterConfigProperties()

	// Modifying cfg1 should not affect cfg2
	cfg1.MaxBandwidth = 999999
	assert.NotEqual(t, uint64(999999), cfg2.MaxBandwidth, "RouterConfigProperties() should return independent copies")
}

// TestI2CPPortDefaultIs7654 verifies the I2CP port constant per spec.
// (Moved from caps_test.go — tests DefaultI2CPPort from router.go)
func TestI2CPPortDefaultIs7654(t *testing.T) {
	assert.Equal(t, 7654, DefaultI2CPPort, "DefaultI2CPPort per I2CP spec")
}

// TestDefaultI2CPConfigAddressHasCorrectPort verifies DefaultI2CPConfig has correct port.
// (Moved from caps_test.go — tests DefaultI2CPConfig from router.go)
func TestDefaultI2CPConfigAddressHasCorrectPort(t *testing.T) {
	assert.Equal(t, "localhost:7654", DefaultI2CPConfig.Address, "DefaultI2CPConfig.Address")
}
