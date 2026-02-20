package config

import (
	"sync"
	"testing"
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
	if original.BaseDir != "/original/base" {
		t.Errorf("BaseDir was modified: got %s, want /original/base", original.BaseDir)
	}
	if original.Bootstrap.LowPeerThreshold != 5 {
		t.Errorf("LowPeerThreshold was modified: got %d, want 5", original.Bootstrap.LowPeerThreshold)
	}
	if original.Bootstrap.ReseedServers[0].Url != "https://original.example.com" {
		t.Errorf("ReseedServer Url was modified: got %s", original.Bootstrap.ReseedServers[0].Url)
	}
	if original.Bootstrap.LocalNetDbPaths[0] != "/original/path" {
		t.Errorf("LocalNetDbPaths was modified: got %s", original.Bootstrap.LocalNetDbPaths[0])
	}
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
	if cfg2.MaxBandwidth == 999999 {
		t.Error("RouterConfigProperties() should return independent copies")
	}
}

// TestI2CPPortDefaultIs7654 verifies the I2CP port constant per spec.
// (Moved from caps_test.go — tests DefaultI2CPPort from router.go)
func TestI2CPPortDefaultIs7654(t *testing.T) {
	if DefaultI2CPPort != 7654 {
		t.Errorf("DefaultI2CPPort = %d, want 7654 per I2CP spec", DefaultI2CPPort)
	}
}

// TestDefaultI2CPConfigAddressHasCorrectPort verifies DefaultI2CPConfig has correct port.
// (Moved from caps_test.go — tests DefaultI2CPConfig from router.go)
func TestDefaultI2CPConfigAddressHasCorrectPort(t *testing.T) {
	if DefaultI2CPConfig.Address != "localhost:7654" {
		t.Errorf("DefaultI2CPConfig.Address = %q, want %q",
			DefaultI2CPConfig.Address, "localhost:7654")
	}
}
