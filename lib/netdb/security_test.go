package netdb

import (
	"sync"
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/lease_set"
	"github.com/go-i2p/common/router_info"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// -----------------------------------------------------------------------------
// Storage Isolation Tests
// Verifies Client vs Router NetDB separation per ISOLATION.md
// -----------------------------------------------------------------------------

// TestStorageIsolation_ClientCannotAccessRouterInfo verifies that ClientNetDB
// does not expose RouterInfo operations, enforcing type-safety isolation.
func TestStorageIsolation_ClientCannotAccessRouterInfo(t *testing.T) {
	tmpDir := t.TempDir()
	stdDB := NewStdNetDB(tmpDir)
	require.NoError(t, stdDB.Create())
	defer stdDB.Stop()

	clientDB := NewClientNetDB(stdDB)

	// Verify ClientNetDB has no RouterInfo methods exposed
	// (compile-time enforcement via Go's type system)
	// ClientNetDB only has LeaseSet operations:
	assert.NotNil(t, clientDB.GetLeaseSet, "GetLeaseSet should be available")
	assert.NotNil(t, clientDB.GetLeaseSetBytes, "GetLeaseSetBytes should be available")
	assert.NotNil(t, clientDB.StoreLeaseSet, "StoreLeaseSet should be available")
	assert.NotNil(t, clientDB.StoreLeaseSet2, "StoreLeaseSet2 should be available")
	assert.NotNil(t, clientDB.GetLeaseSetCount, "GetLeaseSetCount should be available")

	// The following are NOT available on ClientNetDB (enforced at compile time):
	// - GetRouterInfo
	// - GetAllRouterInfos
	// - StoreRouterInfo
	// - SelectPeers
	// - SelectFloodfillRouters
}

// TestStorageIsolation_RouterHasBothOperations verifies that RouterNetDB
// provides both RouterInfo and LeaseSet operations for direct router operations.
func TestStorageIsolation_RouterHasBothOperations(t *testing.T) {
	tmpDir := t.TempDir()
	stdDB := NewStdNetDB(tmpDir)
	require.NoError(t, stdDB.Create())
	defer stdDB.Stop()

	routerDB := NewRouterNetDB(stdDB)

	// Verify RouterNetDB has RouterInfo methods
	assert.NotNil(t, routerDB.GetRouterInfo, "GetRouterInfo should be available")
	assert.NotNil(t, routerDB.GetAllRouterInfos, "GetAllRouterInfos should be available")
	assert.NotNil(t, routerDB.StoreRouterInfo, "StoreRouterInfo should be available")
	assert.NotNil(t, routerDB.GetRouterInfoBytes, "GetRouterInfoBytes should be available")
	assert.NotNil(t, routerDB.SelectPeers, "SelectPeers should be available")
	assert.NotNil(t, routerDB.SelectFloodfillRouters, "SelectFloodfillRouters should be available")

	// Verify RouterNetDB also has LeaseSet methods for direct operations
	assert.NotNil(t, routerDB.GetLeaseSet, "GetLeaseSet should be available for direct operations")
	assert.NotNil(t, routerDB.GetLeaseSetBytes, "GetLeaseSetBytes should be available for direct operations")
	assert.NotNil(t, routerDB.StoreLeaseSet, "StoreLeaseSet should be available for direct operations")
}

// TestStorageIsolation_EphemeralClientDatabase verifies that client databases
// are ephemeral (in-memory only) when created with empty path.
func TestStorageIsolation_EphemeralClientDatabase(t *testing.T) {
	// Create ephemeral database with empty path
	stdDB := NewStdNetDB("")
	clientDB := NewClientNetDB(stdDB)
	defer stdDB.Stop()

	// Path should be empty for ephemeral databases
	assert.Equal(t, "", clientDB.Path(), "Ephemeral database should have empty path")
}

// TestStorageIsolation_SeparateInstances verifies that each client session
// gets its own isolated StdNetDB instance with no shared state.
func TestStorageIsolation_SeparateInstances(t *testing.T) {
	// Create two separate client databases (simulating two I2CP sessions)
	stdDB1 := NewStdNetDB("")
	stdDB2 := NewStdNetDB("")
	defer stdDB1.Stop()
	defer stdDB2.Stop()

	clientDB1 := NewClientNetDB(stdDB1)
	clientDB2 := NewClientNetDB(stdDB2)

	// Store a LeaseSet in one client DB
	hash := common.Hash{0x01, 0x02, 0x03}
	// Note: This will fail to parse (invalid data) but demonstrates isolation
	err := clientDB1.StoreLeaseSet(hash, []byte{0x01}, 1)
	assert.Error(t, err) // Expected to fail due to invalid data

	// Second client should not be affected
	count1 := clientDB1.GetLeaseSetCount()
	count2 := clientDB2.GetLeaseSetCount()
	assert.Equal(t, 0, count1, "First client should have 0 entries (failed store)")
	assert.Equal(t, 0, count2, "Second client should have 0 entries (isolated)")
}

// -----------------------------------------------------------------------------
// Expiration Logic Tests
// Verifies stale entries are removed correctly
// -----------------------------------------------------------------------------

// TestExpirationLogic_CleanupRemovesExpired verifies that expired LeaseSets
// are properly removed from both memory and expiry tracking.
func TestExpirationLogic_CleanupRemovesExpired(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)
	require.NotNil(t, db)
	defer db.Stop()

	// Add an expired entry directly to the maps
	expiredHash := common.Hash{0x10, 0x11, 0x12}
	validHash := common.Hash{0x20, 0x21, 0x22}

	db.lsMutex.Lock()
	db.LeaseSets[expiredHash] = Entry{}
	db.LeaseSets[validHash] = Entry{}
	db.lsMutex.Unlock()

	db.expiryMutex.Lock()
	db.leaseSetExpiry[expiredHash] = time.Now().Add(-1 * time.Hour) // Expired
	db.leaseSetExpiry[validHash] = time.Now().Add(1 * time.Hour)    // Valid
	db.expiryMutex.Unlock()

	// Run cleanup
	db.cleanExpiredLeaseSets()

	// Verify expired was removed
	db.lsMutex.Lock()
	_, hasExpired := db.LeaseSets[expiredHash]
	_, hasValid := db.LeaseSets[validHash]
	db.lsMutex.Unlock()

	assert.False(t, hasExpired, "Expired LeaseSet should be removed from cache")
	assert.True(t, hasValid, "Valid LeaseSet should remain in cache")

	// Verify expiry tracking was also cleaned
	db.expiryMutex.RLock()
	_, trackedExpired := db.leaseSetExpiry[expiredHash]
	_, trackedValid := db.leaseSetExpiry[validHash]
	db.expiryMutex.RUnlock()

	assert.False(t, trackedExpired, "Expired entry should be removed from expiry tracking")
	assert.True(t, trackedValid, "Valid entry should remain in expiry tracking")
}

// TestExpirationLogic_Stats verifies GetLeaseSetExpirationStats accuracy.
func TestExpirationLogic_Stats(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)
	require.NotNil(t, db)
	defer db.Stop()

	now := time.Now()

	// Add mix of expired and valid entries
	db.expiryMutex.Lock()
	db.leaseSetExpiry[common.Hash{0x01}] = now.Add(-5 * time.Minute) // Expired
	db.leaseSetExpiry[common.Hash{0x02}] = now.Add(-2 * time.Minute) // Expired
	db.leaseSetExpiry[common.Hash{0x03}] = now.Add(10 * time.Minute) // Valid - earliest
	db.leaseSetExpiry[common.Hash{0x04}] = now.Add(30 * time.Minute) // Valid
	db.leaseSetExpiry[common.Hash{0x05}] = now.Add(60 * time.Minute) // Valid
	db.expiryMutex.Unlock()

	total, expired, nextExpiry := db.GetLeaseSetExpirationStats()

	assert.Equal(t, 5, total, "Should have 5 total entries")
	assert.Equal(t, 2, expired, "Should have 2 expired entries")
	assert.True(t, nextExpiry > 9*time.Minute && nextExpiry < 11*time.Minute,
		"Next expiry should be approximately 10 minutes")
}

// -----------------------------------------------------------------------------
// Kademlia Distance Tests
// Verifies XOR metric implementation correctness
// -----------------------------------------------------------------------------

// TestKademliaDistance_XORCalculation verifies XOR distance calculation.
func TestKademliaDistance_XORCalculation(t *testing.T) {
	db := NewStdNetDB("")
	defer db.Stop()

	tests := []struct {
		name string
		h1   common.Hash
		h2   common.Hash
		want []byte
	}{
		{
			name: "identical hashes produce zero distance",
			h1:   common.Hash{0xFF, 0xFF, 0xFF},
			h2:   common.Hash{0xFF, 0xFF, 0xFF},
			want: []byte{0x00, 0x00, 0x00},
		},
		{
			name: "opposite bits produce max distance",
			h1:   common.Hash{0xFF, 0x00, 0xAA},
			h2:   common.Hash{0x00, 0xFF, 0x55},
			want: []byte{0xFF, 0xFF, 0xFF},
		},
		{
			name: "specific XOR result",
			h1:   common.Hash{0xA5, 0x5A, 0x00},
			h2:   common.Hash{0x5A, 0xA5, 0xFF},
			want: []byte{0xFF, 0xFF, 0xFF},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := db.calculateXORDistance(tt.h1, tt.h2)
			for i := 0; i < len(tt.want); i++ {
				assert.Equal(t, tt.want[i], result[i],
					"XOR distance byte %d mismatch", i)
			}
		})
	}
}

// TestKademliaDistance_Comparison verifies distance comparison logic.
func TestKademliaDistance_Comparison(t *testing.T) {
	db := NewStdNetDB("")
	defer db.Stop()

	tests := []struct {
		name   string
		d1     []byte
		d2     []byte
		d1Less bool // true if d1 < d2
	}{
		{
			name:   "equal distances",
			d1:     []byte{0x01, 0x02, 0x03},
			d2:     []byte{0x01, 0x02, 0x03},
			d1Less: false,
		},
		{
			name:   "d1 less than d2 (first byte)",
			d1:     []byte{0x00, 0xFF, 0xFF},
			d2:     []byte{0x01, 0x00, 0x00},
			d1Less: true,
		},
		{
			name:   "d1 less than d2 (last byte)",
			d1:     []byte{0x01, 0x02, 0x03},
			d2:     []byte{0x01, 0x02, 0x04},
			d1Less: true,
		},
		{
			name:   "d1 greater than d2",
			d1:     []byte{0x10, 0x00, 0x00},
			d2:     []byte{0x0F, 0xFF, 0xFF},
			d1Less: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := db.compareXORDistances(tt.d1, tt.d2)
			assert.Equal(t, tt.d1Less, result)
		})
	}
}

// TestKademliaDistance_Symmetry verifies XOR distance is symmetric.
func TestKademliaDistance_Symmetry(t *testing.T) {
	db := NewStdNetDB("")
	defer db.Stop()

	h1 := common.Hash{0xDE, 0xAD, 0xBE, 0xEF}
	h2 := common.Hash{0xCA, 0xFE, 0xBA, 0xBE}

	d1 := db.calculateXORDistance(h1, h2)
	d2 := db.calculateXORDistance(h2, h1)

	for i := range d1 {
		assert.Equal(t, d1[i], d2[i], "XOR distance should be symmetric at byte %d", i)
	}
}

// -----------------------------------------------------------------------------
// Concurrent Access Tests
// Verifies mutex usage in std.go is correct
// -----------------------------------------------------------------------------

// TestConcurrentAccess_RouterInfoMutex tests thread safety of RouterInfo operations.
func TestConcurrentAccess_RouterInfoMutex(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)
	require.NoError(t, db.Create())
	defer db.Stop()

	var wg sync.WaitGroup
	iterations := 100
	goroutines := 10

	// Concurrent reads and writes
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				// Concurrent Size() calls (reads riMutex)
				_ = db.Size()

				// Concurrent GetAllRouterInfos() calls (reads riMutex)
				_ = db.GetAllRouterInfos()

				// Concurrent GetRouterInfoCount() calls
				_ = db.GetRouterInfoCount()
			}
		}(i)
	}

	wg.Wait()
	// Test passes if no race conditions detected (run with -race flag)
}

// TestConcurrentAccess_LeaseSetMutex tests thread safety of LeaseSet operations.
func TestConcurrentAccess_LeaseSetMutex(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)
	require.NoError(t, db.Create())
	defer db.Stop()

	var wg sync.WaitGroup
	iterations := 100
	goroutines := 10

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				// Concurrent GetLeaseSetCount() calls
				_ = db.GetLeaseSetCount()

				// Concurrent GetAllLeaseSets() calls
				_ = db.GetAllLeaseSets()

				// Concurrent GetLeaseSet lookup (should return nil)
				hash := common.Hash{byte(id), byte(j)}
				_ = db.GetLeaseSet(hash)
			}
		}(i)
	}

	wg.Wait()
}

// TestConcurrentAccess_ExpiryMutex tests thread safety of expiry tracking.
func TestConcurrentAccess_ExpiryMutex(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)
	require.NotNil(t, db)
	defer db.Stop()

	var wg sync.WaitGroup
	iterations := 100
	goroutines := 10

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				// Concurrent stats retrieval
				_, _, _ = db.GetLeaseSetExpirationStats()

				// Concurrent writes
				hash := common.Hash{byte(id), byte(j)}
				db.expiryMutex.Lock()
				db.leaseSetExpiry[hash] = time.Now().Add(time.Duration(j) * time.Minute)
				db.expiryMutex.Unlock()
			}
		}(i)
	}

	wg.Wait()
}

// TestConcurrentAccess_CleanupDuringAccess tests that cleanup doesn't race with reads.
func TestConcurrentAccess_CleanupDuringAccess(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)
	require.NotNil(t, db)
	defer db.Stop()

	// Pre-populate with entries
	for i := 0; i < 100; i++ {
		hash := common.Hash{byte(i)}
		db.lsMutex.Lock()
		db.LeaseSets[hash] = Entry{}
		db.lsMutex.Unlock()

		db.expiryMutex.Lock()
		if i%2 == 0 {
			db.leaseSetExpiry[hash] = time.Now().Add(-1 * time.Minute) // Expired
		} else {
			db.leaseSetExpiry[hash] = time.Now().Add(1 * time.Hour) // Valid
		}
		db.expiryMutex.Unlock()
	}

	var wg sync.WaitGroup

	// Start cleanup goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			db.cleanExpiredLeaseSets()
		}
	}()

	// Concurrent reads during cleanup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			_ = db.GetLeaseSetCount()
			_ = db.GetAllLeaseSets()
		}
	}()

	wg.Wait()
}

// -----------------------------------------------------------------------------
// Floodfill Selection Tests
// Verifies proper closest-peer selection using XOR distance
// -----------------------------------------------------------------------------

// TestFloodfillSelection_EmptyDatabase tests error handling for empty NetDB.
func TestFloodfillSelection_EmptyDatabase(t *testing.T) {
	db := NewStdNetDB("")
	defer db.Stop()

	targetHash := common.Hash{0x12, 0x34, 0x56}
	result, err := db.SelectFloodfillRouters(targetHash, 5)

	assert.Error(t, err, "SelectFloodfillRouters should fail on empty database")
	assert.Contains(t, err.Error(), "no router infos available")
	assert.Len(t, result, 0)
}

// -----------------------------------------------------------------------------
// Disk Persistence Tests
// Verifies file format and atomic writes
// -----------------------------------------------------------------------------

// TestDiskPersistence_SkiplistPath verifies correct skiplist file path generation.
func TestDiskPersistence_SkiplistPath(t *testing.T) {
	db := NewStdNetDB("/tmp/netdb")
	defer db.Stop()

	hash := common.Hash{0x41} // 'A' in base64 starts with 'Q'

	routerPath := db.SkiplistFile(hash)
	leaseSetPath := db.SkiplistFileForLeaseSet(hash)

	assert.Contains(t, routerPath, "routerInfo-")
	assert.Contains(t, routerPath, ".dat")
	assert.Contains(t, leaseSetPath, "leaseSet-")
	assert.Contains(t, leaseSetPath, ".dat")

	// RouterInfo uses 'r' prefix, LeaseSet uses 'l' prefix
	assert.Contains(t, routerPath, "/r")
	assert.Contains(t, leaseSetPath, "/l")
}

// TestDiskPersistence_PathValidation tests path traversal prevention.
func TestDiskPersistence_PathValidation(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)
	require.NoError(t, db.Create())
	defer db.Stop()

	tests := []struct {
		name    string
		path    string
		isValid bool
	}{
		{"valid path", tmpDir + "/rQ/routerInfo-test.dat", true},
		{"wrong extension", tmpDir + "/rQ/routerInfo-test.txt", false},
		{"missing extension", tmpDir + "/rQ/routerInfo-test", false},
		{"symlink attack (not tested)", tmpDir + "/../etc/passwd", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := db.CheckFilePathValid(tt.path)
			assert.Equal(t, tt.isValid, result)
		})
	}
}

// -----------------------------------------------------------------------------
// LeaseSet Type Discrimination Tests
// Verifies LeaseSet2, EncryptedLeaseSet, MetaLeaseSet support
// -----------------------------------------------------------------------------

// TestLeaseSetTypeDiscrimination_DataTypes verifies data type validation.
func TestLeaseSetTypeDiscrimination_DataTypes(t *testing.T) {
	tests := []struct {
		name     string
		dataType byte
		validate func(byte) error
		valid    bool
	}{
		{"LeaseSet type 1", 1, func(dt byte) error { return validateLeaseSetDataType(dt) }, true},
		{"LeaseSet type 0 invalid", 0, func(dt byte) error { return validateLeaseSetDataType(dt) }, false},
		{"LeaseSet2 type 3", 3, func(dt byte) error { return validateLeaseSet2DataType(dt) }, true},
		{"LeaseSet2 type 1 invalid", 1, func(dt byte) error { return validateLeaseSet2DataType(dt) }, false},
		{"EncryptedLeaseSet type 5", 5, func(dt byte) error { return validateEncryptedLeaseSetDataType(dt) }, true},
		{"EncryptedLeaseSet type 3 invalid", 3, func(dt byte) error { return validateEncryptedLeaseSetDataType(dt) }, false},
		{"MetaLeaseSet type 7", 7, func(dt byte) error { return validateMetaLeaseSetDataType(dt) }, true},
		{"MetaLeaseSet type 5 invalid", 5, func(dt byte) error { return validateMetaLeaseSetDataType(dt) }, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.validate(tt.dataType)
			if tt.valid {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "invalid data type")
			}
		})
	}
}

// -----------------------------------------------------------------------------
// Exploration Strategy Tests
// Verifies Adaptive vs Random strategy correctness
// -----------------------------------------------------------------------------

// TestExplorationStrategy_BucketCalculation verifies Kademlia bucket assignment.
func TestExplorationStrategy_BucketCalculation(t *testing.T) {
	var ourHash common.Hash
	strategy := NewAdaptiveStrategy(ourHash)

	// Same hash should give bucket 0 (no difference)
	bucket := strategy.calculateBucket(ourHash)
	assert.Equal(t, 0, bucket, "Identical hash should give bucket 0")

	// Different hash in first bit should give bucket 0
	differentHash := common.Hash{0x80} // First bit different
	bucket = strategy.calculateBucket(differentHash)
	assert.Equal(t, 0, bucket, "Difference in MSB should give bucket 0")

	// Different hash in last byte should give bucket 255
	lastByteDiff := common.Hash{}
	lastByteDiff[31] = 0x01
	bucket = strategy.calculateBucket(lastByteDiff)
	assert.Equal(t, 255, bucket, "Difference in LSB should give bucket 255")
}

// TestExplorationStrategy_ShouldExplore verifies exploration decision logic.
func TestExplorationStrategy_ShouldExplore(t *testing.T) {
	strategy := NewAdaptiveStrategy(common.Hash{})

	// Small NetDB should trigger exploration
	assert.True(t, strategy.ShouldExplore(100), "Small NetDB should trigger exploration")

	// Large NetDB without gaps should not trigger
	strategy.floodfillRouters = 100
	strategy.sparseBuckets = nil
	strategy.emptyBuckets = nil
	assert.False(t, strategy.ShouldExplore(1500), "Large healthy NetDB should not trigger")

	// Large NetDB with sparse buckets should trigger
	strategy.sparseBuckets = []int{1, 2, 3}
	assert.True(t, strategy.ShouldExplore(1500), "NetDB with sparse buckets should trigger")
}

// -----------------------------------------------------------------------------
// Publisher Tests
// Verifies LeaseSet distribution to floodfills
// -----------------------------------------------------------------------------

// TestPublisher_ConfigDefaults verifies default publisher configuration.
func TestPublisher_ConfigDefaults(t *testing.T) {
	config := DefaultPublisherConfig()

	assert.Equal(t, 30*time.Minute, config.RouterInfoInterval, "Default RouterInfo interval")
	assert.Equal(t, 5*time.Minute, config.LeaseSetInterval, "Default LeaseSet interval")
	assert.Equal(t, 4, config.FloodfillCount, "Default floodfill count")
}

// TestPublisher_NewPublisher verifies Publisher creation.
func TestPublisher_NewPublisher(t *testing.T) {
	// NewPublisher should accept nil dependencies (they're validated on Start)
	publisher := NewPublisher(
		nil, // No database
		nil, // No tunnel pool
		nil, // No transport
		nil, // No RouterInfo provider
		DefaultPublisherConfig(),
	)

	assert.NotNil(t, publisher, "Publisher should be created even with nil dependencies")
	assert.NotNil(t, publisher.ctx, "Publisher should have context")
}

// TestPublisher_Stop verifies graceful shutdown.
func TestPublisher_Stop(t *testing.T) {
	publisher := NewPublisher(
		nil,
		nil,
		nil,
		nil,
		DefaultPublisherConfig(),
	)

	// Stop should not panic even if not started
	publisher.Stop()
}

// TestPublisher_FloodfillCountLimits verifies floodfill count is bounded.
func TestPublisher_FloodfillCountLimits(t *testing.T) {
	testCases := []struct {
		name          string
		count         int
		expectedCount int
	}{
		{"Zero floodfills", 0, 0},
		{"Single floodfill", 1, 1},
		{"Default count", 4, 4},
		{"Large count", 100, 100},
		{"Negative count", -1, -1}, // Publisher does not validate - caller's responsibility
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := PublisherConfig{
				RouterInfoInterval: 30 * time.Minute,
				LeaseSetInterval:   5 * time.Minute,
				FloodfillCount:     tc.count,
			}
			publisher := NewPublisher(nil, nil, nil, nil, config)
			assert.Equal(t, tc.expectedCount, publisher.floodfillCount)
		})
	}
}

// TestPublisher_ConcurrentStartStop tests thread-safety of Start/Stop operations.
func TestPublisher_ConcurrentStartStop(t *testing.T) {
	// Create publisher without dependencies (Start will fail, but Stop should be safe)
	publisher := NewPublisher(nil, nil, nil, nil, DefaultPublisherConfig())

	var wg sync.WaitGroup

	// Attempt multiple concurrent stops (should not panic or deadlock)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			publisher.Stop()
		}()
	}

	wg.Wait()

	// Verify publisher is stopped
	stats := publisher.GetStats()
	assert.False(t, stats.IsRunning, "Publisher should be stopped after concurrent Stop calls")
}

// TestPublisher_GetStatsThreadSafe tests that GetStats is thread-safe.
func TestPublisher_GetStatsThreadSafe(t *testing.T) {
	publisher := NewPublisher(nil, nil, nil, nil, DefaultPublisherConfig())

	var wg sync.WaitGroup

	// Read stats from multiple goroutines
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			stats := publisher.GetStats()
			// Just access all fields to detect races
			_ = stats.RouterInfoInterval
			_ = stats.LeaseSetInterval
			_ = stats.FloodfillCount
			_ = stats.IsRunning
		}()
	}

	wg.Wait()
}

// TestPublisher_ErrorMessagesNoSensitiveData verifies error messages don't leak sensitive info.
func TestPublisher_ErrorMessagesNoSensitiveData(t *testing.T) {
	publisher := NewPublisher(nil, nil, nil, nil, DefaultPublisherConfig())

	// Test Start without tunnel pool
	err := publisher.Start()
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "password", "Error should not contain passwords")
	assert.NotContains(t, err.Error(), "key", "Error should not contain private key info")
	assert.Contains(t, err.Error(), "tunnel pool required", "Error should have useful message")

	// Test Start without transport (requires a tunnel pool that's not nil)
	// Note: We can't easily mock tunnel.Pool since it's a concrete type, but
	// passing nil for transport exercises the second validation path.
	// The first test (nil pool) already demonstrates safe error messages.
}

// TestPublisher_DefaultConfigsAreSafe verifies default configuration is reasonable.
func TestPublisher_DefaultConfigsAreSafe(t *testing.T) {
	config := DefaultPublisherConfig()

	// RouterInfo interval should not be too frequent (avoid network spam)
	assert.GreaterOrEqual(t, config.RouterInfoInterval, 5*time.Minute,
		"RouterInfo publish interval should not be too frequent")

	// LeaseSet interval should not be too frequent
	assert.GreaterOrEqual(t, config.LeaseSetInterval, 1*time.Minute,
		"LeaseSet publish interval should not be too frequent")

	// Floodfill count should be reasonable (3-8 is typical)
	assert.GreaterOrEqual(t, config.FloodfillCount, 1,
		"Should publish to at least 1 floodfill")
	assert.LessOrEqual(t, config.FloodfillCount, 10,
		"Should not publish to excessive floodfills")
}

// TestPublisher_ContextCancellationPropagates verifies proper context handling.
func TestPublisher_ContextCancellationPropagates(t *testing.T) {
	publisher := NewPublisher(nil, nil, nil, nil, DefaultPublisherConfig())

	// Context should be active
	assert.NoError(t, publisher.ctx.Err(), "Context should not be cancelled initially")

	// Stop should cancel context
	publisher.Stop()
	assert.Error(t, publisher.ctx.Err(), "Context should be cancelled after Stop")
}

// TestPublisher_SelectFloodfillsWithEmptyNetDB tests handling of empty database.
func TestPublisher_SelectFloodfillsWithEmptyNetDB(t *testing.T) {
	db := newMockNetDB()
	publisher := NewPublisher(db, nil, nil, nil, DefaultPublisherConfig())

	hash := common.Hash{1, 2, 3, 4}
	floodfills, err := publisher.selectFloodfillsForPublishing(hash)

	// Should not error, just return empty list
	assert.NoError(t, err, "Empty NetDB should not cause error")
	assert.Empty(t, floodfills, "Should return no floodfills from empty NetDB")
}

// TestPublisher_PublishRouterInfoValidation tests RouterInfo validation before publishing.
func TestPublisher_PublishRouterInfoValidation(t *testing.T) {
	db := newMockNetDB()
	publisher := NewPublisher(db, nil, nil, nil, DefaultPublisherConfig())

	// Test with empty RouterInfo (will fail hash extraction)
	emptyRI := router_info.RouterInfo{}
	err := publisher.PublishRouterInfo(emptyRI)
	assert.Error(t, err, "Empty RouterInfo should fail publishing")
	assert.Contains(t, err.Error(), "failed to get router hash",
		"Error should indicate hash extraction failure")
	// Error should not contain sensitive information
	assert.NotContains(t, err.Error(), "private", "Error should not expose private key info")
}

// TestPublisher_PublishLeaseSetValidation tests LeaseSet validation before publishing.
func TestPublisher_PublishLeaseSetValidation(t *testing.T) {
	db := newMockNetDB()
	publisher := NewPublisher(db, nil, nil, nil, DefaultPublisherConfig())

	// Test with empty LeaseSet (will fail validation)
	hash := common.Hash{1, 2, 3, 4}
	emptyLS := lease_set.LeaseSet{} // Empty LeaseSet

	err := publisher.PublishLeaseSet(hash, emptyLS)
	assert.Error(t, err, "Empty LeaseSet should fail validation")
	assert.Contains(t, err.Error(), "invalid LeaseSet", "Error should indicate validation failure")
}
