package netdb

import (
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/go-i2p/lib/config"
)

// TestCongestionCache_BasicOperations tests cache get/set/delete operations
func TestCongestionCache_BasicOperations(t *testing.T) {
	cache := NewCongestionCache()

	// Create test hash
	var hash common.Hash
	copy(hash[:], []byte("test-hash-value-12345678901234"))

	// Test get on empty cache
	flag, _, found := cache.Get(hash)
	if found {
		t.Error("Expected empty cache to return not found")
	}
	if flag != config.CongestionFlagNone {
		t.Errorf("Expected CongestionFlagNone, got %q", flag)
	}

	// Test set
	riAge := time.Now().Add(-5 * time.Minute)
	cache.Set(hash, config.CongestionFlagD, riAge)

	// Test get after set
	flag, age, found := cache.Get(hash)
	if !found {
		t.Error("Expected cache hit after set")
	}
	if flag != config.CongestionFlagD {
		t.Errorf("Expected CongestionFlagD, got %q", flag)
	}
	if !age.Equal(riAge) {
		t.Errorf("Expected age %v, got %v", riAge, age)
	}

	// Test size
	if size := cache.Size(); size != 1 {
		t.Errorf("Expected size 1, got %d", size)
	}

	// Test delete
	cache.Delete(hash)
	_, _, found = cache.Get(hash)
	if found {
		t.Error("Expected cache miss after delete")
	}

	// Test size after delete
	if size := cache.Size(); size != 0 {
		t.Errorf("Expected size 0 after delete, got %d", size)
	}
}

// TestCongestionCache_Clear tests clearing the entire cache
func TestCongestionCache_Clear(t *testing.T) {
	cache := NewCongestionCache()

	// Add multiple entries
	for i := 0; i < 5; i++ {
		var hash common.Hash
		hash[0] = byte(i)
		cache.Set(hash, config.CongestionFlagD, time.Now())
	}

	if size := cache.Size(); size != 5 {
		t.Errorf("Expected size 5, got %d", size)
	}

	cache.Clear()

	if size := cache.Size(); size != 0 {
		t.Errorf("Expected size 0 after clear, got %d", size)
	}
}

// TestCongestionCache_Overwrite tests overwriting existing entries
func TestCongestionCache_Overwrite(t *testing.T) {
	cache := NewCongestionCache()

	var hash common.Hash
	copy(hash[:], []byte("test-hash-value-12345678901234"))

	// Set initial value
	cache.Set(hash, config.CongestionFlagD, time.Now())

	// Overwrite with new value
	newAge := time.Now().Add(-10 * time.Minute)
	cache.Set(hash, config.CongestionFlagE, newAge)

	flag, age, found := cache.Get(hash)
	if !found {
		t.Error("Expected cache hit")
	}
	if flag != config.CongestionFlagE {
		t.Errorf("Expected CongestionFlagE after overwrite, got %q", flag)
	}
	if !age.Equal(newAge) {
		t.Errorf("Expected age %v after overwrite, got %v", newAge, age)
	}

	// Size should still be 1
	if size := cache.Size(); size != 1 {
		t.Errorf("Expected size 1, got %d", size)
	}
}

// TestCongestionStats_CongestedRatio tests the congested ratio calculation
func TestCongestionStats_CongestedRatio(t *testing.T) {
	tests := []struct {
		name          string
		total         int
		dCount        int
		eCount        int
		gCount        int
		expectedRatio float64
	}{
		{
			name:          "no peers",
			total:         0,
			dCount:        0,
			eCount:        0,
			gCount:        0,
			expectedRatio: 0.0,
		},
		{
			name:          "no congestion",
			total:         100,
			dCount:        0,
			eCount:        0,
			gCount:        0,
			expectedRatio: 0.0,
		},
		{
			name:          "all D flags",
			total:         100,
			dCount:        100,
			eCount:        0,
			gCount:        0,
			expectedRatio: 1.0,
		},
		{
			name:          "mixed congestion",
			total:         100,
			dCount:        10,
			eCount:        5,
			gCount:        5,
			expectedRatio: 0.2, // 20/100
		},
		{
			name:          "50% congested",
			total:         100,
			dCount:        30,
			eCount:        15,
			gCount:        5,
			expectedRatio: 0.5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ratio float64
			if tt.total > 0 {
				ratio = float64(tt.dCount+tt.eCount+tt.gCount) / float64(tt.total)
			}

			if ratio != tt.expectedRatio {
				t.Errorf("Expected ratio %.2f, got %.2f", tt.expectedRatio, ratio)
			}

			stats := CongestionStats{
				TotalPeers:     tt.total,
				DFlagCount:     tt.dCount,
				EFlagCount:     tt.eCount,
				GFlagCount:     tt.gCount,
				CongestedRatio: ratio,
			}

			if stats.TotalPeers != tt.total {
				t.Errorf("Expected TotalPeers %d, got %d", tt.total, stats.TotalPeers)
			}
		})
	}
}

// TestParseCongestionFlag tests congestion flag parsing from caps strings
func TestParseCongestionFlag(t *testing.T) {
	tests := []struct {
		name     string
		caps     string
		expected config.CongestionFlag
	}{
		{
			name:     "no congestion flags",
			caps:     "NU",
			expected: config.CongestionFlagNone,
		},
		{
			name:     "D flag only",
			caps:     "NUD",
			expected: config.CongestionFlagD,
		},
		{
			name:     "E flag only",
			caps:     "NUE",
			expected: config.CongestionFlagE,
		},
		{
			name:     "G flag only",
			caps:     "NUG",
			expected: config.CongestionFlagG,
		},
		{
			name:     "floodfill with no congestion",
			caps:     "fR",
			expected: config.CongestionFlagNone,
		},
		{
			name:     "floodfill with D",
			caps:     "fRD",
			expected: config.CongestionFlagD,
		},
		{
			name:     "multiple flags - G takes priority",
			caps:     "NURDEG",
			expected: config.CongestionFlagG,
		},
		{
			name:     "E and D - E takes priority",
			caps:     "NURDE",
			expected: config.CongestionFlagE,
		},
		{
			name:     "empty caps",
			caps:     "",
			expected: config.CongestionFlagNone,
		},
		{
			name:     "bandwidth caps only",
			caps:     "LK",
			expected: config.CongestionFlagNone,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := config.ParseCongestionFlag(tt.caps)
			if result != tt.expected {
				t.Errorf("ParseCongestionFlag(%q) = %q, want %q", tt.caps, result, tt.expected)
			}
		})
	}
}

// TestCongestionCache_Concurrent tests concurrent access to the cache
func TestCongestionCache_Concurrent(t *testing.T) {
	cache := NewCongestionCache()

	const numGoroutines = 100
	const numOperations = 100

	done := make(chan bool, numGoroutines)

	// Start concurrent writers
	for i := 0; i < numGoroutines/2; i++ {
		go func(id int) {
			for j := 0; j < numOperations; j++ {
				var hash common.Hash
				hash[0] = byte(id)
				hash[1] = byte(j % 256)
				cache.Set(hash, config.CongestionFlagD, time.Now())
			}
			done <- true
		}(i)
	}

	// Start concurrent readers
	for i := 0; i < numGoroutines/2; i++ {
		go func(id int) {
			for j := 0; j < numOperations; j++ {
				var hash common.Hash
				hash[0] = byte(id)
				hash[1] = byte(j % 256)
				cache.Get(hash)
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < numGoroutines; i++ {
		<-done
	}

	// Test should not panic or deadlock
	t.Logf("Cache size after concurrent access: %d", cache.Size())
}

// TestNewNetDBCongestionTracker tests tracker creation
func TestNewNetDBCongestionTracker(t *testing.T) {
	db := NewStdNetDB(t.TempDir())
	cfg := config.CongestionDefaults{
		EFlagAgeThreshold: 15 * time.Minute,
	}

	tracker := NewNetDBCongestionTracker(db, cfg)

	if tracker == nil {
		t.Fatal("Expected non-nil tracker")
	}

	if tracker.db != db {
		t.Error("Tracker db reference mismatch")
	}

	if tracker.cache == nil {
		t.Error("Tracker cache should be initialized")
	}
}

// TestNetDBCongestionTracker_EmptyDB tests behavior with empty database
func TestNetDBCongestionTracker_EmptyDB(t *testing.T) {
	db := NewStdNetDB(t.TempDir())
	cfg := config.CongestionDefaults{
		EFlagAgeThreshold: 15 * time.Minute,
	}

	tracker := NewNetDBCongestionTracker(db, cfg)

	// Test GetCongestionStats on empty DB
	stats := tracker.GetCongestionStats()
	if stats.TotalPeers != 0 {
		t.Errorf("Expected 0 total peers, got %d", stats.TotalPeers)
	}
	if stats.CongestedRatio != 0 {
		t.Errorf("Expected 0 congested ratio, got %f", stats.CongestedRatio)
	}

	// Test CountCongestedPeers on empty DB
	d, e, g, total := tracker.CountCongestedPeers()
	if d != 0 || e != 0 || g != 0 || total != 0 {
		t.Errorf("Expected all zeros, got d=%d e=%d g=%d total=%d", d, e, g, total)
	}

	// Test GetPeerCongestionFlag for non-existent peer
	var hash common.Hash
	copy(hash[:], []byte("nonexistent-peer-hash-12345678"))
	flag := tracker.GetPeerCongestionFlag(hash)
	if flag != config.CongestionFlagNone {
		t.Errorf("Expected CongestionFlagNone for non-existent peer, got %q", flag)
	}
}

// TestNetDBCongestionTracker_CacheInvalidation tests cache invalidation
func TestNetDBCongestionTracker_CacheInvalidation(t *testing.T) {
	db := NewStdNetDB(t.TempDir())
	cfg := config.CongestionDefaults{
		EFlagAgeThreshold: 15 * time.Minute,
	}

	tracker := NewNetDBCongestionTracker(db, cfg)

	var hash common.Hash
	copy(hash[:], []byte("test-peer-hash-value-123456789"))

	// Pre-populate cache
	tracker.cache.Set(hash, config.CongestionFlagD, time.Now())

	// Verify cache hit
	flag, _, found := tracker.cache.Get(hash)
	if !found {
		t.Error("Expected cache hit before invalidation")
	}
	if flag != config.CongestionFlagD {
		t.Errorf("Expected CongestionFlagD, got %q", flag)
	}

	// Invalidate
	tracker.InvalidatePeerCache(hash)

	// Verify cache miss
	_, _, found = tracker.cache.Get(hash)
	if found {
		t.Error("Expected cache miss after invalidation")
	}
}

// TestNetDBCongestionTracker_StaleEFlag tests stale E flag detection
func TestNetDBCongestionTracker_StaleEFlag(t *testing.T) {
	db := NewStdNetDB(t.TempDir())
	cfg := config.CongestionDefaults{
		EFlagAgeThreshold: 15 * time.Minute,
	}

	tracker := NewNetDBCongestionTracker(db, cfg)

	tests := []struct {
		name        string
		riAge       time.Time
		expected    bool
		description string
	}{
		{
			name:        "fresh RouterInfo",
			riAge:       time.Now().Add(-5 * time.Minute),
			expected:    false,
			description: "5 minutes old should not be stale",
		},
		{
			name:        "just under threshold",
			riAge:       time.Now().Add(-14 * time.Minute),
			expected:    false,
			description: "14 minutes old should not be stale",
		},
		{
			name:        "stale RouterInfo",
			riAge:       time.Now().Add(-20 * time.Minute),
			expected:    true,
			description: "20 minutes old should be stale",
		},
		{
			name:        "very stale RouterInfo",
			riAge:       time.Now().Add(-60 * time.Minute),
			expected:    true,
			description: "60 minutes old should be stale",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var hash common.Hash
			copy(hash[:], []byte("test-stale-hash-"+tt.name))

			// Set cache entry with specific age
			tracker.cache.Set(hash, config.CongestionFlagE, tt.riAge)

			isStale := tracker.IsStaleEFlag(hash)
			if isStale != tt.expected {
				t.Errorf("IsStaleEFlag() = %v, want %v (%s)", isStale, tt.expected, tt.description)
			}
		})
	}
}

// TestNetDBCongestionTracker_GetEffectiveCongestionFlag tests effective flag with staleness
func TestNetDBCongestionTracker_GetEffectiveCongestionFlag(t *testing.T) {
	db := NewStdNetDB(t.TempDir())
	cfg := config.CongestionDefaults{
		EFlagAgeThreshold: 15 * time.Minute,
	}

	tracker := NewNetDBCongestionTracker(db, cfg)

	tests := []struct {
		name         string
		flag         config.CongestionFlag
		riAge        time.Time
		expectedFlag config.CongestionFlag
	}{
		{
			name:         "D flag stays D",
			flag:         config.CongestionFlagD,
			riAge:        time.Now().Add(-5 * time.Minute),
			expectedFlag: config.CongestionFlagD,
		},
		{
			name:         "fresh E flag stays E",
			flag:         config.CongestionFlagE,
			riAge:        time.Now().Add(-5 * time.Minute),
			expectedFlag: config.CongestionFlagE,
		},
		{
			name:         "stale E flag becomes D",
			flag:         config.CongestionFlagE,
			riAge:        time.Now().Add(-20 * time.Minute),
			expectedFlag: config.CongestionFlagD,
		},
		{
			name:         "G flag stays G",
			flag:         config.CongestionFlagG,
			riAge:        time.Now().Add(-5 * time.Minute),
			expectedFlag: config.CongestionFlagG,
		},
		{
			name:         "stale G flag stays G",
			flag:         config.CongestionFlagG,
			riAge:        time.Now().Add(-60 * time.Minute),
			expectedFlag: config.CongestionFlagG,
		},
		{
			name:         "no flag stays none",
			flag:         config.CongestionFlagNone,
			riAge:        time.Now(),
			expectedFlag: config.CongestionFlagNone,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var hash common.Hash
			copy(hash[:], []byte("test-effective-"+tt.name))

			// Set cache entry
			tracker.cache.Set(hash, tt.flag, tt.riAge)

			effectiveFlag := tracker.GetEffectiveCongestionFlag(hash)
			if effectiveFlag != tt.expectedFlag {
				t.Errorf("GetEffectiveCongestionFlag() = %q, want %q", effectiveFlag, tt.expectedFlag)
			}
		})
	}
}

// TestNetDBCongestionTracker_ClearCache tests full cache clear
func TestNetDBCongestionTracker_ClearCache(t *testing.T) {
	db := NewStdNetDB(t.TempDir())
	cfg := config.CongestionDefaults{
		EFlagAgeThreshold: 15 * time.Minute,
	}

	tracker := NewNetDBCongestionTracker(db, cfg)

	// Populate cache
	for i := 0; i < 10; i++ {
		var hash common.Hash
		hash[0] = byte(i)
		tracker.cache.Set(hash, config.CongestionFlagD, time.Now())
	}

	if tracker.GetCacheSize() != 10 {
		t.Errorf("Expected cache size 10, got %d", tracker.GetCacheSize())
	}

	tracker.ClearCache()

	if tracker.GetCacheSize() != 0 {
		t.Errorf("Expected cache size 0 after clear, got %d", tracker.GetCacheSize())
	}
}

// TestPeerCongestionInfo_Interface tests that NetDBCongestionTracker implements the interface
func TestPeerCongestionInfo_Interface(t *testing.T) {
	db := NewStdNetDB(t.TempDir())
	cfg := config.CongestionDefaults{}

	var _ PeerCongestionInfo = NewNetDBCongestionTracker(db, cfg)
}
