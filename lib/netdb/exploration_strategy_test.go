package netdb

import (
	"fmt"
	"testing"

	common "github.com/go-i2p/common/data"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewAdaptiveStrategy verifies adaptive strategy initialization
func TestNewAdaptiveStrategy(t *testing.T) {
	var ourHash common.Hash
	copy(ourHash[:], []byte("test-router-hash-32-bytes-long!"))

	strategy := NewAdaptiveStrategy(ourHash)

	assert.NotNil(t, strategy)
	assert.Equal(t, ourHash, strategy.ourHash)
	assert.Equal(t, 500, strategy.minNetDBSize)
	assert.Equal(t, 50, strategy.minFloodfillsTotal)
}

// TestCalculateBucket verifies Kademlia bucket calculation
func TestCalculateBucket(t *testing.T) {
	// Our router hash (all zeros for simplicity)
	var ourHash common.Hash

	strategy := NewAdaptiveStrategy(ourHash)

	tests := []struct {
		name        string
		routerHash  common.Hash
		expectedMin int // Minimum expected bucket
		expectedMax int // Maximum expected bucket
	}{
		{
			name:        "identical hash",
			routerHash:  ourHash,
			expectedMin: 0,
			expectedMax: 0,
		},
		{
			name:        "differ in first bit",
			routerHash:  common.Hash{0x80}, // 1000 0000 in binary
			expectedMin: 0,
			expectedMax: 0,
		},
		{
			name:        "differ in second bit",
			routerHash:  common.Hash{0x40}, // 0100 0000 in binary
			expectedMin: 1,
			expectedMax: 1,
		},
		{
			name:        "differ in last byte",
			routerHash:  common.Hash{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
			expectedMin: 255,
			expectedMax: 255,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bucket := strategy.calculateBucket(tt.routerHash)
			assert.GreaterOrEqual(t, bucket, tt.expectedMin)
			assert.LessOrEqual(t, bucket, tt.expectedMax)
		})
	}
}

// TestGenerateKeyInBucket verifies bucket-targeted key generation
func TestGenerateKeyInBucket(t *testing.T) {
	var ourHash common.Hash
	copy(ourHash[:], []byte("test-router-hash-32-bytes-long!"))

	strategy := NewAdaptiveStrategy(ourHash)

	// Test generation for various buckets
	buckets := []int{0, 1, 127, 128, 255}

	for _, bucketIdx := range buckets {
		t.Run(fmt.Sprintf("bucket_%d", bucketIdx), func(t *testing.T) {
			key, err := strategy.generateKeyInBucket(bucketIdx)
			require.NoError(t, err)

			// Verify key is not identical to our hash
			assert.NotEqual(t, ourHash, key)

			// Verify key falls in the correct bucket
			calculatedBucket := strategy.calculateBucket(key)
			assert.Equal(t, bucketIdx, calculatedBucket,
				"Generated key should fall in target bucket")
		})
	}
}

// TestGenerateKeyInBucket_InvalidBucket tests error handling
func TestGenerateKeyInBucket_InvalidBucket(t *testing.T) {
	strategy := NewAdaptiveStrategy(common.Hash{})

	tests := []struct {
		name      string
		bucketIdx int
	}{
		{"negative bucket", -1},
		{"bucket too large", 256},
		{"bucket way too large", 1000},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := strategy.generateKeyInBucket(tt.bucketIdx)
			assert.Error(t, err)
		})
	}
}

// TestUpdateStats verifies statistics tracking
func TestUpdateStats(t *testing.T) {
	db := NewStdNetDB("")

	var ourHash common.Hash
	copy(ourHash[:], []byte("test-router-hash-32-bytes-long!"))

	_ = NewAdaptiveStrategy(ourHash)

	// Initially empty - use RouterNetDB for NetworkDatabase interface
	_ = NewRouterNetDB(db)
	// TODO: Create actual test with mock NetworkDatabase
	// For now we just verify strategy can be created
	// strategy.UpdateStats(db, ourHash)
	// assert.Equal(t, 0, strategy.totalRouters)
	// assert.Equal(t, 0, strategy.floodfillRouters)

	// TODO: Add routers to NetDB and verify stats update
	// This would require creating mock RouterInfo entries
}

// TestShouldExplore verifies exploration decision logic
func TestShouldExplore(t *testing.T) {
	tests := []struct {
		name          string
		netdbSize     int
		setupStrategy func(*AdaptiveStrategy)
		shouldExplore bool
	}{
		{
			name:          "empty netdb",
			netdbSize:     0,
			setupStrategy: func(s *AdaptiveStrategy) {},
			shouldExplore: true,
		},
		{
			name:          "small netdb",
			netdbSize:     100,
			setupStrategy: func(s *AdaptiveStrategy) {},
			shouldExplore: true,
		},
		{
			name:      "large netdb with sparse buckets",
			netdbSize: 1000,
			setupStrategy: func(s *AdaptiveStrategy) {
				s.floodfillRouters = 100
				s.sparseBuckets = []int{0, 1, 2} // Has sparse buckets
			},
			shouldExplore: true,
		},
		{
			name:      "large netdb with empty buckets",
			netdbSize: 1000,
			setupStrategy: func(s *AdaptiveStrategy) {
				s.floodfillRouters = 100
				s.emptyBuckets = []int{10, 20} // Has empty buckets
			},
			shouldExplore: true,
		},
		{
			name:      "healthy netdb",
			netdbSize: 800,
			setupStrategy: func(s *AdaptiveStrategy) {
				s.floodfillRouters = 60
				s.sparseBuckets = nil
				s.emptyBuckets = nil
			},
			shouldExplore: true, // Still true because < minNetDBSize*2
		},
		{
			name:      "very large healthy netdb",
			netdbSize: 1500,
			setupStrategy: func(s *AdaptiveStrategy) {
				s.floodfillRouters = 100
				s.sparseBuckets = nil
				s.emptyBuckets = nil
			},
			shouldExplore: false, // False because >= minNetDBSize*2 and no gaps
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			strategy := NewAdaptiveStrategy(common.Hash{})
			tt.setupStrategy(strategy)

			result := strategy.ShouldExplore(tt.netdbSize)
			assert.Equal(t, tt.shouldExplore, result)
		})
	}
}

// TestGenerateExplorationKeys verifies key generation
func TestGenerateExplorationKeys(t *testing.T) {
	var ourHash common.Hash
	copy(ourHash[:], []byte("test-router-hash-32-bytes-long!"))

	strategy := NewAdaptiveStrategy(ourHash)

	// Generate keys for sparse buckets
	strategy.sparseBuckets = []int{5, 10, 15}
	strategy.emptyBuckets = []int{20, 25}

	keys, err := strategy.GenerateExplorationKeys(10)
	require.NoError(t, err)
	assert.Len(t, keys, 10)

	// Verify all keys are non-zero
	for i, key := range keys {
		assert.NotEqual(t, common.Hash{}, key, "Key %d should not be zero hash", i)
	}

	// Verify keys are unique (highly probable with random generation)
	uniqueKeys := make(map[common.Hash]bool)
	for _, key := range keys {
		uniqueKeys[key] = true
	}
	assert.Len(t, uniqueKeys, len(keys), "All keys should be unique")
}

// TestGenerateExplorationKeys_NoSparseBuckets tests random fallback
func TestGenerateExplorationKeys_NoSparseBuckets(t *testing.T) {
	strategy := NewAdaptiveStrategy(common.Hash{})

	// No sparse or empty buckets - should use random exploration
	strategy.sparseBuckets = nil
	strategy.emptyBuckets = nil

	keys, err := strategy.GenerateExplorationKeys(5)
	require.NoError(t, err)
	assert.Len(t, keys, 5)

	// Verify keys are generated
	for i, key := range keys {
		assert.NotEqual(t, common.Hash{}, key, "Key %d should not be zero hash", i)
	}
}

// TestGetStats verifies statistics retrieval
func TestGetStats(t *testing.T) {
	strategy := NewAdaptiveStrategy(common.Hash{})

	// Set up some state
	strategy.totalRouters = 100
	strategy.floodfillRouters = 20
	strategy.sparseBuckets = []int{1, 2, 3}
	strategy.emptyBuckets = []int{10, 20}

	stats := strategy.GetStats()

	assert.Equal(t, 100, stats.TotalRouters)
	assert.Equal(t, 20, stats.FloodfillRouters)
	assert.Len(t, stats.SparseBuckets, 3)
	assert.Len(t, stats.EmptyBuckets, 2)
	assert.Contains(t, stats.SparseBuckets, 1)
	assert.Contains(t, stats.EmptyBuckets, 10)
}

// TestGetBucketStats verifies per-bucket statistics
func TestGetBucketStats(t *testing.T) {
	strategy := NewAdaptiveStrategy(common.Hash{})

	// Set up bucket stats
	strategy.bucketStats[5] = BucketStats{
		BucketIndex:      5,
		TotalRouters:     10,
		FloodfillRouters: 3,
	}

	stats := strategy.GetBucketStats(5)
	assert.Equal(t, 5, stats.BucketIndex)
	assert.Equal(t, 10, stats.TotalRouters)
	assert.Equal(t, 3, stats.FloodfillRouters)

	// Test invalid bucket
	invalidStats := strategy.GetBucketStats(-1)
	assert.Equal(t, BucketStats{}, invalidStats)

	invalidStats = strategy.GetBucketStats(256)
	assert.Equal(t, BucketStats{}, invalidStats)
}

// TestGetFloodfillGaps verifies gap identification
func TestGetFloodfillGaps(t *testing.T) {
	strategy := NewAdaptiveStrategy(common.Hash{})

	strategy.sparseBuckets = []int{1, 5, 10}

	gaps := strategy.GetFloodfillGaps()
	assert.Len(t, gaps, 3)
	assert.Contains(t, gaps, 1)
	assert.Contains(t, gaps, 5)
	assert.Contains(t, gaps, 10)
}

// TestRandomBit verifies random bit generation
func TestRandomBit(t *testing.T) {
	// Generate many random bits and verify distribution is reasonable
	trueCount := 0
	falseCount := 0
	iterations := 1000

	for i := 0; i < iterations; i++ {
		if randomBit() {
			trueCount++
		} else {
			falseCount++
		}
	}

	// Both should be non-zero (extremely high probability)
	assert.Greater(t, trueCount, 0)
	assert.Greater(t, falseCount, 0)

	// Should be roughly balanced (within 30% of 50/50)
	ratio := float64(trueCount) / float64(iterations)
	assert.Greater(t, ratio, 0.2)
	assert.Less(t, ratio, 0.8)
}

// TestGenerateRandomHashFunc verifies random hash generation
func TestGenerateRandomHashFunc(t *testing.T) {
	hash1, err1 := generateRandomHash()
	hash2, err2 := generateRandomHash()

	require.NoError(t, err1)
	require.NoError(t, err2)

	// Hashes should be non-zero
	assert.NotEqual(t, common.Hash{}, hash1)
	assert.NotEqual(t, common.Hash{}, hash2)

	// Hashes should be different (extremely high probability)
	assert.NotEqual(t, hash1, hash2)
}

// TestIsFloodfillRouter verifies floodfill detection
func TestIsFloodfillRouter(t *testing.T) {
	_ = NewAdaptiveStrategy(common.Hash{})

	// TODO: Create mock RouterInfo with floodfill capability
	// This requires proper RouterInfo construction which depends on common package
	// For now, we document the expected behavior:
	// - Router with "caps" option containing "f" should return true
	// - Router without "f" in caps should return false

	t.Skip("Requires mock RouterInfo creation")
}

// BenchmarkCalculateBucket benchmarks bucket calculation
func BenchmarkCalculateBucket(b *testing.B) {
	strategy := NewAdaptiveStrategy(common.Hash{})
	var testHash common.Hash
	copy(testHash[:], []byte("benchmark-hash-32-bytes-long!!!"))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = strategy.calculateBucket(testHash)
	}
}

// BenchmarkGenerateKeyInBucket benchmarks key generation
func BenchmarkGenerateKeyInBucket(b *testing.B) {
	strategy := NewAdaptiveStrategy(common.Hash{})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = strategy.generateKeyInBucket(100)
	}
}

// BenchmarkGenerateExplorationKeys benchmarks multiple key generation
func BenchmarkGenerateExplorationKeys(b *testing.B) {
	strategy := NewAdaptiveStrategy(common.Hash{})
	strategy.sparseBuckets = []int{1, 5, 10, 50, 100}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = strategy.GenerateExplorationKeys(10)
	}
}
