package netdb

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"
	"time"

	"github.com/go-i2p/common/certificate"
	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/keys_and_cert"
	"github.com/go-i2p/common/router_address"
	"github.com/go-i2p/common/router_identity"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/common/signature"
	"github.com/go-i2p/crypto/ed25519"
	elgamal "github.com/go-i2p/crypto/elg"
	"github.com/go-i2p/crypto/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestRouterInfoWithOptions creates a valid RouterInfo with the specified options.
// This helper is used to construct properly signed RouterInfo objects for testing
// exploration strategy features like floodfill detection and bucket distribution.
func createTestRouterInfoWithOptions(t *testing.T, options map[string]string) *router_info.RouterInfo {
	t.Helper()

	// Generate Ed25519 signing key pair
	ed25519PrivKey, err := ed25519.GenerateEd25519Key()
	require.NoError(t, err, "Failed to generate Ed25519 key")

	ed25519PrivKeyTyped := ed25519PrivKey.(ed25519.Ed25519PrivateKey)
	ed25519PubKeyRaw, err := ed25519PrivKeyTyped.Public()
	require.NoError(t, err, "Failed to derive Ed25519 public key")

	ed25519PubKey, ok := ed25519PubKeyRaw.(types.SigningPublicKey)
	require.True(t, ok, "Failed to cast Ed25519 public key")

	// Generate ElGamal encryption key pair
	var elgPrivKey elgamal.PrivateKey
	err = elgamal.ElgamalGenerate(&elgPrivKey.PrivateKey, rand.Reader)
	require.NoError(t, err, "Failed to generate ElGamal key")

	var elgPubKey elgamal.ElgPublicKey
	yBytes := elgPrivKey.PublicKey.Y.Bytes()
	require.LessOrEqual(t, len(yBytes), 256, "ElGamal public key Y too large")
	copy(elgPubKey[256-len(yBytes):], yBytes)

	// Create KEY certificate for Ed25519/ElGamal
	var payload bytes.Buffer
	signingType, err := common.NewIntegerFromInt(7, 2) // Ed25519
	require.NoError(t, err)
	cryptoType, err := common.NewIntegerFromInt(0, 2) // ElGamal
	require.NoError(t, err)
	payload.Write(*signingType)
	payload.Write(*cryptoType)

	cert, err := certificate.NewCertificateWithType(certificate.CERT_KEY, payload.Bytes())
	require.NoError(t, err, "Failed to create certificate")

	keyCert, err := key_certificate.KeyCertificateFromCertificate(cert)
	require.NoError(t, err, "Failed to create key certificate")

	// Create padding
	pubKeySize := keyCert.CryptoSize()
	sigKeySize := keyCert.SigningPublicKeySize()
	paddingSize := keys_and_cert.KEYS_AND_CERT_DATA_SIZE - pubKeySize - sigKeySize
	padding := make([]byte, paddingSize)
	_, err = rand.Read(padding)
	require.NoError(t, err, "Failed to generate padding")

	// Create RouterIdentity
	routerIdentity, err := router_identity.NewRouterIdentity(elgPubKey, ed25519PubKey, cert, padding)
	require.NoError(t, err, "Failed to create router identity")

	// Create router address
	routerAddr, err := router_address.NewRouterAddress(3, <-time.After(1*time.Second), "NTCP2", map[string]string{})
	require.NoError(t, err, "Failed to create router address")

	// Merge default options with provided options
	mergedOptions := map[string]string{"router.version": "0.9.64"}
	for k, v := range options {
		mergedOptions[k] = v
	}

	// Create RouterInfo
	ri, err := router_info.NewRouterInfo(
		routerIdentity,
		time.Now(),
		[]*router_address.RouterAddress{routerAddr},
		mergedOptions,
		&ed25519PrivKeyTyped,
		signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519,
	)
	require.NoError(t, err, "Failed to create RouterInfo")

	return ri
}

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
	var ourHash common.Hash
	copy(ourHash[:], []byte("test-router-hash-32-bytes-long!"))

	strategy := NewAdaptiveStrategy(ourHash)

	t.Run("empty database", func(t *testing.T) {
		db := newMockNetDB()
		strategy.UpdateStats(db, ourHash)

		assert.Equal(t, 0, strategy.totalRouters)
		assert.Equal(t, 0, strategy.floodfillRouters)
	})

	t.Run("database with non-floodfill routers", func(t *testing.T) {
		db := newMockNetDB()

		// Create and store non-floodfill routers
		for i := 0; i < 3; i++ {
			ri := createTestRouterInfoWithOptions(t, map[string]string{
				"caps": "R",
			})
			db.StoreRouterInfo(*ri)
		}

		strategy.UpdateStats(db, ourHash)

		assert.Equal(t, 3, strategy.totalRouters)
		assert.Equal(t, 0, strategy.floodfillRouters)
	})

	t.Run("database with floodfill routers", func(t *testing.T) {
		db := newMockNetDB()

		// Create floodfill routers (caps containing "f")
		for i := 0; i < 2; i++ {
			ri := createTestRouterInfoWithOptions(t, map[string]string{
				"caps": "fR",
			})
			db.StoreRouterInfo(*ri)
		}

		// Create non-floodfill routers
		ri := createTestRouterInfoWithOptions(t, map[string]string{
			"caps": "R",
		})
		db.StoreRouterInfo(*ri)

		strategy.UpdateStats(db, ourHash)

		assert.Equal(t, 3, strategy.totalRouters)
		assert.Equal(t, 2, strategy.floodfillRouters)
	})

	t.Run("stats reset on subsequent calls", func(t *testing.T) {
		db := newMockNetDB()

		// First call with routers
		ri := createTestRouterInfoWithOptions(t, map[string]string{
			"caps": "fR",
		})
		db.StoreRouterInfo(*ri)

		strategy.UpdateStats(db, ourHash)
		assert.Equal(t, 1, strategy.totalRouters)
		assert.Equal(t, 1, strategy.floodfillRouters)

		// Second call with empty DB should reset
		emptyDB := newMockNetDB()
		strategy.UpdateStats(emptyDB, ourHash)
		assert.Equal(t, 0, strategy.totalRouters)
		assert.Equal(t, 0, strategy.floodfillRouters)
	})
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
	strategy := NewAdaptiveStrategy(common.Hash{})

	t.Run("router with floodfill capability", func(t *testing.T) {
		ri := createTestRouterInfoWithOptions(t, map[string]string{
			"caps": "fR",
		})
		assert.True(t, strategy.isFloodfillRouter(*ri),
			"Router with 'f' in caps should be detected as floodfill")
	})

	t.Run("router without floodfill capability", func(t *testing.T) {
		ri := createTestRouterInfoWithOptions(t, map[string]string{
			"caps": "R",
		})
		assert.False(t, strategy.isFloodfillRouter(*ri),
			"Router without 'f' in caps should not be detected as floodfill")
	})

	t.Run("router with multiple capabilities including floodfill", func(t *testing.T) {
		ri := createTestRouterInfoWithOptions(t, map[string]string{
			"caps": "fRN",
		})
		assert.True(t, strategy.isFloodfillRouter(*ri),
			"Router with 'f' among multiple caps should be detected as floodfill")
	})

	t.Run("router with empty caps", func(t *testing.T) {
		ri := createTestRouterInfoWithOptions(t, map[string]string{
			"caps": "",
		})
		assert.False(t, strategy.isFloodfillRouter(*ri),
			"Router with empty caps should not be detected as floodfill")
	})
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
