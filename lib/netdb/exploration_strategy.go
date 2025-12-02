package netdb

import (
	"fmt"
	"strings"
	"sync"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/crypto/rand"
	"github.com/go-i2p/logger"
)

const (
	// NumKademliaBuckets is the number of Kademlia buckets (256 bits = 256 buckets)
	NumKademliaBuckets = 256

	// MinFloodfillsPerBucket is the minimum desired floodfills per bucket
	MinFloodfillsPerBucket = 2
)

// BucketStats tracks statistics for a single Kademlia bucket
type BucketStats struct {
	BucketIndex      int // 0-255, representing the leading bit position
	TotalRouters     int // Total routers in this bucket
	FloodfillRouters int // Floodfill routers in this bucket
}

// ExplorationStrategy defines an interface for different exploration approaches
type ExplorationStrategy interface {
	// GenerateExplorationKeys generates hashes to explore based on strategy
	GenerateExplorationKeys(count int) ([]common.Hash, error)

	// ShouldExplore determines if exploration is needed based on NetDB state
	ShouldExplore(netdbSize int) bool

	// UpdateStats updates strategy state based on current NetDB
	UpdateStats(db NetworkDatabase, ourHash common.Hash)

	// GetStats returns current strategy statistics
	GetStats() StrategyStats
}

// StrategyStats contains statistics about exploration strategy
type StrategyStats struct {
	TotalRouters       int
	FloodfillRouters   int
	SparseBuckets      []int       // Bucket indices with < MinFloodfillsPerBucket floodfills
	EmptyBuckets       []int       // Bucket indices with no routers
	BucketDistribution map[int]int // Bucket index -> router count
}

// AdaptiveStrategy implements an intelligent exploration strategy that:
// - Tracks Kademlia bucket distribution
// - Identifies gaps in floodfill coverage
// - Generates exploration keys targeting sparse regions
// - Adapts exploration rate based on NetDB size
type AdaptiveStrategy struct {
	mu sync.RWMutex

	// Our router's hash for bucket calculation
	ourHash common.Hash

	// Bucket statistics (index 0-255)
	bucketStats [NumKademliaBuckets]BucketStats

	// Cached stats for quick access
	totalRouters     int
	floodfillRouters int
	sparseBuckets    []int
	emptyBuckets     []int

	// Configuration
	minNetDBSize       int // Minimum desired NetDB size
	minFloodfillsTotal int // Minimum total floodfills desired
}

// NewAdaptiveStrategy creates a new adaptive exploration strategy
func NewAdaptiveStrategy(ourHash common.Hash) *AdaptiveStrategy {
	return &AdaptiveStrategy{
		ourHash:            ourHash,
		minNetDBSize:       500, // Default minimum NetDB size
		minFloodfillsTotal: 50,  // Default minimum floodfills
	}
}

// GenerateExplorationKeys generates exploration keys targeting sparse buckets
func (s *AdaptiveStrategy) GenerateExplorationKeys(count int) ([]common.Hash, error) {
	s.mu.RLock()
	sparseBuckets := make([]int, len(s.sparseBuckets))
	copy(sparseBuckets, s.sparseBuckets)
	emptyBuckets := make([]int, len(s.emptyBuckets))
	copy(emptyBuckets, s.emptyBuckets)
	s.mu.RUnlock()

	keys := make([]common.Hash, count)

	// Prioritize empty buckets first, then sparse buckets
	targetBuckets := append(emptyBuckets, sparseBuckets...)

	for i := 0; i < count; i++ {
		var key common.Hash
		var err error

		if len(targetBuckets) > 0 {
			// Generate key in sparse/empty bucket
			bucketIdx := targetBuckets[i%len(targetBuckets)]
			key, err = s.generateKeyInBucket(bucketIdx)
			if err != nil {
				// Fallback to random if generation fails
				key, err = generateRandomHash()
			}
		} else {
			// No sparse buckets - use random exploration
			key, err = generateRandomHash()
		}

		if err != nil {
			return nil, fmt.Errorf("failed to generate exploration key: %w", err)
		}

		keys[i] = key
	}

	log.WithFields(logger.Fields{
		"count":          count,
		"sparse_buckets": len(sparseBuckets),
		"empty_buckets":  len(emptyBuckets),
	}).Debug("Generated exploration keys targeting sparse regions")

	return keys, nil
}

// ShouldExplore determines if exploration is needed
func (s *AdaptiveStrategy) ShouldExplore(netdbSize int) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Always explore if NetDB is too small
	if netdbSize < s.minNetDBSize {
		return true
	}

	// Explore if we don't have enough floodfills
	if s.floodfillRouters < s.minFloodfillsTotal {
		return true
	}

	// Explore if there are sparse or empty buckets
	if len(s.sparseBuckets) > 0 || len(s.emptyBuckets) > 0 {
		return true
	}

	// NetDB is healthy - less frequent exploration
	return netdbSize < s.minNetDBSize*2
}

// UpdateStats refreshes bucket statistics from current NetDB state
func (s *AdaptiveStrategy) UpdateStats(db NetworkDatabase, ourHash common.Hash) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.ourHash = ourHash
	s.resetStatistics()

	routers := db.GetAllRouterInfos()
	s.totalRouters = len(routers)

	s.processBucketDistribution(routers)
	s.identifyBucketGaps()
	s.logStatisticsUpdate()
}

// resetStatistics clears all bucket statistics and counters to prepare for a fresh update.
func (s *AdaptiveStrategy) resetStatistics() {
	for i := 0; i < NumKademliaBuckets; i++ {
		s.bucketStats[i] = BucketStats{BucketIndex: i}
	}
	s.totalRouters = 0
	s.floodfillRouters = 0
	s.sparseBuckets = nil
	s.emptyBuckets = nil
}

// processBucketDistribution calculates bucket assignments for all routers and updates statistics.
func (s *AdaptiveStrategy) processBucketDistribution(routers []router_info.RouterInfo) {
	for _, ri := range routers {
		riHash, err := ri.IdentHash()
		if err != nil {
			log.WithError(err).Debug("Failed to get router hash, skipping")
			continue
		}
		bucketIdx := s.calculateBucket(riHash)

		s.bucketStats[bucketIdx].TotalRouters++

		if s.isFloodfillRouter(ri) {
			s.bucketStats[bucketIdx].FloodfillRouters++
			s.floodfillRouters++
		}
	}
}

// identifyBucketGaps finds buckets that are empty or have insufficient floodfill coverage.
func (s *AdaptiveStrategy) identifyBucketGaps() {
	for i := 0; i < NumKademliaBuckets; i++ {
		stats := s.bucketStats[i]

		if stats.TotalRouters == 0 {
			s.emptyBuckets = append(s.emptyBuckets, i)
		} else if stats.FloodfillRouters < MinFloodfillsPerBucket {
			s.sparseBuckets = append(s.sparseBuckets, i)
		}
	}
}

// logStatisticsUpdate logs the current exploration strategy statistics for debugging.
func (s *AdaptiveStrategy) logStatisticsUpdate() {
	log.WithFields(logger.Fields{
		"total_routers":  s.totalRouters,
		"floodfills":     s.floodfillRouters,
		"empty_buckets":  len(s.emptyBuckets),
		"sparse_buckets": len(s.sparseBuckets),
	}).Debug("Updated exploration strategy statistics")
}

// GetStats returns current strategy statistics
func (s *AdaptiveStrategy) GetStats() StrategyStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats := StrategyStats{
		TotalRouters:       s.totalRouters,
		FloodfillRouters:   s.floodfillRouters,
		SparseBuckets:      make([]int, len(s.sparseBuckets)),
		EmptyBuckets:       make([]int, len(s.emptyBuckets)),
		BucketDistribution: make(map[int]int),
	}

	copy(stats.SparseBuckets, s.sparseBuckets)
	copy(stats.EmptyBuckets, s.emptyBuckets)

	// Copy bucket distribution
	for i := 0; i < NumKademliaBuckets; i++ {
		if s.bucketStats[i].TotalRouters > 0 {
			stats.BucketDistribution[i] = s.bucketStats[i].TotalRouters
		}
	}

	return stats
}

// calculateBucket determines which Kademlia bucket a router hash belongs to.
// Bucket is determined by the position of the most significant differing bit
// between our hash and the router hash (0-255).
func (s *AdaptiveStrategy) calculateBucket(routerHash common.Hash) int {
	// XOR distance
	var distance common.Hash
	for i := 0; i < 32; i++ {
		distance[i] = s.ourHash[i] ^ routerHash[i]
	}

	// Find first non-zero bit (most significant differing bit)
	for byteIdx := 0; byteIdx < 32; byteIdx++ {
		if distance[byteIdx] != 0 {
			// Find position of most significant bit in this byte
			b := distance[byteIdx]
			for bitIdx := 7; bitIdx >= 0; bitIdx-- {
				if (b & (1 << uint(bitIdx))) != 0 {
					// Bucket index = byte position * 8 + bit position
					return byteIdx*8 + (7 - bitIdx)
				}
			}
		}
	}

	// Distance is zero (same router) - shouldn't happen in practice
	return 0
}

// generateKeyInBucket creates a hash that falls into the specified Kademlia bucket.
// The bucket is determined by the position of the most significant differing bit.
func (s *AdaptiveStrategy) generateKeyInBucket(bucketIdx int) (common.Hash, error) {
	if bucketIdx < 0 || bucketIdx >= NumKademliaBuckets {
		return common.Hash{}, fmt.Errorf("invalid bucket index: %d", bucketIdx)
	}

	// Start with our hash and flip the target bit
	key := s.createKeyWithFlippedBit(bucketIdx)

	// Randomize all less significant bits
	if err := s.randomizeLowerBits(&key, bucketIdx); err != nil {
		return common.Hash{}, err
	}

	return key, nil
}

// createKeyWithFlippedBit creates a key with the bit at bucketIdx flipped.
func (s *AdaptiveStrategy) createKeyWithFlippedBit(bucketIdx int) common.Hash {
	var key common.Hash
	copy(key[:], s.ourHash[:])

	// Flip the bit at position bucketIdx to create distance
	byteIdx := bucketIdx / 8
	bitIdx := 7 - (bucketIdx % 8)
	key[byteIdx] ^= (1 << uint(bitIdx))

	return key
}

// randomizeLowerBits randomizes all bits less significant than bucketIdx.
func (s *AdaptiveStrategy) randomizeLowerBits(key *common.Hash, bucketIdx int) error {
	byteIdx := bucketIdx / 8
	bitIdx := 7 - (bucketIdx % 8)

	// Randomize remaining bits in the target byte
	for bit := bitIdx - 1; bit >= 0; bit-- {
		if randomBit() {
			key[byteIdx] |= (1 << uint(bit))
		} else {
			key[byteIdx] &^= (1 << uint(bit))
		}
	}

	// Randomize all subsequent bytes
	for i := byteIdx + 1; i < 32; i++ {
		var b [1]byte
		_, err := rand.Read(b[:])
		if err != nil {
			return fmt.Errorf("failed to generate random byte: %w", err)
		}
		key[i] = b[0]
	}

	return nil
}

// randomBit returns a random boolean value
func randomBit() bool {
	var b [1]byte
	rand.Read(b[:])
	return (b[0] & 1) == 1
}

// generateRandomHash creates a cryptographically random hash
func generateRandomHash() (common.Hash, error) {
	var hash common.Hash
	_, err := rand.Read(hash[:])
	if err != nil {
		return common.Hash{}, fmt.Errorf("failed to generate random hash: %w", err)
	}
	return hash, nil
}

// GetBucketStats returns statistics for a specific bucket
func (s *AdaptiveStrategy) GetBucketStats(bucketIdx int) BucketStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if bucketIdx < 0 || bucketIdx >= NumKademliaBuckets {
		return BucketStats{}
	}

	return s.bucketStats[bucketIdx]
}

// GetFloodfillGaps returns bucket indices with insufficient floodfill coverage
func (s *AdaptiveStrategy) GetFloodfillGaps() []int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	gaps := make([]int, len(s.sparseBuckets))
	copy(gaps, s.sparseBuckets)
	return gaps
}

// isFloodfillRouter checks if a RouterInfo represents a floodfill router.
// Returns true if the router's "caps" option contains 'f'.
// This uses the same logic as StdNetDB.isFloodfillRouter
func (s *AdaptiveStrategy) isFloodfillRouter(ri router_info.RouterInfo) bool {
	options := ri.Options()
	capsKey, _ := common.ToI2PString("caps")
	capsValue := options.Values().Get(capsKey)
	caps, _ := capsValue.Data()
	return strings.Contains(caps, "f")
}

// Compile-time interface check
var _ ExplorationStrategy = (*AdaptiveStrategy)(nil)
