package netdb

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/go-i2p/crypto/rand"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/go-i2p/logger"
)

// Explorer handles periodic database exploration to discover new routers.
// Database exploration sends DatabaseLookup messages with the exploration flag
// to discover non-floodfill routers and expand NetDB knowledge.
type Explorer struct {
	// netdb to store discovered routers
	db NetworkDatabase

	// tunnel pool to use for lookups
	pool *tunnel.Pool

	// exploration strategy (adaptive or random)
	strategy ExplorationStrategy

	// our router hash for bucket calculations
	ourHash common.Hash

	// exploration control
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// configuration
	interval       time.Duration // base exploration interval
	minInterval    time.Duration // minimum interval when NetDB is sparse
	maxInterval    time.Duration // maximum interval when NetDB is healthy
	concurrency    int           // how many parallel explorations
	lookupTimeout  time.Duration // timeout for each lookup
	useAdaptive    bool          // whether to use adaptive strategy
	statsUpdateInt time.Duration // how often to update strategy stats
}

// ExplorerConfig holds configuration for database exploration
type ExplorerConfig struct {
	// Interval between exploration rounds (default: 5 minutes)
	Interval time.Duration

	// MinInterval is the minimum exploration interval when NetDB is sparse (default: 1 minute)
	MinInterval time.Duration

	// MaxInterval is the maximum exploration interval when NetDB is healthy (default: 15 minutes)
	MaxInterval time.Duration

	// Number of concurrent exploration lookups (default: 3)
	Concurrency int

	// Timeout for individual lookups (default: 30 seconds)
	LookupTimeout time.Duration

	// UseAdaptive enables adaptive exploration strategy (default: true)
	// When true, uses bucket-aware exploration targeting sparse regions
	// When false, uses simple random exploration
	UseAdaptive bool

	// OurHash is our router's identity hash for bucket calculations
	// Required for adaptive strategy
	OurHash common.Hash

	// StatsUpdateInterval determines how often to update strategy statistics (default: 1 minute)
	StatsUpdateInterval time.Duration
}

// DefaultExplorerConfig returns the default explorer configuration
func DefaultExplorerConfig() ExplorerConfig {
	return ExplorerConfig{
		Interval:            5 * time.Minute,
		MinInterval:         1 * time.Minute,
		MaxInterval:         15 * time.Minute,
		Concurrency:         3,
		LookupTimeout:       30 * time.Second,
		UseAdaptive:         true,
		StatsUpdateInterval: 1 * time.Minute,
	}
}

// NewExplorer creates a new database explorer.
// The explorer performs periodic lookups to discover new routers and expand
// the NetDB beyond just floodfill routers.
func NewExplorer(db NetworkDatabase, pool *tunnel.Pool, config ExplorerConfig) *Explorer {
	ctx, cancel := context.WithCancel(context.Background())

	explorer := &Explorer{
		db:             db,
		pool:           pool,
		ctx:            ctx,
		cancel:         cancel,
		interval:       config.Interval,
		minInterval:    config.MinInterval,
		maxInterval:    config.MaxInterval,
		concurrency:    config.Concurrency,
		lookupTimeout:  config.LookupTimeout,
		useAdaptive:    config.UseAdaptive,
		ourHash:        config.OurHash,
		statsUpdateInt: config.StatsUpdateInterval,
	}

	// Initialize exploration strategy
	if config.UseAdaptive {
		explorer.strategy = NewAdaptiveStrategy(config.OurHash)
	}
	// If not adaptive, strategy remains nil and we use simple random exploration

	return explorer
}

// Start begins periodic database exploration.
// Exploration runs in a background goroutine until Stop is called.
func (e *Explorer) Start() error {
	if e.pool == nil {
		return fmt.Errorf("tunnel pool required for exploration")
	}

	log.WithFields(logger.Fields{
		"interval":     e.interval,
		"concurrency":  e.concurrency,
		"use_adaptive": e.useAdaptive,
	}).Info("Starting database exploration")

	e.wg.Add(1)
	go e.explorationLoop()

	// Start stats update loop if using adaptive strategy
	if e.strategy != nil {
		e.wg.Add(1)
		go e.statsUpdateLoop()
	}

	return nil
}

// Stop halts database exploration and waits for in-flight lookups to complete.
func (e *Explorer) Stop() {
	log.WithFields(logger.Fields{
		"at":     "(Explorer) Stop",
		"reason": "shutdown_requested",
	}).Info("stopping database exploration")
	e.cancel()
	e.wg.Wait()
	log.WithFields(logger.Fields{
		"at":     "(Explorer) Stop",
		"reason": "shutdown_complete",
	}).Info("database exploration stopped")
}

// explorationLoop runs periodic exploration rounds
func (e *Explorer) explorationLoop() {
	defer e.wg.Done()

	interval := e.calculateExplorationInterval()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	e.performExplorationRound()
	e.runExplorationTicker(ticker, &interval)
}

// runExplorationTicker manages the main exploration ticker loop
func (e *Explorer) runExplorationTicker(ticker *time.Ticker, interval *time.Duration) {
	for {
		select {
		case <-e.ctx.Done():
			return
		case <-ticker.C:
			e.performExplorationRound()
			e.adjustIntervalIfNeeded(ticker, interval)
		}
	}
}

// adjustIntervalIfNeeded recalculates and updates the exploration interval when using adaptive strategy
func (e *Explorer) adjustIntervalIfNeeded(ticker *time.Ticker, currentInterval *time.Duration) {
	if !e.useAdaptive {
		return
	}

	newInterval := e.calculateExplorationInterval()
	if newInterval == *currentInterval {
		return
	}

	*currentInterval = newInterval
	ticker.Reset(newInterval)
	log.WithFields(logger.Fields{
		"at":           "(Explorer) adjustExplorationInterval",
		"reason":       "dynamic_interval_adjustment",
		"new_interval": newInterval,
	}).Debug("adjusted exploration interval")
}

// performExplorationRound executes one round of exploration with configured concurrency
func (e *Explorer) performExplorationRound() {
	log.WithFields(logger.Fields{
		"at":     "(Explorer) exploreRound",
		"reason": "periodic_network_discovery",
	}).Debug("starting exploration round")

	// Generate exploration keys using strategy
	var keys []common.Hash
	var err error

	if e.strategy != nil {
		// Use adaptive strategy to generate targeted keys
		keys, err = e.strategy.GenerateExplorationKeys(e.concurrency)
		if err != nil {
			log.WithError(err).Warn("Failed to generate strategic exploration keys, using random")
			keys = e.generateRandomKeys(e.concurrency)
		}
	} else {
		// Use simple random exploration
		keys = e.generateRandomKeys(e.concurrency)
	}

	// Create semaphore for concurrency control
	sem := make(chan struct{}, e.concurrency)
	var wg sync.WaitGroup

	// Perform lookups for generated keys
	for i, key := range keys {
		wg.Add(1)
		sem <- struct{}{} // acquire

		go func(index int, hash common.Hash) {
			defer wg.Done()
			defer func() { <-sem }() // release

			if err := e.performExploratoryLookup(index, hash); err != nil {
				log.WithError(err).WithField("index", index).Debug("Exploratory lookup failed")
			}
		}(i, key)
	}

	wg.Wait()
	log.WithFields(logger.Fields{
		"at":     "(Explorer) exploreRound",
		"reason": "round_completed",
	}).Debug("exploration round completed")
}

// performExploratoryLookup executes a single exploratory lookup with the given hash
func (e *Explorer) performExploratoryLookup(index int, lookupHash common.Hash) error {
	log.WithFields(logger.Fields{
		"index": index,
		"hash":  fmt.Sprintf("%x", lookupHash[:8]),
	}).Debug("Performing exploratory lookup")

	// Create resolver for this lookup
	resolver := NewKademliaResolver(e.db, e.pool)
	if resolver == nil {
		return fmt.Errorf("failed to create resolver")
	}

	// Perform lookup with timeout
	// The KademliaResolver will send DatabaseLookup messages with exploration flag
	_, err := resolver.Lookup(lookupHash, e.lookupTimeout)
	// Note: We expect most exploratory lookups to fail (no exact match for random hash)
	// The value is in the DatabaseSearchReply messages we receive, which contain
	// references to non-floodfill routers that get stored in NetDB
	if err != nil {
		log.WithFields(logger.Fields{
			"index": index,
			"error": err.Error(),
		}).Trace("Exploratory lookup returned error (expected for random hash)")
	}

	return nil
}

// generateRandomKeys creates multiple random hashes for exploration
func (e *Explorer) generateRandomKeys(count int) []common.Hash {
	keys := make([]common.Hash, count)
	for i := 0; i < count; i++ {
		rand.Read(keys[i][:])
	}
	return keys
}

// statsUpdateLoop periodically updates exploration strategy statistics
func (e *Explorer) statsUpdateLoop() {
	defer e.wg.Done()

	ticker := time.NewTicker(e.statsUpdateInt)
	defer ticker.Stop()

	// Update stats immediately
	if e.strategy != nil {
		e.strategy.UpdateStats(e.db, e.ourHash)
	}

	for {
		select {
		case <-e.ctx.Done():
			return
		case <-ticker.C:
			if e.strategy != nil {
				e.strategy.UpdateStats(e.db, e.ourHash)
			}
		}
	}
}

// calculateExplorationInterval determines the exploration interval based on NetDB state
func (e *Explorer) calculateExplorationInterval() time.Duration {
	if !e.useAdaptive || e.strategy == nil {
		return e.interval
	}

	// Get NetDB size
	routers := e.db.GetAllRouterInfos()
	netdbSize := len(routers)

	// Check if exploration is urgently needed
	if e.strategy.ShouldExplore(netdbSize) {
		// Use minimum interval for frequent exploration
		return e.minInterval
	}

	// NetDB is healthy - use maximum interval
	return e.maxInterval
}

// generateRandomHash creates a cryptographically random 32-byte hash for exploration
// Deprecated: Use generateRandomKeys instead
func (e *Explorer) generateRandomHash() (common.Hash, error) {
	var hash common.Hash
	_, err := rand.Read(hash[:])
	if err != nil {
		return common.Hash{}, fmt.Errorf("failed to read random bytes: %w", err)
	}
	return hash, nil
}

// ExploreOnce performs a single exploration round and returns immediately.
// Useful for testing or manual exploration triggers.
func (e *Explorer) ExploreOnce() error {
	if e.pool == nil {
		return fmt.Errorf("tunnel pool required for exploration")
	}

	log.WithFields(logger.Fields{
		"at":     "(Explorer) ExploreOnce",
		"reason": "manual_exploration_triggered",
	}).Info("performing one-time exploration")
	e.performExplorationRound()
	return nil
}

// GetStats returns statistics about exploration activity
func (e *Explorer) GetStats() ExplorerStats {
	stats := ExplorerStats{
		Interval:      e.interval,
		Concurrency:   e.concurrency,
		LookupTimeout: e.lookupTimeout,
		IsRunning:     e.ctx.Err() == nil,
		UseAdaptive:   e.useAdaptive,
	}

	if e.strategy != nil {
		strategyStats := e.strategy.GetStats()
		stats.TotalRouters = strategyStats.TotalRouters
		stats.FloodfillRouters = strategyStats.FloodfillRouters
		stats.SparseBuckets = len(strategyStats.SparseBuckets)
		stats.EmptyBuckets = len(strategyStats.EmptyBuckets)
	}

	return stats
}

// ExplorerStats contains statistics about explorer activity
type ExplorerStats struct {
	Interval         time.Duration
	Concurrency      int
	LookupTimeout    time.Duration
	IsRunning        bool
	UseAdaptive      bool
	TotalRouters     int
	FloodfillRouters int
	SparseBuckets    int
	EmptyBuckets     int
}

// Compile-time interface check
var _ interface {
	Start() error
	Stop()
	ExploreOnce() error
} = (*Explorer)(nil)
