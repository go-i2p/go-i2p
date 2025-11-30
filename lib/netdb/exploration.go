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

	// exploration control
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// configuration
	interval      time.Duration // how often to explore
	concurrency   int           // how many parallel explorations
	lookupTimeout time.Duration // timeout for each lookup
}

// ExplorerConfig holds configuration for database exploration
type ExplorerConfig struct {
	// Interval between exploration rounds (default: 5 minutes)
	Interval time.Duration

	// Number of concurrent exploration lookups (default: 3)
	Concurrency int

	// Timeout for individual lookups (default: 30 seconds)
	LookupTimeout time.Duration
}

// DefaultExplorerConfig returns the default explorer configuration
func DefaultExplorerConfig() ExplorerConfig {
	return ExplorerConfig{
		Interval:      5 * time.Minute,
		Concurrency:   3,
		LookupTimeout: 30 * time.Second,
	}
}

// NewExplorer creates a new database explorer.
// The explorer performs periodic lookups to discover new routers and expand
// the NetDB beyond just floodfill routers.
func NewExplorer(db NetworkDatabase, pool *tunnel.Pool, config ExplorerConfig) *Explorer {
	ctx, cancel := context.WithCancel(context.Background())

	return &Explorer{
		db:            db,
		pool:          pool,
		ctx:           ctx,
		cancel:        cancel,
		interval:      config.Interval,
		concurrency:   config.Concurrency,
		lookupTimeout: config.LookupTimeout,
	}
}

// Start begins periodic database exploration.
// Exploration runs in a background goroutine until Stop is called.
func (e *Explorer) Start() error {
	if e.pool == nil {
		return fmt.Errorf("tunnel pool required for exploration")
	}

	log.WithFields(logger.Fields{
		"interval":    e.interval,
		"concurrency": e.concurrency,
	}).Info("Starting database exploration")

	e.wg.Add(1)
	go e.explorationLoop()

	return nil
}

// Stop halts database exploration and waits for in-flight lookups to complete.
func (e *Explorer) Stop() {
	log.Info("Stopping database exploration")
	e.cancel()
	e.wg.Wait()
	log.Info("Database exploration stopped")
}

// explorationLoop runs periodic exploration rounds
func (e *Explorer) explorationLoop() {
	defer e.wg.Done()

	ticker := time.NewTicker(e.interval)
	defer ticker.Stop()

	// Run initial exploration immediately
	e.performExplorationRound()

	for {
		select {
		case <-e.ctx.Done():
			return
		case <-ticker.C:
			e.performExplorationRound()
		}
	}
}

// performExplorationRound executes one round of exploration with configured concurrency
func (e *Explorer) performExplorationRound() {
	log.Debug("Starting exploration round")

	// Create semaphore for concurrency control
	sem := make(chan struct{}, e.concurrency)
	var wg sync.WaitGroup

	// Perform multiple exploratory lookups with random keys
	for i := 0; i < e.concurrency; i++ {
		wg.Add(1)
		sem <- struct{}{} // acquire

		go func(index int) {
			defer wg.Done()
			defer func() { <-sem }() // release

			if err := e.performExploratoryLookup(index); err != nil {
				log.WithError(err).WithField("index", index).Debug("Exploratory lookup failed")
			}
		}(i)
	}

	wg.Wait()
	log.Debug("Exploration round completed")
}

// performExploratoryLookup executes a single exploratory lookup with a random key
func (e *Explorer) performExploratoryLookup(index int) error {
	// Generate random hash for exploration
	randomHash, err := e.generateRandomHash()
	if err != nil {
		return fmt.Errorf("failed to generate random hash: %w", err)
	}

	log.WithFields(logger.Fields{
		"index": index,
		"hash":  fmt.Sprintf("%x", randomHash[:8]),
	}).Debug("Performing exploratory lookup")

	// Create resolver for this lookup
	resolver := NewKademliaResolver(e.db, e.pool)
	if resolver == nil {
		return fmt.Errorf("failed to create resolver")
	}

	// Perform lookup with timeout
	// The KademliaResolver will send DatabaseLookup messages with exploration flag
	_, err = resolver.Lookup(randomHash, e.lookupTimeout)
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

// generateRandomHash creates a cryptographically random 32-byte hash for exploration
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

	log.Info("Performing one-time exploration")
	e.performExplorationRound()
	return nil
}

// GetStats returns statistics about exploration activity
func (e *Explorer) GetStats() ExplorerStats {
	return ExplorerStats{
		Interval:      e.interval,
		Concurrency:   e.concurrency,
		LookupTimeout: e.lookupTimeout,
		IsRunning:     e.ctx.Err() == nil,
	}
}

// ExplorerStats contains statistics about explorer activity
type ExplorerStats struct {
	Interval      time.Duration
	Concurrency   int
	LookupTimeout time.Duration
	IsRunning     bool
}

// Compile-time interface check
var _ interface {
	Start() error
	Stop()
	ExploreOnce() error
} = (*Explorer)(nil)
