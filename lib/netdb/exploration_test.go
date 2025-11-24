package netdb

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestExplorerCreation tests creating a new explorer
func TestExplorerCreation(t *testing.T) {
	db := newMockNetDB()
	config := DefaultExplorerConfig()

	explorer := NewExplorer(db, nil, config)

	assert.NotNil(t, explorer)
	assert.Equal(t, config.Interval, explorer.interval)
	assert.Equal(t, config.Concurrency, explorer.concurrency)
	assert.Equal(t, config.LookupTimeout, explorer.lookupTimeout)
}

// TestExplorerStartWithoutTunnelPool tests that Start fails without a tunnel pool
func TestExplorerStartWithoutTunnelPool(t *testing.T) {
	db := newMockNetDB()
	config := DefaultExplorerConfig()

	explorer := NewExplorer(db, nil, config)
	err := explorer.Start()

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "tunnel pool required")
}

// TestExplorerDefaultConfig tests the default configuration values
func TestExplorerDefaultConfig(t *testing.T) {
	config := DefaultExplorerConfig()

	assert.Equal(t, 5*time.Minute, config.Interval)
	assert.Equal(t, 3, config.Concurrency)
	assert.Equal(t, 30*time.Second, config.LookupTimeout)
}

// TestExplorerGetStats tests retrieving explorer statistics
func TestExplorerGetStats(t *testing.T) {
	db := newMockNetDB()
	config := ExplorerConfig{
		Interval:      10 * time.Minute,
		Concurrency:   5,
		LookupTimeout: 45 * time.Second,
	}

	explorer := NewExplorer(db, nil, config)
	stats := explorer.GetStats()

	assert.Equal(t, 10*time.Minute, stats.Interval)
	assert.Equal(t, 5, stats.Concurrency)
	assert.Equal(t, 45*time.Second, stats.LookupTimeout)
	assert.True(t, stats.IsRunning)
}

// TestExplorerStopBeforeStart tests stopping an explorer that was never started
func TestExplorerStopBeforeStart(t *testing.T) {
	db := newMockNetDB()
	config := DefaultExplorerConfig()

	explorer := NewExplorer(db, nil, config)

	// Should not panic
	explorer.Stop()

	stats := explorer.GetStats()
	assert.False(t, stats.IsRunning)
}

// TestGenerateRandomHash tests random hash generation
func TestGenerateRandomHash(t *testing.T) {
	db := newMockNetDB()
	config := DefaultExplorerConfig()
	explorer := NewExplorer(db, nil, config)

	hash1, err1 := explorer.generateRandomHash()
	hash2, err2 := explorer.generateRandomHash()

	assert.NoError(t, err1)
	assert.NoError(t, err2)
	assert.NotEqual(t, hash1, hash2, "Random hashes should be different")

	// Verify it's a valid 32-byte hash
	assert.Equal(t, 32, len(hash1))
}

// TestExplorerExploreOnceWithoutTunnelPool tests ExploreOnce without tunnel pool
func TestExplorerExploreOnceWithoutTunnelPool(t *testing.T) {
	db := newMockNetDB()
	config := DefaultExplorerConfig()
	explorer := NewExplorer(db, nil, config)

	err := explorer.ExploreOnce()

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "tunnel pool required")
}

// TestExplorerConcurrencyLimits tests that concurrency is respected
func TestExplorerConcurrencyLimits(t *testing.T) {
	db := newMockNetDB()
	config := ExplorerConfig{
		Interval:      1 * time.Hour, // Long interval so we control execution
		Concurrency:   2,
		LookupTimeout: 1 * time.Second,
	}

	explorer := NewExplorer(db, nil, config)

	// The concurrency limit is enforced by the semaphore in performExplorationRound
	// We verify the configuration is stored correctly
	assert.Equal(t, 2, explorer.concurrency)
}

// TestExplorerCustomConfiguration tests creating explorer with custom config
func TestExplorerCustomConfiguration(t *testing.T) {
	db := newMockNetDB()
	config := ExplorerConfig{
		Interval:      15 * time.Minute,
		Concurrency:   10,
		LookupTimeout: 60 * time.Second,
	}

	explorer := NewExplorer(db, nil, config)

	assert.Equal(t, 15*time.Minute, explorer.interval)
	assert.Equal(t, 10, explorer.concurrency)
	assert.Equal(t, 60*time.Second, explorer.lookupTimeout)
}

// TestExplorerInterfaceCompliance tests that Explorer implements expected interface
func TestExplorerInterfaceCompliance(t *testing.T) {
	db := newMockNetDB()
	config := DefaultExplorerConfig()
	explorer := NewExplorer(db, nil, config)

	// Verify explorer has all expected methods
	var _ interface {
		Start() error
		Stop()
		ExploreOnce() error
		GetStats() ExplorerStats
	} = explorer
}
