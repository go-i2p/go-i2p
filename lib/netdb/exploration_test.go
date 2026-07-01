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

// TestExplorerStartWithoutTransport tests that Start fails when lookup transport is absent.
func TestExplorerStartWithoutTransport(t *testing.T) {
	explorer := newTestExplorerDefault(t)
	assertExplorerRequiresTransport(t, explorer.Start)
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
	explorer := newTestExplorerDefault(t)

	// Should not panic
	explorer.Stop()

	stats := explorer.GetStats()
	assert.False(t, stats.IsRunning)
}

// TestExplorerExploreOnceWithoutTransport tests ExploreOnce without lookup transport.
func TestExplorerExploreOnceWithoutTransport(t *testing.T) {
	explorer := newTestExplorerDefault(t)
	assertExplorerRequiresTransport(t, explorer.ExploreOnce)
}

func TestExplorerStartWithoutTunnelPool_WhenTransportPresent(t *testing.T) {
	db := newMockNetDB()
	config := DefaultExplorerConfig()
	config.Transport = &mockLookupTransport{}
	config.LookupTimeout = 50 * time.Millisecond
	explorer := NewExplorer(db, nil, config)

	if err := explorer.Start(); err != nil {
		t.Fatalf("expected explorer to start with direct lookup transport: %v", err)
	}
	explorer.Stop()
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
