package netdb

import (
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/lease_set"
	"github.com/go-i2p/common/router_info"
	"github.com/stretchr/testify/assert"
)

// TestPublisherCreation tests creating a new publisher
func TestPublisherCreation(t *testing.T) {
	db := newMockNetDB()
	config := DefaultPublisherConfig()

	publisher := NewPublisher(db, nil, config)

	assert.NotNil(t, publisher)
	assert.Equal(t, config.RouterInfoInterval, publisher.routerInfoInterval)
	assert.Equal(t, config.LeaseSetInterval, publisher.leaseSetInterval)
	assert.Equal(t, config.FloodfillCount, publisher.floodfillCount)
}

// TestPublisherStartWithoutTunnelPool tests that Start fails without a tunnel pool
func TestPublisherStartWithoutTunnelPool(t *testing.T) {
	db := newMockNetDB()
	config := DefaultPublisherConfig()

	publisher := NewPublisher(db, nil, config)
	err := publisher.Start()

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "tunnel pool required")
}

// TestPublisherDefaultConfig tests the default configuration values
func TestPublisherDefaultConfig(t *testing.T) {
	config := DefaultPublisherConfig()

	assert.Equal(t, 30*time.Minute, config.RouterInfoInterval)
	assert.Equal(t, 5*time.Minute, config.LeaseSetInterval)
	assert.Equal(t, 4, config.FloodfillCount)
}

// TestPublisherGetStats tests retrieving publisher statistics
func TestPublisherGetStats(t *testing.T) {
	db := newMockNetDB()
	config := PublisherConfig{
		RouterInfoInterval: 20 * time.Minute,
		LeaseSetInterval:   3 * time.Minute,
		FloodfillCount:     6,
	}

	publisher := NewPublisher(db, nil, config)
	stats := publisher.GetStats()

	assert.Equal(t, 20*time.Minute, stats.RouterInfoInterval)
	assert.Equal(t, 3*time.Minute, stats.LeaseSetInterval)
	assert.Equal(t, 6, stats.FloodfillCount)
	assert.True(t, stats.IsRunning)
}

// TestPublisherStopBeforeStart tests stopping a publisher that was never started
func TestPublisherStopBeforeStart(t *testing.T) {
	db := newMockNetDB()
	config := DefaultPublisherConfig()

	publisher := NewPublisher(db, nil, config)

	// Should not panic
	publisher.Stop()

	stats := publisher.GetStats()
	assert.False(t, stats.IsRunning)
}

// TestPublisherCustomConfiguration tests creating publisher with custom config
func TestPublisherCustomConfiguration(t *testing.T) {
	db := newMockNetDB()
	config := PublisherConfig{
		RouterInfoInterval: 45 * time.Minute,
		LeaseSetInterval:   10 * time.Minute,
		FloodfillCount:     8,
	}

	publisher := NewPublisher(db, nil, config)

	assert.Equal(t, 45*time.Minute, publisher.routerInfoInterval)
	assert.Equal(t, 10*time.Minute, publisher.leaseSetInterval)
	assert.Equal(t, 8, publisher.floodfillCount)
}

// TestPublishLeaseSetWithNoFloodfills tests publishing when no floodfills are available
func TestPublishLeaseSetWithNoFloodfills(t *testing.T) {
	db := newMockNetDB() // Empty database
	config := DefaultPublisherConfig()
	publisher := NewPublisher(db, nil, config)

	// Create an empty LeaseSet for testing (will use zero values)
	ls := lease_set.LeaseSet{}
	hash := common.Hash{1, 2, 3, 4} // Simple test hash

	err := publisher.PublishLeaseSet(hash, ls)

	// Should return error for invalid LeaseSet (prevents panic)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid LeaseSet")
}

// TestPublishRouterInfoWithFloodfills tests publishing RouterInfo to floodfills
func TestPublishRouterInfoWithFloodfills(t *testing.T) {
	db := newMockNetDB()

	// Note: mockNetDB SelectFloodfillRouters returns empty list
	// In a real scenario, we would populate the database with floodfills

	config := PublisherConfig{
		RouterInfoInterval: 30 * time.Minute,
		LeaseSetInterval:   5 * time.Minute,
		FloodfillCount:     3,
	}
	publisher := NewPublisher(db, nil, config)

	// Create an empty test RouterInfo
	ri := router_info.RouterInfo{}

	err := publisher.PublishRouterInfo(ri)

	// Should return error for invalid RouterInfo (prevents panic)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get router hash")
}

// TestPublisherSelectFloodfills tests floodfill selection for publishing
func TestPublisherSelectFloodfills(t *testing.T) {
	db := newMockNetDB()

	// Note: mockNetDB SelectFloodfillRouters returns empty list
	// In a real scenario, we would populate the database with floodfills

	config := PublisherConfig{
		RouterInfoInterval: 30 * time.Minute,
		LeaseSetInterval:   5 * time.Minute,
		FloodfillCount:     4,
	}
	publisher := NewPublisher(db, nil, config)

	hash := common.Hash{5, 6, 7, 8}
	floodfills, err := publisher.selectFloodfillsForPublishing(hash)

	assert.NoError(t, err)
	// Mock returns empty list since we don't have routers
	assert.LessOrEqual(t, len(floodfills), config.FloodfillCount)
}

// TestPublisherInterfaceCompliance tests that Publisher implements expected interface
func TestPublisherInterfaceCompliance(t *testing.T) {
	db := newMockNetDB()
	config := DefaultPublisherConfig()
	publisher := NewPublisher(db, nil, config)

	// Verify publisher has all expected methods
	var _ interface {
		Start() error
		Stop()
		PublishLeaseSet(hash common.Hash, ls lease_set.LeaseSet) error
		PublishRouterInfo(ri router_info.RouterInfo) error
		GetStats() PublisherStats
	} = publisher
}

// TestPublisherFloodfillCount tests varying floodfill count configurations
func TestPublisherFloodfillCount(t *testing.T) {
	testCases := []struct {
		name           string
		floodfillCount int
	}{
		{"Single floodfill", 1},
		{"Default count", 4},
		{"High count", 10},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			db := newMockNetDB()
			config := PublisherConfig{
				RouterInfoInterval: 30 * time.Minute,
				LeaseSetInterval:   5 * time.Minute,
				FloodfillCount:     tc.floodfillCount,
			}

			publisher := NewPublisher(db, nil, config)
			assert.Equal(t, tc.floodfillCount, publisher.floodfillCount)
		})
	}
}

// TestPublisherIntervalConfigurations tests various time interval configurations
func TestPublisherIntervalConfigurations(t *testing.T) {
	testCases := []struct {
		name               string
		routerInfoInterval time.Duration
		leaseSetInterval   time.Duration
	}{
		{"Short intervals", 1 * time.Minute, 30 * time.Second},
		{"Default intervals", 30 * time.Minute, 5 * time.Minute},
		{"Long intervals", 2 * time.Hour, 30 * time.Minute},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			db := newMockNetDB()
			config := PublisherConfig{
				RouterInfoInterval: tc.routerInfoInterval,
				LeaseSetInterval:   tc.leaseSetInterval,
				FloodfillCount:     4,
			}

			publisher := NewPublisher(db, nil, config)
			assert.Equal(t, tc.routerInfoInterval, publisher.routerInfoInterval)
			assert.Equal(t, tc.leaseSetInterval, publisher.leaseSetInterval)
		})
	}
}
