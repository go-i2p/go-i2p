package i2pcontrol

import (
	"testing"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/go-i2p/go-i2p/lib/netdb"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockRouterAccessForPeerStats implements RouterAccess for testing peer statistics
type mockRouterAccessForPeerStats struct {
	netdb *netdb.StdNetDB
}

func (m *mockRouterAccessForPeerStats) GetNetDB() *netdb.StdNetDB {
	return m.netdb
}

func (m *mockRouterAccessForPeerStats) GetTunnelManager() *i2np.TunnelManager {
	return nil
}

func (m *mockRouterAccessForPeerStats) GetParticipantManager() *tunnel.Manager {
	return nil
}

func (m *mockRouterAccessForPeerStats) GetConfig() *config.RouterConfig {
	return &config.RouterConfig{}
}

func (m *mockRouterAccessForPeerStats) IsRunning() bool {
	return true
}

func (m *mockRouterAccessForPeerStats) IsReseeding() bool {
	return false
}

func (m *mockRouterAccessForPeerStats) GetBandwidthRates() (rate1s, rate15s uint64) {
	return 0, 0
}

func (m *mockRouterAccessForPeerStats) Stop() {
	// Mock implementation - no-op for test
}

// Helper to create test hash
func testHash(suffix byte) common.Hash {
	var hash common.Hash
	for i := range hash {
		hash[i] = suffix
	}
	return hash
}

// TestGetRouterInfo_PeerClassification tests that RouterInfo includes peer classification stats
func TestGetRouterInfo_PeerClassification(t *testing.T) {
	// Create temporary NetDB
	tempDir := t.TempDir()
	db := netdb.NewStdNetDB(tempDir)
	require.NoError(t, db.Create())
	defer db.Stop()

	// Create mock router with NetDB
	mockRouter := &mockRouterAccessForPeerStats{
		netdb: db,
	}

	// Create stats provider
	provider := NewRouterStatsProvider(mockRouter, "0.1.0-test")

	// Initially all peer counts should be 0
	stats := provider.GetRouterInfo()
	assert.Equal(t, 0, stats.ActivePeersCount, "Expected 0 active peers initially")
	assert.Equal(t, 0, stats.FastPeersCount, "Expected 0 fast peers initially")
	assert.Equal(t, 0, stats.HighCapacityPeersCount, "Expected 0 high-capacity peers initially")

	// Add some test peers
	hash1 := testHash(1) // Will be active and fast
	hash2 := testHash(2) // Will be high capacity
	hash3 := testHash(3) // Will be slow/inactive

	// Add peers to NetDB
	db.RouterInfos[hash1] = netdb.Entry{}
	db.RouterInfos[hash2] = netdb.Entry{}
	db.RouterInfos[hash3] = netdb.Entry{}

	// Record peer 1 as active and fast (low latency)
	for i := 0; i < 5; i++ {
		db.PeerTracker.RecordSuccess(hash1, 100) // 100ms response time
	}

	// Record peer 2 as high capacity (high success rate, low latency, many attempts)
	for i := 0; i < 10; i++ {
		db.PeerTracker.RecordSuccess(hash2, 400) // 400ms response time
	}

	// Record peer 3 as slow (high latency)
	// Note: Can't easily simulate "old" success from this package,
	// so we'll just make it slow which excludes it from fast/high-capacity
	for i := 0; i < 5; i++ {
		db.PeerTracker.RecordSuccess(hash3, 2000) // 2000ms response time - very slow
	}

	// Get updated stats
	stats = provider.GetRouterInfo()

	// Verify peer classification counts
	assert.Equal(t, 3, stats.ActivePeersCount, "Expected 3 active peers (all have recent successes)")
	assert.Equal(t, 2, stats.FastPeersCount, "Expected 2 fast peers (hash1 @ 100ms, hash2 @ 400ms, both <500ms)")
	assert.Equal(t, 2, stats.HighCapacityPeersCount, "Expected 2 high-capacity peers (hash1, hash2)")
	assert.Equal(t, 3, stats.KnownPeers, "Expected 3 known peers total")
}

// TestGetRouterInfo_PeerStats_NoNetDB tests graceful handling when NetDB is nil
func TestGetRouterInfo_PeerStats_NoNetDB(t *testing.T) {
	// Create mock router with no NetDB
	mockRouter := &mockRouterAccessForPeerStats{
		netdb: nil,
	}

	// Create stats provider
	provider := NewRouterStatsProvider(mockRouter, "0.1.0-test")

	// Should not panic and should return 0 for all peer counts
	stats := provider.GetRouterInfo()
	assert.Equal(t, 0, stats.ActivePeersCount)
	assert.Equal(t, 0, stats.FastPeersCount)
	assert.Equal(t, 0, stats.HighCapacityPeersCount)
	assert.Equal(t, 0, stats.KnownPeers)
}

// TestGetRouterInfo_PeerStats_EmptyNetDB tests behavior with empty NetDB
func TestGetRouterInfo_PeerStats_EmptyNetDB(t *testing.T) {
	// Create empty NetDB
	tempDir := t.TempDir()
	db := netdb.NewStdNetDB(tempDir)
	require.NoError(t, db.Create())
	defer db.Stop()

	// Create mock router
	mockRouter := &mockRouterAccessForPeerStats{
		netdb: db,
	}

	// Create stats provider
	provider := NewRouterStatsProvider(mockRouter, "0.1.0-test")

	// Should return 0 for all peer counts
	stats := provider.GetRouterInfo()
	assert.Equal(t, 0, stats.ActivePeersCount)
	assert.Equal(t, 0, stats.FastPeersCount)
	assert.Equal(t, 0, stats.HighCapacityPeersCount)
	assert.Equal(t, 0, stats.KnownPeers)
}

// TestGetRouterInfo_PeerStats_VariedQuality tests classification with peers of varied quality
func TestGetRouterInfo_PeerStats_VariedQuality(t *testing.T) {
	// Create NetDB
	tempDir := t.TempDir()
	db := netdb.NewStdNetDB(tempDir)
	require.NoError(t, db.Create())
	defer db.Stop()

	// Add 10 peers with different characteristics
	for i := byte(0); i < 10; i++ {
		hash := testHash(i)
		db.RouterInfos[hash] = netdb.Entry{}

		switch i {
		case 0, 1, 2: // Active and fast peers
			for j := 0; j < 5; j++ {
				db.PeerTracker.RecordSuccess(hash, 200)
			}
		case 3, 4: // High capacity peers
			for j := 0; j < 10; j++ {
				db.PeerTracker.RecordSuccess(hash, 600)
			}
		case 5, 6: // Slow peers
			for j := 0; j < 5; j++ {
				db.PeerTracker.RecordSuccess(hash, 1500)
			}
		case 7, 8: // Slow and low success rate peers (won't qualify for high-capacity)
			for j := 0; j < 10; j++ {
				if j < 4 {
					db.PeerTracker.RecordSuccess(hash, 1200) // Slow but some success
				} else {
					db.PeerTracker.RecordFailure(hash, "timeout")
				}
			}
			// case 9: No tracking data (never connected)
		}
	}

	// Create mock router and stats provider
	mockRouter := &mockRouterAccessForPeerStats{netdb: db}
	provider := NewRouterStatsProvider(mockRouter, "0.1.0-test")

	// Get stats
	stats := provider.GetRouterInfo()

	// Verify counts
	assert.Equal(t, 10, stats.KnownPeers, "Should have 10 known peers")
	assert.Greater(t, stats.ActivePeersCount, 0, "Should have active peers")
	assert.Greater(t, stats.FastPeersCount, 0, "Should have fast peers")

	// Active peers should be those with recent connections (0-8, all have recent activity, 9 has none)
	assert.Equal(t, 9, stats.ActivePeersCount, "Expected 9 active peers (peer 9 has no tracking)")

	// Fast peers should be those with < 500ms avg response time (0-2)
	assert.Equal(t, 3, stats.FastPeersCount, "Expected 3 fast peers")

	// High capacity peers: >= 80% success rate, < 1000ms, not stale (0-4)
	assert.Equal(t, 5, stats.HighCapacityPeersCount, "Expected 5 high-capacity peers")
}
