package tunnel

import (
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockPeerSelector for testing
type MockPeerSelector struct {
	peers []router_info.RouterInfo
}

func (m *MockPeerSelector) SelectPeers(count int, exclude []common.Hash) ([]router_info.RouterInfo, error) {
	if len(m.peers) < count {
		return m.peers, nil
	}
	return m.peers[:count], nil
}

func TestTunnelPool(t *testing.T) {
	selector := &MockPeerSelector{}
	pool := NewTunnelPool(selector)

	require.NotNil(t, pool)
	assert.Empty(t, pool.GetActiveTunnels())
}

func TestTunnelState(t *testing.T) {
	tunnelID := TunnelID(12345)

	state := &TunnelState{
		ID:        tunnelID,
		Hops:      []common.Hash{},
		State:     TunnelBuilding,
		CreatedAt: time.Now(),
	}

	assert.Equal(t, tunnelID, state.ID)
	assert.Equal(t, TunnelBuilding, state.State)
	assert.Empty(t, state.Hops)
}

func TestTunnelPoolOperations(t *testing.T) {
	selector := &MockPeerSelector{}
	pool := NewTunnelPool(selector)

	// Test adding a tunnel
	tunnel := &TunnelState{
		ID:        TunnelID(123),
		State:     TunnelBuilding,
		CreatedAt: time.Now(),
	}

	pool.AddTunnel(tunnel)

	// Test retrieving tunnel
	retrieved, exists := pool.GetTunnel(TunnelID(123))
	assert.True(t, exists)
	assert.Equal(t, tunnel.ID, retrieved.ID)

	// Test tunnel doesn't exist
	_, exists = pool.GetTunnel(TunnelID(999))
	assert.False(t, exists)

	// Test removing tunnel
	pool.RemoveTunnel(TunnelID(123))
	_, exists = pool.GetTunnel(TunnelID(123))
	assert.False(t, exists)
}

func TestTunnelCleanup(t *testing.T) {
	selector := &MockPeerSelector{}
	pool := NewTunnelPool(selector)

	// Add an old tunnel
	oldTunnel := &TunnelState{
		ID:        TunnelID(1),
		State:     TunnelBuilding,
		CreatedAt: time.Now().Add(-10 * time.Minute),
	}

	// Add a recent tunnel
	recentTunnel := &TunnelState{
		ID:        TunnelID(2),
		State:     TunnelBuilding,
		CreatedAt: time.Now(),
	}

	pool.AddTunnel(oldTunnel)
	pool.AddTunnel(recentTunnel)

	// Cleanup tunnels older than 5 minutes
	pool.CleanupExpiredTunnels(5 * time.Minute)

	// Old tunnel should be gone, recent one should remain
	_, exists := pool.GetTunnel(TunnelID(1))
	assert.False(t, exists)

	_, exists = pool.GetTunnel(TunnelID(2))
	assert.True(t, exists)
}
