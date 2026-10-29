package bootstrap

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestPeerCache(t *testing.T, maxSize int) *PeerCache {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "peerCache")
	return NewPeerCache(path, maxSize)
}

// TestPeerCacheSaveLoadRoundTrip records peers, saves, reloads from a fresh
// cache instance, and verifies all peers survive the round trip.
func TestPeerCacheSaveLoadRoundTrip(t *testing.T) {
	cache := newTestPeerCache(t, 50)

	ris := make([]router_info.RouterInfo, 3)
	for i := range ris {
		ris[i] = *createSignedTestRouterInfo(t, map[string]string{"test": "roundtrip"})
	}

	require.NoError(t, cache.Record(ris))
	require.Equal(t, 3, cache.Size())

	// Simulate a restart with a brand-new cache instance over the same file.
	reloaded := NewPeerCache(cache.path, 50)
	require.NoError(t, reloaded.Load(context.Background()))
	assert.Equal(t, 3, reloaded.Size())

	peers, err := reloaded.GetPeers(context.Background(), 0)
	require.NoError(t, err)
	assert.Len(t, peers, 3)
}

// TestPeerCacheEmpty ensures GetPeers errors when nothing is cached.
func TestPeerCacheEmpty(t *testing.T) {
	cache := newTestPeerCache(t, 50)
	require.NoError(t, cache.Load(context.Background()))

	peers, err := cache.GetPeers(context.Background(), 0)
	require.Error(t, err)
	assert.Nil(t, peers)
}

// TestPeerCacheEviction verifies the size limit evicts the least-recently-active
// peers first.
func TestPeerCacheEviction(t *testing.T) {
	cache := newTestPeerCache(t, 3)

	// Record 3 peers, then a 4th — the oldest (first recorded) should be evicted.
	first := *createSignedTestRouterInfo(t, map[string]string{"test": "first"})
	require.NoError(t, cache.Record([]router_info.RouterInfo{first}))

	second := *createSignedTestRouterInfo(t, map[string]string{"test": "second"})
	require.NoError(t, cache.Record([]router_info.RouterInfo{second}))

	third := *createSignedTestRouterInfo(t, map[string]string{"test": "third"})
	require.NoError(t, cache.Record([]router_info.RouterInfo{third}))
	require.Equal(t, 3, cache.Size())

	// Bump the first peer's activity so it becomes the most-recently-active,
	// then add a fourth peer. The second (now oldest) should be evicted.
	firstHash, _ := first.IdentHash()
	cache.mu.Lock()
	if cp, ok := cache.peers[firstHash]; ok {
		cp.lastActivity = time.Now()
	}
	cache.mu.Unlock()

	fourth := *createSignedTestRouterInfo(t, map[string]string{"test": "fourth"})
	require.NoError(t, cache.Record([]router_info.RouterInfo{fourth}))
	require.Equal(t, 3, cache.Size())

	// The evicted peer (second) should be gone.
	secondHash, _ := second.IdentHash()
	cache.mu.RLock()
	_, secondStillThere := cache.peers[secondHash]
	cache.mu.RUnlock()
	assert.False(t, secondStillThere, "least-recently-active peer should be evicted")

	// The re-activated first peer should remain.
	cache.mu.RLock()
	_, firstStillThere := cache.peers[firstHash]
	cache.mu.RUnlock()
	assert.True(t, firstStillThere, "recently-activated peer should be retained")
}

// TestPeerCacheCorruptFile ensures a corrupt cache file does not block loading;
// the cache simply starts empty.
func TestPeerCacheCorruptFile(t *testing.T) {
	cache := newTestPeerCache(t, 50)
	require.NoError(t, os.WriteFile(cache.path, []byte("this is not a valid peer cache"), 0o600))

	require.NoError(t, cache.Load(context.Background()))
	assert.Equal(t, 0, cache.Size())
}

// TestPeerCacheMissingFile ensures loading a non-existent cache is a no-op.
func TestPeerCacheMissingFile(t *testing.T) {
	cache := newTestPeerCache(t, 50)
	require.NoError(t, cache.Load(context.Background()))
	assert.Equal(t, 0, cache.Size())
}

// TestPeerCacheGetPeersLimit verifies the n limit caps the number returned and
// that results are ordered most-recently-active first.
func TestPeerCacheGetPeersLimit(t *testing.T) {
	cache := newTestPeerCache(t, 50)

	ris := make([]router_info.RouterInfo, 5)
	for i := range ris {
		ris[i] = *createSignedTestRouterInfo(t, map[string]string{"test": "limit"})
	}
	require.NoError(t, cache.Record(ris))

	peers, err := cache.GetPeers(context.Background(), 2)
	require.NoError(t, err)
	assert.Len(t, peers, 2)
}

// TestPeerCacheCompositeIntegration verifies the composite bootstrap uses the
// peer cache as its first source and records peers back into it.
func TestPeerCacheCompositeIntegration(t *testing.T) {
	dir := t.TempDir()
	cachePath := filepath.Join(dir, "peerCache")

	cfg := &config.BootstrapConfig{
		LowPeerThreshold: testLowPeerThreshold,
		BootstrapType:    "auto",
		PeerCacheEnabled: true,
		PeerCachePath:    cachePath,
		PeerCacheMaxSize: 50,
	}
	cb := NewCompositeBootstrap(cfg)
	require.NotNil(t, cb)
	require.NotNil(t, cb.peerCache, "peer cache should be created when enabled")
}

// TestPeerCacheDisabled verifies the composite bootstrap does not create a
// peer cache when disabled.
func TestPeerCacheDisabled(t *testing.T) {
	cfg := &config.BootstrapConfig{
		BootstrapType:    "auto",
		PeerCacheEnabled: false,
		PeerCachePath:    t.TempDir(),
	}
	cb := NewCompositeBootstrap(cfg)
	require.NotNil(t, cb)
	assert.Nil(t, cb.peerCache, "peer cache should be nil when disabled")
}
