package tunnel

import (
	"sync"
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockTunnelBuilder for testing pool maintenance
type MockTunnelBuilder struct {
	mu               sync.Mutex
	buildCount       int
	shouldFail       bool
	lastRequest      BuildTunnelRequest
	builtTunnels     []TunnelID
	callbackPool     *Pool         // Allow builder to add tunnels to pool
	completionChan   chan struct{} // Signal when a build completes
	failedPeerHashes []common.Hash // Peer hashes to return on failure
}

func (m *MockTunnelBuilder) BuildTunnel(req BuildTunnelRequest) (*BuildTunnelResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.buildCount++
	m.lastRequest = req

	// Signal completion if channel is set
	defer func() {
		if m.completionChan != nil {
			select {
			case m.completionChan <- struct{}{}:
			default:
			}
		}
	}()

	if m.shouldFail {
		// Return peer hashes even on failure so pool can exclude them on retry
		return &BuildTunnelResult{
			TunnelID:   0,
			PeerHashes: m.failedPeerHashes,
		}, assert.AnError
	}

	// Generate a tunnel ID
	tunnelID := TunnelID(1000 + m.buildCount)
	m.builtTunnels = append(m.builtTunnels, tunnelID)

	// Simulate adding tunnel to pool if callback is set
	if m.callbackPool != nil {
		tunnel := &TunnelState{
			ID:        tunnelID,
			Hops:      make([]common.Hash, 0),
			State:     TunnelReady, // Simulate successful build
			CreatedAt: time.Now(),
		}
		m.callbackPool.AddTunnel(tunnel)
	}

	return &BuildTunnelResult{
		TunnelID:   tunnelID,
		PeerHashes: nil,
	}, nil
}

// GetBuildCount returns the current build count in a thread-safe manner.
func (m *MockTunnelBuilder) GetBuildCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.buildCount
}

func TestPoolConfig(t *testing.T) {
	config := DefaultPoolConfig()

	assert.Equal(t, 4, config.MinTunnels)
	assert.Equal(t, 6, config.MaxTunnels)
	assert.Equal(t, 10*time.Minute, config.TunnelLifetime)
	assert.Equal(t, 2*time.Minute, config.RebuildThreshold)
	assert.Equal(t, 3, config.HopCount)
	assert.False(t, config.IsInbound)
}

func TestPoolWithConfig(t *testing.T) {
	selector := &MockPeerSelector{}
	config := PoolConfig{
		MinTunnels:       2,
		MaxTunnels:       4,
		TunnelLifetime:   5 * time.Minute,
		RebuildThreshold: 1 * time.Minute,
		BuildRetryDelay:  2 * time.Second,
		MaxBuildRetries:  5,
		HopCount:         4,
		IsInbound:        true,
	}

	pool := NewTunnelPoolWithConfig(selector, config)
	defer pool.Stop()

	require.NotNil(t, pool)
	assert.Equal(t, 2, pool.config.MinTunnels)
	assert.Equal(t, 4, pool.config.MaxTunnels)
	assert.Equal(t, 4, pool.config.HopCount)
	assert.True(t, pool.config.IsInbound)
}

func TestSetTunnelBuilder(t *testing.T) {
	selector := &MockPeerSelector{}
	pool := NewTunnelPool(selector)
	defer pool.Stop()

	builder := &MockTunnelBuilder{}
	pool.SetTunnelBuilder(builder)

	assert.NotNil(t, pool.tunnelBuilder)
}

func TestPoolMaintenanceRequiresBuilder(t *testing.T) {
	selector := &MockPeerSelector{}
	pool := NewTunnelPool(selector)
	defer pool.Stop()

	err := pool.StartMaintenance()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "tunnel builder not set")
}

func TestSelectTunnelRoundRobin(t *testing.T) {
	selector := &MockPeerSelector{}
	pool := NewTunnelPool(selector)
	defer pool.Stop()

	// Add multiple ready tunnels
	tunnel1 := &TunnelState{
		ID:        TunnelID(1),
		State:     TunnelReady,
		CreatedAt: time.Now(),
	}
	tunnel2 := &TunnelState{
		ID:        TunnelID(2),
		State:     TunnelReady,
		CreatedAt: time.Now(),
	}
	tunnel3 := &TunnelState{
		ID:        TunnelID(3),
		State:     TunnelReady,
		CreatedAt: time.Now(),
	}

	pool.AddTunnel(tunnel1)
	pool.AddTunnel(tunnel2)
	pool.AddTunnel(tunnel3)

	// Select enough times to verify fair distribution
	// With round-robin, each tunnel should get equal selections
	counts := make(map[TunnelID]int)
	numSelections := 30 // 10 per tunnel
	for i := 0; i < numSelections; i++ {
		tunnel := pool.SelectTunnel()
		require.NotNil(t, tunnel)
		counts[tunnel.ID]++
	}

	// Verify all tunnels were selected
	assert.Equal(t, 3, len(counts), "All 3 tunnels should be selected")

	// Each tunnel should be selected exactly 10 times (30 / 3)
	for id, count := range counts {
		assert.Equal(t, 10, count, "Tunnel %d should be selected exactly 10 times", id)
	}
}

func TestSelectTunnelNoActive(t *testing.T) {
	selector := &MockPeerSelector{}
	pool := NewTunnelPool(selector)
	defer pool.Stop()

	// Add only building tunnels (not ready)
	tunnel := &TunnelState{
		ID:        TunnelID(1),
		State:     TunnelBuilding,
		CreatedAt: time.Now(),
	}
	pool.AddTunnel(tunnel)

	// Should return nil when no active tunnels
	selected := pool.SelectTunnel()
	assert.Nil(t, selected)
}

func TestGetPoolStats(t *testing.T) {
	selector := &MockPeerSelector{}
	config := PoolConfig{
		MinTunnels:       4,
		MaxTunnels:       6,
		TunnelLifetime:   10 * time.Minute,
		RebuildThreshold: 2 * time.Minute,
		HopCount:         3,
		IsInbound:        false,
	}
	pool := NewTunnelPoolWithConfig(selector, config)
	defer pool.Stop()

	// Add tunnels in various states
	pool.AddTunnel(&TunnelState{
		ID:        TunnelID(1),
		State:     TunnelReady,
		CreatedAt: time.Now().Add(-9 * time.Minute), // Near expiry
	})
	pool.AddTunnel(&TunnelState{
		ID:        TunnelID(2),
		State:     TunnelReady,
		CreatedAt: time.Now(),
	})
	pool.AddTunnel(&TunnelState{
		ID:        TunnelID(3),
		State:     TunnelBuilding,
		CreatedAt: time.Now(),
	})
	pool.AddTunnel(&TunnelState{
		ID:        TunnelID(4),
		State:     TunnelFailed,
		CreatedAt: time.Now(),
	})

	stats := pool.GetPoolStats()
	assert.Equal(t, 4, stats.Total)
	assert.Equal(t, 2, stats.Active)
	assert.Equal(t, 1, stats.Building)
	assert.Equal(t, 1, stats.Failed)
	assert.Equal(t, 1, stats.NearExpiry)
}

func TestCleanupExpiredTunnelsLocked(t *testing.T) {
	selector := &MockPeerSelector{}
	config := PoolConfig{
		MinTunnels:     4,
		MaxTunnels:     6,
		TunnelLifetime: 5 * time.Minute,
		HopCount:       3,
		IsInbound:      false,
	}
	pool := NewTunnelPoolWithConfig(selector, config)
	defer pool.Stop()

	// Add old ready tunnel (should be expired)
	pool.AddTunnel(&TunnelState{
		ID:        TunnelID(1),
		State:     TunnelReady,
		CreatedAt: time.Now().Add(-6 * time.Minute),
	})

	// Add recent ready tunnel (should not be expired)
	pool.AddTunnel(&TunnelState{
		ID:        TunnelID(2),
		State:     TunnelReady,
		CreatedAt: time.Now(),
	})

	// Add failed tunnel (should be removed)
	pool.AddTunnel(&TunnelState{
		ID:        TunnelID(3),
		State:     TunnelFailed,
		CreatedAt: time.Now(),
	})

	// Perform cleanup
	pool.mutex.Lock()
	pool.cleanupExpiredTunnelsLocked()
	pool.mutex.Unlock()

	// Check results
	_, exists := pool.GetTunnel(TunnelID(1))
	assert.False(t, exists, "Old tunnel should be removed")

	_, exists = pool.GetTunnel(TunnelID(2))
	assert.True(t, exists, "Recent tunnel should remain")

	_, exists = pool.GetTunnel(TunnelID(3))
	assert.False(t, exists, "Failed tunnel should be removed")
}

func TestCountTunnelsLocked(t *testing.T) {
	selector := &MockPeerSelector{}
	config := PoolConfig{
		MinTunnels:       4,
		MaxTunnels:       6,
		TunnelLifetime:   10 * time.Minute,
		RebuildThreshold: 2 * time.Minute,
		HopCount:         3,
		IsInbound:        false,
	}
	pool := NewTunnelPoolWithConfig(selector, config)
	defer pool.Stop()

	// Add active tunnel not near expiry
	pool.AddTunnel(&TunnelState{
		ID:        TunnelID(1),
		State:     TunnelReady,
		CreatedAt: time.Now(),
	})

	// Add active tunnel near expiry
	pool.AddTunnel(&TunnelState{
		ID:        TunnelID(2),
		State:     TunnelReady,
		CreatedAt: time.Now().Add(-9 * time.Minute), // 9 minutes old, near 10 minute lifetime
	})

	// Add building tunnel (not counted as active)
	pool.AddTunnel(&TunnelState{
		ID:        TunnelID(3),
		State:     TunnelBuilding,
		CreatedAt: time.Now(),
	})

	pool.mutex.Lock()
	active, nearExpiry := pool.countTunnelsLocked()
	pool.mutex.Unlock()

	assert.Equal(t, 2, active)
	assert.Equal(t, 1, nearExpiry)
}

func TestCalculateNeededTunnels(t *testing.T) {
	selector := &MockPeerSelector{}
	config := PoolConfig{
		MinTunnels: 4,
		MaxTunnels: 6,
		HopCount:   3,
		IsInbound:  false,
	}
	pool := NewTunnelPoolWithConfig(selector, config)
	defer pool.Stop()

	tests := []struct {
		name        string
		activeCount int
		nearExpiry  int
		expected    int
	}{
		{
			name:        "Need tunnels",
			activeCount: 2,
			nearExpiry:  0,
			expected:    2, // Need 2 to reach min of 4
		},
		{
			name:        "Need replacements",
			activeCount: 4,
			nearExpiry:  2,
			expected:    2, // Need 2 to replace expiring ones
		},
		{
			name:        "At capacity",
			activeCount: 6,
			nearExpiry:  0,
			expected:    0, // At max, don't build more
		},
		{
			name:        "Exceeds max with expiry",
			activeCount: 5,
			nearExpiry:  1,
			expected:    0, // 5-1=4 usable, at min, no need to exceed max
		},
		{
			name:        "Above min",
			activeCount: 5,
			nearExpiry:  1,
			expected:    0, // 5-1=4 usable, at min, no need
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			needed := pool.calculateNeededTunnels(tt.activeCount, tt.nearExpiry)
			assert.Equal(t, tt.expected, needed)
		})
	}
}

func TestAttemptBuildTunnels(t *testing.T) {
	selector := &MockPeerSelector{}
	pool := NewTunnelPool(selector)
	defer pool.Stop()

	// Test without builder
	success := pool.attemptBuildTunnels(2)
	assert.False(t, success)

	// Test with successful builder
	builder := &MockTunnelBuilder{}
	pool.SetTunnelBuilder(builder)

	success = pool.attemptBuildTunnels(3)
	assert.True(t, success)
	assert.Equal(t, 3, builder.GetBuildCount())
	assert.Equal(t, 3, len(builder.builtTunnels))
}

func TestAttemptBuildTunnelsWithFailures(t *testing.T) {
	selector := &MockPeerSelector{}
	pool := NewTunnelPool(selector)
	defer pool.Stop()

	builder := &MockTunnelBuilder{shouldFail: true}
	pool.SetTunnelBuilder(builder)

	success := pool.attemptBuildTunnels(2)
	assert.False(t, success) // All builds failed
	// Each tunnel attempt retries up to 3 times on failure: 2 tunnels × 3 retries = 6 build calls
	assert.Equal(t, 6, builder.GetBuildCount())
	assert.Empty(t, builder.builtTunnels)
}

func TestBuildTunnelsWithBackoff(t *testing.T) {
	selector := &MockPeerSelector{}
	config := PoolConfig{
		MinTunnels:      4,
		MaxTunnels:      6,
		BuildRetryDelay: 100 * time.Millisecond,
		MaxBuildRetries: 3,
		HopCount:        3,
		IsInbound:       false,
	}
	pool := NewTunnelPoolWithConfig(selector, config)
	defer pool.Stop()

	// Set up builder with completion channel
	completionChan := make(chan struct{}, 10)
	builder := &MockTunnelBuilder{
		completionChan: completionChan,
	}
	pool.SetTunnelBuilder(builder)

	// Test 1: Successful build — checkAndUpdateBackoff under lock, launch outside lock
	pool.mutex.Lock()
	shouldBuild := pool.checkAndUpdateBackoff()
	pool.mutex.Unlock()
	assert.True(t, shouldBuild, "First build should not be blocked by backoff")
	pool.launchAsyncBuild(2)

	// Wait for both tunnels to complete
	<-completionChan
	<-completionChan
	time.Sleep(10 * time.Millisecond) // Brief delay for async goroutine to update state

	assert.Equal(t, 2, builder.GetBuildCount(), "First build should create 2 tunnels")

	// Wait long enough to avoid backoff (backoffDelay with buildFailures=0 is 100ms)
	time.Sleep(150 * time.Millisecond)

	// Test 2: Failed builds should increment failure count
	builder.shouldFail = true
	pool.mutex.Lock()
	pool.buildFailures = 0 // Reset for test
	shouldBuild = pool.checkAndUpdateBackoff()
	initialTime := pool.lastBuildTime // Read the time AFTER calling checkAndUpdateBackoff
	pool.mutex.Unlock()
	assert.True(t, shouldBuild, "Build should proceed after backoff expired")
	pool.launchAsyncBuild(1)

	// Wait for the tunnel build to complete (with retries)
	// Failed builds retry up to 3 times, so wait for all attempts
	<-completionChan
	<-completionChan
	<-completionChan
	time.Sleep(10 * time.Millisecond) // Brief delay for async goroutine to update buildFailures

	pool.mutex.Lock()
	failures := pool.buildFailures
	pool.mutex.Unlock()
	assert.Equal(t, 1, failures, "Failed build should increment buildFailures")

	// Test 3: Backoff should prevent immediate retry
	// With buildFailures=1, backoffDelay = 100ms * 2^1 = 200ms
	// Only ~10ms have passed since initialTime, so this should be skipped
	time.Sleep(50 * time.Millisecond) // Total ~60ms since initialTime

	pool.mutex.Lock()
	shouldBuild = pool.checkAndUpdateBackoff()
	timeAfterSkip := pool.lastBuildTime
	pool.mutex.Unlock()

	// checkAndUpdateBackoff should return false (build was skipped due to backoff)
	assert.False(t, shouldBuild, "Build should be skipped due to backoff")

	// lastBuildTime should not have changed (build was skipped)
	assert.Equal(t, initialTime, timeAfterSkip, "Build should be skipped due to backoff")

	// Build count should be 5 (2 from first + 3 retries from failed second)
	// Note: attemptBuildTunnels retries up to 3 times on failure
	assert.Equal(t, 5, builder.GetBuildCount(), "Skipped build should not increment count")

	// Test 4: After backoff delay, build should proceed
	time.Sleep(200 * time.Millisecond) // Total > 260ms, well past 200ms backoff

	pool.mutex.Lock()
	shouldBuild = pool.checkAndUpdateBackoff()
	timeAfterBackoff := pool.lastBuildTime
	pool.mutex.Unlock()
	assert.True(t, shouldBuild, "Build should proceed after backoff period")
	pool.launchAsyncBuild(1)

	// Wait for the tunnel build to complete (with retries)
	// Failed builds retry up to 3 times, so wait for all attempts
	<-completionChan
	<-completionChan
	<-completionChan
	time.Sleep(10 * time.Millisecond) // Brief delay for async goroutine to update state

	// lastBuildTime should have been updated
	assert.True(t, timeAfterBackoff.After(initialTime), "Build should proceed after backoff period")

	// Build count should be 8 (previous 5 + 3 retries from new failed build)
	// Note: attemptBuildTunnels retries up to 3 times on failure
	assert.Equal(t, 8, builder.GetBuildCount(), "Build after backoff should increment count")
}

func TestMaintainPoolIntegration(t *testing.T) {
	selector := &MockPeerSelector{}
	config := PoolConfig{
		MinTunnels:       3,
		MaxTunnels:       5,
		TunnelLifetime:   1 * time.Second, // Short for testing
		RebuildThreshold: 500 * time.Millisecond,
		BuildRetryDelay:  100 * time.Millisecond,
		MaxBuildRetries:  3,
		HopCount:         3,
		IsInbound:        false,
	}
	pool := NewTunnelPoolWithConfig(selector, config)
	defer pool.Stop()

	// Don't set callbackPool to avoid collision retry issues
	builder := &MockTunnelBuilder{}
	pool.SetTunnelBuilder(builder)

	// Run maintenance without lock (it will acquire internally)
	pool.maintainPool()

	// Wait for async builds to complete
	time.Sleep(200 * time.Millisecond)

	// Manually add the built tunnels to simulate successful builds
	buildCount1 := builder.GetBuildCount()
	t.Logf("After first maintenance: buildCount=%d (expected %d)", buildCount1, config.MinTunnels)
	for i := 0; i < config.MinTunnels; i++ {
		pool.AddTunnel(&TunnelState{
			ID:        TunnelID(2000 + i),
			Hops:      make([]common.Hash, 0),
			State:     TunnelReady,
			CreatedAt: time.Now(),
		})
	}

	// Should have attempted to build min tunnels
	assert.GreaterOrEqual(t, buildCount1, config.MinTunnels)

	// Check tunnel count
	pool.mutex.Lock()
	tunnelCount1 := len(pool.tunnels)
	t.Logf("Tunnel count after first maintenance: %d", tunnelCount1)
	pool.mutex.Unlock()

	// Wait for tunnels to near expiry
	time.Sleep(600 * time.Millisecond)

	// Check what the pool sees before second maintenance
	pool.mutex.Lock()
	activeCount, nearExpiry := pool.countTunnelsLocked()
	needed := pool.calculateNeededTunnels(activeCount, nearExpiry)
	t.Logf("Before second maintenance: active=%d, nearExpiry=%d, needed=%d", activeCount, nearExpiry, needed)
	pool.mutex.Unlock()

	oldBuildCount := builder.GetBuildCount()

	// Run maintenance again
	pool.maintainPool()

	// Wait for async builds
	time.Sleep(200 * time.Millisecond)

	newBuildCount := builder.GetBuildCount()
	t.Logf("After second maintenance: oldBuildCount=%d, newBuildCount=%d", oldBuildCount, newBuildCount)

	// Should build replacement tunnels
	assert.Greater(t, newBuildCount, oldBuildCount, "Second maintenance should build replacement tunnels")
}

func TestPoolStopGracefully(t *testing.T) {
	selector := &MockPeerSelector{}
	pool := NewTunnelPool(selector)

	builder := &MockTunnelBuilder{}
	pool.SetTunnelBuilder(builder)

	err := pool.StartMaintenance()
	require.NoError(t, err)

	// Give goroutine time to start
	time.Sleep(50 * time.Millisecond)

	// Stop should complete without hanging
	done := make(chan struct{})
	go func() {
		pool.Stop()
		close(done)
	}()

	select {
	case <-done:
		// Success
	case <-time.After(2 * time.Second):
		t.Fatal("Pool.Stop() did not complete within timeout")
	}
}

func TestMaintenanceLoop(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping maintenance loop test in short mode")
	}

	selector := &MockPeerSelector{}
	config := PoolConfig{
		MinTunnels:       2,
		MaxTunnels:       4,
		TunnelLifetime:   5 * time.Second,
		RebuildThreshold: 1 * time.Second,
		BuildRetryDelay:  100 * time.Millisecond,
		MaxBuildRetries:  3,
		HopCount:         3,
		IsInbound:        false,
	}
	pool := NewTunnelPoolWithConfig(selector, config)
	defer pool.Stop()

	// Don't set callbackPool to avoid collision retry issues
	builder := &MockTunnelBuilder{}
	pool.SetTunnelBuilder(builder)

	err := pool.StartMaintenance()
	require.NoError(t, err)

	// Wait for initial maintenance
	time.Sleep(200 * time.Millisecond)

	// Manually add tunnels to simulate successful builds
	initialBuildCount := builder.GetBuildCount()
	for i := 0; i < config.MinTunnels; i++ {
		pool.AddTunnel(&TunnelState{
			ID:        TunnelID(3000 + i),
			Hops:      make([]common.Hash, 0),
			State:     TunnelReady,
			CreatedAt: time.Now(),
		})
	}

	// Should have built min tunnels
	stats := pool.GetPoolStats()
	assert.GreaterOrEqual(t, stats.Active, config.MinTunnels)

	// Mark some tunnels as near expiry
	pool.mutex.Lock()
	for _, tunnel := range pool.tunnels {
		if tunnel.State == TunnelReady {
			tunnel.CreatedAt = time.Now().Add(-4 * time.Second) // 4 seconds old
			break
		}
	}
	pool.mutex.Unlock()

	// Trigger maintenance manually
	pool.maintainPool()

	// Wait for builds
	time.Sleep(200 * time.Millisecond)

	// Should have built replacement
	assert.Greater(t, builder.GetBuildCount(), initialBuildCount)
}
