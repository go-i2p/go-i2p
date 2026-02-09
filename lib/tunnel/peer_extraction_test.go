package tunnel

import (
	"sync"
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// PeerTrackingBuilder is a mock builder that reports which peers were selected
// and can be configured to fail with specific peer hashes.
type PeerTrackingBuilder struct {
	mu             sync.Mutex
	buildCount     int
	shouldFail     bool
	failedPeers    []common.Hash // Peers to report on failure
	successPeers   []common.Hash // Peers to report on success
	builtTunnels   []TunnelID
	requestHistory []BuildTunnelRequest // Record all requests for inspection
}

func (b *PeerTrackingBuilder) BuildTunnel(req BuildTunnelRequest) (*BuildTunnelResult, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.buildCount++
	b.requestHistory = append(b.requestHistory, req)

	if b.shouldFail {
		return &BuildTunnelResult{
			TunnelID:   0,
			PeerHashes: b.failedPeers,
		}, assert.AnError
	}

	tunnelID := TunnelID(5000 + b.buildCount)
	b.builtTunnels = append(b.builtTunnels, tunnelID)

	return &BuildTunnelResult{
		TunnelID:   tunnelID,
		PeerHashes: b.successPeers,
	}, nil
}

func (b *PeerTrackingBuilder) GetBuildCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buildCount
}

func (b *PeerTrackingBuilder) GetRequestHistory() []BuildTunnelRequest {
	b.mu.Lock()
	defer b.mu.Unlock()
	cpy := make([]BuildTunnelRequest, len(b.requestHistory))
	copy(cpy, b.requestHistory)
	return cpy
}

// makePeerHash creates a deterministic Hash from a byte seed for testing.
func makePeerHash(seed byte) common.Hash {
	var h common.Hash
	for i := range h {
		h[i] = seed
	}
	return h
}

func TestExtractAndMarkFailedPeers_NilResult(t *testing.T) {
	pool := NewTunnelPool(&MockPeerSelector{})
	defer pool.Stop()

	result := pool.extractAndMarkFailedPeers(nil)
	assert.Nil(t, result)
	assert.Empty(t, pool.failedPeers)
}

func TestExtractAndMarkFailedPeers_EmptyPeerHashes(t *testing.T) {
	pool := NewTunnelPool(&MockPeerSelector{})
	defer pool.Stop()

	result := pool.extractAndMarkFailedPeers(&BuildTunnelResult{
		TunnelID:   0,
		PeerHashes: nil,
	})
	assert.Nil(t, result)
	assert.Empty(t, pool.failedPeers)
}

func TestExtractAndMarkFailedPeers_MarksPeers(t *testing.T) {
	pool := NewTunnelPool(&MockPeerSelector{})
	defer pool.Stop()

	peerA := makePeerHash(0xAA)
	peerB := makePeerHash(0xBB)
	peerC := makePeerHash(0xCC)

	result := pool.extractAndMarkFailedPeers(&BuildTunnelResult{
		TunnelID:   0,
		PeerHashes: []common.Hash{peerA, peerB, peerC},
	})

	assert.Len(t, result, 3)
	assert.True(t, pool.IsPeerFailed(peerA))
	assert.True(t, pool.IsPeerFailed(peerB))
	assert.True(t, pool.IsPeerFailed(peerC))
}

func TestExtractAndMarkFailedPeers_ReportsToTracker(t *testing.T) {
	pool := NewTunnelPool(&MockPeerSelector{})
	defer pool.Stop()

	tracker := &mockPeerTracker{}
	pool.SetPeerTracker(tracker)

	peerA := makePeerHash(0xAA)
	peerB := makePeerHash(0xBB)

	pool.extractAndMarkFailedPeers(&BuildTunnelResult{
		TunnelID:   0,
		PeerHashes: []common.Hash{peerA, peerB},
	})

	assert.Equal(t, 2, tracker.failureCount())
}

func TestExecuteBuildWithRetry_ExcludesFailedPeersOnRetry(t *testing.T) {
	pool := NewTunnelPool(&MockPeerSelector{})
	defer pool.Stop()

	peerA := makePeerHash(0xAA)
	peerB := makePeerHash(0xBB)

	// Builder fails twice (reporting peer hashes), then succeeds
	callCount := 0
	builder := &callbackBuilder{
		callback: func(req BuildTunnelRequest) (*BuildTunnelResult, error) {
			callCount++
			if callCount <= 2 {
				return &BuildTunnelResult{
					TunnelID:   0,
					PeerHashes: []common.Hash{peerA, peerB},
				}, assert.AnError
			}
			return &BuildTunnelResult{
				TunnelID:   TunnelID(9999),
				PeerHashes: nil,
			}, nil
		},
	}
	pool.SetTunnelBuilder(builder)

	req := BuildTunnelRequest{
		HopCount:  3,
		IsInbound: false,
	}

	tunnelID, err := pool.executeBuildWithRetry(&req)
	assert.NoError(t, err)
	assert.Equal(t, TunnelID(9999), tunnelID)
	assert.Equal(t, 3, callCount) // 2 failures + 1 success

	// Peers from failed builds should be marked as failed
	assert.True(t, pool.IsPeerFailed(peerA))
	assert.True(t, pool.IsPeerFailed(peerB))
}

func TestExecuteBuildWithRetry_ProgressiveExclusionGrows(t *testing.T) {
	pool := NewTunnelPool(&MockPeerSelector{})
	defer pool.Stop()

	peerA := makePeerHash(0x01)
	peerB := makePeerHash(0x02)
	peerC := makePeerHash(0x03)
	peerD := makePeerHash(0x04)

	var requestSnapshots [][]common.Hash
	callCount := 0

	builder := &callbackBuilder{
		callback: func(req BuildTunnelRequest) (*BuildTunnelResult, error) {
			callCount++
			// Snapshot the exclude list at the time of each call
			snapshot := make([]common.Hash, len(req.ExcludePeers))
			copy(snapshot, req.ExcludePeers)
			requestSnapshots = append(requestSnapshots, snapshot)

			if callCount == 1 {
				// First attempt: report peers A, B as selected
				return &BuildTunnelResult{
					TunnelID:   0,
					PeerHashes: []common.Hash{peerA, peerB},
				}, assert.AnError
			}
			if callCount == 2 {
				// Second attempt: report peers C, D as selected
				return &BuildTunnelResult{
					TunnelID:   0,
					PeerHashes: []common.Hash{peerC, peerD},
				}, assert.AnError
			}
			// Third attempt: succeed
			return &BuildTunnelResult{
				TunnelID:   TunnelID(8888),
				PeerHashes: nil,
			}, nil
		},
	}
	pool.SetTunnelBuilder(builder)

	req := BuildTunnelRequest{
		HopCount:  3,
		IsInbound: false,
	}

	tunnelID, err := pool.executeBuildWithRetry(&req)
	assert.NoError(t, err)
	assert.Equal(t, TunnelID(8888), tunnelID)
	assert.Equal(t, 3, callCount)

	// First call: no excluded peers (from this retry loop)
	assert.Empty(t, requestSnapshots[0])
	// Second call: peers A, B excluded
	assert.Len(t, requestSnapshots[1], 2)
	assert.Contains(t, requestSnapshots[1], peerA)
	assert.Contains(t, requestSnapshots[1], peerB)
	// Third call: peers A, B, C, D excluded
	assert.Len(t, requestSnapshots[2], 4)
	assert.Contains(t, requestSnapshots[2], peerA)
	assert.Contains(t, requestSnapshots[2], peerB)
	assert.Contains(t, requestSnapshots[2], peerC)
	assert.Contains(t, requestSnapshots[2], peerD)
}

func TestExecuteBuildWithRetry_AllFailures_MarkAllPeers(t *testing.T) {
	pool := NewTunnelPool(&MockPeerSelector{})
	defer pool.Stop()

	peerA := makePeerHash(0x10)
	peerB := makePeerHash(0x20)

	builder := &PeerTrackingBuilder{
		shouldFail:  true,
		failedPeers: []common.Hash{peerA, peerB},
	}
	pool.SetTunnelBuilder(builder)

	req := BuildTunnelRequest{
		HopCount:  3,
		IsInbound: false,
	}

	_, err := pool.executeBuildWithRetry(&req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "tunnel build failed after 3 retries")

	// All peers should be marked as failed
	assert.True(t, pool.IsPeerFailed(peerA))
	assert.True(t, pool.IsPeerFailed(peerB))

	// Builder should have been called 3 times (maxRetries)
	assert.Equal(t, 3, builder.GetBuildCount())
}

func TestExecuteBuildWithRetry_NilPeerHashesOnFailure(t *testing.T) {
	pool := NewTunnelPool(&MockPeerSelector{})
	defer pool.Stop()

	callCount := 0
	builder := &callbackBuilder{
		callback: func(req BuildTunnelRequest) (*BuildTunnelResult, error) {
			callCount++
			if callCount == 1 {
				// First failure: nil peer hashes (builder couldn't select peers)
				return &BuildTunnelResult{
					TunnelID:   0,
					PeerHashes: nil,
				}, assert.AnError
			}
			return &BuildTunnelResult{
				TunnelID:   TunnelID(7777),
				PeerHashes: nil,
			}, nil
		},
	}
	pool.SetTunnelBuilder(builder)

	req := BuildTunnelRequest{
		HopCount:  3,
		IsInbound: false,
	}

	tunnelID, err := pool.executeBuildWithRetry(&req)
	assert.NoError(t, err)
	assert.Equal(t, TunnelID(7777), tunnelID)
	// No peers should be marked (none reported)
	assert.Empty(t, pool.failedPeers)
}

func TestBuildTunnelResult_Struct(t *testing.T) {
	peerA := makePeerHash(0xAA)
	peerB := makePeerHash(0xBB)

	result := &BuildTunnelResult{
		TunnelID:   TunnelID(12345),
		PeerHashes: []common.Hash{peerA, peerB},
	}

	assert.Equal(t, TunnelID(12345), result.TunnelID)
	assert.Len(t, result.PeerHashes, 2)
	assert.Equal(t, peerA, result.PeerHashes[0])
	assert.Equal(t, peerB, result.PeerHashes[1])
}

func TestBuilderInterface_ReturnsBuildTunnelResult(t *testing.T) {
	peerA := makePeerHash(0x11)

	builder := &PeerTrackingBuilder{
		shouldFail:   false,
		successPeers: []common.Hash{peerA},
	}

	req := BuildTunnelRequest{
		HopCount:  3,
		IsInbound: false,
	}

	result, err := builder.BuildTunnel(req)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEqual(t, TunnelID(0), result.TunnelID)
	assert.Len(t, result.PeerHashes, 1)
	assert.Equal(t, peerA, result.PeerHashes[0])
}

func TestBuilderInterface_FailureStillReturnsPeerHashes(t *testing.T) {
	peerA := makePeerHash(0x22)
	peerB := makePeerHash(0x33)

	builder := &PeerTrackingBuilder{
		shouldFail:  true,
		failedPeers: []common.Hash{peerA, peerB},
	}

	req := BuildTunnelRequest{
		HopCount:  3,
		IsInbound: true,
	}

	result, err := builder.BuildTunnel(req)
	assert.Error(t, err)
	require.NotNil(t, result)
	assert.Equal(t, TunnelID(0), result.TunnelID)
	assert.Len(t, result.PeerHashes, 2)
	assert.Equal(t, peerA, result.PeerHashes[0])
	assert.Equal(t, peerB, result.PeerHashes[1])
}

func TestAttemptBuildTunnels_MarksPeersOnFailure(t *testing.T) {
	pool := NewTunnelPool(&MockPeerSelector{})
	defer pool.Stop()

	peerA := makePeerHash(0xAA)
	peerB := makePeerHash(0xBB)

	builder := &PeerTrackingBuilder{
		shouldFail:  true,
		failedPeers: []common.Hash{peerA, peerB},
	}
	pool.SetTunnelBuilder(builder)

	success := pool.attemptBuildTunnels(1)
	assert.False(t, success)

	// Peers should be marked as failed
	assert.True(t, pool.IsPeerFailed(peerA))
	assert.True(t, pool.IsPeerFailed(peerB))
}

func TestRetryTunnelBuild_MarksPeersOnFailure(t *testing.T) {
	pool := NewTunnelPool(&MockPeerSelector{})
	defer pool.Stop()

	peerA := makePeerHash(0xDD)
	peerB := makePeerHash(0xEE)

	builder := &PeerTrackingBuilder{
		shouldFail:  true,
		failedPeers: []common.Hash{peerA, peerB},
	}
	pool.SetTunnelBuilder(builder)

	err := pool.RetryTunnelBuild(TunnelID(100), false, 3)
	assert.Error(t, err)

	// Failed peers from the retry should be marked
	assert.True(t, pool.IsPeerFailed(peerA))
	assert.True(t, pool.IsPeerFailed(peerB))
}

func TestRetryTunnelBuild_SuccessDoesNotMarkPeers(t *testing.T) {
	pool := NewTunnelPool(&MockPeerSelector{})
	defer pool.Stop()

	builder := &PeerTrackingBuilder{
		shouldFail: false,
	}
	pool.SetTunnelBuilder(builder)

	err := pool.RetryTunnelBuild(TunnelID(200), true, 2)
	assert.NoError(t, err)
	assert.Empty(t, pool.failedPeers)
}

func TestFailedPeersExcludedFromSubsequentBuilds(t *testing.T) {
	pool := NewTunnelPool(&MockPeerSelector{})
	defer pool.Stop()

	peerA := makePeerHash(0xAA)

	// Pre-mark peer A as failed
	pool.MarkPeerFailed(peerA)

	var capturedExcludeList []common.Hash
	builder := &callbackBuilder{
		callback: func(req BuildTunnelRequest) (*BuildTunnelResult, error) {
			capturedExcludeList = req.ExcludePeers
			return &BuildTunnelResult{
				TunnelID:   TunnelID(6666),
				PeerHashes: nil,
			}, nil
		},
	}
	pool.SetTunnelBuilder(builder)

	// attemptBuildTunnels gets failed peers and passes them as ExcludePeers
	pool.attemptBuildTunnels(1)

	// Peer A should have been in the exclude list
	assert.Contains(t, capturedExcludeList, peerA)
}

// callbackBuilder is a flexible test builder that delegates to a callback function.
type callbackBuilder struct {
	callback func(req BuildTunnelRequest) (*BuildTunnelResult, error)
}

func (b *callbackBuilder) BuildTunnel(req BuildTunnelRequest) (*BuildTunnelResult, error) {
	return b.callback(req)
}

// mockPeerTracker records peer tracking events for testing.
type mockPeerTracker struct {
	mu        sync.Mutex
	failures  []common.Hash
	successes []common.Hash
}

func (t *mockPeerTracker) RecordFailure(hash common.Hash, reason string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.failures = append(t.failures, hash)
}

func (t *mockPeerTracker) RecordSuccess(hash common.Hash, responseTimeMs int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.successes = append(t.successes, hash)
}

func (t *mockPeerTracker) failureCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.failures)
}

func TestEndToEnd_FailedBuildExcludesPeersFromNextAttempt(t *testing.T) {
	pool := NewTunnelPool(&MockPeerSelector{})
	defer pool.Stop()

	peerX := makePeerHash(0xF1)
	peerY := makePeerHash(0xF2)
	peerZ := makePeerHash(0xF3)

	callCount := 0
	var excludeSnapshots [][]common.Hash

	builder := &callbackBuilder{
		callback: func(req BuildTunnelRequest) (*BuildTunnelResult, error) {
			callCount++
			// Record what was excluded
			snapshot := make([]common.Hash, len(req.ExcludePeers))
			copy(snapshot, req.ExcludePeers)
			excludeSnapshots = append(excludeSnapshots, snapshot)

			switch callCount {
			case 1:
				// First build attempt: fail with peers X, Y
				return &BuildTunnelResult{
					TunnelID:   0,
					PeerHashes: []common.Hash{peerX, peerY},
				}, assert.AnError
			case 2:
				// Second attempt: fail with peer Z (X,Y should be excluded)
				return &BuildTunnelResult{
					TunnelID:   0,
					PeerHashes: []common.Hash{peerZ},
				}, assert.AnError
			default:
				// Third attempt: succeed (X,Y,Z should all be excluded)
				return &BuildTunnelResult{
					TunnelID:   TunnelID(3333),
					PeerHashes: nil,
				}, nil
			}
		},
	}
	pool.SetTunnelBuilder(builder)

	req := BuildTunnelRequest{
		HopCount:  3,
		IsInbound: false,
	}

	tunnelID, err := pool.executeBuildWithRetry(&req)
	require.NoError(t, err)
	assert.Equal(t, TunnelID(3333), tunnelID)

	// Verify progressive exclusion
	require.Len(t, excludeSnapshots, 3)

	// First call: no peers excluded yet
	assert.Empty(t, excludeSnapshots[0])

	// Second call: X, Y excluded
	assert.Len(t, excludeSnapshots[1], 2)
	assert.Contains(t, excludeSnapshots[1], peerX)
	assert.Contains(t, excludeSnapshots[1], peerY)

	// Third call: X, Y, Z excluded
	assert.Len(t, excludeSnapshots[2], 3)
	assert.Contains(t, excludeSnapshots[2], peerX)
	assert.Contains(t, excludeSnapshots[2], peerY)
	assert.Contains(t, excludeSnapshots[2], peerZ)

	// All failed peers should be in the pool's failed list
	assert.True(t, pool.IsPeerFailed(peerX))
	assert.True(t, pool.IsPeerFailed(peerY))
	assert.True(t, pool.IsPeerFailed(peerZ))
}

func TestExtractAndMarkFailedPeers_Concurrent(t *testing.T) {
	pool := NewTunnelPool(&MockPeerSelector{})
	defer pool.Stop()

	var wg sync.WaitGroup
	peerCount := 10

	// Concurrently mark peers as failed
	for i := 0; i < peerCount; i++ {
		wg.Add(1)
		go func(seed byte) {
			defer wg.Done()
			peer := makePeerHash(seed)
			pool.extractAndMarkFailedPeers(&BuildTunnelResult{
				PeerHashes: []common.Hash{peer},
			})
		}(byte(i))
	}

	wg.Wait()

	// All peers should be marked
	for i := 0; i < peerCount; i++ {
		peer := makePeerHash(byte(i))
		assert.True(t, pool.IsPeerFailed(peer), "Peer %d should be marked as failed", i)
	}
}

func TestFailedPeersExpireAfterCooldown(t *testing.T) {
	pool := NewTunnelPool(&MockPeerSelector{})
	defer pool.Stop()

	peerA := makePeerHash(0xAA)

	// Mark peer as failed in the past (beyond cooldown)
	pool.failedPeersMu.Lock()
	pool.failedPeers[peerA] = time.Now().Add(-6 * time.Minute) // 6 minutes ago, past 5-minute cooldown
	pool.failedPeersMu.Unlock()

	// Peer should no longer be considered failed
	assert.False(t, pool.IsPeerFailed(peerA))

	// Cleanup should remove it
	pool.CleanupFailedPeers()

	pool.failedPeersMu.RLock()
	_, exists := pool.failedPeers[peerA]
	pool.failedPeersMu.RUnlock()
	assert.False(t, exists, "Expired failed peer should be cleaned up")
}
