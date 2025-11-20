package i2np

import (
	"sync"
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/common/session_key"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestReplyProcessor_RegisterPendingBuild tests registration of pending builds
func TestReplyProcessor_RegisterPendingBuild(t *testing.T) {
	config := DefaultReplyProcessorConfig()
	config.BuildTimeout = 100 * time.Millisecond
	rp := NewReplyProcessor(config, nil)

	tunnelID := tunnel.TunnelID(12345)
	replyKeys := make([]session_key.SessionKey, 3)
	replyIVs := make([][16]byte, 3)

	err := rp.RegisterPendingBuild(tunnelID, replyKeys, replyIVs, false, 3)

	assert.NoError(t, err, "Should register pending build successfully")
	assert.Equal(t, 1, rp.GetPendingBuildCount(), "Should have one pending build")

	info := rp.GetPendingBuildInfo(tunnelID)
	require.NotNil(t, info, "Should retrieve pending build info")
	assert.Equal(t, tunnelID, info.TunnelID)
	assert.Equal(t, 3, info.HopCount)
	assert.Equal(t, false, info.IsInbound)
	assert.Equal(t, 0, info.Retries)
}

// TestReplyProcessor_RegisterPendingBuild_KeyMismatch tests validation of key counts
func TestReplyProcessor_RegisterPendingBuild_KeyMismatch(t *testing.T) {
	rp := NewReplyProcessor(DefaultReplyProcessorConfig(), nil)

	tunnelID := tunnel.TunnelID(12345)
	replyKeys := make([]session_key.SessionKey, 3)
	replyIVs := make([][16]byte, 2) // Mismatch

	err := rp.RegisterPendingBuild(tunnelID, replyKeys, replyIVs, false, 3)

	assert.Error(t, err, "Should fail with key/IV count mismatch")
	assert.Contains(t, err.Error(), "mismatch")
	assert.Equal(t, 0, rp.GetPendingBuildCount(), "Should not register invalid build")
}

// TestReplyProcessor_ProcessBuildReply_Success tests successful reply processing
func TestReplyProcessor_ProcessBuildReply_Success(t *testing.T) {
	config := DefaultReplyProcessorConfig()
	config.EnableDecryption = false // Disable decryption for simplicity
	rp := NewReplyProcessor(config, nil)

	// Register pending build
	tunnelID := tunnel.TunnelID(12345)
	replyKeys := make([]session_key.SessionKey, 3)
	replyIVs := make([][16]byte, 3)
	err := rp.RegisterPendingBuild(tunnelID, replyKeys, replyIVs, false, 3)
	require.NoError(t, err)

	// Create successful reply
	reply := createSuccessfulVariableTunnelBuildReply(3)

	// Process reply
	err = rp.ProcessBuildReply(reply, tunnelID)

	assert.NoError(t, err, "Should process successful reply")
	assert.Equal(t, 0, rp.GetPendingBuildCount(), "Should remove pending build after success")
}

// TestReplyProcessor_ProcessBuildReply_UnknownTunnel tests reply for unknown tunnel
func TestReplyProcessor_ProcessBuildReply_UnknownTunnel(t *testing.T) {
	config := DefaultReplyProcessorConfig()
	config.EnableDecryption = false
	rp := NewReplyProcessor(config, nil)

	unknownID := tunnel.TunnelID(99999)
	reply := createSuccessfulVariableTunnelBuildReply(3)

	err := rp.ProcessBuildReply(reply, unknownID)

	assert.Error(t, err, "Should fail for unknown tunnel ID")
	assert.Contains(t, err.Error(), "no pending build")
}

// TestReplyProcessor_ProcessBuildReply_Failure tests failed reply processing
func TestReplyProcessor_ProcessBuildReply_Failure(t *testing.T) {
	config := DefaultReplyProcessorConfig()
	config.EnableDecryption = false
	config.MaxRetries = 0 // Disable retries for this test
	rp := NewReplyProcessor(config, nil)

	// Register pending build
	tunnelID := tunnel.TunnelID(12345)
	replyKeys := make([]session_key.SessionKey, 3)
	replyIVs := make([][16]byte, 3)
	err := rp.RegisterPendingBuild(tunnelID, replyKeys, replyIVs, false, 3)
	require.NoError(t, err)

	// Create failed reply (all hops reject)
	reply := createMixedVariableTunnelBuildReply(3) // This has failures

	// Process reply
	err = rp.ProcessBuildReply(reply, tunnelID)

	assert.Error(t, err, "Should fail for rejected tunnel build")
	assert.Equal(t, 0, rp.GetPendingBuildCount(), "Should remove pending build after failure")
}

// TestReplyProcessor_Timeout tests timeout handling
func TestReplyProcessor_Timeout(t *testing.T) {
	config := DefaultReplyProcessorConfig()
	config.BuildTimeout = 50 * time.Millisecond
	config.MaxRetries = 0 // No retries for simplicity
	rp := NewReplyProcessor(config, nil)

	// Register pending build
	tunnelID := tunnel.TunnelID(12345)
	replyKeys := make([]session_key.SessionKey, 3)
	replyIVs := make([][16]byte, 3)
	err := rp.RegisterPendingBuild(tunnelID, replyKeys, replyIVs, false, 3)
	require.NoError(t, err)

	// Wait for timeout
	time.Sleep(100 * time.Millisecond)

	// Check that pending build was removed
	assert.Equal(t, 0, rp.GetPendingBuildCount(), "Timeout should remove pending build")
}

// TestReplyProcessor_Retry tests retry logic
func TestReplyProcessor_Retry(t *testing.T) {
	config := DefaultReplyProcessorConfig()
	config.EnableDecryption = false
	config.MaxRetries = 2
	config.RetryBackoff = 10 * time.Millisecond
	rp := NewReplyProcessor(config, nil)

	// Track retry callbacks
	var retryMutex sync.Mutex
	var retryCalls []tunnel.TunnelID
	rp.SetRetryCallback(func(id tunnel.TunnelID, isInbound bool, hopCount int) error {
		retryMutex.Lock()
		defer retryMutex.Unlock()
		retryCalls = append(retryCalls, id)
		return nil
	})

	// Register pending build
	tunnelID := tunnel.TunnelID(12345)
	replyKeys := make([]session_key.SessionKey, 3)
	replyIVs := make([][16]byte, 3)
	err := rp.RegisterPendingBuild(tunnelID, replyKeys, replyIVs, false, 3)
	require.NoError(t, err)

	// Create failed reply
	reply := createMixedVariableTunnelBuildReply(3)

	// Process reply (should trigger retry)
	err = rp.ProcessBuildReply(reply, tunnelID)

	assert.Error(t, err, "Should fail for rejected tunnel build")
	assert.Contains(t, err.Error(), "retry scheduled")

	// Wait for retry callback
	time.Sleep(50 * time.Millisecond)

	retryMutex.Lock()
	assert.Equal(t, 1, len(retryCalls), "Should have called retry callback once")
	if len(retryCalls) > 0 {
		assert.Equal(t, tunnelID, retryCalls[0], "Should retry correct tunnel ID")
	}
	retryMutex.Unlock()
}

// TestReplyProcessor_RetryExhausted tests behavior when retries are exhausted
func TestReplyProcessor_RetryExhausted(t *testing.T) {
	config := DefaultReplyProcessorConfig()
	config.EnableDecryption = false
	config.MaxRetries = 1
	config.RetryBackoff = 10 * time.Millisecond
	rp := NewReplyProcessor(config, nil)

	var retryCount int
	var retryMutex sync.Mutex
	rp.SetRetryCallback(func(id tunnel.TunnelID, isInbound bool, hopCount int) error {
		retryMutex.Lock()
		defer retryMutex.Unlock()
		retryCount++
		return nil
	})

	// Register pending build with already exhausted retries
	tunnelID := tunnel.TunnelID(12345)
	replyKeys := make([]session_key.SessionKey, 3)
	replyIVs := make([][16]byte, 3)
	err := rp.RegisterPendingBuild(tunnelID, replyKeys, replyIVs, false, 3)
	require.NoError(t, err)

	// Manually set retry count to max
	info := rp.GetPendingBuildInfo(tunnelID)
	require.NotNil(t, info)
	info.Retries = config.MaxRetries

	// Create failed reply
	reply := createMixedVariableTunnelBuildReply(3)

	// Process reply (should NOT trigger retry)
	err = rp.ProcessBuildReply(reply, tunnelID)

	assert.Error(t, err, "Should fail permanently")
	assert.Contains(t, err.Error(), "failed after")

	// Wait to ensure no retry happens
	time.Sleep(50 * time.Millisecond)

	retryMutex.Lock()
	assert.Equal(t, 0, retryCount, "Should not retry when retries exhausted")
	retryMutex.Unlock()
}

// TestReplyProcessor_CleanupExpiredBuilds tests cleanup of expired builds
func TestReplyProcessor_CleanupExpiredBuilds(t *testing.T) {
	config := DefaultReplyProcessorConfig()
	config.BuildTimeout = 1000 * time.Second // Very long to prevent auto-timeout
	config.RetryBackoff = 5 * time.Millisecond
	config.MaxRetries = 0
	rp := NewReplyProcessor(config, nil)

	// Register multiple pending builds with old timestamps
	for i := 1; i <= 3; i++ {
		tunnelID := tunnel.TunnelID(12340 + i)
		replyKeys := make([]session_key.SessionKey, 3)
		replyIVs := make([][16]byte, 3)
		err := rp.RegisterPendingBuild(tunnelID, replyKeys, replyIVs, false, 3)
		require.NoError(t, err)

		// Manually set old timestamp to simulate expiration
		pending := rp.GetPendingBuildInfo(tunnelID)
		require.NotNil(t, pending)
		pending.RequestedAt = time.Now().Add(-2 * time.Hour) // Very old

		// Stop the timeout timer to prevent auto-cleanup
		if pending.TimeoutTimer != nil {
			pending.TimeoutTimer.Stop()
		}
	}

	assert.Equal(t, 3, rp.GetPendingBuildCount(), "Should have 3 pending builds")

	// Cleanup expired builds
	expired := rp.CleanupExpiredBuilds()

	assert.Equal(t, 3, expired, "Should clean up all 3 expired builds")
	assert.Equal(t, 0, rp.GetPendingBuildCount(), "Should have no pending builds after cleanup")
}

// TestReplyProcessor_ConcurrentRegistration tests concurrent build registration
func TestReplyProcessor_ConcurrentRegistration(t *testing.T) {
	rp := NewReplyProcessor(DefaultReplyProcessorConfig(), nil)

	const numBuilds = 100
	var wg sync.WaitGroup

	// Register many builds concurrently
	for i := 0; i < numBuilds; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			tunnelID := tunnel.TunnelID(10000 + id)
			replyKeys := make([]session_key.SessionKey, 3)
			replyIVs := make([][16]byte, 3)
			err := rp.RegisterPendingBuild(tunnelID, replyKeys, replyIVs, false, 3)
			assert.NoError(t, err)
		}(i)
	}

	wg.Wait()

	assert.Equal(t, numBuilds, rp.GetPendingBuildCount(), "Should register all builds")
}

// TestReplyProcessor_ConcurrentProcessing tests concurrent reply processing
func TestReplyProcessor_ConcurrentProcessing(t *testing.T) {
	config := DefaultReplyProcessorConfig()
	config.EnableDecryption = false
	rp := NewReplyProcessor(config, nil)

	const numBuilds = 50
	var wg sync.WaitGroup

	// Register builds
	for i := 0; i < numBuilds; i++ {
		tunnelID := tunnel.TunnelID(10000 + i)
		replyKeys := make([]session_key.SessionKey, 3)
		replyIVs := make([][16]byte, 3)
		err := rp.RegisterPendingBuild(tunnelID, replyKeys, replyIVs, false, 3)
		require.NoError(t, err)
	}

	// Process replies concurrently
	for i := 0; i < numBuilds; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			tunnelID := tunnel.TunnelID(10000 + id)
			reply := createSuccessfulVariableTunnelBuildReply(3)
			err := rp.ProcessBuildReply(reply, tunnelID)
			assert.NoError(t, err)
		}(i)
	}

	wg.Wait()

	assert.Equal(t, 0, rp.GetPendingBuildCount(), "All builds should be processed")
}

// TestReplyProcessor_DefaultConfig tests default configuration values
func TestReplyProcessor_DefaultConfig(t *testing.T) {
	config := DefaultReplyProcessorConfig()

	assert.Equal(t, 90*time.Second, config.BuildTimeout, "Default timeout should be 90s")
	assert.Equal(t, 3, config.MaxRetries, "Default max retries should be 3")
	assert.Equal(t, 5*time.Second, config.RetryBackoff, "Default backoff should be 5s")
	assert.Equal(t, true, config.EnableDecryption, "Decryption should be enabled by default")
}

// TestReplyProcessor_DecryptionDisabled tests behavior with decryption disabled
func TestReplyProcessor_DecryptionDisabled(t *testing.T) {
	config := DefaultReplyProcessorConfig()
	config.EnableDecryption = false
	rp := NewReplyProcessor(config, nil)

	tunnelID := tunnel.TunnelID(12345)
	replyKeys := make([]session_key.SessionKey, 3)
	replyIVs := make([][16]byte, 3)
	err := rp.RegisterPendingBuild(tunnelID, replyKeys, replyIVs, false, 3)
	require.NoError(t, err)

	reply := createSuccessfulVariableTunnelBuildReply(3)
	err = rp.ProcessBuildReply(reply, tunnelID)

	assert.NoError(t, err, "Should process reply without decryption")
}

// TestReplyProcessor_RecordCountMismatch tests handling of record count mismatch
func TestReplyProcessor_RecordCountMismatch(t *testing.T) {
	config := DefaultReplyProcessorConfig()
	config.EnableDecryption = true
	config.MaxRetries = 0 // Disable retries for this test
	rp := NewReplyProcessor(config, nil)

	// Register build with 3 hops
	tunnelID := tunnel.TunnelID(12345)
	replyKeys := make([]session_key.SessionKey, 3)
	replyIVs := make([][16]byte, 3)
	err := rp.RegisterPendingBuild(tunnelID, replyKeys, replyIVs, false, 3)
	require.NoError(t, err)

	// Create reply with different number of records
	reply := createSuccessfulVariableTunnelBuildReply(5) // Mismatch!

	err = rp.ProcessBuildReply(reply, tunnelID)

	// Should fail because record count doesn't match
	assert.Error(t, err, "Should fail with record count mismatch")
}

// TestReplyProcessor_TimeoutCancellation tests that timeout is cancelled on reply
func TestReplyProcessor_TimeoutCancellation(t *testing.T) {
	config := DefaultReplyProcessorConfig()
	config.BuildTimeout = 100 * time.Millisecond
	config.EnableDecryption = false
	rp := NewReplyProcessor(config, nil)

	tunnelID := tunnel.TunnelID(12345)
	replyKeys := make([]session_key.SessionKey, 3)
	replyIVs := make([][16]byte, 3)
	err := rp.RegisterPendingBuild(tunnelID, replyKeys, replyIVs, false, 3)
	require.NoError(t, err)

	// Process reply quickly (before timeout)
	reply := createSuccessfulVariableTunnelBuildReply(3)
	err = rp.ProcessBuildReply(reply, tunnelID)
	assert.NoError(t, err)

	// Wait beyond timeout to ensure timeout handler doesn't fire
	time.Sleep(150 * time.Millisecond)

	// Should still be removed (only once)
	assert.Equal(t, 0, rp.GetPendingBuildCount())
}

// TestReplyProcessor_NoRetryCallback tests behavior without retry callback
func TestReplyProcessor_NoRetryCallback(t *testing.T) {
	config := DefaultReplyProcessorConfig()
	config.EnableDecryption = false
	config.MaxRetries = 2
	rp := NewReplyProcessor(config, nil)
	// No retry callback set

	tunnelID := tunnel.TunnelID(12345)
	replyKeys := make([]session_key.SessionKey, 3)
	replyIVs := make([][16]byte, 3)
	err := rp.RegisterPendingBuild(tunnelID, replyKeys, replyIVs, false, 3)
	require.NoError(t, err)

	reply := createMixedVariableTunnelBuildReply(3)
	err = rp.ProcessBuildReply(reply, tunnelID)

	assert.Error(t, err, "Should fail without retry callback")
	assert.Contains(t, err.Error(), "retry not available")
}

// TestReplyProcessor_IntegrationWithTunnelManager tests integration with TunnelManager
func TestReplyProcessor_IntegrationWithTunnelManager(t *testing.T) {
	// Create mock peer selector
	peerSelector := &mockPeerSelector{}
	tm := NewTunnelManager(peerSelector)

	config := DefaultReplyProcessorConfig()
	config.EnableDecryption = false
	rp := NewReplyProcessor(config, tm)

	tunnelID := tunnel.TunnelID(12345)
	replyKeys := make([]session_key.SessionKey, 3)
	replyIVs := make([][16]byte, 3)
	err := rp.RegisterPendingBuild(tunnelID, replyKeys, replyIVs, false, 3)
	require.NoError(t, err)

	reply := createSuccessfulVariableTunnelBuildReply(3)
	err = rp.ProcessBuildReply(reply, tunnelID)

	assert.NoError(t, err, "Should process reply with tunnel manager integration")
}

// mockPeerSelector is a simple mock for testing
type mockPeerSelector struct{}

func (m *mockPeerSelector) SelectPeers(count int, exclude []common.Hash) ([]router_info.RouterInfo, error) {
	return make([]router_info.RouterInfo, count), nil
}

// Benchmark tests

func BenchmarkReplyProcessor_RegisterPendingBuild(b *testing.B) {
	rp := NewReplyProcessor(DefaultReplyProcessorConfig(), nil)
	replyKeys := make([]session_key.SessionKey, 3)
	replyIVs := make([][16]byte, 3)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tunnelID := tunnel.TunnelID(i)
		_ = rp.RegisterPendingBuild(tunnelID, replyKeys, replyIVs, false, 3)
	}
}

func BenchmarkReplyProcessor_ProcessBuildReply(b *testing.B) {
	config := DefaultReplyProcessorConfig()
	config.EnableDecryption = false
	rp := NewReplyProcessor(config, nil)

	replyKeys := make([]session_key.SessionKey, 3)
	replyIVs := make([][16]byte, 3)

	// Pre-register builds
	for i := 0; i < b.N; i++ {
		tunnelID := tunnel.TunnelID(i)
		_ = rp.RegisterPendingBuild(tunnelID, replyKeys, replyIVs, false, 3)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tunnelID := tunnel.TunnelID(i)
		reply := createSuccessfulVariableTunnelBuildReply(3)
		_ = rp.ProcessBuildReply(reply, tunnelID)
	}
}

func BenchmarkReplyProcessor_CleanupExpiredBuilds(b *testing.B) {
	config := DefaultReplyProcessorConfig()
	config.BuildTimeout = 1 * time.Millisecond
	rp := NewReplyProcessor(config, nil)

	replyKeys := make([]session_key.SessionKey, 3)
	replyIVs := make([][16]byte, 3)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Register some builds
		for j := 0; j < 10; j++ {
			tunnelID := tunnel.TunnelID(i*10 + j)
			_ = rp.RegisterPendingBuild(tunnelID, replyKeys, replyIVs, false, 3)
		}

		time.Sleep(2 * time.Millisecond)
		rp.CleanupExpiredBuilds()
	}
}
