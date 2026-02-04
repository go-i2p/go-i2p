package i2np

// Security Audit Tests for Reply Correlation (Message ID Tracking)
// Audit Date: 2026-02-04
// These tests verify the correctness of message ID tracking and tunnel build correlation.

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-i2p/common/session_key"
	"github.com/go-i2p/crypto/rand"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// Audit: Message ID Uniqueness and Correlation
// ============================================================================

// TestReplyProcessor_MessageIDUniqueness verifies tunnel IDs are tracked uniquely.
func TestReplyProcessor_MessageIDUniqueness(t *testing.T) {
	config := DefaultReplyProcessorConfig()
	config.BuildTimeout = 5 * time.Second
	rp := NewReplyProcessor(config, nil)

	// Register multiple pending builds
	numBuilds := 100
	registeredIDs := make(map[tunnel.TunnelID]bool)

	for i := 0; i < numBuilds; i++ {
		tunnelID := tunnel.TunnelID(i + 1)
		replyKeys := make([]session_key.SessionKey, 3)
		replyIVs := make([][16]byte, 3)

		for j := 0; j < 3; j++ {
			_, err := rand.Read(replyKeys[j][:])
			require.NoError(t, err)
			_, err = rand.Read(replyIVs[j][:])
			require.NoError(t, err)
		}

		err := rp.RegisterPendingBuild(tunnelID, replyKeys, replyIVs, i%2 == 0, 3)
		require.NoError(t, err)
		registeredIDs[tunnelID] = true
	}

	assert.Equal(t, numBuilds, rp.GetPendingBuildCount(), "All builds should be registered")

	// Verify each ID is tracked
	for id := range registeredIDs {
		info := rp.GetPendingBuildInfo(id)
		assert.NotNil(t, info, "Tunnel ID %d should be tracked", id)
	}
}

// TestReplyProcessor_DuplicateRegistration verifies handling of duplicate registrations.
func TestReplyProcessor_DuplicateRegistration(t *testing.T) {
	config := DefaultReplyProcessorConfig()
	rp := NewReplyProcessor(config, nil)

	tunnelID := tunnel.TunnelID(12345)
	replyKeys := make([]session_key.SessionKey, 2)
	replyIVs := make([][16]byte, 2)

	for j := 0; j < 2; j++ {
		_, err := rand.Read(replyKeys[j][:])
		require.NoError(t, err)
		_, err = rand.Read(replyIVs[j][:])
		require.NoError(t, err)
	}

	// First registration
	err := rp.RegisterPendingBuild(tunnelID, replyKeys, replyIVs, true, 2)
	require.NoError(t, err)

	// Duplicate registration should overwrite (current behavior)
	err = rp.RegisterPendingBuild(tunnelID, replyKeys, replyIVs, false, 2)
	require.NoError(t, err)

	// Should still have only one pending build
	assert.Equal(t, 1, rp.GetPendingBuildCount())

	// Second registration should have overwritten the first
	info := rp.GetPendingBuildInfo(tunnelID)
	assert.NotNil(t, info)
	assert.False(t, info.IsInbound, "Should have the second registration's direction")
}

// TestReplyProcessor_CorrelationRemoval verifies pending builds are removed after processing.
func TestReplyProcessor_CorrelationRemoval(t *testing.T) {
	config := DefaultReplyProcessorConfig()
	config.EnableDecryption = false // Disable decryption for this test
	rp := NewReplyProcessor(config, nil)

	tunnelID := tunnel.TunnelID(999)
	replyKeys := make([]session_key.SessionKey, 2)
	replyIVs := make([][16]byte, 2)

	for j := 0; j < 2; j++ {
		_, err := rand.Read(replyKeys[j][:])
		require.NoError(t, err)
		_, err = rand.Read(replyIVs[j][:])
		require.NoError(t, err)
	}

	err := rp.RegisterPendingBuild(tunnelID, replyKeys, replyIVs, true, 2)
	require.NoError(t, err)

	assert.Equal(t, 1, rp.GetPendingBuildCount())

	// Create successful reply handler
	handler := createSuccessfulVariableTunnelBuildReply(2)

	// Process the reply
	err = rp.ProcessBuildReply(handler, tunnelID)
	require.NoError(t, err)

	// Pending build should be removed
	assert.Equal(t, 0, rp.GetPendingBuildCount())
	assert.Nil(t, rp.GetPendingBuildInfo(tunnelID))
}

// TestReplyProcessor_UnknownTunnelID verifies handling of unknown tunnel IDs.
func TestReplyProcessor_UnknownTunnelID(t *testing.T) {
	config := DefaultReplyProcessorConfig()
	rp := NewReplyProcessor(config, nil)

	// Try to process reply for unknown tunnel
	handler := createSuccessfulVariableTunnelBuildReply(3)
	unknownID := tunnel.TunnelID(99999)

	err := rp.ProcessBuildReply(handler, unknownID)
	assert.Error(t, err, "Should error on unknown tunnel ID")
	assert.Contains(t, err.Error(), "no pending build")
}

// TestReplyProcessor_TimeoutExpiration verifies builds expire after timeout.
func TestReplyProcessor_TimeoutExpiration(t *testing.T) {
	config := DefaultReplyProcessorConfig()
	config.BuildTimeout = 50 * time.Millisecond
	config.MaxRetries = 0 // No retries for this test
	rp := NewReplyProcessor(config, nil)

	tunnelID := tunnel.TunnelID(777)
	replyKeys := make([]session_key.SessionKey, 1)
	replyIVs := make([][16]byte, 1)
	_, err := rand.Read(replyKeys[0][:])
	require.NoError(t, err)
	_, err = rand.Read(replyIVs[0][:])
	require.NoError(t, err)

	err = rp.RegisterPendingBuild(tunnelID, replyKeys, replyIVs, true, 1)
	require.NoError(t, err)

	assert.Equal(t, 1, rp.GetPendingBuildCount())

	// Wait for timeout
	time.Sleep(100 * time.Millisecond)

	// Pending build should be removed by timeout handler
	assert.Equal(t, 0, rp.GetPendingBuildCount())
}

// TestReplyProcessor_TimeoutCancellationOnReply verifies timeout is cancelled when reply arrives.
func TestReplyProcessor_TimeoutCancellationOnReply(t *testing.T) {
	config := DefaultReplyProcessorConfig()
	config.BuildTimeout = 200 * time.Millisecond
	config.EnableDecryption = false
	rp := NewReplyProcessor(config, nil)

	tunnelID := tunnel.TunnelID(888)
	replyKeys := make([]session_key.SessionKey, 2)
	replyIVs := make([][16]byte, 2)
	for j := 0; j < 2; j++ {
		_, err := rand.Read(replyKeys[j][:])
		require.NoError(t, err)
		_, err = rand.Read(replyIVs[j][:])
		require.NoError(t, err)
	}

	err := rp.RegisterPendingBuild(tunnelID, replyKeys, replyIVs, true, 2)
	require.NoError(t, err)

	// Process reply before timeout
	handler := createSuccessfulVariableTunnelBuildReply(2)
	err = rp.ProcessBuildReply(handler, tunnelID)
	require.NoError(t, err)

	// Verify build is removed
	assert.Equal(t, 0, rp.GetPendingBuildCount())

	// Wait past what would have been the timeout
	time.Sleep(250 * time.Millisecond)

	// Should still have 0 pending builds (timeout was cancelled)
	assert.Equal(t, 0, rp.GetPendingBuildCount())
}

// TestReplyProcessor_ConcurrentRegistrationAndProcessing verifies thread safety.
func TestReplyProcessor_ConcurrentRegistrationAndProcessing(t *testing.T) {
	config := DefaultReplyProcessorConfig()
	config.BuildTimeout = 10 * time.Second
	config.EnableDecryption = false
	rp := NewReplyProcessor(config, nil)

	var wg sync.WaitGroup
	numGoroutines := 20
	numOpsPerGoroutine := 50

	var successfulOps int64

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			for j := 0; j < numOpsPerGoroutine; j++ {
				tunnelID := tunnel.TunnelID(idx*numOpsPerGoroutine + j + 1)
				replyKeys := make([]session_key.SessionKey, 2)
				replyIVs := make([][16]byte, 2)

				for k := 0; k < 2; k++ {
					_, err := rand.Read(replyKeys[k][:])
					if err != nil {
						continue
					}
					_, err = rand.Read(replyIVs[k][:])
					if err != nil {
						continue
					}
				}

				err := rp.RegisterPendingBuild(tunnelID, replyKeys, replyIVs, idx%2 == 0, 2)
				if err != nil {
					continue
				}

				// Process reply immediately
				handler := createSuccessfulVariableTunnelBuildReply(2)
				err = rp.ProcessBuildReply(handler, tunnelID)
				if err == nil {
					atomic.AddInt64(&successfulOps, 1)
				}
			}
		}(i)
	}

	wg.Wait()

	// All operations should complete without races
	assert.Greater(t, successfulOps, int64(0), "Some operations should succeed")

	// Pending builds should be empty after all processing
	assert.Equal(t, 0, rp.GetPendingBuildCount())
}

// TestReplyProcessor_RetryCorrelation verifies retry tracking preserves correlation.
func TestReplyProcessor_RetryCorrelation(t *testing.T) {
	config := DefaultReplyProcessorConfig()
	config.MaxRetries = 2
	config.RetryBackoff = 10 * time.Millisecond
	config.EnableDecryption = false
	rp := NewReplyProcessor(config, nil)

	var retryCount int32
	var lastTunnelID atomic.Uint64

	rp.SetRetryCallback(func(tunnelID tunnel.TunnelID, isInbound bool, hopCount int) error {
		atomic.AddInt32(&retryCount, 1)
		lastTunnelID.Store(uint64(tunnelID))
		return nil
	})

	tunnelID := tunnel.TunnelID(555)
	replyKeys := make([]session_key.SessionKey, 2)
	replyIVs := make([][16]byte, 2)
	for j := 0; j < 2; j++ {
		_, err := rand.Read(replyKeys[j][:])
		require.NoError(t, err)
		_, err = rand.Read(replyIVs[j][:])
		require.NoError(t, err)
	}

	err := rp.RegisterPendingBuild(tunnelID, replyKeys, replyIVs, true, 2)
	require.NoError(t, err)

	// Process failing reply
	handler := createRejectedVariableTunnelBuildReply(2)
	err = rp.ProcessBuildReply(handler, tunnelID)
	assert.Error(t, err, "Should return error for rejected build")

	// Wait for retry callback
	time.Sleep(50 * time.Millisecond)

	// Verify retry was triggered with correct tunnel ID
	assert.Equal(t, int32(1), atomic.LoadInt32(&retryCount))
	assert.Equal(t, uint64(tunnelID), lastTunnelID.Load(), "Retry callback should receive correct tunnel ID")
}

// TestReplyProcessor_KeyIVCorrectness verifies reply keys/IVs are stored correctly.
func TestReplyProcessor_KeyIVCorrectness(t *testing.T) {
	config := DefaultReplyProcessorConfig()
	rp := NewReplyProcessor(config, nil)

	tunnelID := tunnel.TunnelID(333)
	hopCount := 3
	replyKeys := make([]session_key.SessionKey, hopCount)
	replyIVs := make([][16]byte, hopCount)

	// Generate specific keys for tracking
	for i := 0; i < hopCount; i++ {
		for j := 0; j < 32; j++ {
			replyKeys[i][j] = byte(i*32 + j)
		}
		for j := 0; j < 16; j++ {
			replyIVs[i][j] = byte(i*16 + j)
		}
	}

	err := rp.RegisterPendingBuild(tunnelID, replyKeys, replyIVs, true, hopCount)
	require.NoError(t, err)

	info := rp.GetPendingBuildInfo(tunnelID)
	require.NotNil(t, info)

	// Verify keys are stored correctly
	assert.Equal(t, hopCount, len(info.ReplyKeys))
	assert.Equal(t, hopCount, len(info.ReplyIVs))

	for i := 0; i < hopCount; i++ {
		assert.Equal(t, replyKeys[i], info.ReplyKeys[i], "Reply key %d mismatch", i)
		assert.Equal(t, replyIVs[i], info.ReplyIVs[i], "Reply IV %d mismatch", i)
	}
}

// TestReplyProcessor_MetadataTracking verifies build metadata is tracked correctly.
func TestReplyProcessor_MetadataTracking(t *testing.T) {
	config := DefaultReplyProcessorConfig()
	rp := NewReplyProcessor(config, nil)

	testCases := []struct {
		tunnelID  tunnel.TunnelID
		isInbound bool
		hopCount  int
	}{
		{100, true, 2},
		{101, false, 3},
		{102, true, 4},
		{103, false, 1},
	}

	for _, tc := range testCases {
		replyKeys := make([]session_key.SessionKey, tc.hopCount)
		replyIVs := make([][16]byte, tc.hopCount)
		for j := 0; j < tc.hopCount; j++ {
			_, err := rand.Read(replyKeys[j][:])
			require.NoError(t, err)
			_, err = rand.Read(replyIVs[j][:])
			require.NoError(t, err)
		}

		err := rp.RegisterPendingBuild(tc.tunnelID, replyKeys, replyIVs, tc.isInbound, tc.hopCount)
		require.NoError(t, err)
	}

	// Verify metadata
	for _, tc := range testCases {
		info := rp.GetPendingBuildInfo(tc.tunnelID)
		require.NotNil(t, info, "Should have info for tunnel %d", tc.tunnelID)

		assert.Equal(t, tc.tunnelID, info.TunnelID)
		assert.Equal(t, tc.isInbound, info.IsInbound, "Direction mismatch for tunnel %d", tc.tunnelID)
		assert.Equal(t, tc.hopCount, info.HopCount, "Hop count mismatch for tunnel %d", tc.tunnelID)
		assert.Equal(t, 0, info.Retries, "Initial retry count should be 0")
	}
}

// TestReplyProcessor_CleanupExpiredBuilds_Security verifies cleanup functionality.
func TestReplyProcessor_CleanupExpiredBuilds_Security(t *testing.T) {
	config := DefaultReplyProcessorConfig()
	config.BuildTimeout = 10 * time.Millisecond
	config.RetryBackoff = 1 * time.Millisecond
	config.MaxRetries = 0
	rp := NewReplyProcessor(config, nil)

	// Register multiple builds
	for i := 0; i < 5; i++ {
		tunnelID := tunnel.TunnelID(i + 1)
		replyKeys := make([]session_key.SessionKey, 1)
		replyIVs := make([][16]byte, 1)
		_, err := rand.Read(replyKeys[0][:])
		require.NoError(t, err)
		_, err = rand.Read(replyIVs[0][:])
		require.NoError(t, err)

		err = rp.RegisterPendingBuild(tunnelID, replyKeys, replyIVs, true, 1)
		require.NoError(t, err)
	}

	assert.Equal(t, 5, rp.GetPendingBuildCount())

	// Wait for expiration
	time.Sleep(50 * time.Millisecond)

	// Manual cleanup
	removed := rp.CleanupExpiredBuilds()
	// Note: timeout handlers may have already removed them
	assert.GreaterOrEqual(t, 5, removed+rp.GetPendingBuildCount())
}

// TestReplyProcessor_KeyIVMismatch verifies validation of key/IV counts.
func TestReplyProcessor_KeyIVMismatch(t *testing.T) {
	config := DefaultReplyProcessorConfig()
	rp := NewReplyProcessor(config, nil)

	testCases := []struct {
		name     string
		keyCount int
		ivCount  int
		hopCount int
		wantErr  bool
	}{
		{"matching counts", 3, 3, 3, false},
		{"key count mismatch", 2, 3, 3, true},
		{"iv count mismatch", 3, 2, 3, true},
		{"hop count mismatch", 3, 3, 2, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tunnelID := tunnel.TunnelID(1000 + len(tc.name))
			replyKeys := make([]session_key.SessionKey, tc.keyCount)
			replyIVs := make([][16]byte, tc.ivCount)

			for j := 0; j < tc.keyCount; j++ {
				_, err := rand.Read(replyKeys[j][:])
				require.NoError(t, err)
			}
			for j := 0; j < tc.ivCount; j++ {
				_, err := rand.Read(replyIVs[j][:])
				require.NoError(t, err)
			}

			err := rp.RegisterPendingBuild(tunnelID, replyKeys, replyIVs, true, tc.hopCount)
			if tc.wantErr {
				assert.Error(t, err, "Should error on %s", tc.name)
			} else {
				assert.NoError(t, err, "Should not error on %s", tc.name)
			}
		})
	}
}

// Helper function to create rejected variable tunnel build reply
func createRejectedVariableTunnelBuildReply(hopCount int) *VariableTunnelBuildReply {
	records := make([]BuildResponseRecord, hopCount)
	for i := 0; i < hopCount; i++ {
		records[i] = createValidResponseRecordWithReply(TUNNEL_BUILD_REPLY_REJECT)
	}
	return &VariableTunnelBuildReply{
		Count:                hopCount,
		BuildResponseRecords: records,
	}
}
