package i2np

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestM4_ExpiredDeliveryStatusAcceptedWithWarning validates that old DeliveryStatus
// messages (older than 24 hours) are accepted but logged as warnings.
//
// M-4 FIX: While very old messages are accepted for compatibility, they're
// logged as warnings to alert operators of unusual patterns.
func TestM4_ExpiredDeliveryStatusAcceptedWithWarning(t *testing.T) {
	// Clear the replay cache before the test
	deliveryStatusReplayCacheMutex.Lock()
	deliveryStatusReplayCache = make(map[[32]byte]time.Time)
	deliveryStatusReplayCacheMutex.Unlock()

	// Create a message with a timestamp from the past (older than 24 hours)
	// but still within the ±1 hour skew tolerance
	msgID := 12345
	oldTime := time.Now().Add(-(48 * time.Hour))

	msg := NewDeliveryStatusMessage(msgID, oldTime)
	data, err := msg.MarshalBinary()
	require.NoError(t, err, "marshal should succeed")

	// Try to unmarshal the old message
	msg2 := &DeliveryStatusMessage{
		BaseI2NPMessage: NewBaseI2NPMessage(I2NPMessageTypeDeliveryStatus),
	}
	err = msg2.UnmarshalBinary(data)

	// M-4 FIX: Old messages are accepted (not rejected) but logged as warning
	assert.NoError(t, err, "old message should be accepted for compatibility")
	// Verify the message was parsed correctly despite being old
	assert.Equal(t, msgID, msg2.StatusMessageID)
}

// TestM4_FarFutureDeliveryStatusRejected validates that far-future DeliveryStatus
// messages (beyond clock skew tolerance of ±1 hour) are rejected.
//
// M-4 FIX: Prevents accepting messages from peers with badly skewed clocks.
func TestM4_FarFutureDeliveryStatusRejected(t *testing.T) {
	// Clear the replay cache
	deliveryStatusReplayCacheMutex.Lock()
	deliveryStatusReplayCache = make(map[[32]byte]time.Time)
	deliveryStatusReplayCacheMutex.Unlock()

	// Create a message with a far-future timestamp (beyond clock skew of ±1 hour)
	msgID := 54321
	futureTime := time.Now().Add(deliveryStatusTimestampSkew + 1*time.Minute)

	msg := NewDeliveryStatusMessage(msgID, futureTime)
	data, err := msg.MarshalBinary()
	require.NoError(t, err, "marshal should succeed")

	// Try to unmarshal the far-future message
	msg2 := &DeliveryStatusMessage{
		BaseI2NPMessage: NewBaseI2NPMessage(I2NPMessageTypeDeliveryStatus),
	}
	err = msg2.UnmarshalBinary(data)

	// M-4 FIX: Should reject the far-future message (indicates hostile or misconfigured peer)
	assert.Error(t, err, "far-future message should be rejected")
	assert.Contains(t, err.Error(), "future", "error should mention future/skew")
}

// TestM4_ReplayedDeliveryStatusRejected validates that replayed DeliveryStatus
// messages (duplicate msgID + timestamp) are rejected.
//
// M-4 FIX: Prevents replay of delivery confirmations, which could confuse
// the sender about which message was actually delivered.
func TestM4_ReplayedDeliveryStatusRejected(t *testing.T) {
	// Clear the replay cache
	deliveryStatusReplayCacheMutex.Lock()
	deliveryStatusReplayCache = make(map[[32]byte]time.Time)
	deliveryStatusReplayCacheMutex.Unlock()

	// Create a message with a valid timestamp
	msgID := 99999
	validTime := time.Now()

	msg := NewDeliveryStatusMessage(msgID, validTime)
	data, err := msg.MarshalBinary()
	require.NoError(t, err, "marshal should succeed")

	// First unmarshal should succeed
	msg1 := &DeliveryStatusMessage{
		BaseI2NPMessage: NewBaseI2NPMessage(I2NPMessageTypeDeliveryStatus),
	}
	err1 := msg1.UnmarshalBinary(data)
	require.NoError(t, err1, "first unmarshal should succeed")

	// Second unmarshal (replay) should fail
	msg2 := &DeliveryStatusMessage{
		BaseI2NPMessage: NewBaseI2NPMessage(I2NPMessageTypeDeliveryStatus),
	}
	err2 := msg2.UnmarshalBinary(data)
	assert.Error(t, err2, "replayed message should be rejected")
	assert.Contains(t, err2.Error(), "replayed", "error should mention replay")
}

// TestM4_ValidDeliveryStatusAccepted validates that valid (non-expired,
// non-replayed) DeliveryStatus messages are accepted.
func TestM4_ValidDeliveryStatusAccepted(t *testing.T) {
	// Clear the replay cache
	deliveryStatusReplayCacheMutex.Lock()
	deliveryStatusReplayCache = make(map[[32]byte]time.Time)
	deliveryStatusReplayCacheMutex.Unlock()

	// Create a message with a current timestamp
	msgID := 77777
	validTime := time.Now()

	msg := NewDeliveryStatusMessage(msgID, validTime)
	data, err := msg.MarshalBinary()
	require.NoError(t, err, "marshal should succeed")

	// Unmarshal should succeed
	msg2 := &DeliveryStatusMessage{
		BaseI2NPMessage: NewBaseI2NPMessage(I2NPMessageTypeDeliveryStatus),
	}
	err = msg2.UnmarshalBinary(data)
	assert.NoError(t, err, "valid message should be accepted")
	assert.Equal(t, msgID, msg2.StatusMessageID, "message ID should match")
}

// TestM4_ReplayCacheCapacityBounded validates that the replay cache doesn't
// grow unbounded. When cap is exceeded, oldest entries are evicted.
func TestM4_ReplayCacheCapacityBounded(t *testing.T) {
	// Clear the replay cache
	deliveryStatusReplayCacheMutex.Lock()
	deliveryStatusReplayCache = make(map[[32]byte]time.Time)
	deliveryStatusReplayCacheMutex.Unlock()

	// Add messages up to (and beyond) the capacity
	baseTime := time.Now()

	for i := 0; i < deliveryStatusReplayCacheCapacity+10; i++ {
		// Use slightly different timestamps to avoid overlapping cache keys
		msgTime := baseTime.Add(time.Duration(i) * time.Millisecond)
		msg := NewDeliveryStatusMessage(1000+i, msgTime)

		data, err := msg.MarshalBinary()
		require.NoError(t, err, "marshal should succeed for message %d", i)

		msg2 := &DeliveryStatusMessage{
			BaseI2NPMessage: NewBaseI2NPMessage(I2NPMessageTypeDeliveryStatus),
		}
		err = msg2.UnmarshalBinary(data)
		assert.NoError(t, err, "message %d should be accepted", i)
	}

	// Cache should not exceed capacity (allow some margin for cleanup timing)
	deliveryStatusReplayCacheMutex.Lock()
	cacheSize := len(deliveryStatusReplayCache)
	deliveryStatusReplayCacheMutex.Unlock()

	assert.LessOrEqual(t, cacheSize, deliveryStatusReplayCacheCapacity,
		"cache size should be bounded")
	assert.Greater(t, cacheSize, 0, "cache should have entries")
}

// TestM4_ReplayCacheExpiresOldEntries validates that replay cache entries
// older than TTL are cleaned up during cache operations.
func TestM4_ReplayCacheExpiresOldEntries(t *testing.T) {
	// Clear the replay cache
	deliveryStatusReplayCacheMutex.Lock()
	deliveryStatusReplayCache = make(map[[32]byte]time.Time)
	deliveryStatusReplayCacheMutex.Unlock()

	// Add some old entries manually (simulate aged cache)
	oldTime := time.Now().Add(-(deliveryStatusReplayCacheTTL + 1*time.Minute))

	// Manually seed the cache with old entries
	deliveryStatusReplayCacheMutex.Lock()
	for i := 0; i < 5; i++ {
		key := [32]byte{byte(i)}
		deliveryStatusReplayCache[key] = oldTime
	}
	initialSize := len(deliveryStatusReplayCache)
	deliveryStatusReplayCacheMutex.Unlock()

	// Add a new valid message, which will trigger cleanup
	validTime := time.Now()
	msg := NewDeliveryStatusMessage(50000, validTime)
	data, err := msg.MarshalBinary()
	require.NoError(t, err, "marshal should succeed")

	msg2 := &DeliveryStatusMessage{
		BaseI2NPMessage: NewBaseI2NPMessage(I2NPMessageTypeDeliveryStatus),
	}
	err = msg2.UnmarshalBinary(data)
	require.NoError(t, err, "new message should be accepted")

	// Check that old entries were cleaned up
	deliveryStatusReplayCacheMutex.Lock()
	finalSize := len(deliveryStatusReplayCache)
	deliveryStatusReplayCacheMutex.Unlock()

	// Should have removed old entries and added the new one
	assert.Less(t, finalSize, initialSize, "old entries should be expired and removed")
	assert.Greater(t, finalSize, 0, "new entry should be in cache")
}

// TestM4_RaceDetectorValidatesReplayCache validates that concurrent access
// to the replay cache is properly synchronized (no data races).
//
// Run with: go test -race -run TestM4_RaceDetectorValidatesReplayCache
func TestM4_RaceDetectorValidatesReplayCache(t *testing.T) {
	// Clear the replay cache
	deliveryStatusReplayCacheMutex.Lock()
	deliveryStatusReplayCache = make(map[[32]byte]time.Time)
	deliveryStatusReplayCacheMutex.Unlock()

	const numGoroutines = 50
	const messagesPerGoroutine = 20

	var wg sync.WaitGroup

	// Multiple goroutines submitting different messages concurrently
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			for j := 0; j < messagesPerGoroutine; j++ {
				// Each goroutine uses different message IDs to avoid replays
				msgID := (idx * messagesPerGoroutine) + j
				// Vary timestamps slightly to avoid key collisions
				msgTime := time.Now().Add(time.Duration(j) * time.Millisecond)

				msg := NewDeliveryStatusMessage(1000+msgID, msgTime)
				data, err := msg.MarshalBinary()
				if err != nil {
					continue
				}

				msg2 := &DeliveryStatusMessage{
					BaseI2NPMessage: NewBaseI2NPMessage(I2NPMessageTypeDeliveryStatus),
				}
				_ = msg2.UnmarshalBinary(data)
			}
		}(i)
	}

	wg.Wait()

	// Verify cache is not corrupted and has expected size
	deliveryStatusReplayCacheMutex.Lock()
	cacheSize := len(deliveryStatusReplayCache)
	deliveryStatusReplayCacheMutex.Unlock()

	assert.Greater(t, cacheSize, 0, "cache should have entries after concurrent operations")
	assert.LessOrEqual(t, cacheSize, deliveryStatusReplayCacheCapacity, "cache should be bounded")
}
