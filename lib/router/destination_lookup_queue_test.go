package router

import (
	"sync"
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/lease_set"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockLeaseSetNetDB simulates a NetDB with delayed LeaseSet availability
type mockLeaseSetNetDB struct {
	leaseSets    map[common.Hash]lease_set.LeaseSet
	availability map[common.Hash]time.Time // When each LeaseSet becomes available
	mutex        sync.RWMutex
}

func newMockLeaseSetNetDB() *mockLeaseSetNetDB {
	return &mockLeaseSetNetDB{
		leaseSets:    make(map[common.Hash]lease_set.LeaseSet),
		availability: make(map[common.Hash]time.Time),
	}
}

func (m *mockLeaseSetNetDB) GetRouterInfo(hash common.Hash) chan router_info.RouterInfo {
	return nil
}

func (m *mockLeaseSetNetDB) GetLeaseSet(hash common.Hash) chan lease_set.LeaseSet {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	// Check if LeaseSet will be available
	availableAt, hasSchedule := m.availability[hash]
	ls, exists := m.leaseSets[hash]

	// If not scheduled or doesn't exist, return nil
	if !exists || (!hasSchedule && !exists) {
		return nil
	}

	// If scheduled but not yet available, return nil
	if hasSchedule && time.Now().Before(availableAt) {
		return nil
	}

	// LeaseSet is available
	ch := make(chan lease_set.LeaseSet, 1)
	ch <- ls
	close(ch)
	return ch
}

func (m *mockLeaseSetNetDB) StoreRouterInfo(ri router_info.RouterInfo) {}

func (m *mockLeaseSetNetDB) Size() int {
	return 0
}

func (m *mockLeaseSetNetDB) SelectFloodfillRouters(targetHash common.Hash, count int) ([]router_info.RouterInfo, error) {
	return nil, nil
}

// addLeaseSet adds a LeaseSet that's immediately available
func (m *mockLeaseSetNetDB) addLeaseSet(hash common.Hash, ls lease_set.LeaseSet) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.leaseSets[hash] = ls
}

// createTestLeaseSet creates a minimal LeaseSet for testing.
// Since we're testing the queue logic, not LeaseSet functionality,
// we use a simple empty LeaseSet.
func createTestLeaseSet() lease_set.LeaseSet {
	return lease_set.LeaseSet{}
}

// createTestMessage creates a simple test message
func createTestMessage() i2np.I2NPMessage {
	return i2np.NewDataMessage([]byte("test payload"))
}

// TestQueuePendingMessage_Success tests successful message queueing
func TestQueuePendingMessage_Success(t *testing.T) {
	netdb := newMockLeaseSetNetDB()
	router := NewGarlicMessageRouter(netdb, nil, nil, common.Hash{})
	defer router.Stop()

	destHash := common.Hash{0x01, 0x02, 0x03}
	msg := createTestMessage()

	err := router.queuePendingMessage(destHash, msg)
	require.NoError(t, err)

	router.pendingMutex.RLock()
	pending := router.pendingMsgs[destHash]
	router.pendingMutex.RUnlock()

	assert.Len(t, pending, 1)
	assert.Equal(t, msg, pending[0].msg)
}

// TestQueuePendingMessage_MaxLimit tests queue size limit
func TestQueuePendingMessage_MaxLimit(t *testing.T) {
	netdb := newMockLeaseSetNetDB()
	router := NewGarlicMessageRouter(netdb, nil, nil, common.Hash{})
	defer router.Stop()

	destHash := common.Hash{0x01, 0x02, 0x03}

	// Queue up to the limit
	for i := 0; i < maxPendingMessages; i++ {
		msg := createTestMessage()
		err := router.queuePendingMessage(destHash, msg)
		require.NoError(t, err)
	}

	// Next message should fail
	msg := createTestMessage()
	err := router.queuePendingMessage(destHash, msg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too many pending messages")
}

// TestForwardToDestination_NotFound_QueuesMessage tests async queueing when LeaseSet not found
func TestForwardToDestination_NotFound_QueuesMessage(t *testing.T) {
	netdb := newMockLeaseSetNetDB()
	router := NewGarlicMessageRouter(netdb, nil, nil, common.Hash{})
	defer router.Stop()

	destHash := common.Hash{0x01, 0x02, 0x03}
	msg := createTestMessage()

	// LeaseSet not in NetDB, should queue message
	err := router.ForwardToDestination(destHash, msg)
	require.NoError(t, err)

	// Verify message was queued
	router.pendingMutex.RLock()
	pending := router.pendingMsgs[destHash]
	router.pendingMutex.RUnlock()

	assert.Len(t, pending, 1)
}

// TestProcessPendingMessages_LeaseSetBecomesAvailable tests message processing when LeaseSet arrives
func TestProcessPendingMessages_LeaseSetBecomesAvailable(t *testing.T) {
	netdb := newMockLeaseSetNetDB()
	router := NewGarlicMessageRouter(netdb, nil, nil, common.Hash{})
	defer router.Stop()

	destHash := common.Hash{0x01, 0x02, 0x03}
	msg := createTestMessage()

	// Queue a message for a destination without LeaseSet
	err := router.queuePendingMessage(destHash, msg)
	require.NoError(t, err)

	// Make LeaseSet available
	ls := createTestLeaseSet()
	netdb.addLeaseSet(destHash, ls)

	// Manually trigger retry (simulate background processor)
	router.retryPendingLookups()

	// Verify queue is cleared (messages processed/cleaned up)
	router.pendingMutex.RLock()
	pending := router.pendingMsgs[destHash]
	router.pendingMutex.RUnlock()

	assert.Len(t, pending, 0, "Pending messages should be cleared after processing")
}

// TestCleanupExpiredMessages tests expiration of old queued messages
func TestCleanupExpiredMessages(t *testing.T) {
	netdb := newMockLeaseSetNetDB()
	router := NewGarlicMessageRouter(netdb, nil, nil, common.Hash{})
	defer router.Stop()

	destHash := common.Hash{0x01, 0x02, 0x03}

	// Manually add an expired message
	expiredMsg := pendingMessage{
		msg:      createTestMessage(),
		queuedAt: time.Now().Add(-pendingMessageTimeout - time.Second),
		attempts: 1,
	}

	// Add a fresh message
	freshMsg := pendingMessage{
		msg:      createTestMessage(),
		queuedAt: time.Now(),
		attempts: 1,
	}

	router.pendingMutex.Lock()
	router.pendingMsgs[destHash] = []pendingMessage{expiredMsg, freshMsg}
	router.pendingMutex.Unlock()

	// Trigger cleanup
	router.pendingMutex.Lock()
	router.cleanupExpiredMessages(destHash, router.pendingMsgs[destHash], time.Now())
	router.pendingMutex.Unlock()

	// Verify only fresh message remains
	router.pendingMutex.RLock()
	pending := router.pendingMsgs[destHash]
	router.pendingMutex.RUnlock()

	assert.Len(t, pending, 1)
}

// TestCleanupExpiredMessages_AllExpired tests cleanup when all messages expire
func TestCleanupExpiredMessages_AllExpired(t *testing.T) {
	netdb := newMockLeaseSetNetDB()
	router := NewGarlicMessageRouter(netdb, nil, nil, common.Hash{})
	defer router.Stop()

	destHash := common.Hash{0x01, 0x02, 0x03}

	// Add only expired messages
	expiredMsg1 := pendingMessage{
		msg:      createTestMessage(),
		queuedAt: time.Now().Add(-pendingMessageTimeout - time.Second),
		attempts: 1,
	}
	expiredMsg2 := pendingMessage{
		msg:      createTestMessage(),
		queuedAt: time.Now().Add(-pendingMessageTimeout - 2*time.Second),
		attempts: 1,
	}

	router.pendingMutex.Lock()
	router.pendingMsgs[destHash] = []pendingMessage{expiredMsg1, expiredMsg2}
	router.pendingMutex.Unlock()

	// Trigger cleanup
	router.pendingMutex.Lock()
	router.cleanupExpiredMessages(destHash, router.pendingMsgs[destHash], time.Now())
	router.pendingMutex.Unlock()

	// Verify destination removed from map
	router.pendingMutex.RLock()
	_, exists := router.pendingMsgs[destHash]
	router.pendingMutex.RUnlock()

	assert.False(t, exists, "Destination with all expired messages should be removed")
}

// TestStop_GracefulShutdown tests graceful shutdown
func TestStop_GracefulShutdown(t *testing.T) {
	netdb := newMockLeaseSetNetDB()
	router := NewGarlicMessageRouter(netdb, nil, nil, common.Hash{})

	// Queue a message
	destHash := common.Hash{0x01, 0x02, 0x03}
	msg := createTestMessage()
	err := router.queuePendingMessage(destHash, msg)
	require.NoError(t, err)

	// Stop the router
	router.Stop()

	// Verify context is cancelled
	select {
	case <-router.ctx.Done():
		// Expected
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Context should be cancelled after Stop()")
	}
}

// TestProcessPendingMessages_MultipleMessages tests processing multiple queued messages
func TestProcessPendingMessages_MultipleMessages(t *testing.T) {
	netdb := newMockLeaseSetNetDB()
	router := NewGarlicMessageRouter(netdb, nil, nil, common.Hash{})
	defer router.Stop()

	destHash := common.Hash{0x01, 0x02, 0x03}

	// Queue multiple messages
	for i := 0; i < 5; i++ {
		msg := createTestMessage()
		err := router.queuePendingMessage(destHash, msg)
		require.NoError(t, err)
	}

	// Make LeaseSet available
	ls := createTestLeaseSet()
	netdb.addLeaseSet(destHash, ls)

	// Process pending messages
	router.retryPendingLookups()

	// Verify all messages processed
	router.pendingMutex.RLock()
	pending := router.pendingMsgs[destHash]
	router.pendingMutex.RUnlock()

	assert.Len(t, pending, 0, "All pending messages should be processed")
}

// TestRetryPendingLookups_EmptyQueue tests retry with empty queue
func TestRetryPendingLookups_EmptyQueue(t *testing.T) {
	netdb := newMockLeaseSetNetDB()
	router := NewGarlicMessageRouter(netdb, nil, nil, common.Hash{})
	defer router.Stop()

	// Should not panic with empty queue
	router.retryPendingLookups()
	assert.True(t, true, "retryPendingLookups should handle empty queue")
}

// BenchmarkQueuePendingMessage benchmarks message queueing
func BenchmarkQueuePendingMessage(b *testing.B) {
	netdb := newMockLeaseSetNetDB()
	router := NewGarlicMessageRouter(netdb, nil, nil, common.Hash{})
	defer router.Stop()

	destHash := common.Hash{0x01, 0x02, 0x03}
	msg := createTestMessage()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Clear queue periodically to avoid hitting limit
		if i%50 == 0 {
			router.pendingMutex.Lock()
			router.pendingMsgs[destHash] = nil
			router.pendingMutex.Unlock()
		}
		_ = router.queuePendingMessage(destHash, msg)
	}
}

// BenchmarkRetryPendingLookups benchmarks the retry mechanism
func BenchmarkRetryPendingLookups(b *testing.B) {
	netdb := newMockLeaseSetNetDB()
	router := NewGarlicMessageRouter(netdb, nil, nil, common.Hash{})
	defer router.Stop()

	// Pre-populate with pending messages
	for i := 0; i < 10; i++ {
		destHash := common.Hash{byte(i), 0x02, 0x03}
		msg := createTestMessage()
		_ = router.queuePendingMessage(destHash, msg)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		router.retryPendingLookups()
	}
}
