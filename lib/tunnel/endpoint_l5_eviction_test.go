package tunnel

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestEvictionPrioritizesByCompleteness verifies that L-5 eviction policy
// prioritizes incomplete assemblies over complete ones.
func TestEvictionPrioritizesByCompleteness(t *testing.T) {
	t.Parallel()

	// Create mock tunnel components for Endpoint construction
	decryption := &mockTunnelEncryptor{}
	handler := func(msgBytes []byte) error { return nil }

	endpoint, err := NewEndpoint(123, decryption, handler)
	assert.NoError(t, err, "NewEndpoint should not error")
	defer endpoint.Stop()

	// Manually populate fragments with specific completeness states
	endpoint.fragmentsMutex.Lock()
	defer endpoint.fragmentsMutex.Unlock()

	// Complete assembly (100% - all fragments received)
	completeAsm := &fragmentAssembler{
		fragments:    make(map[int][]byte),
		deliveryType: DTLocal,
		totalCount:   3,
		receivedMask: 0b111, // All 3 fragments received: bits 0,1,2
		createdAt:    time.Now(),
	}
	endpoint.fragments[1001] = completeAsm

	// Partially complete assembly (33% - 1 of 3 fragments)
	partialAsm := &fragmentAssembler{
		fragments:    make(map[int][]byte),
		deliveryType: DTLocal,
		totalCount:   3,
		receivedMask: 0b001,                             // Only 1 fragment received: bit 0
		createdAt:    time.Now().Add(-10 * time.Second), // Older
	}
	endpoint.fragments[1002] = partialAsm

	// Incomplete assembly (0% - no fragments, no last fragment seen)
	incompleteAsm := &fragmentAssembler{
		fragments:    make(map[int][]byte),
		deliveryType: DTLocal,
		totalCount:   0,     // No last fragment seen yet
		receivedMask: 0b001, // Has fragment 0, but totalCount=0
		createdAt:    time.Now().Add(-5 * time.Second),
	}
	endpoint.fragments[1003] = incompleteAsm

	// Before eviction: 3 assemblies
	assert.Equal(t, 3, len(endpoint.fragments), "Should have 3 assemblies before eviction")

	// Trigger eviction
	endpoint.evictOldestFragment()

	// After eviction: 2 assemblies
	assert.Equal(t, 2, len(endpoint.fragments), "Should have 2 assemblies after eviction")

	// Verify that the INCOMPLETE assembly (1003) was evicted (0% complete)
	// NOT the partial (1002) or complete (1001)
	assert.Nil(t, endpoint.fragments[1003], "Incomplete assembly should be evicted")
	assert.NotNil(t, endpoint.fragments[1002], "Partial assembly should remain")
	assert.NotNil(t, endpoint.fragments[1001], "Complete assembly should remain")
}

// TestEvictionOldestAmongIncomplete verifies that among incomplete assemblies,
// the oldest one is evicted first (when completeness is equal).
func TestEvictionOldestAmongIncomplete(t *testing.T) {
	t.Parallel()

	decryption := &mockTunnelEncryptor{}
	handler := func(msgBytes []byte) error { return nil }

	endpoint, err := NewEndpoint(123, decryption, handler)
	assert.NoError(t, err, "NewEndpoint should not error")
	defer endpoint.Stop()

	endpoint.fragmentsMutex.Lock()
	defer endpoint.fragmentsMutex.Unlock()

	now := time.Now()

	// Two incomplete assemblies with same completeness (0%) but different ages
	incompleteOld := &fragmentAssembler{
		fragments:    make(map[int][]byte),
		deliveryType: DTLocal,
		totalCount:   0, // No last fragment seen
		receivedMask: 0b001,
		createdAt:    now.Add(-20 * time.Second), // Oldest
	}
	endpoint.fragments[2001] = incompleteOld

	incompleteNewer := &fragmentAssembler{
		fragments:    make(map[int][]byte),
		deliveryType: DTLocal,
		totalCount:   0, // No last fragment seen
		receivedMask: 0b001,
		createdAt:    now.Add(-10 * time.Second), // Newer
	}
	endpoint.fragments[2002] = incompleteNewer

	// Trigger eviction
	endpoint.evictOldestFragment()

	// Verify the oldest incomplete was evicted (2001)
	assert.Nil(t, endpoint.fragments[2001], "Oldest incomplete should be evicted")
	assert.NotNil(t, endpoint.fragments[2002], "Newer incomplete should remain")
}

// TestEvictionPreferLowerCompleteness verifies that among incomplete assemblies,
// the one with lowest completeness percentage is evicted first.
func TestEvictionPreferLowerCompleteness(t *testing.T) {
	t.Parallel()

	decryption := &mockTunnelEncryptor{}
	handler := func(msgBytes []byte) error { return nil }

	endpoint, err := NewEndpoint(123, decryption, handler)
	assert.NoError(t, err, "NewEndpoint should not error")
	defer endpoint.Stop()

	endpoint.fragmentsMutex.Lock()
	defer endpoint.fragmentsMutex.Unlock()

	now := time.Now()

	// Low completeness (0% - no last fragment seen yet)
	lowCompletion := &fragmentAssembler{
		fragments:    make(map[int][]byte),
		deliveryType: DTLocal,
		totalCount:   0, // No last fragment seen
		receivedMask: 0b001,
		createdAt:    now,
	}
	endpoint.fragments[3001] = lowCompletion

	// Higher completeness (33% - 1 of 3)
	mediumCompletion := &fragmentAssembler{
		fragments:    make(map[int][]byte),
		deliveryType: DTLocal,
		totalCount:   3,
		receivedMask: 0b001,                      // Only 1 of 3 fragments
		createdAt:    now.Add(-10 * time.Second), // Much older
	}
	endpoint.fragments[3002] = mediumCompletion

	// Trigger eviction
	endpoint.evictOldestFragment()

	// Verify the lower-completeness (0%) was evicted, even though mediumCompletion is much older
	assert.Nil(t, endpoint.fragments[3001], "0%% complete assembly should be evicted")
	assert.NotNil(t, endpoint.fragments[3002], "33%% complete assembly should remain (older age doesn't override lower completeness priority)")
}

// TestEvictionFallbackToOldestWhenAllComplete verifies behavior when all assemblies are complete.
func TestEvictionFallbackToOldestWhenAllComplete(t *testing.T) {
	t.Parallel()

	decryption := &mockTunnelEncryptor{}
	handler := func(msgBytes []byte) error { return nil }

	endpoint, err := NewEndpoint(123, decryption, handler)
	assert.NoError(t, err, "NewEndpoint should not error")
	defer endpoint.Stop()

	endpoint.fragmentsMutex.Lock()
	defer endpoint.fragmentsMutex.Unlock()

	now := time.Now()

	// Two complete assemblies (100% each)
	completeOld := &fragmentAssembler{
		fragments:    make(map[int][]byte),
		deliveryType: DTLocal,
		totalCount:   2,
		receivedMask: 0b11, // All 2 fragments received
		createdAt:    now.Add(-20 * time.Second),
	}
	endpoint.fragments[4001] = completeOld

	completeNewer := &fragmentAssembler{
		fragments:    make(map[int][]byte),
		deliveryType: DTLocal,
		totalCount:   2,
		receivedMask: 0b11, // All 2 fragments received
		createdAt:    now,
	}
	endpoint.fragments[4002] = completeNewer

	// Trigger eviction
	endpoint.evictOldestFragment()

	// When all are complete (100%), fall back to oldest-first
	assert.Nil(t, endpoint.fragments[4001], "Oldest complete assembly should be evicted")
	assert.NotNil(t, endpoint.fragments[4002], "Newer complete assembly should remain")
}

// TestEvictionUnderLoad simulates a flood scenario where incomplete assemblies
// are deliberately sent to verify they get evicted before nearly-complete ones.
func TestEvictionUnderLoad(t *testing.T) {
	t.Parallel()

	decryption := &mockTunnelEncryptor{}
	handler := func(msgBytes []byte) error { return nil }

	endpoint, err := NewEndpoint(123, decryption, handler)
	assert.NoError(t, err, "NewEndpoint should not error")
	defer endpoint.Stop()

	endpoint.fragmentsMutex.Lock()
	defer endpoint.fragmentsMutex.Unlock()

	now := time.Now()

	// Create a legitimate complete assembly (100% - all 64 fragments for max supported)
	legitimateAsm := &fragmentAssembler{
		fragments:    make(map[int][]byte),
		deliveryType: DTLocal,
		totalCount:   64,
		receivedMask: ^uint64(0),                 // All 64 bits set (100% complete, max by uint64)
		createdAt:    now.Add(-30 * time.Second), // Old, created first
	}
	endpoint.fragments[5001] = legitimateAsm

	// Create flood of incomplete assemblies (just now, 0% complete)
	for i := 0; i < 5; i++ {
		incompleteFlood := &fragmentAssembler{
			fragments:    make(map[int][]byte),
			deliveryType: DTLocal,
			totalCount:   0, // No last fragment yet (0%)
			receivedMask: 0,
			createdAt:    now, // All created at same time
		}
		endpoint.fragments[uint32(6000+i)] = incompleteFlood
	}

	// Before eviction: 1 legitimate + 5 flood = 6
	assert.Equal(t, 6, len(endpoint.fragments), "Should have 6 assemblies")

	// Trigger 5 evictions to make room
	for j := 0; j < 5; j++ {
		endpoint.evictOldestFragment()
	}

	// After evictions: only legitimate should remain
	assert.Equal(t, 1, len(endpoint.fragments), "Should have only 1 assembly left")
	assert.NotNil(t, endpoint.fragments[5001], "Legitimate complete assembly should survive")
}
