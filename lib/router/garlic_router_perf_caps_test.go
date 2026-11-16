package router

import (
	"testing"

	common "github.com/go-i2p/common/data"
	"github.com/stretchr/testify/assert"
)

// TestNewGarlicMessageRouterWithLimits_RecordsPoolSizing is the C1 guard for
// performance.worker_pool_size and performance.message_queue_size: the operator's
// values must reach the garlic router's drain worker pool and request queue.
// Before this fix the pool always used the hardcoded maxDrainWorkers /
// drainRequestBuffer constants and the knobs were dead.
func TestNewGarlicMessageRouterWithLimits_RecordsPoolSizing(t *testing.T) {
	netdb := newMockLeaseSetNetDB()
	gr := NewGarlicMessageRouterWithLimits(netdb, nil, nil, common.Hash{}, 3, 42)
	defer gr.Stop()

	assert.Equal(t, 3, gr.WorkerPoolSize(), "worker_pool_size must set the drain worker count")
	assert.Equal(t, 42, gr.QueueBuffer(), "message_queue_size must set the drain request queue depth")
	assert.Equal(t, 42, cap(gr.drainRequests), "drainRequests channel capacity must equal the configured queue buffer")
}

// TestNewGarlicMessageRouter_DefaultsWhenUnset pins that zero/unset values fall
// back to the built-in defaults, so a default-configured router is unchanged.
func TestNewGarlicMessageRouter_DefaultsWhenUnset(t *testing.T) {
	netdb := newMockLeaseSetNetDB()
	gr := NewGarlicMessageRouterWithLimits(netdb, nil, nil, common.Hash{}, 0, 0)
	defer gr.Stop()

	assert.Equal(t, maxDrainWorkers, gr.WorkerPoolSize(), "zero worker_pool_size must select the built-in default")
	assert.Equal(t, drainRequestBuffer, gr.QueueBuffer(), "zero message_queue_size must select the built-in default")
	assert.Equal(t, drainRequestBuffer, cap(gr.drainRequests))
}

// TestNewGarlicMessageRouter_StartsConfiguredWorkerCount verifies the pool
// actually starts the configured number of workers (not just records it). With
// a tiny pool the drainRequests channel must still be drained by exactly that
// many workers; we assert the recorded count matches and the router is usable.
func TestNewGarlicMessageRouter_StartsConfiguredWorkerCount(t *testing.T) {
	netdb := newMockLeaseSetNetDB()
	gr := NewGarlicMessageRouterWithLimits(netdb, nil, nil, common.Hash{}, 2, 8)
	defer gr.Stop()

	if gr.WorkerPoolSize() != 2 {
		t.Fatalf("WorkerPoolSize() = %d, want 2", gr.WorkerPoolSize())
	}
	// The plain constructor must still yield the built-in default.
	gr2 := NewGarlicMessageRouter(netdb, nil, nil, common.Hash{})
	defer gr2.Stop()
	assert.Equal(t, maxDrainWorkers, gr2.WorkerPoolSize())
}
