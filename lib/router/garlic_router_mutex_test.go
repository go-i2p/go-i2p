package router

import (
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/lease_set"
	"github.com/go-i2p/common/router_info"
)

// panickingNetDB is a GarlicNetDB whose GetLeaseSet panics, simulating a panic
// in the remote-LeaseSet parse/decrypt path (buildForwardWork) that runs while
// pendingMutex is held.
type panickingNetDB struct {
	panicOnGetLeaseSet bool
}

func (p *panickingNetDB) GetRouterInfo(hash common.Hash) chan router_info.RouterInfo {
	ch := make(chan router_info.RouterInfo, 1)
	close(ch)
	return ch
}

func (p *panickingNetDB) GetLeaseSet(hash common.Hash) chan lease_set.LeaseSet {
	if p.panicOnGetLeaseSet {
		panic("simulated panic parsing remote LeaseSet")
	}
	ch := make(chan lease_set.LeaseSet, 1)
	close(ch)
	return ch
}

func (p *panickingNetDB) StoreRouterInfo(ri router_info.RouterInfo) {}
func (p *panickingNetDB) Size() int                                 { return 0 }
func (p *panickingNetDB) SelectFloodfillRouters(targetHash common.Hash, count int) ([]router_info.RouterInfo, error) {
	return nil, nil
}

// TestRetryPendingLookups_ReleasesMutexOnPanic proves the I2P-B-2 fix: when a
// panic occurs inside the locked phase of retryPendingLookups (parsing a remote
// LeaseSet), the recover seam must still release pendingMutex. Before the fix
// the unlock was not deferred, so one recovered panic left the mutex permanently
// held and wedged the pending-message processor forever — every subsequent tick
// and every queuePendingMessage caller blocked on it.
func TestRetryPendingLookups_ReleasesMutexOnPanic(t *testing.T) {
	gr := NewGarlicMessageRouter(&panickingNetDB{panicOnGetLeaseSet: true}, nil, nil, common.Hash{1, 2, 3, 4})

	// Seed one pending destination so the locked loop reaches GetLeaseSet and panics.
	destHash := common.Hash{0xAA, 0xBB, 0xCC}
	gr.pendingMsgs[destHash] = []pendingMessage{{queuedAt: time.Now(), retryAt: time.Now()}}

	// The guarded call recovers the panic instead of crashing.
	gr.retryPendingLookupsSafe()

	// The critical assertion: after the recovered panic, pendingMutex must be
	// free. TryLock returns false if the mutex is still held (the wedge).
	if !gr.pendingMutex.TryLock() {
		t.Fatal("pendingMutex still held after a recovered panic — the pending-message processor is wedged (I2P-B-2)")
	}
	gr.pendingMutex.Unlock()
}

// TestRetryPendingLookups_KeepsProcessingAfterPanic proves the loop is not
// wedged: a second tick after a recovered panic still runs (does not deadlock).
func TestRetryPendingLookups_KeepsProcessingAfterPanic(t *testing.T) {
	gr := NewGarlicMessageRouter(&panickingNetDB{panicOnGetLeaseSet: true}, nil, nil, common.Hash{1, 2, 3, 4})
	destHash := common.Hash{0xAA, 0xBB, 0xCC}
	gr.pendingMsgs[destHash] = []pendingMessage{{queuedAt: time.Now(), retryAt: time.Now()}}

	done := make(chan struct{})
	go func() {
		defer close(done)
		// Two ticks: the first panics and is recovered; the second must still
		// acquire the mutex and run rather than blocking forever.
		gr.retryPendingLookupsSafe()
		gr.retryPendingLookupsSafe()
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("second retryPendingLookupsSafe tick blocked — mutex was not released after the first panic (I2P-B-2)")
	}
}
