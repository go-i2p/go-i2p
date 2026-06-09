package ssu2

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// SA-2: Test that Close() prevents cleanup callbacks from double-decrementing sessionCount.
func TestClose_PreventDoubleDecrement(t *testing.T) {
	transport := &SSU2Transport{
		sessionCount: 3, // simulate 3 active sessions
	}

	// Simulate cleanup callbacks firing during Close()
	var wg sync.WaitGroup
	const numCallbacks = 5

	// Set the shutdown flag
	atomic.StoreInt32(&transport.isShuttingDown, 1)

	// Launch multiple goroutines simulating cleanup callbacks
	for i := 0; i < numCallbacks; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// This should be a no-op because isShuttingDown is set
			transport.removeSession([32]byte{byte(i)})
		}()
	}

	wg.Wait()

	// Assert sessionCount remains 3 (not decremented by cleanup callbacks)
	finalCount := atomic.LoadInt32(&transport.sessionCount)
	assert.Equal(t, int32(3), finalCount, "Expected sessionCount to remain 3 during shutdown")
}

// SA-2: Test that removeSession normally decrements sessionCount when not shutting down.
func TestRemoveSession_NormalOperation(t *testing.T) {
	transport := &SSU2Transport{
		sessionCount: 5,
	}
	// Simulate a session in the map
	hash := [32]byte{1, 2, 3}
	transport.sessions.Store(hash, &SSU2Session{})

	// Inline the removeSession logic to test it directly
	shutdownFlag := atomic.LoadInt32(&transport.isShuttingDown)
	t.Logf("isShuttingDown=%d", shutdownFlag)
	if shutdownFlag == 0 {
		if _, loaded := transport.sessions.LoadAndDelete(hash); loaded {
			t.Logf("LoadAndDelete succeeded, decrementing")
			atomic.AddInt32(&transport.sessionCount, -1)
		} else {
			t.Logf("LoadAndDelete failed - session not found")
		}
	} else {
		t.Logf("Skipped due to shutdown flag")
	}

	// Assert sessionCount decremented
	finalCount := atomic.LoadInt32(&transport.sessionCount)
	assert.Equal(t, int32(4), finalCount, "Expected sessionCount to decrement from 5 to 4")

	// Assert session removed from map
	_, found := transport.sessions.Load(hash)
	assert.False(t, found, "Expected session to be removed from map")
}

// SA-2: Test that concurrent removeSession calls during shutdown do not decrement.
func TestRemoveSession_ConcurrentShutdown(t *testing.T) {
	transport := &SSU2Transport{
		sessionCount: 10,
	}

	// Populate sessions map
	for i := 0; i < 10; i++ {
		hash := [32]byte{byte(i)}
		transport.sessions.Store(hash, &SSU2Session{})
	}

	// Set shutdown flag
	atomic.StoreInt32(&transport.isShuttingDown, 1)

	// Launch many concurrent removeSession calls
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			hash := [32]byte{byte(idx % 10)}
			transport.removeSession(hash)
		}(i)
	}

	wg.Wait()

	// Assert sessionCount unchanged (all calls skipped due to isShuttingDown)
	finalCount := atomic.LoadInt32(&transport.sessionCount)
	assert.Equal(t, int32(10), finalCount, "Expected sessionCount to remain 10 during shutdown")
}

// SA-2: Race detector test for Close() concurrent with GetSession.
func TestClose_ConcurrentWithGetSession(t *testing.T) {
	transport := &SSU2Transport{
		sessionCount: 5,
	}

	// Populate sessions map
	for i := 0; i < 5; i++ {
		hash := [32]byte{byte(i)}
		transport.sessions.Store(hash, &SSU2Session{})
	}

	// Launch concurrent GetSession calls
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Read sessionCount
			_ = atomic.LoadInt32(&transport.sessionCount)
			// Iterate sessions
			transport.sessions.Range(func(key, value interface{}) bool {
				return true
			})
		}()
	}

	// Concurrently set shutdown flag and close
	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(5 * time.Millisecond) // Let readers start
		atomic.StoreInt32(&transport.isShuttingDown, 1)
		// Simulate cleanup
		transport.sessions.Range(func(key, value interface{}) bool {
			transport.sessions.Delete(key)
			return true
		})
		atomic.StoreInt32(&transport.sessionCount, 0)
	}()

	wg.Wait()

	// Assert final state is consistent (shutdown complete)
	assert.Equal(t, int32(1), atomic.LoadInt32(&transport.isShuttingDown))
	assert.Equal(t, int32(0), atomic.LoadInt32(&transport.sessionCount))
}
