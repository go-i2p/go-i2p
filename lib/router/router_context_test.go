//go:build integration

package router

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRouterContextLifecycle tests that the router context is properly managed
func TestRouterContextLifecycle(t *testing.T) {
	router := createTestRouterWithKeystore(t)

	// Context should be nil before Start()
	assert.Nil(t, router.ctx)
	assert.Nil(t, router.cancel)

	// Start the router
	router.Start()

	// Wait briefly for Start() to complete (it runs in goroutine)
	time.Sleep(50 * time.Millisecond)

	// Context should be initialized after Start()
	ctx := getRouterCtx(t, router)

	router.runMux.RLock()
	cancel := router.cancel
	router.runMux.RUnlock()
	require.NotNil(t, cancel, "Router cancel function should be initialized after Start()")

	// Context should not be cancelled while router is running
	assertContextActive(t, ctx)

	// Stop the router
	router.Stop()

	// Context should be cancelled after Stop()
	assertContextCancelled(t, ctx, 100*time.Millisecond)
}

// TestRouterContextCancellation tests that stopping the router cancels the context
func TestRouterContextCancellation(t *testing.T) {
	router := createTestRouterWithKeystore(t)

	// Start the router
	router.Start()
	time.Sleep(50 * time.Millisecond)

	// Get context before stopping
	ctx := getRouterCtx(t, router)

	// Stop the router
	router.Stop()

	// Verify context was cancelled
	assertContextCancelled(t, ctx, 200*time.Millisecond)
}

// TestRouterMultipleStartStop tests that Start/Stop can be called multiple times
func TestRouterMultipleStartStop(t *testing.T) {
	router := createTestRouterWithKeystore(t)

	// First Start/Stop cycle
	router.Start()
	time.Sleep(50 * time.Millisecond)
	ctx1 := getRouterCtx(t, router)
	router.Stop()

	// Verify first context is cancelled
	assertContextCancelled(t, ctx1, 100*time.Millisecond)

	// Second Start/Stop cycle
	router.Start()
	time.Sleep(50 * time.Millisecond)
	ctx2 := getRouterCtx(t, router)

	// New context should be different from old one
	assert.NotEqual(t, ctx1, ctx2, "New start should create new context")

	// New context should not be cancelled
	assertContextActive(t, ctx2)

	router.Stop()

	// Second context should be cancelled
	assertContextCancelled(t, ctx2, 100*time.Millisecond)
}

// TestRouterStopWithoutStart tests that Stop() is safe to call without Start()
func TestRouterStopWithoutStart(t *testing.T) {
	router := createTestRouter(t)

	// Should not panic when Stop() is called without Start()
	require.NotPanics(t, func() {
		router.Stop()
	})

	// Context should still be nil
	assert.Nil(t, router.ctx)
	assert.Nil(t, router.cancel)
}

// TestRouterContextNotNilInGoroutines tests that goroutines can access router context
func TestRouterContextNotNilInGoroutines(t *testing.T) {
	router := createTestRouterWithKeystore(t)

	router.Start()
	time.Sleep(50 * time.Millisecond)

	// Simulate accessing context from a goroutine (like session processing)
	contextAccessed := make(chan context.Context, 1)
	go func() {
		router.runMux.RLock()
		ctx := router.ctx
		router.runMux.RUnlock()
		contextAccessed <- ctx
	}()

	// Get context from goroutine
	select {
	case ctx := <-contextAccessed:
		assert.NotNil(t, ctx, "Context should be accessible from goroutines")
	case <-time.After(200 * time.Millisecond):
		t.Error("Failed to access context from goroutine")
	}

	router.Stop()
}

// TestRouterContextInheritance tests that router context is properly passed to components
func TestRouterContextInheritance(t *testing.T) {
	router := createTestRouterWithKeystore(t)

	router.Start()
	time.Sleep(50 * time.Millisecond)

	parentCtx := getRouterCtx(t, router)

	// Simulate creating a child context (like sessions would)
	childCtx, childCancel := context.WithCancel(parentCtx)
	defer childCancel()

	// Child should not be done while parent is active
	select {
	case <-childCtx.Done():
		t.Error("Child context should not be done while parent is active")
	default:
		// Expected
	}

	// Stop router (cancels parent context)
	router.Stop()

	// Child context should be cancelled when parent is cancelled
	select {
	case <-childCtx.Done():
		// Expected: child inherits parent cancellation
		assert.Error(t, childCtx.Err())
	case <-time.After(200 * time.Millisecond):
		t.Error("Child context should be cancelled when parent is cancelled")
	}
}

// TestRouterDoubleStop tests that calling Stop() twice is safe
func TestRouterDoubleStop(t *testing.T) {
	router := createTestRouterWithKeystore(t)

	router.Start()
	time.Sleep(50 * time.Millisecond)

	// First stop
	require.NotPanics(t, func() {
		router.Stop()
	})

	// Second stop should not panic
	require.NotPanics(t, func() {
		router.Stop()
	})
}
