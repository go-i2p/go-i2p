package router

import (
	"context"
	"testing"
	"time"

	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRouterContextLifecycle tests that the router context is properly managed
func TestRouterContextLifecycle(t *testing.T) {
	tempDir := t.TempDir()
	cfg := config.DefaultRouterConfig()
	cfg.WorkingDir = tempDir
	cfg.I2CP.Enabled = false

	router, err := FromConfig(cfg)
	require.NoError(t, err)
	require.NotNil(t, router)

	// Initialize keystore
	err = initializeRouterKeystore(router, cfg)
	require.NoError(t, err)

	// Context should be nil before Start()
	assert.Nil(t, router.ctx)
	assert.Nil(t, router.cancel)

	// Start the router
	router.Start()

	// Wait briefly for Start() to complete (it runs in goroutine)
	time.Sleep(50 * time.Millisecond)

	// Context should be initialized after Start()
	router.runMux.RLock()
	ctx := router.ctx
	cancel := router.cancel
	router.runMux.RUnlock()

	require.NotNil(t, ctx, "Router context should be initialized after Start()")
	require.NotNil(t, cancel, "Router cancel function should be initialized after Start()")

	// Context should not be cancelled while router is running
	select {
	case <-ctx.Done():
		t.Error("Context should not be cancelled while router is running")
	default:
		// Expected: context still active
	}

	// Stop the router
	router.Stop()

	// Context should be cancelled after Stop()
	select {
	case <-ctx.Done():
		// Expected: context cancelled
		assert.Error(t, ctx.Err(), "Context error should be set after cancellation")
	case <-time.After(100 * time.Millisecond):
		t.Error("Context should be cancelled after Stop()")
	}
}

// TestRouterContextCancellation tests that stopping the router cancels the context
func TestRouterContextCancellation(t *testing.T) {
	tempDir := t.TempDir()
	cfg := config.DefaultRouterConfig()
	cfg.WorkingDir = tempDir
	cfg.I2CP.Enabled = false

	router, err := FromConfig(cfg)
	require.NoError(t, err)

	// Initialize keystore
	err = initializeRouterKeystore(router, cfg)
	require.NoError(t, err)

	// Start the router
	router.Start()
	time.Sleep(50 * time.Millisecond)

	// Get context before stopping
	router.runMux.RLock()
	ctx := router.ctx
	router.runMux.RUnlock()
	require.NotNil(t, ctx)

	// Create a goroutine that waits on the context
	contextDone := make(chan struct{})
	go func() {
		<-ctx.Done()
		close(contextDone)
	}()

	// Stop the router
	router.Stop()

	// Verify context was cancelled
	select {
	case <-contextDone:
		// Expected: context cancelled
		assert.Error(t, ctx.Err())
	case <-time.After(200 * time.Millisecond):
		t.Error("Context should be cancelled within timeout")
	}
}

// TestRouterMultipleStartStop tests that Start/Stop can be called multiple times
func TestRouterMultipleStartStop(t *testing.T) {
	tempDir := t.TempDir()
	cfg := config.DefaultRouterConfig()
	cfg.WorkingDir = tempDir
	cfg.I2CP.Enabled = false

	router, err := FromConfig(cfg)
	require.NoError(t, err)

	// Initialize keystore
	err = initializeRouterKeystore(router, cfg)
	require.NoError(t, err)

	// First Start/Stop cycle
	router.Start()
	time.Sleep(50 * time.Millisecond)
	router.runMux.RLock()
	ctx1 := router.ctx
	router.runMux.RUnlock()
	require.NotNil(t, ctx1)
	router.Stop()

	// Verify first context is cancelled
	select {
	case <-ctx1.Done():
		// Expected
	case <-time.After(100 * time.Millisecond):
		t.Error("First context should be cancelled")
	}

	// Second Start/Stop cycle
	router.Start()
	time.Sleep(50 * time.Millisecond)
	router.runMux.RLock()
	ctx2 := router.ctx
	router.runMux.RUnlock()
	require.NotNil(t, ctx2)

	// New context should be different from old one
	assert.NotEqual(t, ctx1, ctx2, "New start should create new context")

	// New context should not be cancelled
	select {
	case <-ctx2.Done():
		t.Error("New context should not be cancelled")
	default:
		// Expected
	}

	router.Stop()

	// Second context should be cancelled
	select {
	case <-ctx2.Done():
		// Expected
	case <-time.After(100 * time.Millisecond):
		t.Error("Second context should be cancelled")
	}
}

// TestRouterStopWithoutStart tests that Stop() is safe to call without Start()
func TestRouterStopWithoutStart(t *testing.T) {
	tempDir := t.TempDir()
	cfg := config.DefaultRouterConfig()
	cfg.WorkingDir = tempDir
	cfg.I2CP.Enabled = false

	router, err := FromConfig(cfg)
	require.NoError(t, err)

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
	tempDir := t.TempDir()
	cfg := config.DefaultRouterConfig()
	cfg.WorkingDir = tempDir
	cfg.I2CP.Enabled = false

	router, err := FromConfig(cfg)
	require.NoError(t, err)

	// Initialize keystore
	err = initializeRouterKeystore(router, cfg)
	require.NoError(t, err)

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
	tempDir := t.TempDir()
	cfg := config.DefaultRouterConfig()
	cfg.WorkingDir = tempDir
	cfg.I2CP.Enabled = false

	router, err := FromConfig(cfg)
	require.NoError(t, err)

	// Initialize keystore
	err = initializeRouterKeystore(router, cfg)
	require.NoError(t, err)

	router.Start()
	time.Sleep(50 * time.Millisecond)

	router.runMux.RLock()
	parentCtx := router.ctx
	router.runMux.RUnlock()
	require.NotNil(t, parentCtx)

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
	tempDir := t.TempDir()
	cfg := config.DefaultRouterConfig()
	cfg.WorkingDir = tempDir
	cfg.I2CP.Enabled = false

	router, err := FromConfig(cfg)
	require.NoError(t, err)

	// Initialize keystore
	err = initializeRouterKeystore(router, cfg)
	require.NoError(t, err)

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
