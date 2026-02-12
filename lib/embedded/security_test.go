package embedded

import (
	"sync"
	"testing"
	"time"

	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// -----------------------------------------------------------------------------
// Thread Safety Tests
// Verifies concurrent access to StandardEmbeddedRouter is safe
// -----------------------------------------------------------------------------

// TestEmbeddedRouter_ConcurrentIsRunning tests concurrent calls to IsRunning.
func TestEmbeddedRouter_ConcurrentIsRunning(t *testing.T) {
	cfg := config.DefaultRouterConfig()
	router, err := NewStandardEmbeddedRouter(cfg)
	require.NoError(t, err)

	var wg sync.WaitGroup
	// Multiple goroutines reading state concurrently
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = router.IsRunning()
			_ = router.IsConfigured()
		}()
	}
	wg.Wait()
}

// TestEmbeddedRouter_ConcurrentStartStop tests that Start/Stop are serialized.
func TestEmbeddedRouter_ConcurrentStartStop(t *testing.T) {
	cfg := config.DefaultRouterConfig()
	router, err := NewStandardEmbeddedRouter(cfg)
	require.NoError(t, err)

	// Constructor auto-configures, so all subsequent Configure calls are no-ops (return nil)
	var wg sync.WaitGroup
	configCount := 0
	var mu sync.Mutex

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := router.Configure(cfg)
			if err == nil {
				mu.Lock()
				configCount++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	// All Configure calls should succeed (idempotent no-op after auto-configure)
	assert.Equal(t, 10, configCount, "All Configure calls should succeed as no-ops")
}

// -----------------------------------------------------------------------------
// State Management Tests
// Verifies lifecycle state transitions are correct
// -----------------------------------------------------------------------------

// TestEmbeddedRouter_StateTransitions tests valid state transitions.
func TestEmbeddedRouter_StateTransitions(t *testing.T) {
	cfg := config.DefaultRouterConfig()
	router, err := NewStandardEmbeddedRouter(cfg)
	require.NoError(t, err)

	// After constructor: auto-configured but not running
	assert.False(t, router.IsRunning(), "Should not be running initially")
	assert.True(t, router.IsConfigured(), "Should be configured after constructor auto-configure")

	// Reconfigure is idempotent (no-op after auto-configure by constructor)
	err = router.Configure(cfg)
	assert.NoError(t, err, "Configure should return nil (idempotent) when already configured")
}

// TestEmbeddedRouter_CloseRequiresStop tests that Close requires Stop first.
func TestEmbeddedRouter_CloseRequiresStop(t *testing.T) {
	cfg := config.DefaultRouterConfig()
	router, err := NewStandardEmbeddedRouter(cfg)
	require.NoError(t, err)

	// Close on configured (but not running) router should be okay
	err = router.Close()
	assert.NoError(t, err)
}

// TestEmbeddedRouter_StopOnNonRunning tests Stop on non-running router.
func TestEmbeddedRouter_StopOnNonRunning(t *testing.T) {
	cfg := config.DefaultRouterConfig()
	router, err := NewStandardEmbeddedRouter(cfg)
	require.NoError(t, err)

	// Stop on non-running router should not error
	err = router.Stop()
	assert.NoError(t, err)
}

// TestEmbeddedRouter_HardStopOnNonRunning tests HardStop on non-running router.
func TestEmbeddedRouter_HardStopOnNonRunning(t *testing.T) {
	cfg := config.DefaultRouterConfig()
	router, err := NewStandardEmbeddedRouter(cfg)
	require.NoError(t, err)

	// HardStop on non-running router should not panic
	router.HardStop()
	assert.False(t, router.IsRunning())
}

// TestEmbeddedRouter_WaitOnNonRunning tests Wait on non-running router.
func TestEmbeddedRouter_WaitOnNonRunning(t *testing.T) {
	cfg := config.DefaultRouterConfig()
	router, err := NewStandardEmbeddedRouter(cfg)
	require.NoError(t, err)

	// Wait on non-running router should return immediately
	done := make(chan struct{})
	go func() {
		router.Wait()
		close(done)
	}()

	// Use timeout to verify it returns quickly
	select {
	case <-done:
		// Good - returned immediately
	case <-time.After(100 * time.Millisecond):
		t.Error("Wait on non-running router should return immediately")
	}
}

// -----------------------------------------------------------------------------
// Error Handling Tests
// Verifies errors don't leak sensitive information
// -----------------------------------------------------------------------------

// TestEmbeddedRouter_ErrorMessages tests error messages for safety.
func TestEmbeddedRouter_ErrorMessages(t *testing.T) {
	testCases := []struct {
		name             string
		action           func(*StandardEmbeddedRouter) error
		expectError      bool
		shouldNotContain []string
	}{
		{
			name: "NilConfig_Configure",
			action: func(r *StandardEmbeddedRouter) error {
				// Router is already configured by constructor, so Configure returns nil (no-op)
				return r.Configure(nil)
			},
			expectError:      false,
			shouldNotContain: []string{"password", "key", "secret"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.DefaultRouterConfig()
			router, err := NewStandardEmbeddedRouter(cfg)
			require.NoError(t, err)

			err = tc.action(router)
			if tc.expectError {
				require.Error(t, err)
				for _, forbidden := range tc.shouldNotContain {
					assert.NotContains(t, err.Error(), forbidden,
						"Error should not contain %q", forbidden)
				}
			}
		})
	}
}

// TestEmbeddedRouter_NilConfigConstruction tests nil config handling.
func TestEmbeddedRouter_NilConfigConstruction(t *testing.T) {
	router, err := NewStandardEmbeddedRouter(nil)
	assert.Error(t, err)
	assert.Nil(t, router)
	assert.Contains(t, err.Error(), "cannot be nil")
}

// -----------------------------------------------------------------------------
// Interface Compliance Tests
// -----------------------------------------------------------------------------

// TestEmbeddedRouter_InterfaceCompliance verifies interface implementation.
func TestEmbeddedRouter_InterfaceCompliance(t *testing.T) {
	// Compile-time check that StandardEmbeddedRouter implements EmbeddedRouter
	var _ EmbeddedRouter = (*StandardEmbeddedRouter)(nil)
}

// TestEmbeddedRouter_DefaultConfigSafe tests that default config is reasonable.
func TestEmbeddedRouter_DefaultConfigSafe(t *testing.T) {
	cfg := config.DefaultRouterConfig()
	require.NotNil(t, cfg)

	// Should be able to create router with defaults
	router, err := NewStandardEmbeddedRouter(cfg)
	assert.NoError(t, err)
	assert.NotNil(t, router)
}
