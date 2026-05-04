package router

import (
	"sync"
	"testing"

	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFromConfig_NilConfig verifies that FromConfig returns an error
// when called with a nil config instead of panicking on nil dereference.
func TestFromConfig_NilConfig(t *testing.T) {
	r, err := FromConfig(nil)
	assert.Nil(t, r, "Router should be nil when config is nil")
	require.Error(t, err, "FromConfig should return an error for nil config")
	assert.Contains(t, err.Error(), "nil")
}

// TestFinalizeCloseChannel_ConcurrentSafe verifies that calling
// finalizeCloseChannel concurrently from multiple goroutines does not
// panic from double-closing the channel.
func TestFinalizeCloseChannel_ConcurrentSafe(t *testing.T) {
	r := &Router{
		closeChnl: make(chan bool),
	}

	var wg sync.WaitGroup
	// Spawn 10 goroutines that all try to finalize concurrently
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// This should never panic thanks to sync.Once
			r.finalizeCloseChannel()
		}()
	}
	wg.Wait()

	// Channel should be nil after finalization
	assert.Nil(t, r.closeChnl, "closeChnl should be nil after finalization")
}

// TestFinalizeCloseChannel_NilChannel verifies that calling
// finalizeCloseChannel when closeChnl is already nil is safe.
func TestFinalizeCloseChannel_NilChannel(t *testing.T) {
	r := &Router{
		closeChnl: nil,
	}
	// Should not panic
	r.finalizeCloseChannel()
	assert.Nil(t, r.closeChnl)
}

// TestCreateRouter_NilNetDBReturnsError verifies CreateRouter fails fast with
// a typed error when required nested NetDB config is missing.
func TestCreateRouter_NilNetDBReturnsError(t *testing.T) {
	cfg := config.DefaultRouterConfig()
	cfg.WorkingDir = t.TempDir()
	cfg.NetDB = nil

	assert.NotPanics(t, func() {
		r, err := CreateRouter(cfg)
		assert.Nil(t, r, "router should be nil when NetDB config is nil")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "NetDB")
	})
}

// TestCreateRouter_EmptyNetDBPathReturnsError verifies constructor validation
// rejects empty NetDB path before touching startup subsystems.
func TestCreateRouter_EmptyNetDBPathReturnsError(t *testing.T) {
	cfg := config.DefaultRouterConfig()
	cfg.WorkingDir = t.TempDir()
	cfg.NetDB.Path = ""

	r, err := CreateRouter(cfg)
	assert.Nil(t, r, "router should be nil when NetDB path is empty")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "NetDB.Path")
}
