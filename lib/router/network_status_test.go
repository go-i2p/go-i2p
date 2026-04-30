package router

import (
	"sync"
	"testing"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/go-i2p/go-i2p/lib/transport"
	"github.com/stretchr/testify/assert"
)

// newRunningHiddenRouter returns a minimal Router with running=true and Hidden=true.
func newRunningHiddenRouter() *Router {
	return &Router{
		cfg:     &config.RouterConfig{Hidden: true},
		running: true,
	}
}

// TestGetNetworkStatus_HiddenMode_ZeroSessions asserts that a hidden-mode router
// reports status 3 (HIDDEN) even when it has no active transport sessions.
func TestGetNetworkStatus_HiddenMode_ZeroSessions(t *testing.T) {
	r := newRunningHiddenRouter()
	// activeSessions is nil map — count is 0
	got := r.GetNetworkStatus()
	assert.Equal(t, 3, got, "hidden mode with zero sessions must report 3 (HIDDEN)")
}

// TestGetNetworkStatus_HiddenMode_WithSessions asserts that a hidden-mode router
// reports status 3 (HIDDEN) even when it has active transport sessions.
func TestGetNetworkStatus_HiddenMode_WithSessions(t *testing.T) {
	r := newRunningHiddenRouter()
	r.activeSessions = map[common.Hash]transport.TransportSession{
		{}: nil,
	}
	got := r.GetNetworkStatus()
	assert.Equal(t, 3, got, "hidden mode with active sessions must report 3 (HIDDEN)")
}

// TestGetNetworkStatus_HiddenMode_Reseeding asserts that a hidden-mode router
// reports status 3 (HIDDEN) even while it is reseeding.
func TestGetNetworkStatus_HiddenMode_Reseeding(t *testing.T) {
	r := newRunningHiddenRouter()
	r.isReseeding = true
	got := r.GetNetworkStatus()
	assert.Equal(t, 3, got, "hidden mode while reseeding must report 3 (HIDDEN)")
}

// TestGetNetworkStatus_NotRunning asserts that a stopped router reports 8 (ERROR_I2CP).
func TestGetNetworkStatus_NotRunning(t *testing.T) {
	r := &Router{
		cfg:     &config.RouterConfig{Hidden: true},
		running: false,
	}
	got := r.GetNetworkStatus()
	assert.Equal(t, 8, got, "stopped router must report 8 (ERROR_I2CP)")
}

// TestGetNetworkStatus_Testing asserts that a non-hidden router with no peers reports 1 (TESTING).
func TestGetNetworkStatus_Testing(t *testing.T) {
	r := &Router{
		cfg:          &config.RouterConfig{Hidden: false},
		running:      true,
		sessionMutex: sync.RWMutex{},
	}
	got := r.GetNetworkStatus()
	assert.Equal(t, 1, got, "non-hidden router with no sessions must report 1 (TESTING)")
}
