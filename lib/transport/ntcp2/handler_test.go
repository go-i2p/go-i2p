// Tests for the default NTCP2 handler. Covers replay protection,
// timestamp validation, and handshake error handling.

package ntcp2

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDefaultHandler_OnHandshakeError(t *testing.T) {
	h := NewDefaultHandler()
	defer h.Close()

	// Should not panic with nil conn
	h.OnHandshakeError(nil, nil)

	// Should not panic with a real conn (just applies delay)
	// We use a short test — applyProbingResistance is already tested elsewhere
}

func TestDefaultHandler_CheckReplay(t *testing.T) {
	h := NewDefaultHandler()
	defer h.Close()

	var key [32]byte
	key[0] = 0x42

	assert.False(t, h.CheckReplay(key))
	assert.True(t, h.CheckReplay(key))
}

func TestDefaultHandler_ValidateTimestamp(t *testing.T) {
	h := NewDefaultHandler()
	defer h.Close()

	// H3 FIX: Zero is now treated as invalid (per I2P spec, timestamps are required)
	// Previously zero was accepted as "not provided", but this enables replay attacks.
	err := h.ValidateTimestamp(0)
	assert.Error(t, err)
}

func TestDefaultHandler_ReplayCacheSize(t *testing.T) {
	h := NewDefaultHandler()
	defer h.Close()

	assert.Equal(t, 0, h.ReplayCacheSize())

	var key [32]byte
	h.CheckReplay(key)
	assert.Equal(t, 1, h.ReplayCacheSize())
}

func TestDefaultHandler_Close(t *testing.T) {
	h := NewDefaultHandler()
	// Close should not panic
	h.Close()
}

func TestNTCP2Handler_Interface(t *testing.T) {
	// Verify DefaultHandler implements NTCP2Handler
	var _ NTCP2Handler = (*DefaultHandler)(nil)
}

func TestDefaultHandler_OnHandshakeError_WithConn(t *testing.T) {
	h := NewDefaultHandler()
	defer h.Close()

	// Create a pipe to test with a real connection
	client, server := net.Pipe()
	defer client.Close()

	// Close server side so the junk read returns immediately
	server.Close()

	// Should complete without hanging (probing resistance with closed peer)
	h.OnHandshakeError(client, assert.AnError)
}

// TestApplyReplayDetector_WiresHandlerCache proves the transport's replay cache
// is the detector go-noise consults, rather than the unmanaged process-wide
// fallback it would otherwise install. ntcp2.rst:547-550 makes the duplicate
// handshake cache mandatory for Bob and :879-883 for Alice, and the router owns
// the cache's lifetime via Close(), so the registered detector must be that same
// cache: a key seen through the detector must also be reported as a replay by
// the handler, and must show up in its size.
func TestApplyReplayDetector_WiresHandlerCache(t *testing.T) {
	h := NewDefaultHandler()
	defer h.Close()

	cfg := newTestNTCP2Config(t, false)
	applyReplayDetector(cfg, h)

	if cfg.ReplayDetector == nil {
		t.Fatal("ReplayDetector not registered; go-noise would use the shared fallback cache")
	}

	var key [32]byte
	key[0] = 0x5a

	// Seen through the detector first (this is what the handshake does).
	if seen := cfg.ReplayDetector.CheckAndAdd(key); seen {
		t.Fatal("first use of a fresh key must not be reported as a replay")
	}
	// The handler's own cache must now consider it a replay, proving the two are
	// the same cache rather than two independent ones.
	if !h.CheckReplay(key) {
		t.Error("handler cache and registered detector are not the same instance")
	}
	if got := h.ReplayCacheSize(); got != 1 {
		t.Errorf("ReplayCacheSize() = %d, want 1", got)
	}
}

// TestApplyReplayDetector_NilSafe documents that a missing config or handler
// leaves the detector unset instead of panicking; go-noise then installs its
// mandatory fallback, so replay protection is never actually disabled.
func TestApplyReplayDetector_NilSafe(t *testing.T) {
	applyReplayDetector(nil, NewDefaultHandler())

	applyReplayDetector(newTestNTCP2Config(t, false), nil)
}
