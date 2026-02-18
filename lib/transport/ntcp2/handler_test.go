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

	// Zero should be valid (not provided)
	assert.NoError(t, h.ValidateTimestamp(0))
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
