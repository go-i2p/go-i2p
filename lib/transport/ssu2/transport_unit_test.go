package ssu2

// transport_unit_test.go covers SSU2Transport methods that do not require a
// full network handshake, using either bare struct construction or the
// makeTestTransportWithListener helper from nat_test.go.

import (
	"context"
	"testing"

	"github.com/go-i2p/common/data"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// makeMinimalTransport creates an SSU2Transport with only the fields required
// for non-network methods (Name, Addr, GetSessionCount, etc.).
func makeMinimalTransport() *SSU2Transport {
	ctx, cancel := context.WithCancel(context.Background())
	return &SSU2Transport{
		config:        &Config{ListenerAddress: ":0", MaxSessions: 4},
		handler:       NewDefaultHandler(),
		natStateCache: &natState{},
		ctx:           ctx,
		cancel:        cancel,
		logger:        log.WithField("test", "transport_unit"),
	}
}

// TestTransport_Name verifies the transport returns the correct protocol name.
func TestTransport_Name(t *testing.T) {
	tr := makeMinimalTransport()
	assert.Equal(t, "SSU2", tr.Name())
}

// TestTransport_Addr_NilListener verifies Addr returns nil when there is no
// underlying listener.
func TestTransport_Addr_NilListener(t *testing.T) {
	tr := makeMinimalTransport()
	assert.Nil(t, tr.Addr())
}

// TestTransport_Addr_WithListener verifies Addr returns a valid address when a
// listener is active.
func TestTransport_Addr_WithListener(t *testing.T) {
	tr, cleanup := makeTestTransportWithListener(t)
	defer cleanup()
	assert.NotNil(t, tr.Addr())
}

// TestTransport_GetSessionCount_Zero verifies GetSessionCount starts at zero.
func TestTransport_GetSessionCount_Zero(t *testing.T) {
	tr := makeMinimalTransport()
	assert.Equal(t, 0, tr.GetSessionCount())
}

// TestTransport_GetTotalBandwidth_Empty verifies GetTotalBandwidth returns
// zeros when there are no sessions.
func TestTransport_GetTotalBandwidth_Empty(t *testing.T) {
	tr := makeMinimalTransport()
	sent, received := tr.GetTotalBandwidth()
	assert.Equal(t, uint64(0), sent)
	assert.Equal(t, uint64(0), received)
}

// TestTransport_CheckSessionLimit_Allows verifies that session slots can be
// reserved up to MaxSessions.
func TestTransport_CheckSessionLimit_Allows(t *testing.T) {
	tr := makeMinimalTransport() // MaxSessions = 4
	require.NoError(t, tr.checkSessionLimit())
	require.NoError(t, tr.checkSessionLimit())
	assert.Equal(t, 2, tr.GetSessionCount())
}

// TestTransport_CheckSessionLimit_Rejects verifies that reserving beyond the
// limit returns ErrConnectionPoolFull.
func TestTransport_CheckSessionLimit_Rejects(t *testing.T) {
	tr := makeMinimalTransport() // MaxSessions = 4
	for i := 0; i < 4; i++ {
		require.NoError(t, tr.checkSessionLimit())
	}
	assert.ErrorIs(t, tr.checkSessionLimit(), ErrConnectionPoolFull)
}

// TestTransport_UnreserveSessionSlot verifies that releasing a slot decrements
// the session count.
func TestTransport_UnreserveSessionSlot(t *testing.T) {
	tr := makeMinimalTransport()
	require.NoError(t, tr.checkSessionLimit())
	require.Equal(t, 1, tr.GetSessionCount())
	tr.unreserveSessionSlot()
	assert.Equal(t, 0, tr.GetSessionCount())
}

// TestTransport_UnreserveSessionSlot_BelowZero verifies that releasing a slot
// when the count is already zero is a no-op.
func TestTransport_UnreserveSessionSlot_BelowZero(t *testing.T) {
	tr := makeMinimalTransport()
	tr.unreserveSessionSlot() // should not panic or underflow
	assert.Equal(t, 0, tr.GetSessionCount())
}

// TestTransport_RemoveSession verifies that removeSession decrements the count
// exactly once, and a repeat call is idempotent.
func TestTransport_RemoveSession(t *testing.T) {
	tr := makeMinimalTransport()
	require.NoError(t, tr.checkSessionLimit())

	var hash data.Hash
	hash[0] = 0xAB
	tr.sessions.Store(hash, struct{}{})

	tr.removeSession(hash)
	assert.Equal(t, 0, tr.GetSessionCount())

	// Second call should not change the count
	tr.removeSession(hash)
	assert.Equal(t, 0, tr.GetSessionCount())
}

// TestTransport_Close_Minimal verifies Close does not panic and returns nil
// when called on a minimal transport without a listener.
func TestTransport_Close_Minimal(t *testing.T) {
	tr := makeMinimalTransport()
	assert.NoError(t, tr.Close())
}

// TestTransport_Close_WithListener verifies Close gracefully shuts down a
// transport that has an active listener and NAT managers.
func TestTransport_Close_WithListener(t *testing.T) {
	tr, _ := makeTestTransportWithListener(t)
	// Do not use deferred cleanup — Close IS the cleanup.
	assert.NoError(t, tr.Close())
}
