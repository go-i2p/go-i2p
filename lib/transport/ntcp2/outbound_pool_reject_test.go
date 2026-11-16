package ntcp2

import (
	"testing"

	data "github.com/go-i2p/common/data"
	router_info "github.com/go-i2p/common/router_info"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCreateOutboundSession_PoolFullRejectsBeforeDial is the go-i2p-side guard
// for POOL-002 at the transport layer. When the session pool is at capacity,
// createOutboundSession must reject BEFORE dialing: it must not open a socket
// (which would leak an FD on the reject path) and must not leak a reserved
// session slot. The checkSessionLimit guard runs before dialNTCP2Connection, so
// a full pool returns ErrConnectionPoolFull with the count unchanged.
func TestCreateOutboundSession_PoolFullRejectsBeforeDial(t *testing.T) {
	const max = 2
	tr := newTestTransport(nil, max)
	require.NotNil(t, tr)

	// Fill the pool to capacity by reserving slots the way a successful session
	// would (CheckLimitAndIncrement increments on success).
	for i := 0; i < max; i++ {
		require.NoError(t, tr.checkSessionLimit(), "reserve slot %d", i)
	}
	require.Equal(t, int32(max), tr.GetSessionCount())

	// A further outbound attempt must be rejected at the limit check, before any
	// dial. A zero RouterInfo has no dialable address, so if the code wrongly
	// proceeded to dial it would fail differently (not ErrConnectionPoolFull) —
	// asserting the exact error proves the reject happened at the pool guard.
	_, err := tr.createOutboundSession(router_info.RouterInfo{}, data.Hash{0x01})
	require.ErrorIs(t, err, ErrConnectionPoolFull,
		"full pool must reject at the session-limit guard, not by dialing")

	// The reject must not have incremented the count (no slot leaked) — the count
	// stays exactly at max.
	assert.Equal(t, int32(max), tr.GetSessionCount(),
		"rejected outbound session must not leak a reserved session slot")
}

// TestCreateOutboundSession_RejectDoesNotDial verifies the reject path opens no
// connection: with the pool full, createOutboundSession returns before
// dialNTCP2Connection, so no net.Conn is created and no FD is consumed. We
// assert the count is unchanged across many sustained rejects (the FD-stability
// property POOL-002 asks for, expressed at the session-slot level).
func TestCreateOutboundSession_RejectDoesNotDial(t *testing.T) {
	const max = 1
	tr := newTestTransport(nil, max)
	require.NoError(t, tr.checkSessionLimit()) // fill to capacity

	before := tr.GetSessionCount()
	for i := 0; i < 50; i++ {
		_, err := tr.createOutboundSession(router_info.RouterInfo{}, data.Hash{byte(i)})
		require.ErrorIs(t, err, ErrConnectionPoolFull)
	}
	// 50 sustained rejects must not move the count (no slot/FD leak).
	assert.Equal(t, before, tr.GetSessionCount(),
		"sustained pool rejects must keep the session count stable (no leak)")
}
