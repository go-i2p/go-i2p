// Tests for POOL-002: connection-pool reject paths must not leak a reserved
// session slot (and the file descriptor it pins). A rejected dial reserves a
// slot in beginSessionAttempt; if the reservation is not released on every
// failure branch, the pool fills with phantom reservations and the underlying
// sockets leak, degrading multi-day unattended operation.

package transport

import (
	"errors"
	"net"
	"testing"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// erroringTransport is a Transport whose GetSession always fails, simulating a
// transport that rejects the dial (pool full / unreachable). It is compatible so
// the muxer actually attempts a session and exercises the reject path.
type erroringTransport struct{}

func (erroringTransport) Accept() (net.Conn, error) { return nil, errors.New("no accept") }
func (erroringTransport) Addr() net.Addr             { return nil }
func (erroringTransport) SetIdentity(router_info.RouterInfo) error { return nil }
func (erroringTransport) GetSession(router_info.RouterInfo) (TransportSession, error) {
	return nil, errors.New("transport pool full")
}
func (erroringTransport) Compatible(router_info.RouterInfo) bool { return true }
func (erroringTransport) HasSession(common.Hash) bool            { return false }
func (erroringTransport) Close() error                           { return nil }
func (erroringTransport) Name() string                           { return "ErroringTransport" }

// TestGetSession_PoolRejectDoesNotLeakSlot proves POOL-002 at the muxer level:
// sustained GetSession attempts that all fail must leave activeSessionCount at
// zero. A leaked reservation would keep the pool permanently full and pin its
// socket FD, so the count would climb with each rejected attempt.
func TestGetSession_PoolRejectDoesNotLeakSlot(t *testing.T) {
	muxer := MuxWithLimit(1024, erroringTransport{})

	// A zero RouterInfo is fine: the mock transport ignores it and always errors.
	var ri router_info.RouterInfo

	const attempts = 50
	for i := 0; i < attempts; i++ {
		_, err := muxer.GetSession(ri)
		require.Error(t, err, "attempt %d should be rejected by the failing transport", i)
	}

	// The critical assertion: no reservation leaked across 50 rejected attempts.
	assert.Equal(t, 0, muxer.ActiveSessionCount(),
		"rejected GetSession attempts must not leak reserved session slots (POOL-002)")
}

// TestGetSession_PoolLimitRejectDoesNotLeakSlot proves the connection-limit
// reject path is leak-free: once the pool is genuinely full, further attempts
// are rejected by checkConnectionLimit without incrementing the counter past the
// limit, and releasing one slot lets exactly one new attempt through.
func TestGetSession_PoolLimitRejectDoesNotLeakSlot(t *testing.T) {
	// A transport that succeeds so we can fill the pool with real reservations.
	muxer := MuxWithLimit(2, successTransport{})
	var ri router_info.RouterInfo

	s1, err := muxer.GetSession(ri)
	require.NoError(t, err)
	require.NotNil(t, s1)
	s2, err := muxer.GetSession(ri)
	require.NoError(t, err)
	require.NotNil(t, s2)

	require.Equal(t, 2, muxer.ActiveSessionCount(), "pool should be full at the limit")

	// Sustained rejects while full must not push the counter above the limit.
	for i := 0; i < 20; i++ {
		_, err := muxer.GetSession(ri)
		require.ErrorIs(t, err, ErrConnectionPoolFull, "attempt %d should be rejected: pool full", i)
	}
	assert.Equal(t, 2, muxer.ActiveSessionCount(),
		"pool-full rejects must not leak reservations past the limit (POOL-002)")

	// Releasing one slot must admit exactly one new session, proving the counter
	// tracks real sessions rather than leaked reservations.
	s1.(*trackedSession).Close()
	s3, err := muxer.GetSession(ri)
	require.NoError(t, err, "after releasing a slot, a new session must be admitted")
	require.NotNil(t, s3)
	assert.Equal(t, 2, muxer.ActiveSessionCount())
}

// successTransport returns a non-nil session from GetSession so the muxer can
// fill its connection pool with real reservations.
type successTransport struct{}

func (successTransport) Accept() (net.Conn, error) { return nil, errors.New("no accept") }
func (successTransport) Addr() net.Addr            { return nil }
func (successTransport) SetIdentity(router_info.RouterInfo) error { return nil }
func (successTransport) GetSession(router_info.RouterInfo) (TransportSession, error) {
	return &noopSession{}, nil
}
func (successTransport) Compatible(router_info.RouterInfo) bool { return true }
func (successTransport) HasSession(common.Hash) bool            { return false }
func (successTransport) Close() error                           { return nil }
func (successTransport) Name() string                           { return "SuccessTransport" }

// noopSession is a minimal TransportSession whose Close is a no-op (the muxer's
// trackedSession.Close releases the slot; the underlying session does nothing).
type noopSession struct{}

func (*noopSession) QueueSendI2NP(i2np.Message) error { return nil }
func (*noopSession) SendQueueSize() int               { return 0 }
func (*noopSession) ReadNextI2NP() (i2np.Message, error) {
	return nil, nil
}
func (*noopSession) Close() error { return nil }
