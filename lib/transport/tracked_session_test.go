package transport

import (
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestTrackedSession_AutoDecrement verifies that closing a tracked session
// automatically decrements the active session counter.
func TestTrackedSession_AutoDecrement(t *testing.T) {
	tmux := &TransportMuxer{}
	atomic.StoreInt32(&tmux.activeSessionCount, 3)

	ts := &trackedSession{
		TransportSession: &mockSession{},
		mux:              tmux,
	}

	err := ts.Close()
	assert.NoError(t, err)
	assert.Equal(t, int32(2), atomic.LoadInt32(&tmux.activeSessionCount),
		"active session count should decrement by 1")
}

// TestTrackedSession_DoubleClose verifies that closing a tracked session
// twice only decrements the counter once.
func TestTrackedSession_DoubleClose(t *testing.T) {
	tmux := &TransportMuxer{}
	atomic.StoreInt32(&tmux.activeSessionCount, 3)

	ts := &trackedSession{
		TransportSession: &mockSession{},
		mux:              tmux,
	}

	ts.Close()
	ts.Close()
	assert.Equal(t, int32(2), atomic.LoadInt32(&tmux.activeSessionCount),
		"double close should only decrement once")
}

// TestTrackedConn_AutoDecrement verifies that closing a tracked connection
// automatically decrements the active session counter.
func TestTrackedConn_AutoDecrement(t *testing.T) {
	tmux := &TransportMuxer{}
	atomic.StoreInt32(&tmux.activeSessionCount, 5)

	tc := &trackedConn{
		Conn: &mockConn{},
		mux:  tmux,
	}

	err := tc.Close()
	assert.NoError(t, err)
	assert.Equal(t, int32(4), atomic.LoadInt32(&tmux.activeSessionCount),
		"active session count should decrement by 1")
}

// TestTrackedConn_DoubleClose verifies that closing a tracked connection
// twice only decrements the counter once.
func TestTrackedConn_DoubleClose(t *testing.T) {
	tmux := &TransportMuxer{}
	atomic.StoreInt32(&tmux.activeSessionCount, 5)

	tc := &trackedConn{
		Conn: &mockConn{},
		mux:  tmux,
	}

	tc.Close()
	tc.Close()
	assert.Equal(t, int32(4), atomic.LoadInt32(&tmux.activeSessionCount),
		"double close should only decrement once")
}
