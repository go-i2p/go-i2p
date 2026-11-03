// Tests for UnwrapTrackedConn. The router type-asserts an accepted SSU2
// connection to the concrete go-noise connection type; the transport and the
// muxer each wrap it in a TrackedConn, so without unwrapping the assertion
// always fails and every inbound SSU2 session is dropped (finding 005).

package transport

import (
	"net"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestUnwrapTrackedConn_StripsEveryLayer pins the walk itself: the router
// receives a connection wrapped by its transport and again by the muxer, and
// must reach the value underneath both.
func TestUnwrapTrackedConn_StripsEveryLayer(t *testing.T) {
	inner := &mockConn{}

	one := NewTrackedConn(inner, nil)
	require.Equal(t, net.Conn(inner), UnwrapTrackedConn(one),
		"a single wrapper must unwrap to the connection inside it")

	two := NewTrackedConn(one, nil)
	require.Equal(t, net.Conn(inner), UnwrapTrackedConn(two),
		"the doubly-wrapped shape the router receives must unwrap to the inner conn")

	three := NewTrackedConn(two, nil)
	require.Equal(t, net.Conn(inner), UnwrapTrackedConn(three),
		"unwrapping must not stop at the second layer")
}

func TestUnwrapTrackedConn_UnwrappedConnIsItself(t *testing.T) {
	plain := &mockConn{}
	assert.Equal(t, net.Conn(plain), UnwrapTrackedConn(plain),
		"a connection with no wrapper must come back unchanged")

	assert.Nil(t, UnwrapTrackedConn(nil), "a nil connection must not panic")

	// A wrapper with a nil inner conn is a degenerate construction; unwrapping
	// must hand back the wrapper rather than nil, so the caller's own nil check
	// still describes the value it was given.
	empty := &TrackedConn{}
	assert.Equal(t, net.Conn(empty), UnwrapTrackedConn(empty))
}

// TestUnwrapTrackedConn_KeepsCloseCallbacksAlive pins that unwrapping is a read:
// it must not disturb the accounting the wrappers exist to perform. Closing the
// outermost wrapper still runs every callback exactly once.
func TestUnwrapTrackedConn_KeepsCloseCallbacksAlive(t *testing.T) {
	var muxerReleased, transportReleased atomic.Int32

	inner := &mockConn{}
	byTransport := NewTrackedConn(inner, func() { transportReleased.Add(1) })
	byMuxer := NewTrackedConn(byTransport, func() { muxerReleased.Add(1) })

	assert.Equal(t, net.Conn(inner), UnwrapTrackedConn(byMuxer),
		"the caller must get the concrete connection")

	// Unwrapping alone must not have fired anything.
	assert.Zero(t, transportReleased.Load())
	assert.Zero(t, muxerReleased.Load())

	require.NoError(t, byMuxer.Close())
	assert.Equal(t, int32(1), transportReleased.Load(),
		"the transport's slot must still be released when the connection closes")
	assert.Equal(t, int32(1), muxerReleased.Load(),
		"the muxer's slot must still be released when the connection closes")
	assert.True(t, inner.closed, "the inner connection must be closed")

	_ = byMuxer.Close()
	assert.Equal(t, int32(1), transportReleased.Load(), "callbacks must run exactly once")
	assert.Equal(t, int32(1), muxerReleased.Load(), "callbacks must run exactly once")
}
