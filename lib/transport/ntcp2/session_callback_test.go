package ntcp2

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// mockConn is a minimal net.Conn for testing
type mockCallbackConn struct {
	net.Conn
	closed int32
}

func (m *mockCallbackConn) Read(b []byte) (n int, err error)  { select {} }
func (m *mockCallbackConn) Write(b []byte) (n int, err error) { return len(b), nil }
func (m *mockCallbackConn) Close() error {
	atomic.StoreInt32(&m.closed, 1)
	return nil
}
func (m *mockCallbackConn) LocalAddr() net.Addr { return &net.TCPAddr{} }
func (m *mockCallbackConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}
}
func (m *mockCallbackConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockCallbackConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockCallbackConn) SetWriteDeadline(t time.Time) error { return nil }

// TestSetCleanupCallback_NoRace verifies that SetCleanupCallback and
// callCleanupCallback can be called concurrently without a data race.
// Run with -race to detect.
func TestSetCleanupCallback_NoRace(t *testing.T) {
	session := &NTCP2Session{
		cleanupOnce: sync.Once{},
	}

	var callCount int32
	var wg sync.WaitGroup

	// Concurrently set the callback while trying to call it
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			session.SetCleanupCallback(func() {
				atomic.AddInt32(&callCount, 1)
			})
		}
	}()
	go func() {
		defer wg.Done()
		// callCleanupCallback can only fire once (cleanupOnce), but we still
		// exercise the read path concurrently with the write path above.
		session.callCleanupCallback()
	}()
	wg.Wait()

	// The callback should have been called exactly once
	assert.Equal(t, int32(1), atomic.LoadInt32(&callCount),
		"cleanup callback should fire exactly once")
}

// TestSetCleanupCallback_CalledOnClose verifies that the callback is invoked
// when the session is closed.
func TestSetCleanupCallback_CalledOnClose(t *testing.T) {
	session := &NTCP2Session{
		cleanupOnce: sync.Once{},
	}

	var called int32
	session.SetCleanupCallback(func() {
		atomic.StoreInt32(&called, 1)
	})

	session.callCleanupCallback()
	assert.Equal(t, int32(1), atomic.LoadInt32(&called))
}

// TestSetCleanupCallback_NilSafe verifies no panic when no callback is set.
func TestSetCleanupCallback_NilSafe(t *testing.T) {
	session := &NTCP2Session{
		cleanupOnce: sync.Once{},
	}

	assert.NotPanics(t, func() {
		session.callCleanupCallback()
	})
}
