package ntcp2

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-i2p/go-i2p/lib/transport"
	"github.com/go-i2p/logger"
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
// CallCleanupCallback can be called concurrently without a data race.
// Run with -race to detect.
func TestSetCleanupCallback_NoRace(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	session := &NTCP2Session{
		SessionCore: transport.NewSessionCore(ctx, logger.WithField("test", "callback")),
	}

	var callCount int32
	var wg sync.WaitGroup

	// Set the callback first so we know it's in place
	session.SetCleanupCallback(func() {
		atomic.AddInt32(&callCount, 1)
	})

	// Concurrently overwrite the callback while trying to call it.
	// The race detector should not trigger on the mutex-protected access.
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
		// CallCleanupCallback can only fire once (cleanupOnce), but we still
		// exercise the read path concurrently with the write path above.
		session.CallCleanupCallback()
	}()
	wg.Wait()

	// The callback should have been called exactly once (via cleanupOnce)
	assert.Equal(t, int32(1), atomic.LoadInt32(&callCount),
		"cleanup callback should fire exactly once")
}

// TestSetCleanupCallback_CalledOnClose verifies that the callback is invoked
// when the session is closed.
func TestSetCleanupCallback_CalledOnClose(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	session := &NTCP2Session{
		SessionCore: transport.NewSessionCore(ctx, logger.WithField("test", "callback")),
	}

	var called int32
	session.SetCleanupCallback(func() {
		atomic.StoreInt32(&called, 1)
	})

	session.CallCleanupCallback()
	assert.Equal(t, int32(1), atomic.LoadInt32(&called))
}

func TestAppendCleanupCallback_CallsBothCallbacksOnce(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	session := &NTCP2Session{
		SessionCore: transport.NewSessionCore(ctx, logger.WithField("test", "callback_append")),
	}

	var firstCalled int32
	var secondCalled int32

	session.SetCleanupCallback(func() {
		atomic.AddInt32(&firstCalled, 1)
	})
	session.AppendCleanupCallback(func() {
		atomic.AddInt32(&secondCalled, 1)
	})

	session.CallCleanupCallback()
	session.CallCleanupCallback() // cleanupOnce should prevent re-run

	assert.Equal(t, int32(1), atomic.LoadInt32(&firstCalled), "first callback should run exactly once")
	assert.Equal(t, int32(1), atomic.LoadInt32(&secondCalled), "second callback should run exactly once")
}

// TestSetCleanupCallback_NilSafe verifies no panic when no callback is set.
func TestSetCleanupCallback_NilSafe(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	session := &NTCP2Session{
		SessionCore: transport.NewSessionCore(ctx, logger.WithField("test", "callback")),
	}

	assert.NotPanics(t, func() {
		session.CallCleanupCallback()
	})
}
