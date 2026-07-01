package i2cp

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type testAddr string

func (a testAddr) Network() string { return "tcp" }
func (a testAddr) String() string  { return string(a) }

type panicThenBlockListener struct {
	calls   atomic.Int32
	unblock chan struct{}
	once    sync.Once
}

func newPanicThenBlockListener() *panicThenBlockListener {
	return &panicThenBlockListener{unblock: make(chan struct{})}
}

func (l *panicThenBlockListener) Accept() (net.Conn, error) {
	if l.calls.Add(1) == 1 {
		panic("accept panic")
	}
	<-l.unblock
	return nil, net.ErrClosed
}

func (l *panicThenBlockListener) Close() error {
	l.once.Do(func() {
		close(l.unblock)
	})
	return nil
}

func (l *panicThenBlockListener) Addr() net.Addr {
	return testAddr("127.0.0.1:0")
}

func TestAcceptLoop_RecoversAndContinuesAfterPanic(t *testing.T) {
	srv, err := NewServer(&ServerConfig{
		ListenAddr:  "127.0.0.1:0",
		Network:     "tcp",
		MaxSessions: 10,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	listener := newPanicThenBlockListener()
	srv.listener = listener

	srv.wg.Add(1)
	go srv.acceptLoop()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if listener.calls.Load() >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if listener.calls.Load() < 2 {
		t.Fatalf("accept loop did not continue after panic, calls=%d", listener.calls.Load())
	}

	srv.cancel()
	_ = listener.Close()

	done := make(chan struct{})
	go func() {
		srv.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("accept loop did not exit after cancellation")
	}
}
