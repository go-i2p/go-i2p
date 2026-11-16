package i2cp

import (
	"testing"
	"time"
)

// TestRecoverFromRoutingPanic_CatchesPanic proves the I2P-E-1 recover seam on
// the async message-routing goroutine: a panic while routing a client message
// (which parses/decrypts client-supplied destination data) is caught rather than
// crashing the router process.
func TestRecoverFromRoutingPanic_CatchesPanic(t *testing.T) {
	server, err := NewServer(DefaultServerConfig())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	session := &Session{id: 42}

	done := make(chan struct{})
	go func() {
		defer close(done)
		defer server.recoverFromRoutingPanic(session)
		panic("boom in async routing")
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("recoverFromRoutingPanic did not contain the panic")
	}
}

// TestRecoverFromMonitoringPanic_CatchesPanic proves the I2P-E-1 recover seam on
// the per-session tunnel-monitoring goroutine: a panic in the up-to-2-minute
// monitoring loop is caught rather than crashing the router process.
func TestRecoverFromMonitoringPanic_CatchesPanic(t *testing.T) {
	server, err := NewServer(DefaultServerConfig())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	session := &Session{id: 7}

	done := make(chan struct{})
	go func() {
		defer close(done)
		defer server.recoverFromMonitoringPanic(session)
		panic("boom in tunnel monitoring")
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("recoverFromMonitoringPanic did not contain the panic")
	}
}
