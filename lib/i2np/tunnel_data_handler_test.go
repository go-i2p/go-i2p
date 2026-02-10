package i2np

import (
	"errors"
	"testing"
	"time"
)

// mockTunnelDataHandler implements TunnelDataHandler for testing
type mockTunnelDataHandler struct {
	called    bool
	msg       I2NPMessage
	returnErr error
}

func (m *mockTunnelDataHandler) HandleTunnelData(msg I2NPMessage) error {
	m.called = true
	m.msg = msg
	return m.returnErr
}

// TestSetTunnelDataHandler verifies the setter wires the handler correctly
func TestSetTunnelDataHandler(t *testing.T) {
	proc := NewMessageProcessor()
	proc.DisableExpirationCheck()

	handler := &mockTunnelDataHandler{}
	proc.SetTunnelDataHandler(handler)

	if proc.tunnelDataHandler == nil {
		t.Fatal("expected tunnelDataHandler to be set")
	}
}

// TestProcessTunnelDataDelegatesToHandler verifies that when a TunnelDataHandler
// is configured, incoming TunnelData messages are delegated to it.
func TestProcessTunnelDataDelegatesToHandler(t *testing.T) {
	proc := NewMessageProcessor()
	proc.DisableExpirationCheck()

	handler := &mockTunnelDataHandler{}
	proc.SetTunnelDataHandler(handler)

	// Create a TunnelData message using the constructor
	var data [1024]byte
	msg := NewTunnelDataMessage(12345, data)
	msg.BaseI2NPMessage.SetExpiration(time.Now().Add(5 * time.Minute))

	err := proc.ProcessMessage(msg)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if !handler.called {
		t.Fatal("expected handler to be called")
	}
}

// TestProcessTunnelDataHandlerError verifies handler errors are propagated.
func TestProcessTunnelDataHandlerError(t *testing.T) {
	proc := NewMessageProcessor()
	proc.DisableExpirationCheck()

	handler := &mockTunnelDataHandler{
		returnErr: errors.New("handler test error"),
	}
	proc.SetTunnelDataHandler(handler)

	var data [1024]byte
	msg := NewTunnelDataMessage(12345, data)
	msg.BaseI2NPMessage.SetExpiration(time.Now().Add(5 * time.Minute))

	err := proc.ProcessMessage(msg)
	if err == nil {
		t.Fatal("expected error from handler")
	}
	if err.Error() != "handler test error" {
		t.Fatalf("expected 'handler test error', got: %v", err)
	}
}

// TestProcessTunnelDataWithoutHandler verifies that without a handler,
// TunnelData messages are validated but not delivered.
func TestProcessTunnelDataWithoutHandler(t *testing.T) {
	proc := NewMessageProcessor()
	proc.DisableExpirationCheck()

	var data [1024]byte
	msg := NewTunnelDataMessage(12345, data)
	msg.BaseI2NPMessage.SetExpiration(time.Now().Add(5 * time.Minute))

	// Should succeed without error (validated but not delivered)
	err := proc.ProcessMessage(msg)
	if err != nil {
		t.Fatalf("expected no error without handler, got: %v", err)
	}
}

// TestProcessTunnelDataInvalidMessage verifies that non-TunnelCarrier messages
// are rejected with an appropriate error.
func TestProcessTunnelDataInvalidMessage(t *testing.T) {
	proc := NewMessageProcessor()
	proc.DisableExpirationCheck()

	// Use a Data message which doesn't implement TunnelCarrier
	msg := NewBaseI2NPMessage(I2NP_MESSAGE_TYPE_TUNNEL_DATA)
	msg.SetExpiration(time.Now().Add(5 * time.Minute))

	err := proc.processTunnelDataMessage(msg)
	if err == nil {
		t.Fatal("expected error for non-TunnelCarrier message")
	}
}

// TestTunnelDataHandlerInterface verifies compile-time interface compliance.
func TestTunnelDataHandlerInterface(t *testing.T) {
	var _ TunnelDataHandler = (*mockTunnelDataHandler)(nil)
}
