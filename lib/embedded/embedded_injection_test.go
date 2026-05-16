package embedded

import (
	"context"
	"testing"

	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/go-i2p/go-i2p/lib/router"
)

// MockRouter is a minimal mock implementation of router.Lifecycle for testing.
type MockRouter struct {
	startCalled           bool
	stopCalled            bool
	stopWithContextCalled bool
	waitCalled            bool
	closeCalled           bool
	hardStopCalled        bool
}

// Compile-time check that MockRouter implements router.Lifecycle
var _ router.Lifecycle = (*MockRouter)(nil)

func (m *MockRouter) Start() error {
	m.startCalled = true
	return nil
}

func (m *MockRouter) Stop() {
	m.stopCalled = true
}

func (m *MockRouter) StopWithContext(ctx context.Context) error {
	m.stopWithContextCalled = true
	return nil
}

func (m *MockRouter) Wait() {
	m.waitCalled = true
}

func (m *MockRouter) Close() error {
	m.closeCalled = true
	return nil
}

func TestNewStandardEmbeddedRouterWith_AcceptsInterface(t *testing.T) {
	mock := &MockRouter{}
	cfg := &config.RouterConfig{
		BaseDir:    "/tmp/test",
		WorkingDir: "/tmp/test/working",
	}

	embedded, err := NewStandardEmbeddedRouterWith(mock, cfg)
	if err != nil {
		t.Fatalf("NewStandardEmbeddedRouterWith failed: %v", err)
	}

	if embedded == nil {
		t.Fatal("embedded router is nil")
	}

	if !embedded.IsConfigured() {
		t.Error("embedded router should be configured")
	}
}

func TestNewStandardEmbeddedRouterWith_RejectsNilRouter(t *testing.T) {
	cfg := &config.RouterConfig{
		BaseDir:    "/tmp/test",
		WorkingDir: "/tmp/test/working",
	}

	_, err := NewStandardEmbeddedRouterWith(nil, cfg)
	if err == nil {
		t.Error("expected error when router is nil")
	}
}

func TestNewStandardEmbeddedRouterWith_RejectsNilConfig(t *testing.T) {
	mock := &MockRouter{}

	_, err := NewStandardEmbeddedRouterWith(mock, nil)
	if err == nil {
		t.Error("expected error when config is nil")
	}
}
