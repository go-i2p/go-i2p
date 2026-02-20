package util

import (
	"io"
	"sync"
)

// =============================================================================
// Shared Test Mocks and Helpers
// =============================================================================

// resetCloseables clears global closer state for test isolation.
// Used by both closeables unit and integration tests.
func resetCloseables() {
	closeMutex.Lock()
	closeOnExit = nil
	closeMutex.Unlock()
}

// mockCloser is a test implementation of io.Closer that tracks whether
// Close was called and can be configured to return an error.
type mockCloser struct {
	closed     bool
	closeError error
	mu         sync.Mutex
}

func (m *mockCloser) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return m.closeError
}

// IsClosed reports whether Close has been called. Thread-safe.
func (m *mockCloser) IsClosed() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.closed
}

// closerWrapper wraps an io.Reader to add Close functionality,
// used for testing CloseAll with non-file io.Closer implementations.
type closerWrapper struct {
	io.Reader
	closed bool
}

func (c *closerWrapper) Close() error {
	c.closed = true
	return nil
}
