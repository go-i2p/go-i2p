package closeables

import (
	"errors"
	"sync"
	"testing"
)

// =============================================================================
// Unit Tests for closeables.go — RegisterCloser, CloseAll
// =============================================================================

// registerClosersAndVerifyAll registers the given closers, calls CloseAll,
// and asserts every closer was closed.
func registerClosersAndVerifyAll(t *testing.T, closers ...*mockCloser) {
	t.Helper()
	resetCloseables()
	for _, c := range closers {
		RegisterCloser(c)
	}
	CloseAll()
	for i, c := range closers {
		if !c.IsClosed() {
			t.Errorf("closer%d was not closed", i+1)
		}
	}
}

// TestRegisterAndCloseAll verifies basic registration and cleanup.
func TestRegisterAndCloseAll(t *testing.T) {
	closer1 := &mockCloser{}
	closer2 := &mockCloser{}
	closer3 := &mockCloser{}

	registerClosersAndVerifyAll(t, closer1, closer2, closer3)

	// Verify list is cleared
	closeMutex.Lock()
	count := len(closeOnExit)
	closeMutex.Unlock()
	if count != 0 {
		t.Errorf("closeOnExit should be empty after CloseAll, got %d items", count)
	}
}

func TestCloseAllVariants(t *testing.T) {
	tests := []struct {
		name    string
		closers []*mockCloser
	}{
		{
			name: "all_closers_succeed",
			closers: []*mockCloser{
				{},
				{},
				{},
			},
		},
		{
			name: "close_error_does_not_stop_others",
			closers: []*mockCloser{
				{},
				{closeError: errors.New("close error")},
				{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registerClosersAndVerifyAll(t, tt.closers...)
		})
	}
}

// TestRegisterCloserThreadSafety verifies thread-safe registration.
func TestRegisterCloserThreadSafety(t *testing.T) {
	resetCloseables()

	var wg sync.WaitGroup
	numGoroutines := 100

	closers := make([]*mockCloser, numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		closers[i] = &mockCloser{}
	}

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			RegisterCloser(closers[idx])
		}(i)
	}

	wg.Wait()

	closeMutex.Lock()
	count := len(closeOnExit)
	closeMutex.Unlock()

	if count != numGoroutines {
		t.Errorf("Expected %d closers registered, got %d", numGoroutines, count)
	}

	// Clean up
	CloseAll()
}

// TestCloseAllEmptyList verifies CloseAll handles empty list gracefully.
func TestCloseAllIdempotence(t *testing.T) {
	tests := []struct {
		name          string
		registerCount int
		closeCalls    int
	}{
		{name: "empty_list", registerCount: 0, closeCalls: 1},
		{name: "multiple_close_calls", registerCount: 1, closeCalls: 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetCloseables()
			closers := make([]*mockCloser, 0, tt.registerCount)
			for i := 0; i < tt.registerCount; i++ {
				c := &mockCloser{}
				closers = append(closers, c)
				RegisterCloser(c)
			}

			for i := 0; i < tt.closeCalls; i++ {
				CloseAll()
			}

			for i, c := range closers {
				if !c.IsClosed() {
					t.Errorf("closer%d was not closed", i+1)
				}
			}
		})
	}
}
