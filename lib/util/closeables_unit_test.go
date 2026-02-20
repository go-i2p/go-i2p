package util

import (
	"errors"
	"sync"
	"testing"
)

// =============================================================================
// Unit Tests for closeables.go — RegisterCloser, CloseAll
// =============================================================================

// TestRegisterAndCloseAll verifies basic registration and cleanup.
func TestRegisterAndCloseAll(t *testing.T) {
	resetCloseables()

	closer1 := &mockCloser{}
	closer2 := &mockCloser{}
	closer3 := &mockCloser{}

	RegisterCloser(closer1)
	RegisterCloser(closer2)
	RegisterCloser(closer3)

	CloseAll()

	if !closer1.IsClosed() {
		t.Error("closer1 was not closed")
	}
	if !closer2.IsClosed() {
		t.Error("closer2 was not closed")
	}
	if !closer3.IsClosed() {
		t.Error("closer3 was not closed")
	}

	// Verify list is cleared
	closeMutex.Lock()
	count := len(closeOnExit)
	closeMutex.Unlock()
	if count != 0 {
		t.Errorf("closeOnExit should be empty after CloseAll, got %d items", count)
	}
}

// TestCloseAllWithErrors verifies errors during close don't stop other closers.
func TestCloseAllWithErrors(t *testing.T) {
	resetCloseables()

	closer1 := &mockCloser{}
	closer2 := &mockCloser{closeError: errors.New("close error")}
	closer3 := &mockCloser{}

	RegisterCloser(closer1)
	RegisterCloser(closer2) // This will error
	RegisterCloser(closer3)

	// Should not panic and should close all closers
	CloseAll()

	if !closer1.IsClosed() {
		t.Error("closer1 was not closed")
	}
	if !closer2.IsClosed() {
		t.Error("closer2 was not closed despite error")
	}
	if !closer3.IsClosed() {
		t.Error("closer3 was not closed (should continue after error)")
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
func TestCloseAllEmptyList(t *testing.T) {
	resetCloseables()

	// Should not panic
	CloseAll()
}

// TestCloseAllIdempotent verifies calling CloseAll multiple times is safe.
func TestCloseAllIdempotent(t *testing.T) {
	resetCloseables()

	closer := &mockCloser{}
	RegisterCloser(closer)

	CloseAll()
	CloseAll() // Second call should be safe
	CloseAll() // Third call should be safe

	if !closer.IsClosed() {
		t.Error("closer was not closed")
	}
}
