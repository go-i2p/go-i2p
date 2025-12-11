package router

import (
	"testing"
	"time"
)

// TestIsReseeding_InitialState verifies that IsReseeding returns false initially
func TestIsReseeding_InitialState(t *testing.T) {
	r := &Router{}

	if r.IsReseeding() {
		t.Error("IsReseeding() should return false for new Router")
	}
}

// TestIsReseeding_ThreadSafety verifies concurrent access to IsReseeding is safe
func TestIsReseeding_ThreadSafety(t *testing.T) {
	r := &Router{}

	// Simulate concurrent reads
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				_ = r.IsReseeding()
			}
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}
}

// TestIsReseeding_SetAndClear verifies the flag can be set and cleared
func TestIsReseeding_SetAndClear(t *testing.T) {
	r := &Router{}

	// Initially false
	if r.IsReseeding() {
		t.Error("IsReseeding() should return false initially")
	}

	// Set flag
	r.reseedMutex.Lock()
	r.isReseeding = true
	r.reseedMutex.Unlock()

	// Verify it's set
	if !r.IsReseeding() {
		t.Error("IsReseeding() should return true after setting")
	}

	// Clear flag
	r.reseedMutex.Lock()
	r.isReseeding = false
	r.reseedMutex.Unlock()

	// Verify it's cleared
	if r.IsReseeding() {
		t.Error("IsReseeding() should return false after clearing")
	}
}

// TestIsReseeding_ConcurrentSetAndRead verifies concurrent set/read operations
func TestIsReseeding_ConcurrentSetAndRead(t *testing.T) {
	r := &Router{}

	done := make(chan bool, 20)

	// Start readers
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 50; j++ {
				_ = r.IsReseeding()
				time.Sleep(time.Microsecond)
			}
			done <- true
		}()
	}

	// Start writers
	for i := 0; i < 10; i++ {
		go func(id int) {
			for j := 0; j < 50; j++ {
				r.reseedMutex.Lock()
				r.isReseeding = (id%2 == 0)
				r.reseedMutex.Unlock()
				time.Sleep(time.Microsecond)
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 20; i++ {
		<-done
	}

	// Should complete without deadlock or race conditions
}
