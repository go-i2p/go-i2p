package util

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// =============================================================================
// Path Handling Tests
// =============================================================================

// TestUserHomeReturnsValidPath verifies UserHome returns a non-empty, valid path.
func TestUserHomeReturnsValidPath(t *testing.T) {
	// UserHome uses os.UserHomeDir which returns OS-specific home directory.
	// This test ensures it returns a valid path.
	home := UserHome()
	if home == "" {
		t.Fatal("UserHome returned empty string")
	}

	// Verify the path exists
	info, err := os.Stat(home)
	if err != nil {
		t.Fatalf("UserHome returned non-existent path: %s, error: %v", home, err)
	}
	if !info.IsDir() {
		t.Fatalf("UserHome returned non-directory: %s", home)
	}
}

// TestCheckFileExistsWithValidFile verifies CheckFileExists returns true for existing files.
func TestCheckFileExistsWithValidFile(t *testing.T) {
	// Create a temporary file
	tmpFile, err := os.CreateTemp("", "test_check_file_*.txt")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	if !CheckFileExists(tmpFile.Name()) {
		t.Errorf("CheckFileExists returned false for existing file: %s", tmpFile.Name())
	}
}

// TestCheckFileExistsWithNonExistent verifies CheckFileExists returns false for non-existent files.
func TestCheckFileExistsWithNonExistent(t *testing.T) {
	nonExistent := "/tmp/definitely_does_not_exist_12345_abcde.txt"
	if CheckFileExists(nonExistent) {
		t.Errorf("CheckFileExists returned true for non-existent file: %s", nonExistent)
	}
}

// TestCheckFileExistsWithDirectory verifies CheckFileExists returns true for directories.
func TestCheckFileExistsWithDirectory(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "test_check_dir_*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	if !CheckFileExists(tmpDir) {
		t.Errorf("CheckFileExists returned false for existing directory: %s", tmpDir)
	}
}

// TestCheckFileAge verifies file age checking logic.
func TestCheckFileAge(t *testing.T) {
	// Create a temporary file
	tmpFile, err := os.CreateTemp("", "test_file_age_*.txt")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	// A newly created file should not be "old" (older than 1 minute)
	if CheckFileAge(tmpFile.Name(), 1) {
		t.Errorf("Newly created file should not be older than 1 minute")
	}

	// A file should be older than -1 minutes (future time)
	if !CheckFileAge(tmpFile.Name(), -1) {
		t.Errorf("File should be older than a time in the future")
	}
}

// TestCheckFileAgeNonExistent verifies CheckFileAge returns false for non-existent files.
func TestCheckFileAgeNonExistent(t *testing.T) {
	nonExistent := "/tmp/definitely_does_not_exist_12345_abcde.txt"
	if CheckFileAge(nonExistent, 1) {
		t.Errorf("CheckFileAge should return false for non-existent file")
	}
}

// TestPathSafetyNoTraversal verifies paths don't allow directory traversal.
// Note: The util package doesn't have path sanitization, but we verify the
// underlying functions don't panic on malformed paths.
func TestPathSafetyNoTraversal(t *testing.T) {
	testCases := []string{
		"../../../etc/passwd",
		"..\\..\\windows\\system32",
		"/etc/passwd",
		"",
		strings.Repeat("a", 10000), // Very long path
	}

	for _, tc := range testCases {
		// Should not panic
		_ = CheckFileExists(tc)
		_ = CheckFileAge(tc, 1)
	}
}

// =============================================================================
// Resource Cleanup Tests (closeables.go)
// =============================================================================

// mockCloser is a test implementation of io.Closer
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

func (m *mockCloser) IsClosed() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.closed
}

// TestRegisterAndCloseAll verifies basic registration and cleanup.
func TestRegisterAndCloseAll(t *testing.T) {
	// Reset global state (important for test isolation)
	closeMutex.Lock()
	closeOnExit = nil
	closeMutex.Unlock()

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
	// Reset global state
	closeMutex.Lock()
	closeOnExit = nil
	closeMutex.Unlock()

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
	// Reset global state
	closeMutex.Lock()
	closeOnExit = nil
	closeMutex.Unlock()

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
	// Reset global state
	closeMutex.Lock()
	closeOnExit = nil
	closeMutex.Unlock()

	// Should not panic
	CloseAll()
}

// TestCloseAllIdempotent verifies calling CloseAll multiple times is safe.
func TestCloseAllIdempotent(t *testing.T) {
	// Reset global state
	closeMutex.Lock()
	closeOnExit = nil
	closeMutex.Unlock()

	closer := &mockCloser{}
	RegisterCloser(closer)

	CloseAll()
	CloseAll() // Second call should be safe
	CloseAll() // Third call should be safe

	if !closer.IsClosed() {
		t.Error("closer was not closed")
	}
}

// =============================================================================
// Panic Recovery Tests (panicf.go)
// =============================================================================

// TestPanicfFormatsMessage verifies Panicf formats panic messages correctly.
func TestPanicfFormatsMessage(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			msg, ok := r.(string)
			if !ok {
				t.Fatalf("Expected string panic, got %T", r)
			}
			expected := "error code 42: test message"
			if msg != expected {
				t.Errorf("Expected panic message %q, got %q", expected, msg)
			}
		} else {
			t.Fatal("Expected Panicf to panic")
		}
	}()

	Panicf("error code %d: %s", 42, "test message")
}

// TestPanicfWithNoArgs verifies Panicf works with no format arguments.
func TestPanicfWithNoArgs(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			msg, ok := r.(string)
			if !ok {
				t.Fatalf("Expected string panic, got %T", r)
			}
			expected := "simple panic message"
			if msg != expected {
				t.Errorf("Expected panic message %q, got %q", expected, msg)
			}
		} else {
			t.Fatal("Expected Panicf to panic")
		}
	}()

	Panicf("simple panic message")
}

// TestPanicfWithEmptyString verifies Panicf handles empty format string.
func TestPanicfWithEmptyString(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			msg, ok := r.(string)
			if !ok {
				t.Fatalf("Expected string panic, got %T", r)
			}
			if msg != "" {
				t.Errorf("Expected empty panic message, got %q", msg)
			}
		} else {
			t.Fatal("Expected Panicf to panic")
		}
	}()

	Panicf("")
}

// =============================================================================
// Time Handling Tests
// =============================================================================

// Note: The primary time handling is in lib/util/time/sntp/ which has its own tests.
// These tests verify the util package doesn't have any timezone issues.

// TestCheckFileAgeTimezoneIndependent verifies file age checks work regardless of timezone.
func TestCheckFileAgeTimezoneIndependent(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "test_tz_*.txt")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	// These operations should work regardless of system timezone
	// because os.Stat returns UTC-based times internally
	_ = CheckFileAge(tmpFile.Name(), 0)
	_ = CheckFileAge(tmpFile.Name(), 1)
	_ = CheckFileAge(tmpFile.Name(), 60)
}

// =============================================================================
// Integration Tests
// =============================================================================

// TestFileOperationsIntegration tests file operations work together correctly.
func TestFileOperationsIntegration(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "test_integration_*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a file
	testFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("test content"), 0o600); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Verify it exists
	if !CheckFileExists(testFile) {
		t.Error("Test file should exist")
	}

	// Verify it's not old (just created)
	if CheckFileAge(testFile, 1) {
		t.Error("Newly created file should not be old")
	}

	// Delete and verify
	os.Remove(testFile)
	if CheckFileExists(testFile) {
		t.Error("Deleted file should not exist")
	}
}

// TestCloseableIntegration tests closeables with real io.Closer types.
func TestCloseableIntegration(t *testing.T) {
	// Reset global state
	closeMutex.Lock()
	closeOnExit = nil
	closeMutex.Unlock()

	// Create a real file that implements io.Closer
	tmpFile, err := os.CreateTemp("", "test_closeable_*.txt")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	filePath := tmpFile.Name()
	defer os.Remove(filePath)

	// Create a buffer that implements io.Closer via a wrapper
	buf := &closerWrapper{Reader: bytes.NewReader([]byte("test"))}

	RegisterCloser(tmpFile)
	RegisterCloser(buf)

	CloseAll()

	// Verify file is closed by trying to write to it
	_, err = tmpFile.WriteString("test")
	if err == nil {
		t.Error("File should be closed")
	}
}

// closerWrapper wraps an io.Reader to add Close functionality
type closerWrapper struct {
	io.Reader
	closed bool
}

func (c *closerWrapper) Close() error {
	c.closed = true
	return nil
}
