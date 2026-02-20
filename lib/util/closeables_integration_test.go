package util

import (
	"bytes"
	"os"
	"testing"
)

// =============================================================================
// Integration Tests for closeables.go — real io.Closer types
// =============================================================================

// TestCloseableIntegration tests closeables with real io.Closer types.
func TestCloseableIntegration(t *testing.T) {
	resetCloseables()

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
