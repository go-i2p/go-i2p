package util

import (
	"os"
	"path/filepath"
	"testing"
)

// =============================================================================
// Integration Tests for checkfile.go — combined file operations
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
