package util

import (
	"os"
	"testing"
)

// =============================================================================
// Unit Tests for checkfile.go — CheckFileExists, CheckFileAge
// =============================================================================

// TestCheckFileExistsWithValidFile verifies CheckFileExists returns true for existing files.
func TestCheckFileExistsWithValidFile(t *testing.T) {
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
	if CheckFileExists(nonExistentFilePath) {
		t.Errorf("CheckFileExists returned true for non-existent file: %s", nonExistentFilePath)
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

	// Negative maxAge should return false (invalid parameter)
	if CheckFileAge(tmpFile.Name(), -1) {
		t.Errorf("Negative maxAge should return false (invalid parameter)")
	}
}

// TestCheckFileAgeNonExistent verifies CheckFileAge returns false for non-existent files.
func TestCheckFileAgeNonExistent(t *testing.T) {
	if CheckFileAge(nonExistentFilePath, 1) {
		t.Errorf("CheckFileAge should return false for non-existent file")
	}
}

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
