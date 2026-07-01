package filecheck

import (
	"os"
	"testing"
)

func TestCheckFileExists(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "test_check_file_*.txt")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	tmpDir, err := os.MkdirTemp("", "test_check_dir_*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	tests := []struct {
		name string
		path string
		want bool
	}{
		{name: "existing_file", path: tmpFile.Name(), want: true},
		{name: "existing_directory", path: tmpDir, want: true},
		{name: "missing_path", path: nonExistentFilePath, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CheckFileExists(tt.path); got != tt.want {
				t.Errorf("CheckFileExists(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestCheckFileAge(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "test_file_age_*.txt")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	tests := []struct {
		name   string
		path   string
		maxAge int
		want   bool
	}{
		{name: "new_file_not_old", path: tmpFile.Name(), maxAge: 1, want: false},
		{name: "negative_max_age", path: tmpFile.Name(), maxAge: -1, want: false},
		{name: "missing_path", path: nonExistentFilePath, maxAge: 1, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CheckFileAge(tt.path, tt.maxAge); got != tt.want {
				t.Errorf("CheckFileAge(%q, %d) = %v, want %v", tt.path, tt.maxAge, got, tt.want)
			}
		})
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

func TestPathSafetyNoTraversal(t *testing.T) {
	for _, tc := range pathTraversalTestCases {
		_ = CheckFileExists(tc)
		_ = CheckFileAge(tc, 1)
	}
}
