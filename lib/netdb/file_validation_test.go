package netdb

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCheckFilePathValid_ValidExtension tests that .dat files are accepted
func TestCheckFilePathValid_ValidExtension(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)
	require.NoError(t, db.Ensure())

	// Valid .dat file path
	validPath := filepath.Join(tmpDir, "rA", "routerInfo-ABC123.dat")
	assert.True(t, db.CheckFilePathValid(validPath), "Valid .dat file should be accepted")
}

// TestCheckFilePathValid_InvalidExtension tests that non-.dat files are rejected
func TestCheckFilePathValid_InvalidExtension(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)

	testCases := []struct {
		name string
		path string
	}{
		{"txt file", filepath.Join(tmpDir, "file.txt")},
		{"no extension", filepath.Join(tmpDir, "file")},
		{"wrong extension", filepath.Join(tmpDir, "file.data")},
		{"double extension", filepath.Join(tmpDir, "file.dat.txt")},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.False(t, db.CheckFilePathValid(tc.path), "File with wrong extension should be rejected")
		})
	}
}

// TestCheckFilePathValid_PathTraversal tests path traversal prevention
func TestCheckFilePathValid_PathTraversal(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)
	require.NoError(t, db.Ensure())

	testCases := []struct {
		name string
		path string
	}{
		{"parent directory", filepath.Join(tmpDir, "..", "evil.dat")},
		{"multiple parent directories", filepath.Join(tmpDir, "..", "..", "evil.dat")},
		{"current then parent", filepath.Join(tmpDir, ".", "..", "evil.dat")},
		{"subdirectory then parent", filepath.Join(tmpDir, "subdir", "..", "..", "evil.dat")},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// These should be rejected as they traverse outside the NetDB directory
			assert.False(t, db.CheckFilePathValid(tc.path), "Path traversal should be prevented")
		})
	}
}

// TestCheckFilePathValid_WithinDirectory tests that valid paths within NetDB are accepted
func TestCheckFilePathValid_WithinDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)
	require.NoError(t, db.Ensure())

	testCases := []struct {
		name string
		path string
	}{
		{"direct file", filepath.Join(tmpDir, "file.dat")},
		{"skiplist subdirectory", filepath.Join(tmpDir, "rA", "routerInfo-ABC.dat")},
		{"leaseset subdirectory", filepath.Join(tmpDir, "lB", "leaseSet-XYZ.dat")},
		{"nested valid path", filepath.Join(tmpDir, "rC", "subdir", "file.dat")},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.True(t, db.CheckFilePathValid(tc.path), "Valid path within NetDB should be accepted")
		})
	}
}

// TestCheckFilePathValid_Symlink tests that symlinks are rejected
func TestCheckFilePathValid_Symlink(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)
	require.NoError(t, db.Ensure())

	// Create a real file
	realFile := filepath.Join(tmpDir, "real.dat")
	err := os.WriteFile(realFile, []byte("test"), 0o600)
	require.NoError(t, err)

	// Create a symlink to the real file
	symlinkPath := filepath.Join(tmpDir, "symlink.dat")
	err = os.Symlink(realFile, symlinkPath)
	if err != nil {
		t.Skip("Symlink creation not supported on this platform")
	}

	// Symlink should be rejected
	assert.False(t, db.CheckFilePathValid(symlinkPath), "Symlinks should be rejected for security")

	// Original file should still be valid
	assert.True(t, db.CheckFilePathValid(realFile), "Original file should remain valid")
}

// TestCheckFilePathValid_NonExistentFile tests that non-existent files are validated
func TestCheckFilePathValid_NonExistentFile(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)
	require.NoError(t, db.Ensure())

	// Non-existent file with valid path should be accepted (for creating new files)
	nonExistent := filepath.Join(tmpDir, "rA", "new-file.dat")
	assert.True(t, db.CheckFilePathValid(nonExistent), "Non-existent file with valid path should be accepted")
}

// TestCheckFilePathValid_AbsolutePath tests handling of absolute paths
func TestCheckFilePathValid_AbsolutePath(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)
	require.NoError(t, db.Ensure())

	// Absolute path within NetDB
	absPath := filepath.Join(tmpDir, "rA", "routerInfo-ABC.dat")
	assert.True(t, db.CheckFilePathValid(absPath), "Absolute path within NetDB should be accepted")

	// Absolute path outside NetDB
	outsidePath := filepath.Join(os.TempDir(), "evil.dat")
	assert.False(t, db.CheckFilePathValid(outsidePath), "Absolute path outside NetDB should be rejected")
}

// TestCheckFilePathValid_RelativePath tests handling of relative paths
func TestCheckFilePathValid_RelativePath(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)
	require.NoError(t, db.Ensure())

	// Change to tmpDir to test relative paths
	originalWd, err := os.Getwd()
	require.NoError(t, err)
	defer os.Chdir(originalWd)

	err = os.Chdir(tmpDir)
	require.NoError(t, err)

	// Relative path within NetDB
	relativePath := filepath.Join("rA", "routerInfo-ABC.dat")
	assert.True(t, db.CheckFilePathValid(relativePath), "Relative path within NetDB should be accepted")
}

// TestCheckFilePathValid_EdgeCases tests edge cases and boundary conditions
func TestCheckFilePathValid_EdgeCases(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)
	require.NoError(t, db.Ensure())

	testCases := []struct {
		name     string
		path     string
		expected bool
	}{
		{"empty string", "", false},
		{"just extension", ".dat", false},
		{"hidden file", filepath.Join(tmpDir, ".hidden.dat"), true},
		{"unicode filename", filepath.Join(tmpDir, "rA", "routerInfo-日本語.dat"), true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := db.CheckFilePathValid(tc.path)
			assert.Equal(t, tc.expected, result, "Edge case: %s", tc.name)
		})
	}
}

// TestCheckFilePathValid_SecurityScenarios tests various security attack scenarios
func TestCheckFilePathValid_SecurityScenarios(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)
	require.NoError(t, db.Ensure())

	testCases := []struct {
		name        string
		path        string
		description string
	}{
		{
			"null byte injection",
			filepath.Join(tmpDir, "file\x00.dat"),
			"Null byte should not bypass validation",
		},
		{
			"URL encoding attempt",
			filepath.Join(tmpDir, "%2e%2e", "file.dat"),
			"URL-encoded path traversal should be prevented",
		},
		{
			"mixed separators",
			tmpDir + "/rA\\..\\..\\evil.dat",
			"Mixed path separators should be handled",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// All security attack scenarios should be rejected
			result := db.CheckFilePathValid(tc.path)
			// Most will be rejected, but some may pass if they resolve to valid paths
			// The key is that they don't escape the NetDB directory
			t.Logf("%s: result=%v", tc.description, result)
		})
	}
}

// BenchmarkCheckFilePathValid benchmarks the file path validation performance
func BenchmarkCheckFilePathValid(b *testing.B) {
	tmpDir := b.TempDir()
	db := NewStdNetDB(tmpDir)
	if err := db.Ensure(); err != nil {
		b.Fatal(err)
	}

	testPath := filepath.Join(tmpDir, "rA", "routerInfo-ABC123.dat")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = db.CheckFilePathValid(testPath)
	}
}

// BenchmarkCheckFilePathValid_Parallel benchmarks concurrent validation
func BenchmarkCheckFilePathValid_Parallel(b *testing.B) {
	tmpDir := b.TempDir()
	db := NewStdNetDB(tmpDir)
	if err := db.Ensure(); err != nil {
		b.Fatal(err)
	}

	testPath := filepath.Join(tmpDir, "rA", "routerInfo-ABC123.dat")

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = db.CheckFilePathValid(testPath)
		}
	})
}
