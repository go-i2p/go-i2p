package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Unit Tests for security.go — SanitizePath, ValidateConfigPath,
// CreateSecureDirectory, WriteSecureFile, IsPathSecure, SecureExistingPath
// =============================================================================

// TestSanitizePath_ValidPaths verifies that valid paths within the base directory are allowed
func TestSanitizePath_ValidPaths(t *testing.T) {
	tempDir := t.TempDir()

	testCases := []struct {
		name     string
		basePath string
		userPath string
		wantPath string // Expected suffix after base
	}{
		{
			name:     "simple relative path",
			basePath: tempDir,
			userPath: "config.yaml",
			wantPath: filepath.Join(tempDir, "config.yaml"),
		},
		{
			name:     "nested relative path",
			basePath: tempDir,
			userPath: "sub/dir/file.txt",
			wantPath: filepath.Join(tempDir, "sub/dir/file.txt"),
		},
		{
			name:     "empty user path returns base",
			basePath: tempDir,
			userPath: "",
			wantPath: tempDir,
		},
		{
			name:     "path with dots that stays within base",
			basePath: tempDir,
			userPath: "foo/../bar",
			wantPath: filepath.Join(tempDir, "bar"),
		},
		{
			name:     "absolute path within base",
			basePath: tempDir,
			userPath: filepath.Join(tempDir, "subdir", "file.txt"),
			wantPath: filepath.Join(tempDir, "subdir", "file.txt"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := SanitizePath(tc.basePath, tc.userPath)
			require.NoError(t, err, "SanitizePath(%q, %q)", tc.basePath, tc.userPath)
			assert.Equal(t, tc.wantPath, got, "SanitizePath(%q, %q)", tc.basePath, tc.userPath)
		})
	}
}

// TestSanitizePath_PathTraversal verifies that path traversal attempts are blocked
func TestSanitizePath_PathTraversal(t *testing.T) {
	tempDir := t.TempDir()

	testCases := []struct {
		name     string
		basePath string
		userPath string
	}{
		{
			name:     "simple parent traversal",
			basePath: tempDir,
			userPath: "../outside",
		},
		{
			name:     "multiple parent traversal",
			basePath: tempDir,
			userPath: "../../outside",
		},
		{
			name:     "traversal after valid path",
			basePath: tempDir,
			userPath: "valid/../../outside",
		},
		{
			name:     "absolute path outside base",
			basePath: tempDir,
			userPath: "/etc/passwd",
		},
		{
			name:     "traversal to root",
			basePath: tempDir,
			userPath: "../../../../../../../../etc/passwd",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := SanitizePath(tc.basePath, tc.userPath)
			assert.Error(t, err, "SanitizePath(%q, %q) should have returned an error for path traversal", tc.basePath, tc.userPath)
		})
	}
}

// TestSanitizePath_EmptyBasePath verifies that empty base path is rejected
func TestSanitizePath_EmptyBasePath(t *testing.T) {
	_, err := SanitizePath("", "some/path")
	assert.Error(t, err, "SanitizePath with empty base path should return an error")
}

// TestValidateConfigPath verifies the convenience wrapper works
func TestValidateConfigPath(t *testing.T) {
	basePath := BuildI2PDirPath()

	result, err := ValidateConfigPath("config.yaml")
	require.NoError(t, err, "ValidateConfigPath(\"config.yaml\")")

	expected := filepath.Join(basePath, "config.yaml")
	assert.Equal(t, expected, result, "ValidateConfigPath(\"config.yaml\")")

	// Path traversal should fail
	_, err = ValidateConfigPath("../../../etc/passwd")
	assert.Error(t, err, "ValidateConfigPath with traversal should return an error")
}

// TestCreateSecureDirectory verifies directories are created with secure permissions
func TestCreateSecureDirectory(t *testing.T) {
	tempDir := t.TempDir()
	securePath := filepath.Join(tempDir, "secure_subdir")

	require.NoError(t, CreateSecureDirectory(securePath), "CreateSecureDirectory")

	info, err := os.Stat(securePath)
	require.NoError(t, err, "Directory was not created")
	assert.True(t, info.IsDir(), "Created path is not a directory")
	assert.Equal(t, SecureDirPermissions, info.Mode().Perm(), "Directory permissions")
}

// TestCreateStandardDirectory verifies directories are created with standard permissions
func TestCreateStandardDirectory(t *testing.T) {
	tempDir := t.TempDir()
	standardPath := filepath.Join(tempDir, "standard_subdir")

	require.NoError(t, CreateStandardDirectory(standardPath), "CreateStandardDirectory")

	info, err := os.Stat(standardPath)
	require.NoError(t, err, "Directory was not created")
	assert.True(t, info.IsDir(), "Created path is not a directory")
}

// TestWriteSecureFile verifies files are created with secure permissions
func TestWriteSecureFile(t *testing.T) {
	tempDir := t.TempDir()
	securePath := filepath.Join(tempDir, "secret.txt")
	testData := []byte("secret content")

	require.NoError(t, WriteSecureFile(securePath, testData), "WriteSecureFile")

	data, err := os.ReadFile(securePath)
	require.NoError(t, err, "Could not read file")
	assert.Equal(t, string(testData), string(data), "File content mismatch")

	info, err := os.Stat(securePath)
	require.NoError(t, err, "Could not stat file")
	assert.Equal(t, SecureFilePermissions, info.Mode().Perm(), "File permissions")
}

// TestIsPathSecure verifies permission checking works
func TestIsPathSecure(t *testing.T) {
	tempDir := t.TempDir()

	// Create a file with secure permissions
	securePath := filepath.Join(tempDir, "secure.txt")
	require.NoError(t, os.WriteFile(securePath, []byte("test"), SecureFilePermissions))

	isSecure, err := IsPathSecure(securePath, 0o600)
	require.NoError(t, err, "IsPathSecure(secure)")
	assert.True(t, isSecure, "Path with 0600 should be considered secure")

	// Create a file with world-readable permissions
	insecurePath := filepath.Join(tempDir, "insecure.txt")
	require.NoError(t, os.WriteFile(insecurePath, []byte("test"), 0o644))

	isSecure, err = IsPathSecure(insecurePath, 0o600)
	require.NoError(t, err, "IsPathSecure(insecure)")
	assert.False(t, isSecure, "Path with 0644 should NOT be considered secure for max 0600")

	// Non-existent paths should be considered secure (nothing to leak)
	isSecure, err = IsPathSecure(filepath.Join(tempDir, "nonexistent.txt"), 0o600)
	require.NoError(t, err, "IsPathSecure(nonexistent)")
	assert.True(t, isSecure, "Non-existent path should be considered secure")
}

// TestSecureExistingPath verifies permission fixing works
func TestSecureExistingPath(t *testing.T) {
	tempDir := t.TempDir()

	// Create a file with insecure permissions
	filePath := filepath.Join(tempDir, "insecure.txt")
	require.NoError(t, os.WriteFile(filePath, []byte("test"), 0o644))

	require.NoError(t, SecureExistingPath(filePath, false), "SecureExistingPath(file)")

	info, err := os.Stat(filePath)
	require.NoError(t, err, "Could not stat file")
	assert.Equal(t, SecureFilePermissions, info.Mode().Perm(), "File permissions after securing")

	// Create a directory with insecure permissions
	dirPath := filepath.Join(tempDir, "insecure_dir")
	require.NoError(t, os.Mkdir(dirPath, 0o755))

	require.NoError(t, SecureExistingPath(dirPath, true), "SecureExistingPath(dir)")

	info, err = os.Stat(dirPath)
	require.NoError(t, err, "Could not stat directory")
	assert.Equal(t, SecureDirPermissions, info.Mode().Perm(), "Directory permissions after securing")
}

// TestSecureExistingPath_TypeMismatch verifies type checking
func TestSecureExistingPath_TypeMismatch(t *testing.T) {
	tempDir := t.TempDir()

	filePath := filepath.Join(tempDir, "file.txt")
	require.NoError(t, os.WriteFile(filePath, []byte("test"), 0o644))

	assert.Error(t, SecureExistingPath(filePath, true),
		"SecureExistingPath should fail when treating file as directory")

	dirPath := filepath.Join(tempDir, "dir")
	require.NoError(t, os.Mkdir(dirPath, 0o755))

	assert.Error(t, SecureExistingPath(dirPath, false),
		"SecureExistingPath should fail when treating directory as file")
}

// TestCheckDefaultPasswordWarning verifies warning is logged for default password
func TestCheckDefaultPasswordWarning(t *testing.T) {
	// This test just verifies the function doesn't panic
	// Actual log output verification would require a log capture mechanism
	CheckDefaultPasswordWarning("itoopie") // Should log warning
	CheckDefaultPasswordWarning("custom")  // Should not log warning
}

// TestSecurityConstants verifies permission constants are correct
func TestSecurityConstants(t *testing.T) {
	assert.Equal(t, os.FileMode(0o600), SecureFilePermissions, "SecureFilePermissions")
	assert.Equal(t, os.FileMode(0o700), SecureDirPermissions, "SecureDirPermissions")
	assert.Equal(t, os.FileMode(0o644), StandardFilePermissions, "StandardFilePermissions")
	assert.Equal(t, os.FileMode(0o755), StandardDirPermissions, "StandardDirPermissions")
}
