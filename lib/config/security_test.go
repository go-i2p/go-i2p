package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

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
			if err != nil {
				t.Fatalf("SanitizePath(%q, %q) returned error: %v", tc.basePath, tc.userPath, err)
			}
			if got != tc.wantPath {
				t.Errorf("SanitizePath(%q, %q) = %q, want %q", tc.basePath, tc.userPath, got, tc.wantPath)
			}
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
			if err == nil {
				t.Errorf("SanitizePath(%q, %q) should have returned an error for path traversal", tc.basePath, tc.userPath)
			}
		})
	}
}

// TestSanitizePath_EmptyBasePath verifies that empty base path is rejected
func TestSanitizePath_EmptyBasePath(t *testing.T) {
	_, err := SanitizePath("", "some/path")
	if err == nil {
		t.Error("SanitizePath with empty base path should return an error")
	}
}

// TestValidateConfigPath verifies the convenience wrapper works
func TestValidateConfigPath(t *testing.T) {
	// ValidateConfigPath uses BuildI2PDirPath() as base
	basePath := BuildI2PDirPath()

	// Valid relative path should work
	result, err := ValidateConfigPath("config.yaml")
	if err != nil {
		t.Fatalf("ValidateConfigPath(\"config.yaml\") returned error: %v", err)
	}

	expected := filepath.Join(basePath, "config.yaml")
	if result != expected {
		t.Errorf("ValidateConfigPath(\"config.yaml\") = %q, want %q", result, expected)
	}

	// Path traversal should fail
	_, err = ValidateConfigPath("../../../etc/passwd")
	if err == nil {
		t.Error("ValidateConfigPath with traversal should return an error")
	}
}

// TestCreateSecureDirectory verifies directories are created with secure permissions
func TestCreateSecureDirectory(t *testing.T) {
	tempDir := t.TempDir()
	securePath := filepath.Join(tempDir, "secure_subdir")

	err := CreateSecureDirectory(securePath)
	if err != nil {
		t.Fatalf("CreateSecureDirectory(%q) returned error: %v", securePath, err)
	}

	// Verify directory exists
	info, err := os.Stat(securePath)
	if err != nil {
		t.Fatalf("Directory was not created: %v", err)
	}
	if !info.IsDir() {
		t.Error("Created path is not a directory")
	}

	// Verify permissions (on Unix-like systems)
	perm := info.Mode().Perm()
	if perm != SecureDirPermissions {
		t.Errorf("Directory permissions = %04o, want %04o", perm, SecureDirPermissions)
	}
}

// TestCreateStandardDirectory verifies directories are created with standard permissions
func TestCreateStandardDirectory(t *testing.T) {
	tempDir := t.TempDir()
	standardPath := filepath.Join(tempDir, "standard_subdir")

	err := CreateStandardDirectory(standardPath)
	if err != nil {
		t.Fatalf("CreateStandardDirectory(%q) returned error: %v", standardPath, err)
	}

	// Verify directory exists
	info, err := os.Stat(standardPath)
	if err != nil {
		t.Fatalf("Directory was not created: %v", err)
	}
	if !info.IsDir() {
		t.Error("Created path is not a directory")
	}
}

// TestWriteSecureFile verifies files are created with secure permissions
func TestWriteSecureFile(t *testing.T) {
	tempDir := t.TempDir()
	securePath := filepath.Join(tempDir, "secret.txt")
	testData := []byte("secret content")

	err := WriteSecureFile(securePath, testData)
	if err != nil {
		t.Fatalf("WriteSecureFile(%q) returned error: %v", securePath, err)
	}

	// Verify file exists and has correct content
	data, err := os.ReadFile(securePath)
	if err != nil {
		t.Fatalf("Could not read file: %v", err)
	}
	if string(data) != string(testData) {
		t.Error("File content mismatch")
	}

	// Verify permissions
	info, err := os.Stat(securePath)
	if err != nil {
		t.Fatalf("Could not stat file: %v", err)
	}

	perm := info.Mode().Perm()
	if perm != SecureFilePermissions {
		t.Errorf("File permissions = %04o, want %04o", perm, SecureFilePermissions)
	}
}

// TestIsPathSecure verifies permission checking works
func TestIsPathSecure(t *testing.T) {
	tempDir := t.TempDir()

	// Create a file with secure permissions
	securePath := filepath.Join(tempDir, "secure.txt")
	if err := os.WriteFile(securePath, []byte("test"), SecureFilePermissions); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Should be secure with maxMode of 0600
	isSecure, err := IsPathSecure(securePath, 0o600)
	if err != nil {
		t.Fatalf("IsPathSecure returned error: %v", err)
	}
	if !isSecure {
		t.Error("Path with 0600 should be considered secure")
	}

	// Create a file with world-readable permissions
	insecurePath := filepath.Join(tempDir, "insecure.txt")
	if err := os.WriteFile(insecurePath, []byte("test"), 0o644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Should not be secure with maxMode of 0600
	isSecure, err = IsPathSecure(insecurePath, 0o600)
	if err != nil {
		t.Fatalf("IsPathSecure returned error: %v", err)
	}
	if isSecure {
		t.Error("Path with 0644 should NOT be considered secure for max 0600")
	}

	// Non-existent paths should be considered secure (nothing to leak)
	isSecure, err = IsPathSecure(filepath.Join(tempDir, "nonexistent.txt"), 0o600)
	if err != nil {
		t.Fatalf("IsPathSecure returned error for non-existent: %v", err)
	}
	if !isSecure {
		t.Error("Non-existent path should be considered secure")
	}
}

// TestSecureExistingPath verifies permission fixing works
func TestSecureExistingPath(t *testing.T) {
	tempDir := t.TempDir()

	// Create a file with insecure permissions
	filePath := filepath.Join(tempDir, "insecure.txt")
	if err := os.WriteFile(filePath, []byte("test"), 0o644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Secure it
	if err := SecureExistingPath(filePath, false); err != nil {
		t.Fatalf("SecureExistingPath returned error: %v", err)
	}

	// Verify permissions were updated
	info, err := os.Stat(filePath)
	if err != nil {
		t.Fatalf("Could not stat file: %v", err)
	}

	perm := info.Mode().Perm()
	if perm != SecureFilePermissions {
		t.Errorf("File permissions after securing = %04o, want %04o", perm, SecureFilePermissions)
	}

	// Create a directory with insecure permissions
	dirPath := filepath.Join(tempDir, "insecure_dir")
	if err := os.Mkdir(dirPath, 0o755); err != nil {
		t.Fatalf("Failed to create test directory: %v", err)
	}

	// Secure it
	if err := SecureExistingPath(dirPath, true); err != nil {
		t.Fatalf("SecureExistingPath returned error for dir: %v", err)
	}

	// Verify permissions were updated
	info, err = os.Stat(dirPath)
	if err != nil {
		t.Fatalf("Could not stat directory: %v", err)
	}

	perm = info.Mode().Perm()
	if perm != SecureDirPermissions {
		t.Errorf("Directory permissions after securing = %04o, want %04o", perm, SecureDirPermissions)
	}
}

// TestSecureExistingPath_TypeMismatch verifies type checking
func TestSecureExistingPath_TypeMismatch(t *testing.T) {
	tempDir := t.TempDir()

	// Create a file
	filePath := filepath.Join(tempDir, "file.txt")
	if err := os.WriteFile(filePath, []byte("test"), 0o644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Try to secure as directory should fail
	err := SecureExistingPath(filePath, true)
	if err == nil {
		t.Error("SecureExistingPath should fail when treating file as directory")
	}

	// Create a directory
	dirPath := filepath.Join(tempDir, "dir")
	if err := os.Mkdir(dirPath, 0o755); err != nil {
		t.Fatalf("Failed to create test directory: %v", err)
	}

	// Try to secure as file should fail
	err = SecureExistingPath(dirPath, false)
	if err == nil {
		t.Error("SecureExistingPath should fail when treating directory as file")
	}
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
	// Secure file permissions should be owner-only read/write
	if SecureFilePermissions != 0o600 {
		t.Errorf("SecureFilePermissions = %04o, want 0600", SecureFilePermissions)
	}

	// Secure directory permissions should be owner-only rwx
	if SecureDirPermissions != 0o700 {
		t.Errorf("SecureDirPermissions = %04o, want 0700", SecureDirPermissions)
	}

	// Standard file permissions should be owner read/write, others read
	if StandardFilePermissions != 0o644 {
		t.Errorf("StandardFilePermissions = %04o, want 0644", StandardFilePermissions)
	}

	// Standard directory permissions should be owner rwx, others rx
	if StandardDirPermissions != 0o755 {
		t.Errorf("StandardDirPermissions = %04o, want 0755", StandardDirPermissions)
	}
}

// TestDefaults_SecuritySensitiveValues verifies security-related defaults
func TestDefaults_SecuritySensitiveValues(t *testing.T) {
	cfg := Defaults()

	// I2CP should bind to localhost only by default
	if cfg.I2CP.Address != "localhost:7654" {
		t.Errorf("I2CP.Address should be localhost-only, got %s", cfg.I2CP.Address)
	}

	// I2PControl should bind to localhost only by default
	if cfg.I2PControl.Address != "localhost:7650" {
		t.Errorf("I2PControl.Address should be localhost-only, got %s", cfg.I2PControl.Address)
	}

	// NTCP2/SSU2 ports should be 0 (random) for privacy
	if cfg.Transport.NTCP2Port != 0 {
		t.Errorf("Transport.NTCP2Port should be 0 (random), got %d", cfg.Transport.NTCP2Port)
	}
	if cfg.Transport.SSU2Port != 0 {
		t.Errorf("Transport.SSU2Port should be 0 (random), got %d", cfg.Transport.SSU2Port)
	}

	// Token expiration should be reasonable (not too long - 30 minutes max)
	maxTokenExpiration := 30 * time.Minute
	if cfg.I2PControl.TokenExpiration > maxTokenExpiration {
		t.Errorf("I2PControl.TokenExpiration is too long: %v (max %v)", cfg.I2PControl.TokenExpiration, maxTokenExpiration)
	}

	// Session timeout should be reasonable (1 hour max)
	maxSessionTimeout := 1 * time.Hour
	if cfg.I2CP.SessionTimeout > maxSessionTimeout {
		t.Errorf("I2CP.SessionTimeout is too long: %v (max %v)", cfg.I2CP.SessionTimeout, maxSessionTimeout)
	}
}

// TestDefaults_TimeoutsAreSafe verifies timeout values are safe
func TestDefaults_TimeoutsAreSafe(t *testing.T) {
	cfg := Defaults()

	// Connection timeout should be at least 10 seconds
	minConnectionTimeout := 10 * time.Second
	if cfg.Transport.ConnectionTimeout < minConnectionTimeout {
		t.Errorf("Transport.ConnectionTimeout is too short: %v (min %v)", cfg.Transport.ConnectionTimeout, minConnectionTimeout)
	}

	// Connection timeout should not be too long (DoS risk)
	maxConnectionTimeout := 2 * time.Minute
	if cfg.Transport.ConnectionTimeout > maxConnectionTimeout {
		t.Errorf("Transport.ConnectionTimeout is too long: %v (max %v)", cfg.Transport.ConnectionTimeout, maxConnectionTimeout)
	}

	// Idle timeout should allow for reasonable session duration
	minIdleTimeout := 1 * time.Minute
	if cfg.Transport.IdleTimeout < minIdleTimeout {
		t.Errorf("Transport.IdleTimeout is too short: %v (min %v)", cfg.Transport.IdleTimeout, minIdleTimeout)
	}
}
