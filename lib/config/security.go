package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-i2p/logger"
)

// SecureFilePermissions for files containing sensitive data (e.g., passwords, keys)
const SecureFilePermissions = 0o600

// SecureDirPermissions for directories containing sensitive files
const SecureDirPermissions = 0o700

// StandardFilePermissions for non-sensitive configuration files
const StandardFilePermissions = 0o644

// StandardDirPermissions for non-sensitive directories
const StandardDirPermissions = 0o755

// SanitizePath cleans and validates a path to prevent directory traversal attacks.
// It ensures the path does not escape the specified base directory.
// Returns the sanitized absolute path or an error if the path is invalid.
func SanitizePath(basePath, userPath string) (string, error) {
	cleanBase, err := validateAndCleanBasePath(basePath)
	if err != nil {
		return "", err
	}

	if userPath == "" {
		return cleanBase, nil
	}

	absResolved, err := resolveUserPath(cleanBase, userPath)
	if err != nil {
		return "", err
	}

	if err := validatePathWithinBase(cleanBase, absResolved, userPath, basePath); err != nil {
		return "", err
	}

	return absResolved, nil
}

// validateAndCleanBasePath validates and returns the absolute clean base path.
func validateAndCleanBasePath(basePath string) (string, error) {
	if basePath == "" {
		return "", fmt.Errorf("base path cannot be empty")
	}

	cleanBase, err := filepath.Abs(filepath.Clean(basePath))
	if err != nil {
		return "", fmt.Errorf("invalid base path: %w", err)
	}
	return cleanBase, nil
}

// resolveUserPath resolves the user path to an absolute path.
func resolveUserPath(cleanBase, userPath string) (string, error) {
	var resolvedPath string
	if filepath.IsAbs(userPath) {
		resolvedPath = filepath.Clean(userPath)
	} else {
		resolvedPath = filepath.Clean(filepath.Join(cleanBase, userPath))
	}

	absResolved, err := filepath.Abs(resolvedPath)
	if err != nil {
		return "", fmt.Errorf("invalid path: %w", err)
	}
	return absResolved, nil
}

// validatePathWithinBase ensures the resolved path is within the base directory.
func validatePathWithinBase(cleanBase, absResolved, userPath, basePath string) error {
	baseWithSep := cleanBase + string(filepath.Separator)
	if absResolved != cleanBase && !strings.HasPrefix(absResolved, baseWithSep) {
		log.WithFields(logger.Fields{
			"at":            "SanitizePath",
			"reason":        "path_traversal_attempt",
			"base_path":     cleanBase,
			"resolved_path": absResolved,
		}).Warn("potential path traversal blocked")
		return fmt.Errorf("path %q escapes base directory %q", userPath, basePath)
	}
	return nil
}

// ValidateConfigPath validates a configuration path is safe to use.
// This is a convenience wrapper around SanitizePath using the current base directory.
func ValidateConfigPath(userPath string) (string, error) {
	basePath := BuildI2PDirPath()
	return SanitizePath(basePath, userPath)
}

// CreateSecureDirectory creates a directory with secure permissions.
// Use this for directories that contain or will contain sensitive files.
func CreateSecureDirectory(path string) error {
	// Clean the path
	cleanPath := filepath.Clean(path)

	// Create directory with secure permissions
	if err := os.MkdirAll(cleanPath, SecureDirPermissions); err != nil {
		return fmt.Errorf("failed to create secure directory %q: %w", cleanPath, err)
	}

	// Verify and fix permissions (MkdirAll may inherit from parent)
	if err := os.Chmod(cleanPath, SecureDirPermissions); err != nil {
		log.WithFields(logger.Fields{
			"at":     "CreateSecureDirectory",
			"reason": "chmod_failed",
			"path":   cleanPath,
			"error":  err.Error(),
		}).Warn("could not set secure permissions on directory")
	}

	log.WithFields(logger.Fields{
		"at":     "CreateSecureDirectory",
		"reason": "directory_created",
		"path":   cleanPath,
		"mode":   fmt.Sprintf("%04o", SecureDirPermissions),
	}).Debug("created secure directory")

	return nil
}

// CreateStandardDirectory creates a directory with standard permissions.
// Use this for directories containing non-sensitive configuration.
func CreateStandardDirectory(path string) error {
	cleanPath := filepath.Clean(path)

	if err := os.MkdirAll(cleanPath, StandardDirPermissions); err != nil {
		return fmt.Errorf("failed to create directory %q: %w", cleanPath, err)
	}

	return nil
}

// WriteSecureFile writes data to a file with secure permissions.
// Use this for files containing sensitive data like passwords or keys.
func WriteSecureFile(path string, data []byte) error {
	cleanPath := filepath.Clean(path)

	// Write with secure permissions
	if err := os.WriteFile(cleanPath, data, SecureFilePermissions); err != nil {
		return fmt.Errorf("failed to write secure file %q: %w", cleanPath, err)
	}

	// Verify permissions are set correctly
	if err := os.Chmod(cleanPath, SecureFilePermissions); err != nil {
		log.WithFields(logger.Fields{
			"at":     "WriteSecureFile",
			"reason": "chmod_failed",
			"path":   cleanPath,
			"error":  err.Error(),
		}).Warn("could not set secure permissions on file")
	}

	return nil
}

// CheckDefaultPasswordWarning logs a warning if the I2PControl password
// is still set to the default value in production environments.
func CheckDefaultPasswordWarning(password string) {
	if password == "itoopie" {
		log.WithFields(logger.Fields{
			"at":     "CheckDefaultPasswordWarning",
			"reason": "default_password_in_use",
		}).Warn("I2PControl is using the default password 'itoopie' - change this in production!")
	}
}

// IsPathSecure checks if a file or directory has secure permissions.
// Returns true if the path exists and has permissions <= maxMode.
func IsPathSecure(path string, maxMode os.FileMode) (bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return true, nil // Non-existent paths are "secure"
		}
		return false, err
	}

	// Get the permission bits only
	actualPerm := info.Mode().Perm()

	// Check if actual permissions are stricter than or equal to max allowed
	// For security, we want actual permissions to have fewer bits set
	if actualPerm&^maxMode != 0 {
		return false, nil
	}

	return true, nil
}

// SecureExistingPath attempts to secure an existing path by setting appropriate permissions.
// This is useful for paths that may have been created with insecure defaults.
func SecureExistingPath(path string, isDir bool) error {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // Nothing to secure
		}
		return err
	}

	targetMode, err := determineTargetMode(info, path, isDir)
	if err != nil {
		return err
	}

	return applySecurePermissions(path, targetMode)
}

// determineTargetMode determines the appropriate permission mode based on path type.
func determineTargetMode(info os.FileInfo, path string, expectDir bool) (os.FileMode, error) {
	if info.IsDir() {
		if expectDir {
			return SecureDirPermissions, nil
		}
		return 0, fmt.Errorf("expected file but found directory: %s", path)
	}

	if !expectDir {
		return SecureFilePermissions, nil
	}
	return 0, fmt.Errorf("expected directory but found file: %s", path)
}

// applySecurePermissions applies the target permissions and logs the change.
func applySecurePermissions(path string, targetMode os.FileMode) error {
	if err := os.Chmod(path, targetMode); err != nil {
		return fmt.Errorf("failed to secure path %q: %w", path, err)
	}

	log.WithFields(logger.Fields{
		"at":     "SecureExistingPath",
		"reason": "permissions_updated",
		"path":   path,
		"mode":   fmt.Sprintf("%04o", targetMode),
	}).Debug("updated path permissions")

	return nil
}
