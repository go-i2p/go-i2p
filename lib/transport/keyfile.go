package transport

import (
	"crypto/rand"
	"os"
	"path/filepath"

	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// ErrInvalidKeyFile is returned when a key file exists but contains invalid data.
var ErrInvalidKeyFile = oops.New("invalid key file")

// LoadOrGenerateKeyFile loads a key/IV file from the given path.
// If the file doesn't exist, it generates random bytes and saves them with mode 0o600.
// If the file exists but has an incorrect size, returns an error.
// The workingDir is used to ensure it exists with secure permissions before writing.
func LoadOrGenerateKeyFile(workingDir, filePath string, expectedSize int, keyName string) ([]byte, error) {
	log := logger.New().WithField("key_name", keyName).WithField("path", filePath)

	// Try to load existing key
	data, err := os.ReadFile(filePath)
	if err == nil {
		// File exists, validate size
		if len(data) != expectedSize {
			log.WithField("actual_size", len(data)).Errorf("Key file has wrong size: expected %d bytes", expectedSize)
			return nil, oops.Wrapf(
				ErrInvalidKeyFile,
				"%s file has wrong size: expected %d bytes, got %d",
				keyName, expectedSize, len(data),
			)
		}
		log.Debug("Successfully loaded existing key")
		return data, nil
	}

	// Check if file exists but couldn't be read (permission error, etc.)
	if _, statErr := os.Stat(filePath); statErr == nil {
		// File exists but couldn't be read
		log.WithError(err).Error("Key file exists but could not be read")
		return nil, oops.Wrapf(err, "failed to read %s file", keyName)
	}

	// File doesn't exist - generate new key
	log.Infof("Key file not found, generating new %s", keyName)

	// Ensure directory exists with owner-only permissions
	if err := config.CreateSecureDirectory(workingDir); err != nil {
		log.WithError(err).Error("Failed to create config directory")
		return nil, oops.Wrapf(err, "failed to create secure directory for %s", keyName)
	}

	// Generate random key
	key := make([]byte, expectedSize)
	if _, err := rand.Read(key); err != nil {
		log.WithError(err).Error("Failed to generate random key")
		return nil, oops.Wrapf(err, "failed to generate random %s", keyName)
	}

	// Save to file with restricted permissions (owner read/write only)
	if err := os.WriteFile(filePath, key, 0o600); err != nil {
		log.WithError(err).Error("Failed to save key file")
		return nil, oops.Wrapf(err, "failed to store %s to file", keyName)
	}

	log.Infof("Successfully generated and stored new %s", keyName)
	return key, nil
}

// LoadOrGenerateKeyFileInDir is a convenience wrapper that constructs the full path.
func LoadOrGenerateKeyFileInDir(workingDir, filename string, size int, keyName string) ([]byte, error) {
	fullPath := filepath.Join(workingDir, filename)
	return LoadOrGenerateKeyFile(workingDir, fullPath, size, keyName)
}
