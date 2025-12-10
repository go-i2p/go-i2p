package ntcp2

import (
	"crypto/rand"
	"os"
	"path/filepath"

	"github.com/go-i2p/crypto/types"
	"github.com/samber/oops"
)

const (
	// obfuscationIVSize is the size of the NTCP2 obfuscation IV in bytes
	obfuscationIVSize = 16
	// obfuscationIVFilename is the name of the file storing the obfuscation IV
	obfuscationIVFilename = "ntcp2_obfuscation.dat"
)

// PersistentConfig manages persistent NTCP2 configuration data.
// It handles loading and storing the obfuscation IV which must remain
// consistent across router restarts to maintain session continuity.
type PersistentConfig struct {
	workingDir string
}

// NewPersistentConfig creates a new persistent configuration manager.
// workingDir is the router's working directory (typically ~/.go-i2p/config).
func NewPersistentConfig(workingDir string) *PersistentConfig {
	return &PersistentConfig{
		workingDir: workingDir,
	}
}

// LoadOrGenerateObfuscationIV loads the obfuscation IV from persistent storage.
// If the file doesn't exist, generates a new random IV and saves it.
// Returns an error if the file exists but contains invalid data.
// Returns the 16-byte obfuscation IV or an error if loading/generation fails.
func (pc *PersistentConfig) LoadOrGenerateObfuscationIV() ([]byte, error) {
	ivPath := filepath.Join(pc.workingDir, obfuscationIVFilename)
	log.WithField("iv_path", ivPath).Debug("Loading or generating obfuscation IV")

	// Try to load existing IV
	iv, err := pc.loadObfuscationIV(ivPath)
	if err == nil {
		log.Debug("Successfully loaded existing obfuscation IV")
		return iv, nil
	}

	// If file exists but is invalid, return error (don't overwrite)
	if _, statErr := os.Stat(ivPath); statErr == nil {
		log.WithError(err).Error("Obfuscation IV file exists but is invalid")
		return nil, err // Return the validation error from loadObfuscationIV
	}

	// File doesn't exist - generate new IV
	log.Info("Obfuscation IV file not found, generating new IV")
	return pc.generateAndStoreObfuscationIV(ivPath)
}

// loadObfuscationIV reads the obfuscation IV from the specified file.
// Returns an error if the file doesn't exist or contains invalid data.
func (pc *PersistentConfig) loadObfuscationIV(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		log.WithError(err).WithField("path", path).Debug("Failed to read obfuscation IV file")
		return nil, err
	}

	if len(data) != obfuscationIVSize {
		log.WithField("size", len(data)).Error("Obfuscation IV file has wrong size")
		return nil, oops.Wrapf(
			ErrInvalidConfig,
			"obfuscation IV file has wrong size: expected 16 bytes, got %d", len(data),
		)
	}

	log.Debug("Successfully loaded obfuscation IV from file")
	return data, nil
}

// generateAndStoreObfuscationIV creates a new random obfuscation IV and saves it.
// Returns the generated IV or an error if generation/storage fails.
func (pc *PersistentConfig) generateAndStoreObfuscationIV(path string) ([]byte, error) {
	log.WithField("path", path).Info("Generating new obfuscation IV")
	// Ensure directory exists
	if err := os.MkdirAll(pc.workingDir, 0o755); err != nil {
		log.WithError(err).Error("Failed to create config directory")
		return nil, WrapNTCP2Error(err, "creating config directory")
	}

	// Generate random IV
	iv := make([]byte, obfuscationIVSize)
	if _, err := rand.Read(iv); err != nil {
		log.WithError(err).Error("Failed to generate random obfuscation IV")
		return nil, WrapNTCP2Error(err, "generating obfuscation IV")
	}

	// Save to file with restricted permissions (owner read/write only)
	if err := os.WriteFile(path, iv, 0o600); err != nil {
		log.WithError(err).Error("Failed to store obfuscation IV to file")
		return nil, WrapNTCP2Error(err, "storing obfuscation IV")
	}

	log.Info("Successfully generated and stored new obfuscation IV")
	return iv, nil
}

// GetStaticKeyFromRouter extracts the X25519 encryption private key from the router keystore.
// This key serves as the NTCP2 static key, ensuring consistent peer identification
// across router restarts. The key is already persisted by the RouterInfoKeystore.
//
// Parameters:
//   - encryptionKey: The router's X25519 encryption private key
//
// Returns:
//   - 32-byte static key suitable for NTCP2 configuration
func GetStaticKeyFromRouter(encryptionKey types.PrivateEncryptionKey) []byte {
	// X25519 private keys are already 32 bytes - perfect for NTCP2 static key
	return encryptionKey.Bytes()
}
