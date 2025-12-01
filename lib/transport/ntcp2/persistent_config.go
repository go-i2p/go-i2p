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

	// Try to load existing IV
	iv, err := pc.loadObfuscationIV(ivPath)
	if err == nil {
		return iv, nil
	}

	// If file exists but is invalid, return error (don't overwrite)
	if _, statErr := os.Stat(ivPath); statErr == nil {
		return nil, err // Return the validation error from loadObfuscationIV
	}

	// File doesn't exist - generate new IV
	return pc.generateAndStoreObfuscationIV(ivPath)
}

// loadObfuscationIV reads the obfuscation IV from the specified file.
// Returns an error if the file doesn't exist or contains invalid data.
func (pc *PersistentConfig) loadObfuscationIV(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	if len(data) != obfuscationIVSize {
		return nil, oops.Wrapf(
			ErrInvalidConfig,
			"obfuscation IV file has wrong size: expected 16 bytes, got %d", len(data),
		)
	}

	return data, nil
}

// generateAndStoreObfuscationIV creates a new random obfuscation IV and saves it.
// Returns the generated IV or an error if generation/storage fails.
func (pc *PersistentConfig) generateAndStoreObfuscationIV(path string) ([]byte, error) {
	// Ensure directory exists
	if err := os.MkdirAll(pc.workingDir, 0o755); err != nil {
		return nil, WrapNTCP2Error(err, "creating config directory")
	}

	// Generate random IV
	iv := make([]byte, obfuscationIVSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, WrapNTCP2Error(err, "generating obfuscation IV")
	}

	// Save to file with restricted permissions (owner read/write only)
	if err := os.WriteFile(path, iv, 0o600); err != nil {
		return nil, WrapNTCP2Error(err, "storing obfuscation IV")
	}

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
