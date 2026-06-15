package ntcp2

import (
	"path/filepath"

	"github.com/go-i2p/crypto/types"
	"github.com/go-i2p/go-i2p/lib/transport"
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

	// Delegate to shared transport helper (consolidation H-6)
	return transport.LoadOrGenerateKeyFile(pc.workingDir, ivPath, obfuscationIVSize, "NTCP2 obfuscation IV")
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
