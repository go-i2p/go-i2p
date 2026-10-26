package ntcp2

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"time"

	"github.com/go-i2p/crypto/types"
	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/go-i2p/go-i2p/lib/transport"
	"github.com/samber/oops"
)

const (
	// obfuscationIVSize is the size of the NTCP2 obfuscation IV in bytes
	obfuscationIVSize = 16
	// obfuscationIVFilename is the name of the file storing the obfuscation IV
	obfuscationIVFilename = "ntcp2_obfuscation.dat"
	// lastShutdownFilename is the name of the file storing the last-shutdown
	// time (ntcp2.rst:1917-1918: "Routers must persistently store, or
	// otherwise determine, last-shutdown time, so that the previous downtime
	// may be calculated at startup").
	lastShutdownFilename = "ntcp2_last_shutdown.dat"
	// lastShutdownSize is the size of the stored last-shutdown record: 8-byte
	// big-endian Unix seconds.
	lastShutdownSize = 8
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

	// Delegate to shared transport helper
	return transport.LoadOrGenerateKeyFile(pc.workingDir, ivPath, obfuscationIVSize, "NTCP2 obfuscation IV")
}

// GetStaticKeyFromRouter extracts the X25519 encryption private key from the router keystore.
// This key serves as the NTCP2 static key, ensuring consistent peer identification
// across router restarts. The key is already persisted by the RouterInfoKeystore.
// Parameters:
// - encryptionKey: The router's X25519 encryption private key
// Returns:
// - 32-byte static key suitable for NTCP2 configuration
func GetStaticKeyFromRouter(encryptionKey types.PrivateEncryptionKey) []byte {
	// X25519 private keys are already 32 bytes - perfect for NTCP2 static key
	return encryptionKey.Bytes()
}

// SaveLastShutdownTime persistently stores the router's last-shutdown time,
// satisfying ntcp2.rst:1917-1918 ("Routers must persistently store, or
// otherwise determine, last-shutdown time, so that the previous downtime may
// be calculated at startup"). It follows the same file-location convention as
// the obfuscation IV persistence above: a mode-0600 file in the router
// working directory, created with config.CreateSecureDirectory.
//
// The time is stored as 8-byte big-endian Unix seconds. A zero time is not
// written (there was no shutdown to record).
func (pc *PersistentConfig) SaveLastShutdownTime(t time.Time) error {
	if pc.workingDir == "" {
		return oops.Errorf("no working directory configured for NTCP2 last-shutdown persistence")
	}
	if t.IsZero() {
		return nil
	}
	if err := config.CreateSecureDirectory(pc.workingDir); err != nil {
		return oops.Wrapf(err, "failed to create secure directory for NTCP2 last-shutdown file")
	}
	record := make([]byte, lastShutdownSize)
	binary.BigEndian.PutUint64(record, uint64(t.Unix()))
	path := filepath.Join(pc.workingDir, lastShutdownFilename)
	if err := os.WriteFile(path, record, 0o600); err != nil {
		return oops.Wrapf(err, "failed to store NTCP2 last-shutdown time")
	}
	log.WithField("path", path).Debug("Stored NTCP2 last-shutdown time")
	return nil
}

// LoadLastShutdownTime returns the persistently stored last-shutdown time, or
// the zero time when nothing has been stored yet (first run). Callers compute
// the previous downtime as time.Since(returned). See ntcp2.rst:1917-1918.
func (pc *PersistentConfig) LoadLastShutdownTime() (time.Time, error) {
	if pc.workingDir == "" {
		return time.Time{}, oops.Errorf("no working directory configured for NTCP2 last-shutdown persistence")
	}
	path := filepath.Join(pc.workingDir, lastShutdownFilename)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return time.Time{}, nil
		}
		return time.Time{}, oops.Wrapf(err, "failed to read NTCP2 last-shutdown file")
	}
	if len(data) != lastShutdownSize {
		return time.Time{}, oops.Wrapf(transport.ErrInvalidKeyFile,
			"NTCP2 last-shutdown file has wrong size: expected %d bytes, got %d", lastShutdownSize, len(data))
	}
	return time.Unix(int64(binary.BigEndian.Uint64(data)), 0), nil
}

// PreviousDowntime returns how long the router was down before this start,
// based on the persisted last-shutdown time (ntcp2.rst:1917-1918). The second
// return value is false when no previous shutdown has been recorded.
func (pc *PersistentConfig) PreviousDowntime() (time.Duration, bool) {
	last, err := pc.LoadLastShutdownTime()
	if err != nil || last.IsZero() {
		return 0, false
	}
	return time.Since(last), true
}
