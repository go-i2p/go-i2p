package ssu2

import (
	"path/filepath"

	"github.com/go-i2p/go-i2p/lib/transport"
	ssu2noise "github.com/go-i2p/go-noise/ssu2"
)

const (
	// obfuscationIVSize is the size of the SSU2 ChaCha20 obfuscation IV in bytes.
	obfuscationIVSize = 8

	// obfuscationIVFilename is the name of the file storing the obfuscation IV.
	obfuscationIVFilename = "ssu2_obfuscation.dat"

	// introKeySize is the size of the SSU2 introduction key in bytes.
	introKeySize = 32

	// introKeyFilename is the name of the file storing the introduction key.
	introKeyFilename = "ssu2_intro_key.dat"
)

// PersistentConfig manages persistent SSU2 configuration data.
// It handles loading and storing the obfuscation IV and introduction key, both
// of which must remain consistent across router restarts.
type PersistentConfig struct {
	workingDir string
}

// NewPersistentConfig creates a new persistent configuration manager.
// workingDir is the router's working directory (e.g. ~/.go-i2p/config).
func NewPersistentConfig(workingDir string) *PersistentConfig {
	return &PersistentConfig{workingDir: workingDir}
}

// LoadOrGenerateObfuscationIV loads the 8-byte ChaCha20 obfuscation IV from
// persistent storage, or generates and stores a new one if the file is absent.
// Returns an error if the file exists but contains invalid data.
func (pc *PersistentConfig) LoadOrGenerateObfuscationIV() ([]byte, error) {
	ivPath := filepath.Join(pc.workingDir, obfuscationIVFilename)
	log.WithField("iv_path", ivPath).Debug("loading or generating SSU2 obfuscation IV")

	// Delegate to shared transport helper (consolidation H-6)
	return transport.LoadOrGenerateKeyFile(pc.workingDir, ivPath, obfuscationIVSize, "SSU2 obfuscation IV")
}

// LoadOrGenerateIntroKey loads the 32-byte introduction key from persistent
// storage, or generates and stores a new one if the file is absent.
// Returns an error if the file exists but contains invalid data.
func (pc *PersistentConfig) LoadOrGenerateIntroKey() ([]byte, error) {
	keyPath := filepath.Join(pc.workingDir, introKeyFilename)
	log.WithField("key_path", keyPath).Debug("loading or generating SSU2 intro key")

	// Delegate to shared transport helper (consolidation H-6)
	return transport.LoadOrGenerateKeyFile(pc.workingDir, keyPath, introKeySize, "SSU2 intro key")
}

// initKeyManagement sets up the PersistentConfig, loads/generates the intro key
// and obfuscation IV, wires them into ssu2Config, and starts the
// KeyRotationManager for the transport.
func initKeyManagement(t *SSU2Transport, ssu2Config *ssu2noise.SSU2Config) error {
	// R-2 fix: Atomic config snapshot
	cfg := t.config.Load()
	pc := NewPersistentConfig(cfg.WorkingDir)
	t.persistentConfig = pc

	introKey, err := pc.LoadOrGenerateIntroKey()
	if err != nil {
		return WrapSSU2Error(err, "loading intro key")
	}

	obfuscationIV, err := pc.LoadOrGenerateObfuscationIV()
	if err != nil {
		return WrapSSU2Error(err, "loading obfuscation IV")
	}

	// Apply obfuscation IV to the SSU2Config so new sessions use it.
	ssu2Config.WithChaChaObfuscation(true, obfuscationIV)

	staticKey := ssu2Config.StaticKey
	krm, err := ssu2noise.NewKeyRotationManager(staticKey, introKey, true)
	if err != nil {
		return WrapSSU2Error(err, "creating key rotation manager")
	}

	krm.SetRotationCallback(func(keyType string, oldKey, newKey *ssu2noise.ManagedKey) {
		log.WithFields(map[string]interface{}{
			"key_type": keyType,
		}).Info("SSU2 key rotated")
	})

	krm.Start()
	t.keyRotationManager = krm

	// Wire the intro key into the SSU2Config so that header protection is
	// initialised for inbound connections (initHeaderProtection requires a
	// non-nil IntroKey of length HeaderKeySize == 32).
	ssu2Config.IntroKey = introKey

	return nil
}

// GetIntroKey returns the current introduction key, or nil if key management is
// not initialised.
func (t *SSU2Transport) GetIntroKey() []byte {
	if t.keyRotationManager == nil {
		return nil
	}
	return t.keyRotationManager.GetIntroKey()
}
