package ssu2

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-i2p/common/data"
	ssu2noise "github.com/go-i2p/go-noise/ssu2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewPersistentConfig verifies that constructor stores the workingDir.
func TestNewPersistentConfig(t *testing.T) {
	pc := NewPersistentConfig("/some/path")
	assert.Equal(t, "/some/path", pc.workingDir)
}

// TestLoadOrGenerateObfuscationIV_GeneratesOnFirstCall checks that a fresh dir
// produces a valid 8-byte IV and persists it to disk.
func TestLoadOrGenerateObfuscationIV_GeneratesOnFirstCall(t *testing.T) {
	dir := t.TempDir()
	pc := NewPersistentConfig(dir)

	iv, err := pc.LoadOrGenerateObfuscationIV()
	require.NoError(t, err)
	assert.Len(t, iv, obfuscationIVSize)

	// File must exist.
	data, err := os.ReadFile(filepath.Join(dir, obfuscationIVFilename))
	require.NoError(t, err)
	assert.Equal(t, iv, data)
}

// TestLoadOrGenerateObfuscationIV_LoadsExisting checks that a second call
// returns the persisted IV without regenerating.
func TestLoadOrGenerateObfuscationIV_LoadsExisting(t *testing.T) {
	dir := t.TempDir()
	pc := NewPersistentConfig(dir)

	iv1, err := pc.LoadOrGenerateObfuscationIV()
	require.NoError(t, err)

	iv2, err := pc.LoadOrGenerateObfuscationIV()
	require.NoError(t, err)
	assert.Equal(t, iv1, iv2, "should return the same persisted IV")
}

// TestLoadOrGenerateObfuscationIV_RejectsCorruptFile checks that an existing
// file with the wrong size returns an error rather than overwriting.
func TestLoadOrGenerateObfuscationIV_RejectsCorruptFile(t *testing.T) {
	dir := t.TempDir()
	// Write a file with the wrong size.
	err := os.WriteFile(filepath.Join(dir, obfuscationIVFilename), []byte("bad"), 0o600)
	require.NoError(t, err)

	pc := NewPersistentConfig(dir)
	_, err = pc.LoadOrGenerateObfuscationIV()
	assert.Error(t, err, "corrupt IV file should return an error")
}

// TestLoadOrGenerateIntroKey_GeneratesOnFirstCall checks that a fresh dir
// produces a valid 32-byte introduction key and persists it.
func TestLoadOrGenerateIntroKey_GeneratesOnFirstCall(t *testing.T) {
	dir := t.TempDir()
	pc := NewPersistentConfig(dir)

	key, err := pc.LoadOrGenerateIntroKey()
	require.NoError(t, err)
	assert.Len(t, key, introKeySize)

	data, err := os.ReadFile(filepath.Join(dir, introKeyFilename))
	require.NoError(t, err)
	assert.Equal(t, key, data)
}

// TestLoadOrGenerateIntroKey_LoadsExisting checks that a second call returns
// the same persisted intro key.
func TestLoadOrGenerateIntroKey_LoadsExisting(t *testing.T) {
	dir := t.TempDir()
	pc := NewPersistentConfig(dir)

	key1, err := pc.LoadOrGenerateIntroKey()
	require.NoError(t, err)

	key2, err := pc.LoadOrGenerateIntroKey()
	require.NoError(t, err)
	assert.Equal(t, key1, key2, "should return the same persisted intro key")
}

// TestLoadOrGenerateIntroKey_RejectsCorruptFile checks that an existing file
// with the wrong size returns an error rather than overwriting.
func TestLoadOrGenerateIntroKey_RejectsCorruptFile(t *testing.T) {
	dir := t.TempDir()
	err := os.WriteFile(filepath.Join(dir, introKeyFilename), []byte("tooshort"), 0o600)
	require.NoError(t, err)

	pc := NewPersistentConfig(dir)
	_, err = pc.LoadOrGenerateIntroKey()
	assert.Error(t, err, "corrupt intro key file should return an error")
}

// TestInitKeyManagement_Integration checks that initKeyManagement wires up
// the KeyRotationManager on a real transport.
func TestInitKeyManagement_Integration(t *testing.T) {
	dir := t.TempDir()

	listener, cleanup := makeTestListener(t)
	defer cleanup()

	// Build a fresh SSU2Config with a valid static key for the rotation manager.
	routerHash := make([]byte, 32)
	_, err := rand.Read(routerHash)
	require.NoError(t, err)
	var routerHashArr data.Hash
	copy(routerHashArr[:], routerHash)
	ssu2Config, err := ssu2noise.NewSSU2Config(routerHashArr, false)
	require.NoError(t, err)
	staticKey := make([]byte, 32)
	_, err = rand.Read(staticKey)
	require.NoError(t, err)
	ssu2Config = ssu2Config.WithStaticKey(staticKey)

	trans := &SSU2Transport{
		listener: listener,
		config:   &Config{WorkingDir: dir},
		logger:   log.WithField("test", "key_management"),
	}

	err = initKeyManagement(trans, ssu2Config)
	require.NoError(t, err)

	assert.NotNil(t, trans.persistentConfig)
	assert.NotNil(t, trans.keyRotationManager)
	assert.True(t, trans.keyRotationManager.IsRunning())

	introKey := trans.GetIntroKey()
	assert.Len(t, introKey, introKeySize)

	trans.keyRotationManager.Stop()
}

// TestGetIntroKey_NilManager checks that GetIntroKey returns nil when key
// management is not initialised.
func TestGetIntroKey_NilManager(t *testing.T) {
	trans := &SSU2Transport{}
	assert.Nil(t, trans.GetIntroKey())
}
