package keys

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDestinationKeyStore_StoreAndLoad_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	name := "test-dest"

	// Create a fresh key store
	original, err := NewDestinationKeyStore()
	require.NoError(t, err)
	require.NotNil(t, original)

	// Store to disk
	err = original.StoreKeys(dir, name)
	require.NoError(t, err)

	// Verify file was created
	filename := filepath.Join(dir, name+".dest.key")
	_, err = os.Stat(filename)
	require.NoError(t, err, "key file should exist on disk")

	// Load back
	loaded, err := LoadDestinationKeyStore(dir, name)
	require.NoError(t, err)
	require.NotNil(t, loaded)

	// Verify the destination identity is preserved (same .b32.i2p address)
	origDest := original.Destination()
	loadedDest := loaded.Destination()
	require.NotNil(t, origDest)
	require.NotNil(t, loadedDest)

	origDestBytes, err := origDest.KeysAndCert.Bytes()
	require.NoError(t, err)
	loadedDestBytes, err := loadedDest.KeysAndCert.Bytes()
	require.NoError(t, err)
	assert.Equal(t, origDestBytes, loadedDestBytes,
		"destination identity should be identical after round-trip")

	// Verify signing keys match
	origSigPriv := original.SigningPrivateKey()
	loadedSigPriv := loaded.SigningPrivateKey()
	origSigBytes := origSigPriv.(interface{ Bytes() []byte }).Bytes()
	loadedSigBytes := loadedSigPriv.(interface{ Bytes() []byte }).Bytes()
	assert.Equal(t, origSigBytes, loadedSigBytes,
		"signing private key should be identical after round-trip")

	// Verify encryption keys match
	origEncPriv := original.EncryptionPrivateKey()
	loadedEncPriv := loaded.EncryptionPrivateKey()
	assert.Equal(t, origEncPriv.Bytes(), loadedEncPriv.Bytes(),
		"encryption private key should be identical after round-trip")
}

func TestDestinationKeyStore_StoreKeys_CreatesDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "subdir")
	name := "test-dest"

	dks, err := NewDestinationKeyStore()
	require.NoError(t, err)

	err = dks.StoreKeys(dir, name)
	require.NoError(t, err)

	// Directory should have been created
	info, err := os.Stat(dir)
	require.NoError(t, err)
	assert.True(t, info.IsDir())
}

func TestDestinationKeyStore_StoreKeys_FilePermissions(t *testing.T) {
	dir := t.TempDir()
	name := "test-perm"

	dks, err := NewDestinationKeyStore()
	require.NoError(t, err)

	err = dks.StoreKeys(dir, name)
	require.NoError(t, err)

	filename := filepath.Join(dir, name+".dest.key")
	info, err := os.Stat(filename)
	require.NoError(t, err)

	// File should be owner-only readable/writable (0600)
	perm := info.Mode().Perm()
	assert.Equal(t, os.FileMode(0o600), perm,
		"key file should have 0600 permissions")
}

func TestLoadDestinationKeyStore_FileNotFound(t *testing.T) {
	dir := t.TempDir()

	_, err := LoadDestinationKeyStore(dir, "nonexistent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestLoadDestinationKeyStore_CorruptedFile(t *testing.T) {
	dir := t.TempDir()
	name := "corrupt"

	// Write garbage data
	filename := filepath.Join(dir, name+".dest.key")
	err := os.WriteFile(filename, []byte("not a valid key file"), 0o600)
	require.NoError(t, err)

	_, err = LoadDestinationKeyStore(dir, name)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid magic header")
}

func TestLoadDestinationKeyStore_TruncatedFile(t *testing.T) {
	dir := t.TempDir()
	name := "truncated"

	// Write just the magic header
	filename := filepath.Join(dir, name+".dest.key")
	err := os.WriteFile(filename, destinationKeyStoreMagicV2, 0o600)
	require.NoError(t, err)

	_, err = LoadDestinationKeyStore(dir, name)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too short")
}

func TestLoadOrCreateDestinationKeyStore_CreatesNew(t *testing.T) {
	dir := t.TempDir()
	name := "fresh"

	dks, err := LoadOrCreateDestinationKeyStore(dir, name)
	require.NoError(t, err)
	require.NotNil(t, dks)

	// File should exist now
	filename := filepath.Join(dir, name+".dest.key")
	_, err = os.Stat(filename)
	assert.NoError(t, err)
}

func TestLoadOrCreateDestinationKeyStore_LoadsExisting(t *testing.T) {
	dir := t.TempDir()
	name := "reuse"

	// Create first
	dks1, err := LoadOrCreateDestinationKeyStore(dir, name)
	require.NoError(t, err)

	// Load second time — should get same identity
	dks2, err := LoadOrCreateDestinationKeyStore(dir, name)
	require.NoError(t, err)

	dest1Bytes, err := dks1.Destination().KeysAndCert.Bytes()
	require.NoError(t, err)
	dest2Bytes, err := dks2.Destination().KeysAndCert.Bytes()
	require.NoError(t, err)
	assert.Equal(t, dest1Bytes, dest2Bytes,
		"second load should return identical destination identity")
}

func TestLoadOrCreateDestinationKeyStore_StableAcrossMultipleLoads(t *testing.T) {
	dir := t.TempDir()
	name := "stable"

	// Create once
	original, err := LoadOrCreateDestinationKeyStore(dir, name)
	require.NoError(t, err)

	origDestBytes, err := original.Destination().KeysAndCert.Bytes()
	require.NoError(t, err)

	// Load 5 times and verify identity is always the same
	for i := 0; i < 5; i++ {
		loaded, err := LoadOrCreateDestinationKeyStore(dir, name)
		require.NoError(t, err)

		loadedBytes, err := loaded.Destination().KeysAndCert.Bytes()
		require.NoError(t, err)
		assert.Equal(t, origDestBytes, loadedBytes,
			"load #%d should return identical destination", i)
	}
}

func TestDestinationKeyStore_LoadedKeysAreUsable(t *testing.T) {
	dir := t.TempDir()
	name := "usable"

	original, err := NewDestinationKeyStore()
	require.NoError(t, err)

	err = original.StoreKeys(dir, name)
	require.NoError(t, err)

	loaded, err := LoadDestinationKeyStore(dir, name)
	require.NoError(t, err)

	// Verify the loaded signing key can produce a public key
	sigPub, err := loaded.SigningPublicKey()
	assert.NoError(t, err)
	assert.NotNil(t, sigPub)

	// Verify the loaded encryption key can produce a public key
	encPub, err := loaded.EncryptionPublicKey()
	assert.NoError(t, err)
	assert.NotNil(t, encPub)
}

func TestMarshalUnmarshal_MagicHeader(t *testing.T) {
	dks, err := NewDestinationKeyStore()
	require.NoError(t, err)

	data, err := dks.marshal()
	require.NoError(t, err)

	// Check magic header
	assert.Equal(t, destinationKeyStoreMagicV2, data[:4],
		"marshaled data should start with v2 magic header")
}

func TestUnmarshal_EmptyData(t *testing.T) {
	_, err := unmarshalDestinationKeyStore([]byte{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too short")
}

func TestUnmarshal_WrongMagic(t *testing.T) {
	_, err := unmarshalDestinationKeyStore([]byte("XXXX"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid magic")
}
