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

	original, err := NewDestinationKeyStore()
	require.NoError(t, err)
	require.NotNil(t, original)

	err = original.StoreKeys(dir, name)
	require.NoError(t, err)

	filename := filepath.Join(dir, name+".dest.key")
	_, err = os.Stat(filename)
	require.NoError(t, err, "key file should exist on disk")

	loaded, err := LoadDestinationKeyStore(dir, name)
	require.NoError(t, err)
	require.NotNil(t, loaded)

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

	origSigPriv := original.SigningPrivateKey()
	loadedSigPriv := loaded.SigningPrivateKey()
	origSigBytes := origSigPriv.(interface{ Bytes() []byte }).Bytes()
	loadedSigBytes := loadedSigPriv.(interface{ Bytes() []byte }).Bytes()
	assert.Equal(t, origSigBytes, loadedSigBytes,
		"signing private key should be identical after round-trip")

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

	info, err := os.Stat(dir)
	require.NoError(t, err)
	assert.True(t, info.IsDir())
}

func TestLoadOrCreateDestinationKeyStore_CreatesNew(t *testing.T) {
	dir := t.TempDir()
	name := "fresh"

	dks, err := LoadOrCreateDestinationKeyStore(dir, name)
	require.NoError(t, err)
	require.NotNil(t, dks)

	filename := filepath.Join(dir, name+".dest.key")
	_, err = os.Stat(filename)
	assert.NoError(t, err)
}

func TestLoadOrCreateDestinationKeyStore_LoadsExisting(t *testing.T) {
	dir := t.TempDir()
	name := "reuse"

	dks1, err := LoadOrCreateDestinationKeyStore(dir, name)
	require.NoError(t, err)

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

	original, err := LoadOrCreateDestinationKeyStore(dir, name)
	require.NoError(t, err)

	origDestBytes, err := original.Destination().KeysAndCert.Bytes()
	require.NoError(t, err)

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

	sigPub, err := loaded.SigningPublicKey()
	assert.NoError(t, err)
	assert.NotNil(t, sigPub)

	encPub, err := loaded.EncryptionPublicKey()
	assert.NoError(t, err)
	assert.NotNil(t, encPub)
}

func TestLoadOrCreateDestinationKeyStore_MissingFileCreatesNew(t *testing.T) {
	dir := t.TempDir()
	name := "newkeys"
	filename := filepath.Join(dir, name+".dest.key")

	_, err := os.Stat(filename)
	require.True(t, os.IsNotExist(err))

	dks, err := LoadOrCreateDestinationKeyStore(dir, name)
	require.NoError(t, err)
	require.NotNil(t, dks)

	_, err = os.Stat(filename)
	assert.NoError(t, err, "key file should have been created")
}
