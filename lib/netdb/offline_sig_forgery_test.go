// End-to-end regression tests for finding 002: a MetaLeaseSet / EncryptedLeaseSet
// carrying an unverified offline signature used to pass Verify(), so a malicious
// DatabaseStore could get a forged lease set stored, persisted and served by this
// router's netdb. The verification now happens in go-i2p/common; these tests pin
// the behavior at the floodfill store boundary.

package netdb

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/destination"
	"github.com/go-i2p/common/encrypted_leaseset"
	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/meta_leaseset"
	"github.com/go-i2p/common/offline_signature"
	sigpkg "github.com/go-i2p/common/signature"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// destWithSigningKey embeds an Ed25519 public key in a destination's signing
// key field so signatures verify against it.
func destWithSigningKey(t *testing.T, pubKey ed25519.PublicKey) destination.Destination {
	t.Helper()
	keysData := make([]byte, 384)
	copy(keysData[352:384], pubKey)
	certData := []byte{
		0x05,       // Certificate type = KEY (5)
		0x00, 0x04, // Certificate length = 4 bytes
		0x00, 0x07, // Signing key type = Ed25519 (7)
		0x00, 0x04, // Crypto key type = X25519 (4)
	}
	dest, _, err := destination.ReadDestination(append(keysData, certData...))
	require.NoError(t, err)
	return dest
}

// buildForgedMetaLeaseSetWire serializes a MetaLeaseSet for the victim
// destination whose offline signature is random bytes and whose outer signature
// is made with an attacker-chosen transient key.
func buildForgedMetaLeaseSetWire(t *testing.T) (wire []byte, victim destination.Destination) {
	t.Helper()

	victimPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	victim = destWithSigningKey(t, victimPub)

	transientPub, transientPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	forged := make([]byte, sigpkg.EdDSA_SHA512_Ed25519_SIZE)
	_, err = rand.Read(forged)
	require.NoError(t, err)

	offSig, err := offline_signature.NewOfflineSignature(
		uint32(time.Now().Add(24*time.Hour).Unix()),
		uint16(key_certificate.KEYCERT_SIGN_ED25519),
		transientPub,
		forged,
		uint16(key_certificate.KEYCERT_SIGN_ED25519),
	)
	require.NoError(t, err)

	var entryHash [32]byte
	_, err = rand.Read(entryHash[:])
	require.NoError(t, err)
	entry, err := meta_leaseset.NewMetaLeaseSetEntry(
		entryHash[:], meta_leaseset.META_LEASESET_ENTRY_TYPE_LEASESET2, 1,
		uint32(time.Now().Add(time.Hour).Unix()),
	)
	require.NoError(t, err)
	entries := []meta_leaseset.MetaLeaseSetEntry{entry}

	mls, err := meta_leaseset.NewMetaLeaseSet(
		victim, uint32(time.Now().Unix()), 600,
		meta_leaseset.META_LEASESET_FLAG_OFFLINE_KEYS, &offSig,
		common.Mapping{}, entries, nil, transientPriv,
	)
	require.NoError(t, err)

	wire, err = mls.Bytes()
	require.NoError(t, err)
	return wire, victim
}

// TestStoreMetaLeaseSetRejectsForgedOfflineSignature proves the floodfill store
// path refuses a MetaLeaseSet with a forged offline signature: neither the
// cache nor the filesystem gets the entry.
func TestStoreMetaLeaseSetRejectsForgedOfflineSignature(t *testing.T) {
	db := newTestNetDB(t)

	wire, victim := buildForgedMetaLeaseSetWire(t)

	key, err := victim.Hash()
	require.NoError(t, err)

	err = db.StoreMetaLeaseSet(key, wire, metaLeaseSetType)
	require.Error(t, err, "forged MetaLeaseSet must not be stored")
	assert.Contains(t, err.Error(), "offline signature",
		"storage must fail because the offline signature chain is invalid")

	// Nothing may be retrievable for the victim destination.
	_, ok := <-db.GetMetaLeaseSet(key)
	assert.False(t, ok, "forged entry must not be retrievable")
}

// TestStoreEncryptedLeaseSetRejectsForgedOfflineSignature proves the same for
// the EncryptedLeaseSet store path.
func TestStoreEncryptedLeaseSetRejectsForgedOfflineSignature(t *testing.T) {
	db := newTestNetDB(t)

	blindedPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	transientPub, transientPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	forged := make([]byte, sigpkg.EdDSA_SHA512_Ed25519_SIZE)
	_, err = rand.Read(forged)
	require.NoError(t, err)

	offSig, err := offline_signature.NewOfflineSignature(
		uint32(time.Now().Add(24*time.Hour).Unix()),
		uint16(key_certificate.KEYCERT_SIGN_ED25519),
		transientPub,
		forged,
		uint16(key_certificate.KEYCERT_SIGN_ED25519),
	)
	require.NoError(t, err)

	inner := make([]byte, 80)
	_, err = rand.Read(inner)
	require.NoError(t, err)

	els, err := encrypted_leaseset.NewEncryptedLeaseSet(
		uint16(key_certificate.KEYCERT_SIGN_ED25519),
		blindedPub,
		uint32(time.Now().Unix()),
		600,
		encrypted_leaseset.ENCRYPTED_LEASESET_FLAG_OFFLINE_KEYS,
		&offSig,
		inner,
		transientPriv,
	)
	require.NoError(t, err)

	wire, err := els.Bytes()
	require.NoError(t, err)

	key := common.HashData(blindedPub)

	err = db.StoreEncryptedLeaseSet(key, wire, encryptedLeaseSetType)
	require.Error(t, err, "forged EncryptedLeaseSet must not be stored")
	assert.Contains(t, err.Error(), "offline signature",
		"storage must fail because the offline signature chain is invalid")

	_, ok := <-db.GetEncryptedLeaseSet(key)
	assert.False(t, ok, "forged entry must not be retrievable")
}
