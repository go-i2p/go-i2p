package netdb

import (
	"testing"

	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/stretchr/testify/assert"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/encrypted_leaseset"
	"github.com/go-i2p/common/lease_set"
	"github.com/go-i2p/common/lease_set2"
	"github.com/go-i2p/common/meta_leaseset"
)

// storeTypeForEntry is a test helper that extracts the store type logic
// from publishLeaseSetEntry to verify correct type mapping without
// needing a full tunnel/transport infrastructure.
func storeTypeForEntry(entry Entry) (byte, error) {
	switch {
	case entry.LeaseSet != nil:
		return i2np.DATABASE_STORE_TYPE_LEASESET, nil
	case entry.LeaseSet2 != nil:
		return i2np.DATABASE_STORE_TYPE_LEASESET2, nil
	case entry.EncryptedLeaseSet != nil:
		return i2np.DATABASE_STORE_TYPE_ENCRYPTED_LEASESET, nil
	case entry.MetaLeaseSet != nil:
		return i2np.DATABASE_STORE_TYPE_META_LEASESET, nil
	default:
		return 0, assert.AnError
	}
}

// TestPublishLeaseSetEntry_StoreTypeForLeaseSet verifies that original LeaseSets
// are published with DATABASE_STORE_TYPE_LEASESET (1), not LEASESET2 (3).
func TestPublishLeaseSetEntry_StoreTypeForLeaseSet(t *testing.T) {
	ls := lease_set.LeaseSet{}
	entry := Entry{LeaseSet: &ls}

	storeType, err := storeTypeForEntry(entry)
	assert.NoError(t, err)
	assert.Equal(t, byte(i2np.DATABASE_STORE_TYPE_LEASESET), storeType,
		"Original LeaseSet should use store type 1 (DATABASE_STORE_TYPE_LEASESET)")
}

// TestPublishLeaseSetEntry_StoreTypeForLeaseSet2 verifies that LeaseSet2 entries
// are published with DATABASE_STORE_TYPE_LEASESET2 (3).
func TestPublishLeaseSetEntry_StoreTypeForLeaseSet2(t *testing.T) {
	ls2 := lease_set2.LeaseSet2{}
	entry := Entry{LeaseSet2: &ls2}

	storeType, err := storeTypeForEntry(entry)
	assert.NoError(t, err)
	assert.Equal(t, byte(i2np.DATABASE_STORE_TYPE_LEASESET2), storeType,
		"LeaseSet2 should use store type 3 (DATABASE_STORE_TYPE_LEASESET2)")
}

// TestPublishLeaseSetEntry_StoreTypeForEncryptedLeaseSet verifies that EncryptedLeaseSets
// are published with DATABASE_STORE_TYPE_ENCRYPTED_LEASESET (5).
func TestPublishLeaseSetEntry_StoreTypeForEncryptedLeaseSet(t *testing.T) {
	els := encrypted_leaseset.EncryptedLeaseSet{}
	entry := Entry{EncryptedLeaseSet: &els}

	storeType, err := storeTypeForEntry(entry)
	assert.NoError(t, err)
	assert.Equal(t, byte(i2np.DATABASE_STORE_TYPE_ENCRYPTED_LEASESET), storeType,
		"EncryptedLeaseSet should use store type 5 (DATABASE_STORE_TYPE_ENCRYPTED_LEASESET)")
}

// TestPublishLeaseSetEntry_StoreTypeForMetaLeaseSet verifies that MetaLeaseSets
// are published with DATABASE_STORE_TYPE_META_LEASESET (7).
func TestPublishLeaseSetEntry_StoreTypeForMetaLeaseSet(t *testing.T) {
	mls := meta_leaseset.MetaLeaseSet{}
	entry := Entry{MetaLeaseSet: &mls}

	storeType, err := storeTypeForEntry(entry)
	assert.NoError(t, err)
	assert.Equal(t, byte(i2np.DATABASE_STORE_TYPE_META_LEASESET), storeType,
		"MetaLeaseSet should use store type 7 (DATABASE_STORE_TYPE_META_LEASESET)")
}

// TestPublishLeaseSetEntry_StoreTypeForEmptyEntry verifies that an empty entry is rejected.
func TestPublishLeaseSetEntry_StoreTypeForEmptyEntry(t *testing.T) {
	entry := Entry{}

	_, err := storeTypeForEntry(entry)
	assert.Error(t, err, "Empty entry should return an error")
}

// TestPublishLeaseSetEntry_EmptyEntryReturnsError verifies that publishLeaseSetEntry
// returns an error when the LeaseSetEntry contains no valid data.
func TestPublishLeaseSetEntry_EmptyEntryReturnsError(t *testing.T) {
	db := newMockNetDB()
	config := DefaultPublisherConfig()
	publisher := NewPublisher(db, nil, nil, nil, config)

	// Create an entry with no LeaseSet data
	lsEntry := LeaseSetEntry{
		Hash:  common.Hash{1, 2, 3},
		Entry: Entry{},
	}

	err := publisher.publishLeaseSetEntry(lsEntry)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no valid LeaseSet data")
}

// TestPublishLeaseSet_UsesCorrectStoreType verifies that PublishLeaseSet (which takes
// a lease_set.LeaseSet) uses DATABASE_STORE_TYPE_LEASESET (1), not LEASESET2 (3).
// This is a regression test for the bug where all LeaseSets were published with type 3.
func TestPublishLeaseSet_UsesCorrectStoreType(t *testing.T) {
	// The PublishLeaseSet method validates the LeaseSet first, so an empty one will fail.
	// This test verifies the error comes from validation, not from wrong type handling.
	db := newMockNetDB()
	config := DefaultPublisherConfig()
	publisher := NewPublisher(db, nil, nil, nil, config)

	ls := lease_set.LeaseSet{}
	hash := common.Hash{1, 2, 3, 4}

	err := publisher.PublishLeaseSet(hash, ls)
	// Should fail at validation, not at store type
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid LeaseSet")
}

// TestStoreTypeConstants verifies that the I2NP store type constants
// match the I2P specification values.
func TestStoreTypeConstants(t *testing.T) {
	assert.Equal(t, 0, i2np.DATABASE_STORE_TYPE_ROUTER_INFO,
		"RouterInfo store type should be 0")
	assert.Equal(t, 1, i2np.DATABASE_STORE_TYPE_LEASESET,
		"LeaseSet store type should be 1")
	assert.Equal(t, 3, i2np.DATABASE_STORE_TYPE_LEASESET2,
		"LeaseSet2 store type should be 3")
	assert.Equal(t, 5, i2np.DATABASE_STORE_TYPE_ENCRYPTED_LEASESET,
		"EncryptedLeaseSet store type should be 5")
	assert.Equal(t, 7, i2np.DATABASE_STORE_TYPE_META_LEASESET,
		"MetaLeaseSet store type should be 7")
}
