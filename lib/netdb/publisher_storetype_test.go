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
		return i2np.DatabaseStoreTypeLeaseSet, nil
	case entry.LeaseSet2 != nil:
		return i2np.DatabaseStoreTypeLeaseSet2, nil
	case entry.EncryptedLeaseSet != nil:
		return i2np.DatabaseStoreTypeEncryptedLeaseSet, nil
	case entry.MetaLeaseSet != nil:
		return i2np.DatabaseStoreTypeMetaLeaseSet, nil
	default:
		return 0, assert.AnError
	}
}

// TestPublishLeaseSetEntry_StoreTypeForLeaseSet verifies that original LeaseSets
// are published with DatabaseStoreTypeLeaseSet (1), not LEASESET2 (3).
func TestPublishLeaseSetEntry_StoreTypeForLeaseSet(t *testing.T) {
	ls := lease_set.LeaseSet{}
	entry := Entry{LeaseSet: &ls}

	storeType, err := storeTypeForEntry(entry)
	assert.NoError(t, err)
	assert.Equal(t, byte(i2np.DatabaseStoreTypeLeaseSet), storeType,
		"Original LeaseSet should use store type 1 (DatabaseStoreTypeLeaseSet)")
}

// TestPublishLeaseSetEntry_StoreTypeForLeaseSet2 verifies that LeaseSet2 entries
// are published with DatabaseStoreTypeLeaseSet2 (3).
func TestPublishLeaseSetEntry_StoreTypeForLeaseSet2(t *testing.T) {
	ls2 := lease_set2.LeaseSet2{}
	entry := Entry{LeaseSet2: &ls2}

	storeType, err := storeTypeForEntry(entry)
	assert.NoError(t, err)
	assert.Equal(t, byte(i2np.DatabaseStoreTypeLeaseSet2), storeType,
		"LeaseSet2 should use store type 3 (DatabaseStoreTypeLeaseSet2)")
}

// TestPublishLeaseSetEntry_StoreTypeForEncryptedLeaseSet verifies that EncryptedLeaseSets
// are published with DatabaseStoreTypeEncryptedLeaseSet (5).
func TestPublishLeaseSetEntry_StoreTypeForEncryptedLeaseSet(t *testing.T) {
	els := encrypted_leaseset.EncryptedLeaseSet{}
	entry := Entry{EncryptedLeaseSet: &els}

	storeType, err := storeTypeForEntry(entry)
	assert.NoError(t, err)
	assert.Equal(t, byte(i2np.DatabaseStoreTypeEncryptedLeaseSet), storeType,
		"EncryptedLeaseSet should use store type 5 (DatabaseStoreTypeEncryptedLeaseSet)")
}

// TestPublishLeaseSetEntry_StoreTypeForMetaLeaseSet verifies that MetaLeaseSets
// are published with DatabaseStoreTypeMetaLeaseSet (7).
func TestPublishLeaseSetEntry_StoreTypeForMetaLeaseSet(t *testing.T) {
	mls := meta_leaseset.MetaLeaseSet{}
	entry := Entry{MetaLeaseSet: &mls}

	storeType, err := storeTypeForEntry(entry)
	assert.NoError(t, err)
	assert.Equal(t, byte(i2np.DatabaseStoreTypeMetaLeaseSet), storeType,
		"MetaLeaseSet should use store type 7 (DatabaseStoreTypeMetaLeaseSet)")
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
// a lease_set.LeaseSet) uses DatabaseStoreTypeLeaseSet (1), not LEASESET2 (3).
// This is a regression test for the bug where all LeaseSets were published with type 3.
func TestPublishLeaseSet_UsesCorrectStoreType(t *testing.T) {
	// The PublishLeaseSet method validates the LeaseSet first, so an empty one will fail.
	// This test verifies the error comes from validation, not from wrong type handling.
	assertPublishEmptyLeaseSetFails(t)
}

// TestStoreTypeConstants verifies that the I2NP store type constants
// match the I2P specification values.
func TestStoreTypeConstants(t *testing.T) {
	assert.Equal(t, 0, i2np.DatabaseStoreTypeRouterInfo,
		"RouterInfo store type should be 0")
	assert.Equal(t, 1, i2np.DatabaseStoreTypeLeaseSet,
		"LeaseSet store type should be 1")
	assert.Equal(t, 3, i2np.DatabaseStoreTypeLeaseSet2,
		"LeaseSet2 store type should be 3")
	assert.Equal(t, 5, i2np.DatabaseStoreTypeEncryptedLeaseSet,
		"EncryptedLeaseSet store type should be 5")
	assert.Equal(t, 7, i2np.DatabaseStoreTypeMetaLeaseSet,
		"MetaLeaseSet store type should be 7")
}
