package netdb

import (
	"testing"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/lease_set2"
	"github.com/stretchr/testify/assert"
)

// TestGetLeaseSet_NilLeaseSetField verifies that GetLeaseSet does not panic
// when the entry exists in the LeaseSets map but holds a LeaseSet2 (or other
// modern variant) instead of a classic LeaseSet.
//
// Before the fix, GetLeaseSet dereferenced entry.LeaseSet unconditionally,
// causing a nil-pointer panic for non-classic LeaseSet entries.
func TestGetLeaseSet_NilLeaseSetField(t *testing.T) {
	db := NewStdNetDB(t.TempDir())

	var hash common.Hash
	copy(hash[:], []byte("test-hash-for-ls2-entry-32bytes!"))

	// Store a LeaseSet2 entry under the hash (no classic LeaseSet).
	db.lsMutex.Lock()
	db.LeaseSets[hash] = Entry{
		LeaseSet2: &lease_set2.LeaseSet2{},
	}
	db.lsMutex.Unlock()

	// GetLeaseSet must NOT panic. It should return nil (no classic LeaseSet).
	chnl := db.GetLeaseSet(hash)
	assert.Nil(t, chnl, "GetLeaseSet should return nil when entry holds a LeaseSet2, not a classic LeaseSet")
}

// TestGetLeaseSet_MissingEntry ensures GetLeaseSet returns nil for a
// completely missing hash.
func TestGetLeaseSet_MissingEntry(t *testing.T) {
	db := NewStdNetDB(t.TempDir())

	var hash common.Hash
	copy(hash[:], []byte("nonexistent-hash-32-bytes-long!!"))

	chnl := db.GetLeaseSet(hash)
	assert.Nil(t, chnl, "GetLeaseSet should return nil for missing hash")
}
