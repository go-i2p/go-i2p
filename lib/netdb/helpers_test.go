package netdb

import (
	"testing"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/lease_set"
	"github.com/stretchr/testify/assert"
)

// leaseSetReader is a test-only interface covering the LeaseSet read operations
// shared by ClientNetDB and RouterNetDB.
type leaseSetReader interface {
	GetLeaseSetCount() int
	GetLeaseSet(common.Hash) chan lease_set.LeaseSet
	GetLeaseSetBytes(common.Hash) ([]byte, error)
}

// assertEmptyLeaseSetOperations verifies that an empty database returns the
// expected results for LeaseSet read operations. Consolidates the identical
// assertions previously duplicated in client_netdb_test.go and router_netdb_test.go.
func assertEmptyLeaseSetOperations(t *testing.T, db leaseSetReader) {
	t.Helper()

	count := db.GetLeaseSetCount()
	assert.Equal(t, 0, count)

	var testHash common.Hash
	copy(testHash[:], "test-leaseset-hash-00000000000")

	chnl := db.GetLeaseSet(testHash)
	assert.NotNil(t, chnl, "Non-existent LeaseSet should return a closed channel, not nil")
	_, ok := <-chnl
	assert.False(t, ok, "Channel should be closed for non-existent LeaseSet")

	_, err := db.GetLeaseSetBytes(testHash)
	assert.Error(t, err, "Non-existent LeaseSet should return error")
}
