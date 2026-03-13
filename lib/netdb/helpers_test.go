package netdb

import (
	"testing"
	"time"

	"github.com/go-i2p/crypto/rand"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/lease_set"
	"github.com/go-i2p/common/router_info"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// StdNetDB construction helpers
// ---------------------------------------------------------------------------

// newTestStdNetDB creates a StdNetDB backed by a temp dir, calls Create(), and
// registers a cleanup to Stop it. Use when tests need a fully initialized DB.
func newTestStdNetDB(t *testing.T) *StdNetDB {
	t.Helper()
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)
	require.NoError(t, db.Create())
	t.Cleanup(db.Stop)
	return db
}

// newTestStdNetDBBasic creates a StdNetDB backed by a temp dir without calling
// Create(). Use for expiration / stat tests that don't need directory structure.
func newTestStdNetDBBasic(t *testing.T) *StdNetDB {
	t.Helper()
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)
	require.NotNil(t, db)
	return db
}

// newTestClientNetDB returns a ClientNetDB wrapping a fully initialised StdNetDB.
func newTestClientNetDB(t *testing.T) *ClientNetDB {
	t.Helper()
	return NewClientNetDB(newTestStdNetDB(t))
}

// newTestRouterNetDB returns a RouterNetDB wrapping a fully initialised StdNetDB.
func newTestRouterNetDB(t *testing.T) *RouterNetDB {
	t.Helper()
	return NewRouterNetDB(newTestStdNetDB(t))
}

// ---------------------------------------------------------------------------
// Map-population helpers
// ---------------------------------------------------------------------------

// addRouterInfoEntries populates db with count RouterInfo entries keyed by
// sequential hashes (using two bytes for uniqueness up to 65535).
func addRouterInfoEntries(db *StdNetDB, count int) {
	for i := 0; i < count; i++ {
		var h common.Hash
		h[0] = byte(i >> 8)
		h[1] = byte(i & 0xFF)
		ri := router_info.RouterInfo{}
		db.riMutex.Lock()
		db.RouterInfos[h] = Entry{RouterInfo: &ri}
		db.riMutex.Unlock()
	}
}

// addLeaseSetWithExpiry inserts an empty LeaseSet entry and its expiration
// tracking into db. offset is relative to time.Now() (negative = already expired).
func addLeaseSetWithExpiry(db *StdNetDB, hash common.Hash, offset time.Duration) {
	db.lsMutex.Lock()
	db.LeaseSets[hash] = Entry{}
	db.lsMutex.Unlock()

	db.expiryMutex.Lock()
	db.leaseSetExpiry[hash] = time.Now().Add(offset)
	db.expiryMutex.Unlock()
}

// addRouterInfoWithExpiry inserts an empty RouterInfo entry and its expiration
// tracking into db. offset is relative to time.Now().
func addRouterInfoWithExpiry(db *StdNetDB, hash common.Hash, offset time.Duration) {
	db.riMutex.Lock()
	db.RouterInfos[hash] = Entry{}
	db.riMutex.Unlock()

	db.expiryMutex.Lock()
	db.routerInfoExpiry[hash] = time.Now().Add(offset)
	db.expiryMutex.Unlock()
}

// ---------------------------------------------------------------------------
// Assertion helpers
// ---------------------------------------------------------------------------

// assertLeaseSetPresence checks whether hash is (or is not) present in both
// the LeaseSets map and the expiry tracking map.
func assertLeaseSetPresence(t *testing.T, db *StdNetDB, hash common.Hash, shouldExist bool, label string) {
	t.Helper()
	db.lsMutex.Lock()
	_, inCache := db.LeaseSets[hash]
	db.lsMutex.Unlock()

	db.expiryMutex.RLock()
	_, inExpiry := db.leaseSetExpiry[hash]
	db.expiryMutex.RUnlock()

	if shouldExist {
		assert.True(t, inCache, "%s should be in LeaseSet cache", label)
		assert.True(t, inExpiry, "%s should be in expiry tracking", label)
	} else {
		assert.False(t, inCache, "%s should be removed from LeaseSet cache", label)
		assert.False(t, inExpiry, "%s should be removed from expiry tracking", label)
	}
}

// assertPublishLeaseSetInvalid verifies that publishing an empty LeaseSet
// returns an "invalid LeaseSet" error.
func assertPublishLeaseSetInvalid(t *testing.T, publisher *Publisher) {
	t.Helper()
	ls := lease_set.LeaseSet{}
	hash := common.Hash{1, 2, 3, 4}
	err := publisher.PublishLeaseSet(hash, ls)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid LeaseSet")
}

// ---------------------------------------------------------------------------
// leaseSetReader interface + assertEmptyLeaseSetOperations
// ---------------------------------------------------------------------------

// leaseSetReader is a test-only interface covering the LeaseSet read operations
// shared by ClientNetDB and RouterNetDB.
type leaseSetReader interface {
	GetLeaseSetCount() int
	GetLeaseSet(common.Hash) chan lease_set.LeaseSet
	GetLeaseSetBytes(common.Hash) ([]byte, error)
}

// assertEmptyLeaseSetOperations verifies that an empty database returns the
// expected results for LeaseSet read operations.
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

// ---------------------------------------------------------------------------
// Destination resolver helpers
// ---------------------------------------------------------------------------

// newTestResolverWithHash creates a mockNetDB, DestinationResolver, and a
// random hash for use in destination resolution tests.
func newTestResolverWithHash(t *testing.T) (*DestinationResolver, *mockNetDB, common.Hash) {
	t.Helper()
	db := newMockNetDB()
	resolver := NewDestinationResolver(db)
	var h common.Hash
	_, err := rand.Read(h[:])
	require.NoError(t, err)
	return resolver, db, h
}
