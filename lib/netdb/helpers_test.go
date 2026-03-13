package netdb

import (
	"os"
	"sync"
	"testing"
	"time"

	"github.com/go-i2p/crypto/rand"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/lease_set"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/i2np"
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

// ---------------------------------------------------------------------------
// Ephemeral StdNetDB helper
// ---------------------------------------------------------------------------

// newEphemeralStdNetDB creates a StdNetDB with empty path (in-memory only)
// and registers cleanup. Use for distance/XOR tests that don't need disk.
func newEphemeralStdNetDB(t *testing.T) *StdNetDB {
	t.Helper()
	db := NewStdNetDB("")
	t.Cleanup(db.Stop)
	return db
}

// ---------------------------------------------------------------------------
// Resolver + DatabaseSearchReply setup
// ---------------------------------------------------------------------------

// newResolverWithSearchReply creates a KademliaResolver with a mock database and
// a pre-built DatabaseSearchReply with standard test hashes. Returns the resolver,
// target hash, search reply (for caller to marshal), and peer hashes.
func newResolverWithSearchReply(t *testing.T) (*KademliaResolver, common.Hash, *i2np.DatabaseSearchReply, []common.Hash) {
	t.Helper()
	mockDB := newMockNetworkDatabase()
	resolver := &KademliaResolver{
		NetworkDatabase: mockDB,
		responseHandler: NewLookupResponseHandler(),
	}
	targetHash := common.Hash{1, 2, 3, 4}
	fromHash := common.Hash{5, 6, 7, 8}
	peerHashes := []common.Hash{{9, 10, 11}, {12, 13, 14}}
	searchReply := i2np.NewDatabaseSearchReply(targetHash, fromHash, peerHashes)
	return resolver, targetHash, searchReply, peerHashes
}

// ---------------------------------------------------------------------------
// Explorer creation helper
// ---------------------------------------------------------------------------

// newTestExplorerDefault creates an Explorer with a mock database and default
// config. Use for tests that don't need custom explorer configuration.
func newTestExplorerDefault(t *testing.T) *Explorer {
	t.Helper()
	db := newMockNetDB()
	config := DefaultExplorerConfig()
	return NewExplorer(db, nil, config)
}

// ---------------------------------------------------------------------------
// Path/Ensure assertion helpers
// ---------------------------------------------------------------------------

// netDBPathEnsurer covers Path()/Ensure() common to ClientNetDB and RouterNetDB.
type netDBPathEnsurer interface {
	Path() string
	Ensure() error
}

// assertNetDBPath verifies that a netDB wrapper returns the expected path.
func assertNetDBPath(t *testing.T, db netDBPathEnsurer, expectedPath string) {
	t.Helper()
	assert.Equal(t, expectedPath, db.Path())
}

// assertNetDBEnsure verifies Ensure() succeeds and the directory exists.
func assertNetDBEnsure(t *testing.T, db netDBPathEnsurer, dir string) {
	t.Helper()
	err := db.Ensure()
	assert.NoError(t, err)
	info, err := os.Stat(dir)
	assert.NoError(t, err)
	assert.True(t, info.IsDir())
}

// ---------------------------------------------------------------------------
// Expiration cleanup assertion helper
// ---------------------------------------------------------------------------

// assertLeaseSetCleanupResult verifies that after cleanup, the expired hash is
// gone and the valid hash remains (checking both cache and expiry tracking),
// and the total LeaseSet count matches expectedCount.
func assertLeaseSetCleanupResult(t *testing.T, db *StdNetDB, expiredHash, validHash common.Hash, expectedCount int) {
	t.Helper()
	assertLeaseSetPresence(t, db, expiredHash, false, "Expired")
	assertLeaseSetPresence(t, db, validHash, true, "Valid")
	db.lsMutex.Lock()
	count := len(db.LeaseSets)
	db.lsMutex.Unlock()
	assert.Equal(t, expectedCount, count)
}

// ---------------------------------------------------------------------------
// Concurrent execution helpers
// ---------------------------------------------------------------------------

// runConcurrentOps launches count goroutines, each calling work opsPerGoroutine
// times, and waits for all to finish via a done channel.
func runConcurrentOps(t *testing.T, count, opsPerGoroutine int, work func()) {
	t.Helper()
	done := make(chan bool)
	for i := 0; i < count; i++ {
		go func() {
			for j := 0; j < opsPerGoroutine; j++ {
				work()
			}
			done <- true
		}()
	}
	for i := 0; i < count; i++ {
		<-done
	}
}

// runConcurrentWg launches goroutines workers, each calling work(id, iter)
// iterations times, using a sync.WaitGroup for synchronization.
func runConcurrentWg(t *testing.T, goroutines, iterations int, work func(id, iter int)) {
	t.Helper()
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				work(id, j)
			}
		}(i)
	}
	wg.Wait()
}

// ---------------------------------------------------------------------------
// Basic NetDB operation assertion helpers
// ---------------------------------------------------------------------------

// assertBasicNetDBOperations verifies that Path() is non-nil and Ensure() succeeds.
func assertBasicNetDBOperations(t *testing.T, db netDBPathEnsurer) {
	t.Helper()
	assert.NotNil(t, db.Path())
	assert.NoError(t, db.Ensure())
}

// assertClientLeaseSetMethodsExist verifies that a ClientNetDB exposes all
// expected LeaseSet operation methods.
func assertClientLeaseSetMethodsExist(t *testing.T, clientDB *ClientNetDB) {
	t.Helper()
	assert.NotNil(t, clientDB.GetLeaseSet, "GetLeaseSet should be available")
	assert.NotNil(t, clientDB.GetLeaseSetBytes, "GetLeaseSetBytes should be available")
	assert.NotNil(t, clientDB.StoreLeaseSet, "StoreLeaseSet should be available")
	assert.NotNil(t, clientDB.StoreLeaseSet2, "StoreLeaseSet2 should be available")
	assert.NotNil(t, clientDB.GetLeaseSetCount, "GetLeaseSetCount should be available")
}

// assertRouterInfoMethodsExist verifies that a RouterNetDB exposes the
// expected RouterInfo operation methods.
func assertRouterInfoMethodsExist(t *testing.T, routerDB *RouterNetDB) {
	t.Helper()
	assert.NotNil(t, routerDB.GetRouterInfo, "GetRouterInfo should be available")
	assert.NotNil(t, routerDB.GetAllRouterInfos, "GetAllRouterInfos should be available")
	assert.NotNil(t, routerDB.StoreRouterInfo, "StoreRouterInfo should be available")
	assert.NotNil(t, routerDB.GetRouterInfoBytes, "GetRouterInfoBytes should be available")
	assert.NotNil(t, routerDB.SelectPeers, "SelectPeers should be available")
	assert.NotNil(t, routerDB.SelectFloodfillRouters, "SelectFloodfillRouters should be available")
}

// ---------------------------------------------------------------------------
// Explorer assertion helpers
// ---------------------------------------------------------------------------

// assertExplorerRequiresTunnelPool verifies that the given explorer operation
// fails with a "tunnel pool required" error.
func assertExplorerRequiresTunnelPool(t *testing.T, op func() error) {
	t.Helper()
	err := op()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "tunnel pool required")
}

// ---------------------------------------------------------------------------
// Search reply processing helper
// ---------------------------------------------------------------------------

// marshalAndProcessSearchReply sets up a KademliaResolver with a canned
// DatabaseSearchReply, marshals it via marshalFn, processes the response,
// and asserts that the result is a nil RouterInfo with a non-nil error.
// Returns the processing error and the peer hashes from the reply.
func marshalAndProcessSearchReply(t *testing.T, marshalFn func(*i2np.DatabaseSearchReply) ([]byte, error)) (error, []common.Hash) {
	t.Helper()
	resolver, targetHash, searchReply, peerHashes := newResolverWithSearchReply(t)
	data, err := marshalFn(searchReply)
	if err != nil {
		t.Fatalf("Failed to marshal search reply: %v", err)
	}
	ri, processErr := resolver.processDatabaseSearchReplyResponse(data, targetHash)
	if ri != nil {
		t.Error("Should return nil RouterInfo for search reply")
	}
	if processErr == nil {
		t.Fatal("Should return error for search reply")
	}
	return processErr, peerHashes
}

// assertPublishEmptyLeaseSetFails creates a Publisher with default config and
// verifies that publishing an empty LeaseSet returns an "invalid LeaseSet" error.
func assertPublishEmptyLeaseSetFails(t *testing.T) {
	t.Helper()
	db := newMockNetDB()
	config := DefaultPublisherConfig()
	publisher := NewPublisher(db, nil, nil, nil, config)

	ls := lease_set.LeaseSet{}
	hash := common.Hash{1, 2, 3, 4}

	err := publisher.PublishLeaseSet(hash, ls)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid LeaseSet")
}
