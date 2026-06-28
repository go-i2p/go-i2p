package netdb

import (
	"testing"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	"github.com/stretchr/testify/assert"
)

// TestRouterNetDB_Isolation tests that RouterNetDB only exposes RouterInfo operations.
// This validates the interface isolation principle.
func TestRouterNetDB_Isolation(t *testing.T) {
	routerDB := newTestRouterNetDB(t)

	// Verify RouterNetDB has RouterInfo operations
	assert.NotNil(t, routerDB.GetRouterInfo)
	assert.NotNil(t, routerDB.GetAllRouterInfos)
	assert.NotNil(t, routerDB.StoreRouterInfo)
	assert.NotNil(t, routerDB.GetRouterInfoBytes)
	assert.NotNil(t, routerDB.GetRouterInfoCount)
	assert.NotNil(t, routerDB.SelectPeers)
	assert.NotNil(t, routerDB.SelectFloodfillRouters)
	assert.NotNil(t, routerDB.Reseed)
	assert.NotNil(t, routerDB.Size)
	assert.NotNil(t, routerDB.RecalculateSize)

	// Verify basic operations work
	assertBasicNetDBOperations(t, routerDB)
}

// TestRouterNetDB_RouterInfoOperations tests RouterInfo storage and retrieval.
func TestRouterNetDB_RouterInfoOperations(t *testing.T) {
	routerDB := newTestRouterNetDB(t)

	// Test GetRouterInfoCount on empty database
	count := routerDB.GetRouterInfoCount()
	assert.Equal(t, 0, count)

	// Test Size on empty database
	size := routerDB.Size()
	assert.Equal(t, 0, size)

	// Test GetRouterInfo for non-existent entry
	var testHash common.Hash
	copy(testHash[:], "test-routerinfo-hash-00000000000")

	chnl := routerDB.GetRouterInfo(testHash)
	assert.NotNil(t, chnl, "Non-existent RouterInfo should return a closed (non-nil) channel")
	// The channel should be closed with no value, so receiving yields zero value immediately
	_, ok := <-chnl
	assert.False(t, ok, "Channel should be closed for non-existent RouterInfo")

	// Test GetRouterInfoBytes for non-existent entry
	_, err := routerDB.GetRouterInfoBytes(testHash)
	assert.Error(t, err, "Non-existent RouterInfo should return error")

	// Test GetAllRouterInfos on empty database
	allRouterInfos := routerDB.GetAllRouterInfos()
	assert.NotNil(t, allRouterInfos)
	assert.Equal(t, 0, len(allRouterInfos))
}

// TestRouterNetDB_PeerSelection tests peer selection operations.
func TestRouterNetDB_PeerSelection(t *testing.T) {
	routerDB := newTestRouterNetDB(t)

	// Test SelectPeers on empty database - should return error
	peers, err := routerDB.SelectPeers(5, nil)
	assert.Error(t, err, "SelectPeers should fail on empty database")
	assert.Equal(t, 0, len(peers))

	// Test SelectFloodfillRouters on empty database - should return error
	var targetHash common.Hash
	copy(targetHash[:], "target-hash-00000000000000000000")

	floodfills, err := routerDB.SelectFloodfillRouters(targetHash, 3)
	assert.Error(t, err, "SelectFloodfillRouters should fail on empty database")
	assert.Equal(t, 0, len(floodfills))
}

// TestRouterNetDB_Path tests filesystem path access.
func TestRouterNetDB_Path(t *testing.T) {
	tempDir := t.TempDir()
	stdDB := NewStdNetDB(tempDir)
	routerDB := NewRouterNetDB(stdDB)
	assertNetDBPath(t, routerDB, tempDir)
}

// TestRouterNetDB_Ensure tests database initialization.
func TestRouterNetDB_Ensure(t *testing.T) {
	tempDir := t.TempDir()
	stdDB := NewStdNetDB(tempDir)
	routerDB := NewRouterNetDB(stdDB)
	assertNetDBEnsure(t, routerDB, tempDir)
}

// TestRouterNetDB_RecalculateSize tests size recalculation.
func TestRouterNetDB_RecalculateSize(t *testing.T) {
	routerDB := newTestRouterNetDB(t)

	// RecalculateSize should succeed on empty database
	err := routerDB.RecalculateSize()
	assert.NoError(t, err)

	size := routerDB.Size()
	assert.Equal(t, 0, size)
}

// TestRouterNetDB_ConcurrentAccess tests thread safety of RouterNetDB operations.
func TestRouterNetDB_ConcurrentAccess(t *testing.T) {
	routerDB := newTestRouterNetDB(t)

	// Run concurrent operations
	runConcurrentOps(t, 10, 100, func() {
		_ = routerDB.GetRouterInfoCount()
		_ = routerDB.Size()
		_, _ = routerDB.SelectPeers(1, nil)
	})
}

// TestRouterNetDB_IsolationFromClient tests that RouterNetDB doesn't expose LeaseSet operations.
// This is a design validation test - RouterNetDB should not have LeaseSet methods accessible.
func TestRouterNetDB_IsolationFromClient(t *testing.T) {
	tempDir := t.TempDir()
	stdDB := NewStdNetDB(tempDir)
	defer stdDB.Stop()

	routerDB := NewRouterNetDB(stdDB)

	// RouterNetDB should not have LeaseSet methods accessible
	// This is enforced at compile time by the type system
	// We're just verifying the object exists and has expected type
	assert.IsType(t, &RouterNetDB{}, routerDB)
	assert.NotNil(t, routerDB.StdNetDB) // Has access to underlying StdNetDB
}

// TestRouterNetDB_LeaseSetOperations tests LeaseSet storage and retrieval for direct router operations.
func TestRouterNetDB_LeaseSetOperations(t *testing.T) {
	routerDB := newTestRouterNetDB(t)
	assertEmptyLeaseSetOperations(t, routerDB)
}

func TestSelectPeers_DoesNotHardExcludeStalePeers(t *testing.T) {
	routerDB := newTestRouterNetDB(t)
	db := routerDB.StdNetDB

	peerA := *createTestRouterInfoWithOptions(t, map[string]string{"caps": "R"})
	peerB := *createTestRouterInfoWithOptions(t, map[string]string{"caps": "R"})
	setRouterHostPort(t, &peerA, "198.51.100.10", "12345")
	setRouterHostPort(t, &peerB, "198.51.100.11", "12345")

	hashA, err := peerA.IdentHash()
	assert.NoError(t, err)
	hashB, err := peerB.IdentHash()
	assert.NoError(t, err)

	db.riCache.put(hashA, Entry{RouterInfo: &peerA})
	db.riCache.put(hashB, Entry{RouterInfo: &peerB})

	for i := 0; i < 3; i++ {
		db.PeerTracker.RecordFailure(hashA, "simulated transient failure")
	}

	peers, err := routerDB.SelectPeers(2, nil)
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, len(peers), 1)

	seenA := false
	for _, ri := range peers {
		h, herr := ri.IdentHash()
		assert.NoError(t, herr)
		if h == hashA {
			seenA = true
			break
		}
	}
	assert.True(t, seenA, "stale-classified peer should remain eligible for selection")
}

func TestSelectFloodfillRouters_DoesNotHardExcludeStaleFloodfills(t *testing.T) {
	routerDB := newTestRouterNetDB(t)
	db := routerDB.StdNetDB

	ffA := *createTestRouterInfoWithOptions(t, map[string]string{"caps": "fR"})
	ffB := *createTestRouterInfoWithOptions(t, map[string]string{"caps": "fR"})
	setRouterHostPort(t, &ffA, "203.0.113.10", "12345")
	setRouterHostPort(t, &ffB, "203.0.113.11", "12345")

	hashA, err := ffA.IdentHash()
	assert.NoError(t, err)
	hashB, err := ffB.IdentHash()
	assert.NoError(t, err)

	db.riCache.put(hashA, Entry{RouterInfo: &ffA})
	db.riCache.put(hashB, Entry{RouterInfo: &ffB})

	for i := 0; i < 3; i++ {
		db.PeerTracker.RecordFailure(hashA, "simulated transient floodfill failure")
	}

	selected, err := routerDB.SelectFloodfillRouters(hashB, 2)
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, len(selected), 1)

	seenA := false
	for _, ri := range selected {
		h, herr := ri.IdentHash()
		assert.NoError(t, herr)
		if h == hashA {
			seenA = true
			break
		}
	}
	assert.True(t, seenA, "stale-classified floodfill should remain eligible for selection")
}

func setRouterHostPort(t *testing.T, ri *router_info.RouterInfo, host, port string) {
	t.Helper()
	addrs := ri.RouterAddresses()
	assert.NotNil(t, addrs)
	assert.GreaterOrEqual(t, len(addrs), 1)
	for i := range addrs {
		assert.NoError(t, addrs[i].SetOption("host", host))
		assert.NoError(t, addrs[i].SetOption("port", port))
	}
}
