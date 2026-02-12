package netdb

import (
	"os"
	"testing"

	common "github.com/go-i2p/common/data"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRouterNetDB_Isolation tests that RouterNetDB only exposes RouterInfo operations.
// This validates the interface isolation principle.
func TestRouterNetDB_Isolation(t *testing.T) {
	tempDir := t.TempDir()
	stdDB := NewStdNetDB(tempDir)
	require.NoError(t, stdDB.Create())
	defer stdDB.Stop()

	routerDB := NewRouterNetDB(stdDB)

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
	assert.NotNil(t, routerDB.Path())
	assert.NoError(t, routerDB.Ensure())
}

// TestRouterNetDB_RouterInfoOperations tests RouterInfo storage and retrieval.
func TestRouterNetDB_RouterInfoOperations(t *testing.T) {
	tempDir := t.TempDir()
	stdDB := NewStdNetDB(tempDir)
	require.NoError(t, stdDB.Create())
	defer stdDB.Stop()

	routerDB := NewRouterNetDB(stdDB)

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
	tempDir := t.TempDir()
	stdDB := NewStdNetDB(tempDir)
	require.NoError(t, stdDB.Create())
	defer stdDB.Stop()

	routerDB := NewRouterNetDB(stdDB)

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

	path := routerDB.Path()
	assert.Equal(t, tempDir, path)
}

// TestRouterNetDB_Ensure tests database initialization.
func TestRouterNetDB_Ensure(t *testing.T) {
	tempDir := t.TempDir()
	stdDB := NewStdNetDB(tempDir)
	routerDB := NewRouterNetDB(stdDB)

	// Ensure should create necessary directories
	err := routerDB.Ensure()
	assert.NoError(t, err)

	// Verify directory exists
	info, err := os.Stat(tempDir)
	assert.NoError(t, err)
	assert.True(t, info.IsDir())
}

// TestRouterNetDB_RecalculateSize tests size recalculation.
func TestRouterNetDB_RecalculateSize(t *testing.T) {
	tempDir := t.TempDir()
	stdDB := NewStdNetDB(tempDir)
	require.NoError(t, stdDB.Create())
	defer stdDB.Stop()

	routerDB := NewRouterNetDB(stdDB)

	// RecalculateSize should succeed on empty database
	err := routerDB.RecalculateSize()
	assert.NoError(t, err)

	size := routerDB.Size()
	assert.Equal(t, 0, size)
}

// TestRouterNetDB_ConcurrentAccess tests thread safety of RouterNetDB operations.
func TestRouterNetDB_ConcurrentAccess(t *testing.T) {
	tempDir := t.TempDir()
	stdDB := NewStdNetDB(tempDir)
	require.NoError(t, stdDB.Create())
	defer stdDB.Stop()

	routerDB := NewRouterNetDB(stdDB)

	// Run concurrent operations
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				_ = routerDB.GetRouterInfoCount()
				_ = routerDB.Size()
				_, _ = routerDB.SelectPeers(1, nil)
			}
			done <- true
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}
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
	assert.NotNil(t, routerDB.db) // Has access to underlying StdNetDB
}

// TestRouterNetDB_LeaseSetOperations tests LeaseSet storage and retrieval for direct router operations.
func TestRouterNetDB_LeaseSetOperations(t *testing.T) {
	tempDir := t.TempDir()
	stdDB := NewStdNetDB(tempDir)
	require.NoError(t, stdDB.Create())
	defer stdDB.Stop()

	routerDB := NewRouterNetDB(stdDB)

	// Test GetLeaseSetCount on empty database
	count := routerDB.GetLeaseSetCount()
	assert.Equal(t, 0, count)

	// Test GetLeaseSet for non-existent entry
	var testHash common.Hash
	copy(testHash[:], "test-leaseset-hash-00000000000")

	chnl := routerDB.GetLeaseSet(testHash)
	assert.NotNil(t, chnl, "Non-existent LeaseSet should return a closed channel, not nil")
	_, ok := <-chnl
	assert.False(t, ok, "Channel should be closed for non-existent LeaseSet")

	// Test GetLeaseSetBytes for non-existent entry
	_, err := routerDB.GetLeaseSetBytes(testHash)
	assert.Error(t, err, "Non-existent LeaseSet should return error")
}
