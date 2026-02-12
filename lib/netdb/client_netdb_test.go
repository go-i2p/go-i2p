package netdb

import (
	"os"
	"testing"

	common "github.com/go-i2p/common/data"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestClientNetDB_Isolation tests that ClientNetDB only exposes LeaseSet operations.
// This validates the interface isolation principle.
func TestClientNetDB_Isolation(t *testing.T) {
	tempDir := t.TempDir()
	stdDB := NewStdNetDB(tempDir)
	require.NoError(t, stdDB.Create())
	defer stdDB.Stop()

	clientDB := NewClientNetDB(stdDB)

	// Verify ClientNetDB has LeaseSet operations
	assert.NotNil(t, clientDB.GetLeaseSet)
	assert.NotNil(t, clientDB.GetLeaseSetBytes)
	assert.NotNil(t, clientDB.StoreLeaseSet)
	assert.NotNil(t, clientDB.StoreLeaseSet2)
	assert.NotNil(t, clientDB.GetLeaseSetCount)

	// Verify basic operations work
	assert.NotNil(t, clientDB.Path())
	assert.NoError(t, clientDB.Ensure())
}

// TestClientNetDB_LeaseSetOperations tests LeaseSet storage and retrieval.
func TestClientNetDB_LeaseSetOperations(t *testing.T) {
	tempDir := t.TempDir()
	stdDB := NewStdNetDB(tempDir)
	require.NoError(t, stdDB.Create())
	defer stdDB.Stop()

	clientDB := NewClientNetDB(stdDB)

	// Test GetLeaseSetCount on empty database
	count := clientDB.GetLeaseSetCount()
	assert.Equal(t, 0, count)

	// Test GetLeaseSet for non-existent entry
	var testHash common.Hash
	copy(testHash[:], "test-leaseset-hash-00000000000")

	chnl := clientDB.GetLeaseSet(testHash)
	assert.NotNil(t, chnl, "Non-existent LeaseSet should return a closed channel, not nil")
	_, ok := <-chnl
	assert.False(t, ok, "Channel should be closed for non-existent LeaseSet")

	// Test GetLeaseSetBytes for non-existent entry
	_, err := clientDB.GetLeaseSetBytes(testHash)
	assert.Error(t, err, "Non-existent LeaseSet should return error")
}

// TestClientNetDB_Path tests filesystem path access.
func TestClientNetDB_Path(t *testing.T) {
	tempDir := t.TempDir()
	stdDB := NewStdNetDB(tempDir)
	clientDB := NewClientNetDB(stdDB)

	path := clientDB.Path()
	assert.Equal(t, tempDir, path)
}

// TestClientNetDB_Ensure tests database initialization.
func TestClientNetDB_Ensure(t *testing.T) {
	tempDir := t.TempDir()
	stdDB := NewStdNetDB(tempDir)
	clientDB := NewClientNetDB(stdDB)

	// Ensure should create necessary directories
	err := clientDB.Ensure()
	assert.NoError(t, err)

	// Verify directory exists
	info, err := os.Stat(tempDir)
	assert.NoError(t, err)
	assert.True(t, info.IsDir())
}

// TestClientNetDB_ConcurrentAccess tests thread safety of ClientNetDB operations.
func TestClientNetDB_ConcurrentAccess(t *testing.T) {
	tempDir := t.TempDir()
	stdDB := NewStdNetDB(tempDir)
	require.NoError(t, stdDB.Create())
	defer stdDB.Stop()

	clientDB := NewClientNetDB(stdDB)

	// Run concurrent GetLeaseSetCount operations
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				_ = clientDB.GetLeaseSetCount()
			}
			done <- true
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}
}

// TestClientNetDB_SharedStdNetDB tests that ClientNetDB and RouterNetDB can share the same StdNetDB.
func TestClientNetDB_SharedStdNetDB(t *testing.T) {
	tempDir := t.TempDir()
	stdDB := NewStdNetDB(tempDir)
	require.NoError(t, stdDB.Create())
	defer stdDB.Stop()

	clientDB := NewClientNetDB(stdDB)
	routerDB := NewRouterNetDB(stdDB)

	// Both should point to the same underlying database
	assert.Equal(t, clientDB.Path(), routerDB.Path())

	// Both should be able to initialize the same database
	assert.NoError(t, clientDB.Ensure())
	assert.NoError(t, routerDB.Ensure())
}
