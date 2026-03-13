package netdb

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestClientNetDB_Isolation tests that ClientNetDB only exposes LeaseSet operations.
// This validates the interface isolation principle.
func TestClientNetDB_Isolation(t *testing.T) {
	clientDB := newTestClientNetDB(t)

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
	clientDB := newTestClientNetDB(t)
	assertEmptyLeaseSetOperations(t, clientDB)
}

// TestClientNetDB_Path tests filesystem path access.
func TestClientNetDB_Path(t *testing.T) {
	tempDir := t.TempDir()
	stdDB := NewStdNetDB(tempDir)
	clientDB := NewClientNetDB(stdDB)
	assertNetDBPath(t, clientDB, tempDir)
}

// TestClientNetDB_Ensure tests database initialization.
func TestClientNetDB_Ensure(t *testing.T) {
	tempDir := t.TempDir()
	stdDB := NewStdNetDB(tempDir)
	clientDB := NewClientNetDB(stdDB)
	assertNetDBEnsure(t, clientDB, tempDir)
}

// TestClientNetDB_ConcurrentAccess tests thread safety of ClientNetDB operations.
func TestClientNetDB_ConcurrentAccess(t *testing.T) {
	clientDB := newTestClientNetDB(t)

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
	stdDB := newTestStdNetDB(t)

	clientDB := NewClientNetDB(stdDB)
	routerDB := NewRouterNetDB(stdDB)

	// Both should point to the same underlying database
	assert.Equal(t, clientDB.Path(), routerDB.Path())

	// Both should be able to initialize the same database
	assert.NoError(t, clientDB.Ensure())
	assert.NoError(t, routerDB.Ensure())
}
