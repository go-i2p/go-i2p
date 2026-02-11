package netdb

import (
	"testing"

	"github.com/go-i2p/common/lease_set"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSaveEntry_NilRouterInfo verifies that SaveEntry returns an error
// (instead of panicking with nil pointer dereference) when the Entry
// contains no RouterInfo (e.g. only a LeaseSet).
func TestSaveEntry_NilRouterInfo(t *testing.T) {
	tempDir := t.TempDir()
	db := NewStdNetDB(tempDir)

	// Create an Entry that has only a LeaseSet, no RouterInfo.
	ls := &lease_set.LeaseSet{}
	entry := &Entry{
		LeaseSet: ls,
	}

	// This should return an error, NOT panic.
	err := db.SaveEntry(entry)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "RouterInfo is nil")
}

// TestSaveEntry_EmptyEntry verifies that SaveEntry handles a completely
// empty Entry (no RouterInfo, no LeaseSet, nothing) without panicking.
func TestSaveEntry_EmptyEntry(t *testing.T) {
	tempDir := t.TempDir()
	db := NewStdNetDB(tempDir)

	entry := &Entry{}

	err := db.SaveEntry(entry)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "RouterInfo is nil")
}
