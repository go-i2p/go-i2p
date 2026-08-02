package netdb

import (
	"testing"

	common "github.com/go-i2p/common/data"
	"github.com/stretchr/testify/assert"
)

// TestGetLeaseSetBytes_TriggersNetworkLookupOnMiss verifies that a local
// cache+disk miss invokes the configured on-demand network LeaseSet lookup.
// This is the fix for .b32.i2p hash lookups returning KEY_NOT_FOUND without
// ever querying the network.
func TestGetLeaseSetBytes_TriggersNetworkLookupOnMiss(t *testing.T) {
	db := NewStdNetDB(t.TempDir())

	var hash common.Hash
	hash[0] = 0xAB

	called := false
	var calledWith common.Hash
	db.SetLeaseSetNetworkLookup(func(h common.Hash) bool {
		called = true
		calledWith = h
		return false // simulate "not found on the network either"
	})

	_, err := db.GetLeaseSetBytes(hash)
	assert.Error(t, err, "missing LeaseSet with a failed network lookup should still error")
	assert.True(t, called, "network LeaseSet lookup should be invoked on a local miss")
	assert.Equal(t, hash, calledWith, "network lookup should be called with the requested hash")
}

// TestGetLeaseSet_TriggersNetworkLookupOnMiss verifies the channel-based
// GetLeaseSet path also attempts the network lookup on a local miss.
func TestGetLeaseSet_TriggersNetworkLookupOnMiss(t *testing.T) {
	db := NewStdNetDB(t.TempDir())

	var hash common.Hash
	hash[0] = 0xCD

	called := false
	db.SetLeaseSetNetworkLookup(func(h common.Hash) bool {
		called = true
		return false
	})

	ch := db.GetLeaseSet(hash)
	// Drain the (empty) channel so we do not leak; the value is irrelevant.
	select {
	case <-ch:
	default:
	}
	assert.True(t, called, "network LeaseSet lookup should be invoked on a local miss")
}

// TestGetLeaseSetBytes_NoLookupWiredIsLocalOnly verifies that without a
// provider a local miss behaves exactly as before (immediate not-found, no
// panic).
func TestGetLeaseSetBytes_NoLookupWiredIsLocalOnly(t *testing.T) {
	db := NewStdNetDB(t.TempDir())

	var hash common.Hash
	hash[0] = 0xEF

	_, err := db.GetLeaseSetBytes(hash)
	assert.Error(t, err, "missing LeaseSet with no network lookup wired should error")
}

// TestTryNetworkLeaseSetLookup_NilProvider verifies the accessor is safe when
// no provider is configured.
func TestTryNetworkLeaseSetLookup_NilProvider(t *testing.T) {
	db := NewStdNetDB(t.TempDir())
	var hash common.Hash
	assert.False(t, db.tryNetworkLeaseSetLookup(hash))
}
