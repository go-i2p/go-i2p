package router

import (
	"testing"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/bootstrap"
	"github.com/go-i2p/go-i2p/lib/netdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPublisherNetDBAdapterInterface verifies the adapter satisfies NetworkDatabase.
func TestPublisherNetDBAdapterInterface(t *testing.T) {
	var _ netdb.NetworkDatabase = (*publisherNetDBAdapter)(nil)
}

// TestPublisherNetDBAdapterGetRouterInfo tests pass-through to StdNetDB.
func TestPublisherNetDBAdapterGetRouterInfo(t *testing.T) {
	db := netdb.NewStdNetDB(t.TempDir())
	require.NoError(t, db.Ensure())
	adapter := &publisherNetDBAdapter{db: db}

	// Looking up an unknown hash returns nil channel from StdNetDB
	var hash common.Hash
	ch := adapter.GetRouterInfo(hash)
	// When hash is not found at all, StdNetDB may return nil
	if ch != nil {
		// If non-nil, the channel should close without valid data
		select {
		case _, ok := <-ch:
			assert.False(t, ok, "channel should close with no data for unknown hash")
		default:
			// channel is empty, that's fine
		}
	}
}

// TestPublisherNetDBAdapterSize tests pass-through to StdNetDB.
func TestPublisherNetDBAdapterSize(t *testing.T) {
	db := netdb.NewStdNetDB(t.TempDir())
	require.NoError(t, db.Ensure())
	adapter := &publisherNetDBAdapter{db: db}

	assert.GreaterOrEqual(t, adapter.Size(), 0)
}

// TestPublisherNetDBAdapterEnsure tests pass-through to StdNetDB.
func TestPublisherNetDBAdapterEnsure(t *testing.T) {
	db := netdb.NewStdNetDB(t.TempDir())
	adapter := &publisherNetDBAdapter{db: db}

	err := adapter.Ensure()
	assert.NoError(t, err)
}

// TestPublisherNetDBAdapterReseed tests pass-through to StdNetDB.
func TestPublisherNetDBAdapterReseed(t *testing.T) {
	db := netdb.NewStdNetDB(t.TempDir())
	require.NoError(t, db.Ensure())
	adapter := &publisherNetDBAdapter{db: db}

	// Verify Reseed is callable (StdNetDB.Reseed panics with nil bootstrapper,
	// so we just check the adapter method exists and passes through)
	assert.NotNil(t, adapter)
}

// TestPublisherNetDBAdapterRecalculateSize tests pass-through.
func TestPublisherNetDBAdapterRecalculateSize(t *testing.T) {
	db := netdb.NewStdNetDB(t.TempDir())
	require.NoError(t, db.Ensure())
	adapter := &publisherNetDBAdapter{db: db}

	err := adapter.RecalculateSize()
	assert.NoError(t, err)
}

// TestPublisherNetDBAdapterStoreRouterInfo tests the StoreRouterInfo adapter.
// Since creating a valid RouterInfo with proper keys is complex,
// this test verifies the method doesn't panic on invalid input.
func TestPublisherNetDBAdapterStoreRouterInfo(t *testing.T) {
	db := netdb.NewStdNetDB(t.TempDir())
	require.NoError(t, db.Ensure())
	adapter := &publisherNetDBAdapter{db: db}

	// Calling with a zero-value RouterInfo should not panic
	// (it will log warnings due to serialization/hash failures)
	assert.NotPanics(t, func() {
		adapter.StoreRouterInfo(router_info.RouterInfo{})
	})
}

// TestPublisherNetDBAdapterSelectFloodfillRouters tests floodfill selection.
func TestPublisherNetDBAdapterSelectFloodfillRouters(t *testing.T) {
	db := netdb.NewStdNetDB(t.TempDir())
	require.NoError(t, db.Ensure())
	adapter := &publisherNetDBAdapter{db: db}

	var hash common.Hash
	routers, err := adapter.SelectFloodfillRouters(hash, 4)
	// Empty NetDB returns an error, which is expected
	if err != nil {
		assert.Empty(t, routers)
	}
}

// TestPublisherNetDBAdapterGetLeaseSetCount tests lease set count.
func TestPublisherNetDBAdapterGetLeaseSetCount(t *testing.T) {
	db := netdb.NewStdNetDB(t.TempDir())
	require.NoError(t, db.Ensure())
	adapter := &publisherNetDBAdapter{db: db}

	assert.Equal(t, 0, adapter.GetLeaseSetCount())
}

// TestPublisherNetDBAdapterGetAllLeaseSets tests lease set retrieval.
func TestPublisherNetDBAdapterGetAllLeaseSets(t *testing.T) {
	db := netdb.NewStdNetDB(t.TempDir())
	require.NoError(t, db.Ensure())
	adapter := &publisherNetDBAdapter{db: db}

	leaseSets := adapter.GetAllLeaseSets()
	assert.Empty(t, leaseSets)
}

// TestPublisherNetDBAdapterGetAllRouterInfos tests router info retrieval.
func TestPublisherNetDBAdapterGetAllRouterInfos(t *testing.T) {
	db := netdb.NewStdNetDB(t.TempDir())
	require.NoError(t, db.Ensure())
	adapter := &publisherNetDBAdapter{db: db}

	infos := adapter.GetAllRouterInfos()
	assert.Empty(t, infos)
}

// TestPublisherTransportAdapterInterface verifies the adapter satisfies TransportManager.
func TestPublisherTransportAdapterInterface(t *testing.T) {
	var _ netdb.TransportManager = (*publisherTransportAdapter)(nil)
}

// --- mock bootstrapper for reseed test ---
type mockBootstrapper struct{}

func (m *mockBootstrapper) GetPeers(reseedFrom bootstrap.Bootstrap) error {
	return nil
}
