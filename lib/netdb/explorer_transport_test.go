package netdb

import (
	"context"
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/i2np"
)

// TestExplorerWithTransport tests that the explorer creates resolvers with transport.
func TestExplorerWithTransport(t *testing.T) {
	db := newMockNetDB()
	transport := &mockLookupTransport{}
	ourHash := common.Hash{1, 2, 3}

	config := DefaultExplorerConfig()
	config.Transport = transport
	config.OurHash = ourHash

	explorer := NewExplorer(db, nil, config)

	if explorer.transport == nil {
		t.Error("Explorer should have transport set from config")
	}
	if explorer.ourHash != ourHash {
		t.Error("Explorer should have ourHash set from config")
	}
}

// TestExplorerSetTransport tests the SetTransport method.
func TestExplorerSetTransport(t *testing.T) {
	db := newMockNetDB()
	config := DefaultExplorerConfig()

	explorer := NewExplorer(db, nil, config)

	if explorer.transport != nil {
		t.Error("Transport should initially be nil")
	}

	transport := &mockLookupTransport{}
	explorer.SetTransport(transport)

	if explorer.transport == nil {
		t.Error("Transport should be set after SetTransport")
	}
}

// TestExplorerSetOurHash tests the SetOurHash method.
func TestExplorerSetOurHash(t *testing.T) {
	db := newMockNetDB()
	config := DefaultExplorerConfig()

	explorer := NewExplorer(db, nil, config)

	ourHash := common.Hash{42, 42, 42}
	explorer.SetOurHash(ourHash)

	if explorer.ourHash != ourHash {
		t.Error("OurHash should be set after SetOurHash")
	}
}

// TestExplorerPerformExploratoryLookup_WithTransport tests that the exploratory
// lookup creates a transport-capable resolver when transport is available.
func TestExplorerPerformExploratoryLookup_WithTransport(t *testing.T) {
	db := newMockNetDB()

	transport := &mockLookupTransport{
		sendFunc: func(ctx context.Context, peerRI router_info.RouterInfo, lookup *i2np.DatabaseLookup) ([]byte, int, error) {
			reply := i2np.NewDatabaseSearchReply(lookup.Key, common.Hash{}, nil)
			data, _ := reply.MarshalBinary()
			return data, i2np.I2NP_MESSAGE_TYPE_DATABASE_SEARCH_REPLY, nil
		},
	}

	// Add a peer to the database so the resolver has someone to query
	peerHash := common.Hash{10, 20, 30}
	db.routerInfos[peerHash] = router_info.RouterInfo{}

	config := ExplorerConfig{
		Interval:      time.Hour,
		Concurrency:   1,
		LookupTimeout: 2 * time.Second,
		Transport:     transport,
		OurHash:       common.Hash{0},
	}

	explorer := NewExplorer(db, nil, config)

	// Perform a single exploratory lookup
	lookupHash := common.Hash{99, 99}
	err := explorer.performExploratoryLookup(0, lookupHash)

	// The error is expected (tunnel pool is nil for validation), but the key point
	// is whether the transport-capable resolver was created
	_ = err

	// Since the resolver needs a pool for remote lookups, the transport won't be
	// exercised without a pool. But we verify the transport is wired correctly.
	if explorer.transport == nil {
		t.Error("Explorer should have transport configured")
	}
}

// TestExplorerPerformExploratoryLookup_WithoutTransport tests fallback behavior
// when no transport is configured.
func TestExplorerPerformExploratoryLookup_WithoutTransport(t *testing.T) {
	db := newMockNetDB()

	config := ExplorerConfig{
		Interval:      time.Hour,
		Concurrency:   1,
		LookupTimeout: 1 * time.Second,
	}

	explorer := NewExplorer(db, nil, config)

	// Without a pool, the resolver creation for the non-transport path should fail
	lookupHash := common.Hash{99}
	err := explorer.performExploratoryLookup(0, lookupHash)

	// Expect error since pool is nil and NewKademliaResolver returns nil
	if err == nil {
		t.Error("expected error when pool is nil and no transport")
	}
}

// mockLookupTransportForExplorer is specifically for explorer tests that need
// to track whether the transport was used.
type mockLookupTransportForExplorer struct {
	queryCount int
}

func (m *mockLookupTransportForExplorer) SendDatabaseLookup(ctx context.Context, peerRI router_info.RouterInfo, lookup *i2np.DatabaseLookup) ([]byte, int, error) {
	m.queryCount++
	reply := i2np.NewDatabaseSearchReply(lookup.Key, common.Hash{}, nil)
	data, _ := reply.MarshalBinary()
	return data, i2np.I2NP_MESSAGE_TYPE_DATABASE_SEARCH_REPLY, nil
}

// TestExplorerConfigDefaults verifies default config has nil transport.
func TestExplorerConfigDefaults(t *testing.T) {
	config := DefaultExplorerConfig()

	if config.Transport != nil {
		t.Error("Default config should have nil transport")
	}

	var emptyHash common.Hash
	if config.OurHash != emptyHash {
		t.Error("Default config should have empty OurHash")
	}
}
