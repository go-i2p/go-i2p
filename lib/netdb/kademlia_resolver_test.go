package netdb

import (
	"context"
	"errors"
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/bootstrap"
	"github.com/go-i2p/go-i2p/lib/i2np"
)

// mockLookupTransport implements LookupTransport for testing
type mockLookupTransport struct {
	sendFunc func(ctx context.Context, peerRI router_info.RouterInfo, lookup *i2np.DatabaseLookup) ([]byte, int, error)
}

func (m *mockLookupTransport) SendDatabaseLookup(ctx context.Context, peerRI router_info.RouterInfo, lookup *i2np.DatabaseLookup) ([]byte, int, error) {
	if m.sendFunc != nil {
		return m.sendFunc(ctx, peerRI, lookup)
	}
	return nil, 0, errors.New("mock not configured")
}

// mockNetworkDatabase implements NetworkDatabase interface for testing
type mockNetworkDatabase struct {
	routerInfos map[common.Hash]router_info.RouterInfo
	storedRIs   []router_info.RouterInfo
}

func newMockNetworkDatabase() *mockNetworkDatabase {
	return &mockNetworkDatabase{
		routerInfos: make(map[common.Hash]router_info.RouterInfo),
		storedRIs:   make([]router_info.RouterInfo, 0),
	}
}

func (m *mockNetworkDatabase) GetRouterInfo(hash common.Hash) chan router_info.RouterInfo {
	ch := make(chan router_info.RouterInfo, 1)
	if ri, ok := m.routerInfos[hash]; ok {
		ch <- ri
	}
	close(ch)
	return ch
}

func (m *mockNetworkDatabase) GetAllRouterInfos() []router_info.RouterInfo {
	result := make([]router_info.RouterInfo, 0, len(m.routerInfos))
	for _, ri := range m.routerInfos {
		result = append(result, ri)
	}
	return result
}

func (m *mockNetworkDatabase) StoreRouterInfo(ri router_info.RouterInfo) {
	m.storedRIs = append(m.storedRIs, ri)
}

func (m *mockNetworkDatabase) Reseed(b bootstrap.Bootstrap, minRouters int) error {
	return nil
}

func (m *mockNetworkDatabase) Size() int {
	return len(m.routerInfos)
}

func (m *mockNetworkDatabase) RecalculateSize() error {
	return nil
}

func (m *mockNetworkDatabase) Ensure() error {
	return nil
}

func (m *mockNetworkDatabase) SelectFloodfillRouters(targetHash common.Hash, count int) ([]router_info.RouterInfo, error) {
	return nil, nil
}

func (m *mockNetworkDatabase) GetLeaseSetCount() int {
	return 0
}

func (m *mockNetworkDatabase) GetAllLeaseSets() []LeaseSetEntry {
	return nil
}

// TestLookupResponseHandler tests the response handler correlation mechanism
func TestLookupResponseHandler(t *testing.T) {
	handler := NewLookupResponseHandler()

	t.Run("RegisterAndHandle", func(t *testing.T) {
		messageID := 12345
		ch := handler.RegisterPending(messageID)

		// Simulate response arrival
		handled := handler.HandleResponse(messageID, i2np.I2NP_MESSAGE_TYPE_DATABASE_STORE, []byte("test data"))
		if !handled {
			t.Error("HandleResponse should return true for registered message")
		}

		// Check response received
		select {
		case resp := <-ch:
			if resp.msgType != i2np.I2NP_MESSAGE_TYPE_DATABASE_STORE {
				t.Errorf("Expected msgType %d, got %d", i2np.I2NP_MESSAGE_TYPE_DATABASE_STORE, resp.msgType)
			}
			if string(resp.data) != "test data" {
				t.Errorf("Expected data 'test data', got '%s'", string(resp.data))
			}
		case <-time.After(100 * time.Millisecond):
			t.Error("Timeout waiting for response")
		}
	})

	t.Run("HandleUnregistered", func(t *testing.T) {
		handled := handler.HandleResponse(99999, i2np.I2NP_MESSAGE_TYPE_DATABASE_STORE, []byte("data"))
		if handled {
			t.Error("HandleResponse should return false for unregistered message")
		}
	})

	t.Run("Unregister", func(t *testing.T) {
		messageID := 54321
		ch := handler.RegisterPending(messageID)
		handler.UnregisterPending(messageID)

		// Channel should be closed
		select {
		case _, ok := <-ch:
			if ok {
				t.Error("Channel should be closed after unregister")
			}
		case <-time.After(100 * time.Millisecond):
			t.Error("Timeout waiting for channel close")
		}

		// HandleResponse should return false
		handled := handler.HandleResponse(messageID, i2np.I2NP_MESSAGE_TYPE_DATABASE_STORE, []byte("data"))
		if handled {
			t.Error("HandleResponse should return false after unregister")
		}
	})
}

// TestNewKademliaResolver tests the basic resolver creation
func TestNewKademliaResolver(t *testing.T) {
	mockDB := newMockNetworkDatabase()

	t.Run("WithNilPool", func(t *testing.T) {
		resolver := NewKademliaResolver(mockDB, nil)
		if resolver != nil {
			t.Error("Should return nil with nil pool")
		}
	})

	t.Run("WithNilDB", func(t *testing.T) {
		resolver := NewKademliaResolver(nil, nil)
		if resolver != nil {
			t.Error("Should return nil with nil database")
		}
	})
}

// TestNewKademliaResolverWithTransport tests the transport-enabled resolver creation
func TestNewKademliaResolverWithTransport(t *testing.T) {
	mockDB := newMockNetworkDatabase()
	mockTransport := &mockLookupTransport{}
	ourHash := common.Hash{1, 2, 3, 4}

	t.Run("WithAllParams", func(t *testing.T) {
		resolver := NewKademliaResolverWithTransport(mockDB, nil, mockTransport, ourHash)
		if resolver == nil {
			t.Fatal("Should create resolver with valid params")
		}
		if resolver.transport == nil {
			t.Error("Transport should be set")
		}
		if resolver.ourHash != ourHash {
			t.Error("OurHash should be set")
		}
		if resolver.responseHandler == nil {
			t.Error("ResponseHandler should be initialized")
		}
	})

	t.Run("WithNilDB", func(t *testing.T) {
		resolver := NewKademliaResolverWithTransport(nil, nil, mockTransport, ourHash)
		if resolver != nil {
			t.Error("Should return nil with nil database")
		}
	})
}

// TestQueryPeerNoTransport tests queryPeer behavior without transport
func TestQueryPeerNoTransport(t *testing.T) {
	mockDB := newMockNetworkDatabase()
	resolver := &KademliaResolver{
		NetworkDatabase: mockDB,
		transport:       nil,
		responseHandler: NewLookupResponseHandler(),
	}

	ctx := context.Background()
	peerHash := common.Hash{1, 2, 3}
	targetHash := common.Hash{4, 5, 6}

	_, err := resolver.queryPeer(ctx, peerHash, targetHash)
	if err == nil {
		t.Error("Should return error without transport")
	}
	if err.Error() != "transport not configured for remote lookups" {
		t.Errorf("Unexpected error: %v", err)
	}
}

// TestQueryPeerPeerNotFound tests queryPeer when peer is not in database
func TestQueryPeerPeerNotFound(t *testing.T) {
	mockDB := newMockNetworkDatabase()
	mockTransport := &mockLookupTransport{}
	ourHash := common.Hash{1, 2, 3, 4}

	resolver := NewKademliaResolverWithTransport(mockDB, nil, mockTransport, ourHash)

	ctx := context.Background()
	peerHash := common.Hash{10, 20, 30} // Not in database
	targetHash := common.Hash{4, 5, 6}

	_, err := resolver.queryPeer(ctx, peerHash, targetHash)
	if err == nil {
		t.Error("Should return error when peer not found")
	}
	// The hash is 32 bytes, first 8 bytes are 0a141e00 00000000
	expectedPrefix := "peer 0a141e0000000000 not found in local database"
	if err.Error() != expectedPrefix {
		t.Errorf("Unexpected error: %v", err)
	}
}

// TestProcessDatabaseSearchReplyResponse tests handling of search reply responses
func TestProcessDatabaseSearchReplyResponse(t *testing.T) {
	mockDB := newMockNetworkDatabase()
	resolver := &KademliaResolver{
		NetworkDatabase: mockDB,
		responseHandler: NewLookupResponseHandler(),
	}

	targetHash := common.Hash{1, 2, 3, 4}
	fromHash := common.Hash{5, 6, 7, 8}
	peerHashes := []common.Hash{{9, 10, 11}, {12, 13, 14}}

	// Create a valid DatabaseSearchReply
	searchReply := i2np.NewDatabaseSearchReply(targetHash, fromHash, peerHashes)
	data, err := searchReply.MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to marshal search reply: %v", err)
	}

	// Process the response
	ri, err := resolver.processDatabaseSearchReplyResponse(data, targetHash)
	if err == nil {
		t.Error("Should return error for search reply (peer didn't have target)")
	}
	if ri != nil {
		t.Error("Should return nil RouterInfo for search reply")
	}
}

// TestSetTransport tests the SetTransport method
func TestSetTransport(t *testing.T) {
	mockDB := newMockNetworkDatabase()
	resolver := &KademliaResolver{
		NetworkDatabase: mockDB,
		responseHandler: NewLookupResponseHandler(),
	}

	if resolver.transport != nil {
		t.Error("Transport should initially be nil")
	}

	mockTransport := &mockLookupTransport{}
	resolver.SetTransport(mockTransport)

	if resolver.transport == nil {
		t.Error("Transport should be set after SetTransport")
	}
}

// TestSetOurHash tests the SetOurHash method
func TestSetOurHash(t *testing.T) {
	mockDB := newMockNetworkDatabase()
	resolver := &KademliaResolver{
		NetworkDatabase: mockDB,
		responseHandler: NewLookupResponseHandler(),
	}

	ourHash := common.Hash{1, 2, 3, 4, 5, 6, 7, 8}
	resolver.SetOurHash(ourHash)

	if resolver.ourHash != ourHash {
		t.Error("OurHash should be set after SetOurHash")
	}
}

// TestGetResponseHandler tests the GetResponseHandler method
func TestGetResponseHandler(t *testing.T) {
	mockDB := newMockNetworkDatabase()
	handler := NewLookupResponseHandler()
	resolver := &KademliaResolver{
		NetworkDatabase: mockDB,
		responseHandler: handler,
	}

	got := resolver.GetResponseHandler()
	if got != handler {
		t.Error("GetResponseHandler should return the response handler")
	}
}
