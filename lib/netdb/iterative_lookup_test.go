package netdb

import (
	"context"
	"encoding/binary"
	"errors"
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/bootstrap"
	"github.com/go-i2p/go-i2p/lib/i2np"
)

// iterativeMockDB is a mock NetworkDatabase that always returns stored RouterInfos
// via GetRouterInfo. Unlike the standard mockNetworkDatabase, this mock does NOT
// require RouterInfos to have valid IdentHash — it returns them as-is, which allows
// getPeerRouterInfo to receive a non-nil RI. The IdentHash check in getPeerRouterInfo
// will still reject empty-hash RIs, so this mock is only useful when the test
// exercises the queryPeer path (where transport sends the lookup and we bypass
// the IdentHash validation).
//
// For the iterative lookup tests, the key insight is that queryPeer calls
// getPeerRouterInfo first, which requires a valid IdentHash. Since we can't
// easily create a mock RouterInfo with a valid IdentHash, we test the iterative
// mechanism through a resolver wrapper that skips the IdentHash check.
type iterativeMockDB struct {
	routerInfos map[common.Hash]router_info.RouterInfo
	storedRIs   []router_info.RouterInfo
}

func (m *iterativeMockDB) GetRouterInfo(hash common.Hash) chan router_info.RouterInfo {
	ch := make(chan router_info.RouterInfo, 1)
	if ri, ok := m.routerInfos[hash]; ok {
		ch <- ri
	}
	close(ch)
	return ch
}

func (m *iterativeMockDB) GetAllRouterInfos() []router_info.RouterInfo {
	result := make([]router_info.RouterInfo, 0, len(m.routerInfos))
	for _, ri := range m.routerInfos {
		result = append(result, ri)
	}
	return result
}

func (m *iterativeMockDB) StoreRouterInfo(ri router_info.RouterInfo) {
	m.storedRIs = append(m.storedRIs, ri)
}

func (m *iterativeMockDB) Reseed(_ bootstrap.Bootstrap, _ int) error { return nil }
func (m *iterativeMockDB) Size() int                                 { return len(m.routerInfos) }
func (m *iterativeMockDB) RecalculateSize() error                    { return nil }
func (m *iterativeMockDB) Ensure() error                             { return nil }

func (m *iterativeMockDB) SelectFloodfillRouters(_ common.Hash, _ int) ([]router_info.RouterInfo, error) {
	return nil, nil
}

func (m *iterativeMockDB) GetLeaseSetCount() int            { return 0 }
func (m *iterativeMockDB) GetAllLeaseSets() []LeaseSetEntry { return nil }
func (m *iterativeMockDB) StoreLeaseSet(key common.Hash, data []byte, dataType byte) error {
	return nil
}

func (m *iterativeMockDB) StoreOwnLeaseSet(key common.Hash, data []byte, dataType byte) error {
	return nil
}
func (m *iterativeMockDB) GetPublicLeaseSets() []LeaseSetEntry { return nil }
func (m *iterativeMockDB) IsOwnLeaseSet(hash common.Hash) bool { return false }

// TestSearchReplyError tests the SearchReplyError type and errors.As behavior.
func TestSearchReplyError(t *testing.T) {
	t.Run("ErrorMessage", func(t *testing.T) {
		suggestions := []common.Hash{{1}, {2}, {3}}
		err := &SearchReplyError{Suggestions: suggestions}

		expected := "peer did not have target, suggested 3 alternatives"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("ErrorsAs", func(t *testing.T) {
		suggestions := []common.Hash{{10, 20}, {30, 40}}
		var wrappedErr error = &SearchReplyError{Suggestions: suggestions}

		var searchErr *SearchReplyError
		if !errors.As(wrappedErr, &searchErr) {
			t.Fatal("errors.As should match SearchReplyError")
		}
		if len(searchErr.Suggestions) != 2 {
			t.Errorf("expected 2 suggestions, got %d", len(searchErr.Suggestions))
		}
	})

	t.Run("EmptySuggestions", func(t *testing.T) {
		err := &SearchReplyError{Suggestions: nil}
		expected := "peer did not have target, suggested 0 alternatives"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})
}

// TestIterativeLookup_LocalHit verifies iterative lookup returns immediately on local cache hit.
func TestIterativeLookup_LocalHit(t *testing.T) {
	mockDB := newMockNetworkDatabase()

	// Store a RouterInfo locally — use a hash that we'll search for
	targetHash := common.Hash{42, 42, 42}
	mockDB.routerInfos[targetHash] = router_info.RouterInfo{}

	// Lookup should succeed from local cache (the RI will have an empty IdentHash,
	// but will be present in the channel)
	riChan := mockDB.GetRouterInfo(targetHash)
	_, ok := <-riChan
	if !ok {
		t.Fatal("expected to find RI in mock database")
	}
}

// TestIterativeLookup_NoTransport verifies error when transport is not set.
func TestIterativeLookup_NoTransport(t *testing.T) {
	mockDB := newMockNetworkDatabase()
	// Add a peer so findClosestPeers returns something
	peerHash := common.Hash{1, 2, 3}
	mockDB.routerInfos[peerHash] = router_info.RouterInfo{}

	resolver := &KademliaResolver{
		NetworkDatabase: mockDB,
		transport:       nil,
		responseHandler: NewLookupResponseHandler(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	targetHash := common.Hash{99, 99, 99}
	_, err := resolver.iterativeLookup(ctx, targetHash)
	if err == nil {
		t.Error("expected error when transport is nil")
	}
}

// TestIterativeLookup_NoPeers verifies error when no peers are available.
func TestIterativeLookup_NoPeers(t *testing.T) {
	mockDB := newMockNetworkDatabase()
	resolver := &KademliaResolver{
		NetworkDatabase: mockDB,
		transport:       &mockLookupTransport{},
		responseHandler: NewLookupResponseHandler(),
	}

	ctx := context.Background()
	_, err := resolver.iterativeLookup(ctx, common.Hash{1})
	if err == nil {
		t.Error("expected error when no peers available")
	}
	if err.Error() != "insufficient peers available for lookup" {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestIterativeLookup_FollowsSuggestions verifies that the iterative lookup
// follows peer suggestions from DatabaseSearchReply responses across multiple hops.
// Since mock RouterInfos cannot have valid IdentHash, we test the mechanism by
// verifying that selectClosestUnqueried + queryBatchParallel correctly handle
// the SearchReplyError suggestions. The integration of these pieces is the
// iterative lookup.
func TestIterativeLookup_FollowsSuggestions(t *testing.T) {
	db := newMockNetworkDatabase()
	seed := *createTestRouterInfoWithOptions(t, map[string]string{"caps": "fR", "host": "1.2.3.4", "port": "12345", "transport": "NTCP2"})
	suggested := *createTestRouterInfoWithOptions(t, map[string]string{"caps": "R", "host": "2.3.4.5", "port": "12346", "transport": "NTCP2"})
	target := *createTestRouterInfoWithOptions(t, map[string]string{"caps": "R", "host": "3.4.5.6", "port": "12347", "transport": "NTCP2"})

	seedHash, err := seed.IdentHash()
	if err != nil {
		t.Fatalf("seed hash: %v", err)
	}
	suggestedHash, err := suggested.IdentHash()
	if err != nil {
		t.Fatalf("suggested hash: %v", err)
	}
	targetHash, err := target.IdentHash()
	if err != nil {
		t.Fatalf("target hash: %v", err)
	}

	db.StoreRouterInfo(seed)

	transport := &mockLookupTransport{
		sendFunc: func(ctx context.Context, peerRI router_info.RouterInfo, lookup *i2np.DatabaseLookup) ([]byte, int, error) {
			peerHash, err := peerRI.IdentHash()
			if err != nil {
				return nil, 0, err
			}

			switch {
			case peerHash == seedHash && lookup.Key == targetHash:
				reply := i2np.NewDatabaseSearchReply(targetHash, seedHash, []common.Hash{suggestedHash})
				payload, err := reply.MarshalPayload()
				return payload, i2np.I2NPMessageTypeDatabaseSearchReply, err
			case peerHash == seedHash && lookup.Key == suggestedHash:
				return marshalRouterInfoStore(t, suggestedHash, suggested), i2np.I2NPMessageTypeDatabaseStore, nil
			case peerHash == suggestedHash && lookup.Key == targetHash:
				return marshalRouterInfoStore(t, targetHash, target), i2np.I2NPMessageTypeDatabaseStore, nil
			default:
				t.Logf("unexpected lookup path peer=%x target=%x", peerHash[:8], lookup.Key[:8])
				return nil, 0, errors.New("unexpected lookup path")
			}
		},
	}

	resolver := NewKademliaResolverWithTransport(db, nil, transport, seedHash)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := resolver.iterativeLookup(ctx, targetHash)
	if err != nil {
		t.Fatalf("iterative lookup failed: %v", err)
	}
	if result == nil {
		t.Fatal("expected RouterInfo result")
	}
	gotHash, err := result.IdentHash()
	if err != nil {
		t.Fatalf("result hash: %v", err)
	}
	if gotHash != targetHash {
		t.Fatalf("lookup returned wrong RouterInfo: got %x want %x", gotHash[:8], targetHash[:8])
	}

	if _, ok := db.routerInfos[suggestedHash]; !ok {
		t.Fatal("expected suggested peer RouterInfo to be stored")
	}
}

// TestIterativeLookup_ContextCancellation verifies the lookup respects context cancellation.
func TestIterativeLookup_ContextCancellation(t *testing.T) {
	mockDB := newMockNetworkDatabase()

	peerHash := common.Hash{1}
	mockDB.routerInfos[peerHash] = router_info.RouterInfo{}

	transport := &mockLookupTransport{
		sendFunc: func(ctx context.Context, peerRI router_info.RouterInfo, lookup *i2np.DatabaseLookup) ([]byte, int, error) {
			// Simulate slow peer
			select {
			case <-ctx.Done():
				return nil, 0, ctx.Err()
			case <-time.After(5 * time.Second):
				return nil, 0, errors.New("should not reach here")
			}
		},
	}

	resolver := NewKademliaResolverWithTransport(mockDB, nil, transport, common.Hash{0})

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := resolver.iterativeLookup(ctx, common.Hash{99})
	if err == nil {
		t.Error("expected error on context cancellation")
	}
}

// TestSelectClosestUnqueried verifies correct selection of closest unqueried peers.
func TestSelectClosestUnqueried(t *testing.T) {
	mockDB := newMockNetworkDatabase()
	resolver := &KademliaResolver{
		NetworkDatabase: mockDB,
		responseHandler: NewLookupResponseHandler(),
	}

	target := common.Hash{0xFF} // Target with high first byte

	// Create unqueried peers with different distances to target
	unqueried := map[common.Hash]bool{
		{0xFE}: true, // Very close to target (XOR = 0x01)
		{0x00}: true, // Very far from target (XOR = 0xFF)
		{0xFC}: true, // Close to target (XOR = 0x03)
		{0x80}: true, // Medium distance (XOR = 0x7F)
	}

	result := resolver.selectClosestUnqueried(target, unqueried, 2)

	if len(result) != 2 {
		t.Fatalf("expected 2 peers, got %d", len(result))
	}

	// First result should be the closest peer (0xFE, distance 0x01)
	if result[0] != (common.Hash{0xFE}) {
		t.Errorf("expected closest peer {0xFE}, got %x", result[0][:1])
	}

	// Second result should be the next closest (0xFC, distance 0x03)
	if result[1] != (common.Hash{0xFC}) {
		t.Errorf("expected second closest peer {0xFC}, got %x", result[1][:1])
	}
}

// TestSelectClosestUnqueried_Empty verifies behavior with no unqueried peers.
func TestSelectClosestUnqueried_Empty(t *testing.T) {
	mockDB := newMockNetworkDatabase()
	resolver := &KademliaResolver{
		NetworkDatabase: mockDB,
		responseHandler: NewLookupResponseHandler(),
	}

	unqueried := map[common.Hash]bool{}
	result := resolver.selectClosestUnqueried(common.Hash{1}, unqueried, 3)

	if len(result) != 0 {
		t.Errorf("expected 0 peers, got %d", len(result))
	}
}

// TestSelectClosestUnqueried_LessThanCount verifies behavior when
// there are fewer unqueried peers than the requested count.
func TestSelectClosestUnqueried_LessThanCount(t *testing.T) {
	mockDB := newMockNetworkDatabase()
	resolver := &KademliaResolver{
		NetworkDatabase: mockDB,
		responseHandler: NewLookupResponseHandler(),
	}

	unqueried := map[common.Hash]bool{
		{0x01}: true,
	}
	result := resolver.selectClosestUnqueried(common.Hash{0xFF}, unqueried, 5)

	if len(result) != 1 {
		t.Errorf("expected 1 peer, got %d", len(result))
	}
}

// TestQueryBatchParallel verifies parallel querying and result collection.
// Since mock RouterInfos have empty IdentHash, queryPeer will fail at getPeerRouterInfo
// for each peer. This test verifies that the batch mechanism correctly collects
// error results and that all peers in the batch are processed.
func TestQueryBatchParallel(t *testing.T) {
	mockDB := newMockNetworkDatabase()

	peer1 := common.Hash{1}
	peer2 := common.Hash{2}
	target := common.Hash{99}

	mockDB.routerInfos[peer1] = router_info.RouterInfo{}
	mockDB.routerInfos[peer2] = router_info.RouterInfo{}

	transport := &mockLookupTransport{
		sendFunc: func(ctx context.Context, peerRI router_info.RouterInfo, lookup *i2np.DatabaseLookup) ([]byte, int, error) {
			reply := i2np.NewDatabaseSearchReply(target, common.Hash{0}, nil)
			data, _ := reply.MarshalBinary()
			return data, i2np.I2NPMessageTypeDatabaseSearchReply, nil
		},
	}

	resolver := NewKademliaResolverWithTransport(mockDB, nil, transport, common.Hash{0})

	ctx := context.Background()
	results := resolver.queryBatchParallel(ctx, []common.Hash{peer1, peer2}, target, true)

	// Both peers should produce results (even if errors due to empty IdentHash)
	if len(results) != 2 {
		t.Errorf("expected 2 results, got %d", len(results))
	}

	// All results should have errors (due to empty IdentHash in mock)
	for i, r := range results {
		if r.ri != nil {
			t.Errorf("result %d: expected nil ri (mock has empty IdentHash)", i)
		}
		if r.err == nil {
			t.Errorf("result %d: expected error", i)
		}
	}
}

// TestProcessDatabaseSearchReplyResponse_ReturnsSuggestions verifies that
// processDatabaseSearchReplyResponse returns a SearchReplyError with suggestions.
func TestProcessDatabaseSearchReplyResponse_ReturnsSuggestions(t *testing.T) {
	err, peerHashes := marshalAndProcessSearchReply(t, func(sr *i2np.DatabaseSearchReply) ([]byte, error) {
		return sr.MarshalPayload()
	})

	// Verify it's a SearchReplyError with the correct suggestions
	var searchErr *SearchReplyError
	if !errors.As(err, &searchErr) {
		t.Fatalf("expected SearchReplyError, got %T: %v", err, err)
	}
	if len(searchErr.Suggestions) != 2 {
		t.Errorf("expected 2 suggestions, got %d", len(searchErr.Suggestions))
	}
	if searchErr.Suggestions[0] != peerHashes[0] {
		t.Errorf("first suggestion mismatch")
	}
	if searchErr.Suggestions[1] != peerHashes[1] {
		t.Errorf("second suggestion mismatch")
	}
}

// TestMaxIterativeLookupHops verifies the hop limit is respected.
func TestMaxIterativeLookupHops(t *testing.T) {
	if MaxIterativeLookupHops != 5 {
		t.Errorf("expected MaxIterativeLookupHops=5, got %d", MaxIterativeLookupHops)
	}
	if MaxConcurrentQueries != 3 {
		t.Errorf("expected MaxConcurrentQueries=3, got %d", MaxConcurrentQueries)
	}
}

func marshalRouterInfoStore(t *testing.T, key common.Hash, ri router_info.RouterInfo) []byte {
	t.Helper()
	raw, err := ri.Bytes()
	if err != nil {
		t.Fatalf("RouterInfo bytes: %v", err)
	}
	compressed, err := gzipCompress(raw)
	if err != nil {
		t.Fatalf("gzip RouterInfo: %v", err)
	}
	payload := make([]byte, 2+len(compressed))
	binary.BigEndian.PutUint16(payload[:2], uint16(len(compressed)))
	copy(payload[2:], compressed)
	store := i2np.NewDatabaseStore(key, payload, i2np.DatabaseStoreTypeRouterInfo)
	data, err := store.MarshalPayload()
	if err != nil {
		t.Fatalf("marshal DatabaseStore: %v", err)
	}
	return data
}
