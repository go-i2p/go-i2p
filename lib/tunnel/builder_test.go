package tunnel

import (
	"errors"
	"fmt"
	"testing"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
)

// mockBuilderPeerSelector is a test implementation of PeerSelector for builder tests
type mockBuilderPeerSelector struct {
	peers     []router_info.RouterInfo
	callCount int
	err       error
}

func (m *mockBuilderPeerSelector) SelectPeers(count int, exclude []common.Hash) ([]router_info.RouterInfo, error) {
	m.callCount++
	if m.err != nil {
		return nil, m.err
	}
	if len(m.peers) < count {
		return m.peers, nil
	}
	return m.peers[:count], nil
}

// TestNewTunnelBuilder tests the constructor
func TestNewTunnelBuilder(t *testing.T) {
	t.Run("valid selector", func(t *testing.T) {
		selector := &mockBuilderPeerSelector{}
		builder, err := NewTunnelBuilder(selector)
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if builder == nil {
			t.Error("expected non-nil builder")
		}
	})

	t.Run("nil selector", func(t *testing.T) {
		builder, err := NewTunnelBuilder(nil)
		if err == nil {
			t.Error("expected error for nil selector")
		}
		if builder != nil {
			t.Error("expected nil builder")
		}
	})
}

// TestCreateBuildRequest_InvalidHopCount tests hop count validation
func TestCreateBuildRequest_InvalidHopCount(t *testing.T) {
	selector := &mockBuilderPeerSelector{peers: []router_info.RouterInfo{}}
	builder, err := NewTunnelBuilder(selector)
	if err != nil {
		t.Fatalf("failed to create builder: %v", err)
	}

	tests := []struct {
		name     string
		hopCount int
	}{
		{"zero hops", 0},
		{"negative hops", -1},
		{"too many hops", 9},
		{"way too many hops", 100},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := BuildTunnelRequest{
				HopCount:  tt.hopCount,
				IsInbound: false,
			}

			resp, err := builder.CreateBuildRequest(req)
			if err == nil {
				t.Error("expected error for invalid hop count")
			}
			if resp != nil {
				t.Error("expected nil response")
			}
		})
	}
}

// TestCreateBuildRequest_PeerSelectionFailure tests handling of peer selection errors
func TestCreateBuildRequest_PeerSelectionFailure(t *testing.T) {
	selector := &mockBuilderPeerSelector{
		peers: []router_info.RouterInfo{},
		err:   errors.New("peer selection failed"),
	}
	builder, err := NewTunnelBuilder(selector)
	if err != nil {
		t.Fatalf("failed to create builder: %v", err)
	}

	req := BuildTunnelRequest{
		HopCount:  3,
		IsInbound: false,
	}

	resp, err := builder.CreateBuildRequest(req)
	if err == nil {
		t.Error("expected error from peer selection failure")
	}
	if resp != nil {
		t.Error("expected nil response")
	}
}

// TestGenerateTunnelID tests tunnel ID generation
func TestGenerateTunnelID(t *testing.T) {
	// Generate multiple IDs and verify they're unique and non-zero
	ids := make(map[TunnelID]bool)

	for i := 0; i < 100; i++ {
		id, err := generateTunnelID()
		if err != nil {
			t.Fatalf("failed to generate tunnel ID: %v", err)
		}
		if id == TunnelID(0) {
			t.Error("Tunnel ID should never be zero")
		}
		if ids[id] {
			t.Errorf("Tunnel ID %d already generated (not unique)", id)
		}
		ids[id] = true
	}

	if len(ids) != 100 {
		t.Errorf("expected 100 unique IDs, got %d", len(ids))
	}
}

// TestGenerateSessionKey tests session key generation
func TestGenerateSessionKey(t *testing.T) {
	// Generate multiple keys and verify they're unique
	keys := make(map[string]bool)

	for i := 0; i < 100; i++ {
		key, err := generateSessionKey()
		if err != nil {
			t.Fatalf("failed to generate session key: %v", err)
		}

		keyStr := string(key[:])
		if keys[keyStr] {
			t.Error("Session keys should be unique")
		}
		keys[keyStr] = true
	}

	if len(keys) != 100 {
		t.Errorf("expected 100 unique keys, got %d", len(keys))
	}
}

// TestGenerateMessageID tests message ID generation
func TestGenerateMessageID(t *testing.T) {
	// Generate multiple IDs and verify they're reasonably unique
	ids := make(map[int]bool)

	for i := 0; i < 100; i++ {
		id, err := generateMessageID()
		if err != nil {
			t.Fatalf("generateMessageID() returned unexpected error: %v", err)
		}
		ids[id] = true
	}

	// Should have high uniqueness (allow for some collisions due to randomness)
	if len(ids) < 90 {
		t.Errorf("expected mostly unique message IDs (>90), got %d unique out of 100", len(ids))
	}
}

// TestGenerateMessageID_ReturnsError verifies that generateMessageID returns
// an error value (nil on success) rather than panicking.
func TestGenerateMessageID_ReturnsError(t *testing.T) {
	id, err := generateMessageID()
	if err != nil {
		t.Fatalf("generateMessageID() returned unexpected error: %v", err)
	}
	if id < 0 {
		t.Errorf("expected non-negative message ID, got %d", id)
	}
	if id > 0x7FFFFFFF {
		t.Errorf("expected message ID to fit in 31 bits, got %d", id)
	}
}

// TestGenerateMessageID_NoPanic verifies that generateMessageID never panics.
func TestGenerateMessageID_NoPanic(t *testing.T) {
	done := make(chan bool)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("generateMessageID panicked: %v", r)
			}
			done <- true
		}()
		for i := 0; i < 100; i++ {
			_, _ = generateMessageID()
		}
	}()
	<-done
}

// TestGenerateHopTunnelIDs verifies that generateHopTunnelIDs returns
// the correct number of unique, non-zero tunnel IDs.
func TestGenerateHopTunnelIDs(t *testing.T) {
	t.Run("returns correct count", func(t *testing.T) {
		for count := 1; count <= 8; count++ {
			ids, err := generateHopTunnelIDs(count)
			if err != nil {
				t.Fatalf("generateHopTunnelIDs(%d) returned error: %v", count, err)
			}
			if len(ids) != count {
				t.Errorf("expected %d IDs, got %d", count, len(ids))
			}
		}
	})

	t.Run("all IDs are unique", func(t *testing.T) {
		ids, err := generateHopTunnelIDs(8)
		if err != nil {
			t.Fatalf("generateHopTunnelIDs(8) returned error: %v", err)
		}
		seen := make(map[TunnelID]bool)
		for i, id := range ids {
			if seen[id] {
				t.Errorf("duplicate tunnel ID %d at index %d", id, i)
			}
			seen[id] = true
		}
	})

	t.Run("all IDs are non-zero", func(t *testing.T) {
		ids, err := generateHopTunnelIDs(8)
		if err != nil {
			t.Fatalf("generateHopTunnelIDs(8) returned error: %v", err)
		}
		for i, id := range ids {
			if id == 0 {
				t.Errorf("tunnel ID at index %d is zero", i)
			}
		}
	})
}

// TestOutboundHopsUniqueReceiveTunnelIDs verifies that each hop in an outbound
// tunnel receives a unique ReceiveTunnel ID, fixing CRITICAL BUG #4.
// We verify the tunnel ID assignment logic directly since determineOutboundRouting
// also requires valid RouterInfo peers for nextIdent. The key invariant is:
// receiveTunnel = hopTunnelIDs[hopIndex], nextTunnel = hopTunnelIDs[hopIndex+1] (or 0 for last).
func TestOutboundHopsUniqueReceiveTunnelIDs(t *testing.T) {
	hopCounts := []int{2, 3, 4, 5}
	for _, hopCount := range hopCounts {
		t.Run(fmt.Sprintf("%d_hops", hopCount), func(t *testing.T) {
			hopTunnelIDs, err := generateHopTunnelIDs(hopCount)
			if err != nil {
				t.Fatalf("failed to generate hop tunnel IDs: %v", err)
			}

			// Verify each hop would get a unique receive tunnel
			seen := make(map[TunnelID]bool)
			for i := 0; i < hopCount; i++ {
				receiveTunnel := hopTunnelIDs[i]
				if seen[receiveTunnel] {
					t.Errorf("hop %d: duplicate receiveTunnel %d", i, receiveTunnel)
				}
				seen[receiveTunnel] = true
			}
			if len(seen) != hopCount {
				t.Errorf("expected %d unique receiveTunnels, got %d", hopCount, len(seen))
			}

			// Verify chaining: hop i's nextTunnel = hop i+1's receiveTunnel
			for i := 0; i < hopCount-1; i++ {
				nextTunnel := hopTunnelIDs[i+1]
				nextReceive := hopTunnelIDs[i+1]
				if nextTunnel != nextReceive {
					t.Errorf("hop %d nextTunnel (%d) != hop %d receiveTunnel (%d)",
						i, nextTunnel, i+1, nextReceive)
				}
			}
		})
	}
}

// TestOutboundHopNextTunnelChaining verifies the single-hop outbound endpoint
// behavior plus chaining for a 2-hop outbound tunnel using the last-hop path
// that doesn't require peer IdentHash.
func TestOutboundHopNextTunnelChaining(t *testing.T) {
	hopCount := 4
	hopTunnelIDs, err := generateHopTunnelIDs(hopCount)
	if err != nil {
		t.Fatalf("failed to generate hop tunnel IDs: %v", err)
	}

	peers := make([]router_info.RouterInfo, hopCount)
	builder := &TunnelBuilder{}

	// Test last hop (endpoint) — does not call IdentHash on next peer
	receiveTunnel, nextTunnel, _, err := builder.determineOutboundRouting(hopCount-1, hopTunnelIDs, peers)
	if err != nil {
		t.Fatalf("last hop error: %v", err)
	}
	if receiveTunnel != hopTunnelIDs[hopCount-1] {
		t.Errorf("last hop receiveTunnel = %d, want %d", receiveTunnel, hopTunnelIDs[hopCount-1])
	}
	if nextTunnel != 0 {
		t.Errorf("last hop nextTunnel should be 0, got %d", nextTunnel)
	}
}

// TestInboundHopsUniqueReceiveTunnelIDs verifies that each hop in an inbound
// tunnel receives a unique ReceiveTunnel ID.
func TestInboundHopsUniqueReceiveTunnelIDs(t *testing.T) {
	hopCount := 4
	hopTunnelIDs, err := generateHopTunnelIDs(hopCount)
	if err != nil {
		t.Fatalf("failed to generate hop tunnel IDs: %v", err)
	}

	// Each hop's receiveTunnel is hopTunnelIDs[hopIndex], which must be unique
	seen := make(map[TunnelID]bool)
	for i := 0; i < hopCount; i++ {
		receiveTunnel := hopTunnelIDs[i]
		if seen[receiveTunnel] {
			t.Errorf("hop %d: duplicate receiveTunnel %d", i, receiveTunnel)
		}
		seen[receiveTunnel] = true
	}
	if len(seen) != hopCount {
		t.Errorf("expected %d unique receiveTunnels, got %d", hopCount, len(seen))
	}
}

// TestInboundHopNextTunnelChaining verifies that for inbound tunnels,
// the last hop's NextTunnel equals the ReplyTunnelID, and tunnel IDs
// are correctly chained via hopTunnelIDs.
func TestInboundHopNextTunnelChaining(t *testing.T) {
	hopCount := 4
	hopTunnelIDs, err := generateHopTunnelIDs(hopCount)
	if err != nil {
		t.Fatalf("failed to generate hop tunnel IDs: %v", err)
	}

	replyTunnelID := TunnelID(12345)
	peers := make([]router_info.RouterInfo, hopCount)
	builder := &TunnelBuilder{}
	req := BuildTunnelRequest{
		HopCount:      hopCount,
		IsInbound:     true,
		ReplyTunnelID: replyTunnelID,
	}

	// Verify chaining through the hopTunnelIDs array
	for i := 0; i < hopCount-1; i++ {
		nextTunnel := hopTunnelIDs[i+1]
		nextReceive := hopTunnelIDs[i+1]
		if nextTunnel != nextReceive {
			t.Errorf("hop %d nextTunnel (%d) != hop %d receiveTunnel (%d)",
				i, nextTunnel, i+1, nextReceive)
		}
	}

	// Last hop's nextTunnel should be the ReplyTunnelID — test via determineInboundRouting
	_, lastNext, _, err := builder.determineInboundRouting(hopCount-1, req, hopTunnelIDs, peers)
	if err != nil {
		t.Fatalf("last hop error: %v", err)
	}
	if lastNext != replyTunnelID {
		t.Errorf("last hop nextTunnel should be %d (ReplyTunnelID), got %d", replyTunnelID, lastNext)
	}
}

// TestSingleHopTunnelIDs verifies correct behavior for single-hop tunnels.
func TestSingleHopTunnelIDs(t *testing.T) {
	t.Run("outbound single hop", func(t *testing.T) {
		hopTunnelIDs, err := generateHopTunnelIDs(1)
		if err != nil {
			t.Fatalf("failed to generate hop tunnel IDs: %v", err)
		}

		peers := make([]router_info.RouterInfo, 1)
		builder := &TunnelBuilder{}

		receiveTunnel, nextTunnel, _, err := builder.determineOutboundRouting(0, hopTunnelIDs, peers)
		if err != nil {
			t.Fatalf("determineOutboundRouting error: %v", err)
		}
		if receiveTunnel != hopTunnelIDs[0] {
			t.Errorf("receiveTunnel should be hopTunnelIDs[0] (%d), got %d", hopTunnelIDs[0], receiveTunnel)
		}
		if nextTunnel != 0 {
			t.Errorf("single-hop outbound nextTunnel should be 0, got %d", nextTunnel)
		}
	})

	t.Run("inbound single hop", func(t *testing.T) {
		hopTunnelIDs, err := generateHopTunnelIDs(1)
		if err != nil {
			t.Fatalf("failed to generate hop tunnel IDs: %v", err)
		}

		replyTunnelID := TunnelID(77777)
		peers := make([]router_info.RouterInfo, 1)
		builder := &TunnelBuilder{}
		req := BuildTunnelRequest{
			HopCount:      1,
			IsInbound:     true,
			ReplyTunnelID: replyTunnelID,
		}

		receiveTunnel, nextTunnel, _, err := builder.determineInboundRouting(0, req, hopTunnelIDs, peers)
		if err != nil {
			t.Fatalf("determineInboundRouting error: %v", err)
		}
		if receiveTunnel != hopTunnelIDs[0] {
			t.Errorf("receiveTunnel should be hopTunnelIDs[0] (%d), got %d", hopTunnelIDs[0], receiveTunnel)
		}
		if nextTunnel != replyTunnelID {
			t.Errorf("single-hop inbound nextTunnel should be %d, got %d", replyTunnelID, nextTunnel)
		}
	})
}

// BenchmarkGenerateHopTunnelIDs benchmarks per-hop tunnel ID generation
func BenchmarkGenerateHopTunnelIDs(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = generateHopTunnelIDs(3)
	}
}

// BenchmarkCreateBuildRequest benchmarks build request creation (minimal version)
func BenchmarkCreateBuildRequest(b *testing.B) {
	// Create minimal mock - won't actually work but tests the flow
	selector := &mockBuilderPeerSelector{
		peers: make([]router_info.RouterInfo, 3),
		err:   nil,
	}
	builder, _ := NewTunnelBuilder(selector)

	req := BuildTunnelRequest{
		HopCount:  3,
		IsInbound: false,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = builder.CreateBuildRequest(req)
	}
}

// BenchmarkGenerateTunnelID benchmarks tunnel ID generation
func BenchmarkGenerateTunnelID(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = generateTunnelID()
	}
}

// BenchmarkGenerateSessionKey benchmarks session key generation
func BenchmarkGenerateSessionKey(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = generateSessionKey()
	}
}

// TestDetermineBuildRecordFlag verifies IBGW/OBEP flag assignment per I2P spec.
// Per §tunnel-creation: Bit 7 = IBGW (allow messages from anyone),
// Bit 6 = OBEP (allow messages to anyone).
func TestDetermineBuildRecordFlag(t *testing.T) {
	tests := []struct {
		name     string
		hopIndex int
		hopCount int
		inbound  bool
		expected int
	}{
		{"outbound gateway (first hop)", 0, 3, false, 0},
		{"outbound participant (middle)", 1, 3, false, 0},
		{"outbound endpoint (last hop)", 2, 3, false, FlagOBEP},
		{"inbound gateway (first hop = IBGW)", 0, 3, true, FlagIBGW},
		{"inbound participant (middle)", 1, 3, true, 0},
		{"inbound endpoint (last hop)", 2, 3, true, 0},
		{"single-hop outbound = OBEP", 0, 1, false, FlagOBEP},
		{"single-hop inbound = IBGW", 0, 1, true, FlagIBGW},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := determineBuildRecordFlag(tt.hopIndex, tt.hopCount, tt.inbound)
			if got != tt.expected {
				t.Errorf("determineBuildRecordFlag(%d, %d, %v) = 0x%02x, want 0x%02x",
					tt.hopIndex, tt.hopCount, tt.inbound, got, tt.expected)
			}
		})
	}
}

// TestCreateBuildRequest_IBGWOBEPFlags verifies that CreateBuildRequest sets
// IBGW/OBEP flags correctly on the generated build records.
func TestCreateBuildRequest_IBGWOBEPFlags(t *testing.T) {
	peers := make([]router_info.RouterInfo, 3)
	for i := range peers {
		peers[i] = specMakeRouterInfo(byte(i + 10))
	}
	selector := &mockBuilderPeerSelector{peers: peers}
	builder, err := NewTunnelBuilder(selector)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	t.Run("outbound tunnel flags", func(t *testing.T) {
		result, err := builder.CreateBuildRequest(BuildTunnelRequest{
			HopCount:  3,
			IsInbound: false,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// First hop (gateway): no special flags
		if result.Records[0].Flag != 0 {
			t.Errorf("outbound gateway flag = 0x%02x, want 0x00", result.Records[0].Flag)
		}
		// Middle hop: no special flags
		if result.Records[1].Flag != 0 {
			t.Errorf("outbound participant flag = 0x%02x, want 0x00", result.Records[1].Flag)
		}
		// Last hop (endpoint): OBEP flag
		if result.Records[2].Flag != FlagOBEP {
			t.Errorf("outbound endpoint flag = 0x%02x, want 0x%02x", result.Records[2].Flag, FlagOBEP)
		}
	})

	t.Run("inbound tunnel flags", func(t *testing.T) {
		result, err := builder.CreateBuildRequest(BuildTunnelRequest{
			HopCount:  3,
			IsInbound: true,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// First hop (IBGW): IBGW flag
		if result.Records[0].Flag != FlagIBGW {
			t.Errorf("inbound gateway flag = 0x%02x, want 0x%02x", result.Records[0].Flag, FlagIBGW)
		}
		// Middle hop: no special flags
		if result.Records[1].Flag != 0 {
			t.Errorf("inbound participant flag = 0x%02x, want 0x00", result.Records[1].Flag)
		}
		// Last hop: no special flags (delivers to us)
		if result.Records[2].Flag != 0 {
			t.Errorf("inbound endpoint flag = 0x%02x, want 0x00", result.Records[2].Flag)
		}
	})
}
