package tunnel

import (
	"errors"
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
		id := generateMessageID()
		ids[id] = true
	}

	// Should have high uniqueness (allow for some collisions due to randomness)
	if len(ids) < 90 {
		t.Errorf("expected mostly unique message IDs (>90), got %d unique out of 100", len(ids))
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
