package tunnel

import (
	"encoding/binary"
	"testing"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	cryptotunnel "github.com/go-i2p/crypto/tunnel"
)

// =============================================================================
// Shared mock implementations for lib/tunnel test suite
// =============================================================================
// Mocks and test helpers that are used by two or more test files live here.
// Single-file mocks remain in their respective test files.

// ---------------------------------------------------------------------------
// Mock encryptors (passthrough — no real crypto)
// ---------------------------------------------------------------------------

// mockTunnelEncryptor is a passthrough TunnelEncryptor that reports ECIES type.
// Used by: manager_test.go, source_limiter_test.go
type mockTunnelEncryptor struct{}

func (m *mockTunnelEncryptor) Encrypt(data []byte) ([]byte, error) {
	result := make([]byte, len(data))
	copy(result, data)
	return result, nil
}

func (m *mockTunnelEncryptor) Decrypt(data []byte) ([]byte, error) {
	result := make([]byte, len(data))
	copy(result, data)
	return result, nil
}

func (m *mockTunnelEncryptor) Type() cryptotunnel.TunnelEncryptionType {
	return cryptotunnel.TunnelEncryptionECIES
}

// mockPassthroughEncryptor is a passthrough TunnelEncryptor that reports AES type.
// Used by: gateway_test.go, spec_compliance_test.go
type mockPassthroughEncryptor struct{}

func (m *mockPassthroughEncryptor) Encrypt(data []byte) ([]byte, error) {
	result := make([]byte, len(data))
	copy(result, data)
	return result, nil
}

func (m *mockPassthroughEncryptor) Decrypt(data []byte) ([]byte, error) {
	result := make([]byte, len(data))
	copy(result, data)
	return result, nil
}

func (m *mockPassthroughEncryptor) Type() cryptotunnel.TunnelEncryptionType {
	return cryptotunnel.TunnelEncryptionAES
}

// ---------------------------------------------------------------------------
// Mock peer selectors
// ---------------------------------------------------------------------------

// MockPeerSelector returns a static list of peers, truncated to the
// requested count. Used by: pool_test.go, pool_maintenance_test.go,
// peer_extraction_test.go
type MockPeerSelector struct {
	peers []router_info.RouterInfo
}

func (m *MockPeerSelector) SelectPeers(count int, exclude []common.Hash) ([]router_info.RouterInfo, error) {
	if len(m.peers) < count {
		return m.peers, nil
	}
	return m.peers[:count], nil
}

// mockPeerSelector supports configurable error and fixed peer list.
// Used by: security_test.go, selector_stack_test.go
type mockPeerSelector struct {
	returnError bool
	returnPeers []router_info.RouterInfo
}

func (m *mockPeerSelector) SelectPeers(count int, exclude []common.Hash) ([]router_info.RouterInfo, error) {
	if m.returnError {
		return nil, ErrInvalidMessage
	}
	if m.returnPeers != nil {
		return m.returnPeers, nil
	}
	return nil, nil
}

// fakeDB implements NetDBSelector for tests.
// Used by: peer_selector_test.go, selector_stack_test.go
type fakeDB struct {
	peers []router_info.RouterInfo
	err   error
}

func (f *fakeDB) SelectPeers(count int, exclude []common.Hash) ([]router_info.RouterInfo, error) {
	if f.err != nil {
		return nil, f.err
	}
	if len(f.peers) < count {
		return f.peers, nil
	}
	return f.peers[:count], nil
}

// ---------------------------------------------------------------------------
// Shared test helpers
// ---------------------------------------------------------------------------

// addParticipantToManager creates a Participant with the given tunnel ID and
// adds it to the manager. Returns the participant for optional field tweaking
// (e.g., setting createdAt or lastActivity). Consolidates the repeated
// NewParticipant+AddParticipant+error-check boilerplate across cleanup tests.
func addParticipantToManager(t *testing.T, m *Manager, id TunnelID) *Participant {
	t.Helper()
	p, _ := NewParticipant(id, &mockTunnelEncryptor{})
	if err := m.AddParticipant(p); err != nil {
		t.Fatalf("Failed to add participant %d: %v", id, err)
	}
	return p
}

// specMakeRouterInfo creates a minimal RouterInfo for testing by constructing
// raw bytes and parsing them via ReadRouterInfo. Each unique id byte produces a
// RouterInfo with a distinct IdentHash.
// Used by: builder_test.go, spec_compliance_test.go
func specMakeRouterInfo(id byte) router_info.RouterInfo {
	buf := make([]byte, 467)
	// Bytes 0-255: ElGamal public key (unique per id)
	for i := 0; i < 256; i++ {
		buf[i] = id
	}
	// Bytes 256-383: signing key area (96 padding + 32 Ed25519 key)
	for i := 256; i < 384; i++ {
		buf[i] = id
	}
	// Certificate: type=5 (KEY), length=4, sigType=7 (Ed25519), cryptoType=0 (ElGamal)
	buf[384] = 0x05
	buf[385] = 0x00
	buf[386] = 0x04
	buf[387] = 0x00
	buf[388] = 0x07
	buf[389] = 0x00
	buf[390] = 0x00
	// Published date (8 bytes) — use a fixed timestamp to be deterministic
	binary.BigEndian.PutUint64(buf[391:399], uint64(1700000000000))
	// Address count: 0
	buf[399] = 0x00
	// Peer size: 0
	buf[400] = 0x00
	// Mapping (empty): 2-byte length = 0
	buf[401] = 0x00
	buf[402] = 0x00
	// Signature: 64 bytes for Ed25519
	for i := 403; i < 467; i++ {
		buf[i] = id
	}
	ri, _, err := router_info.ReadRouterInfo(buf)
	if err != nil {
		// Fallback: should never happen with the hardcoded layout above
		return router_info.RouterInfo{}
	}
	return ri
}
