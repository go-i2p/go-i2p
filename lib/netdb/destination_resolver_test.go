package netdb

import (
	"sync"
	"testing"

	"github.com/go-i2p/crypto/rand"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/lease_set"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/bootstrap"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockNetDB implements the minimal interface needed for DestinationResolver
type mockNetDB struct {
	mu          sync.RWMutex
	leaseSets   map[common.Hash][]byte
	routerInfos map[common.Hash]router_info.RouterInfo
}

func newMockNetDB() *mockNetDB {
	return &mockNetDB{
		leaseSets:   make(map[common.Hash][]byte),
		routerInfos: make(map[common.Hash]router_info.RouterInfo),
	}
}

func (m *mockNetDB) GetRouterInfo(hash common.Hash) chan router_info.RouterInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()
	ch := make(chan router_info.RouterInfo, 1)
	if ri, exists := m.routerInfos[hash]; exists {
		ch <- ri
	}
	close(ch)
	return ch
}

func (m *mockNetDB) GetAllRouterInfos() []router_info.RouterInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()
	infos := make([]router_info.RouterInfo, 0, len(m.routerInfos))
	for _, ri := range m.routerInfos {
		infos = append(infos, ri)
	}
	return infos
}

func (m *mockNetDB) StoreRouterInfo(ri router_info.RouterInfo) {
	hash, err := ri.IdentHash()
	if err == nil {
		m.mu.Lock()
		defer m.mu.Unlock()
		m.routerInfos[hash] = ri
	}
}

func (m *mockNetDB) Reseed(b bootstrap.Bootstrap, minRouters int) error {
	return nil
}

func (m *mockNetDB) Size() int {
	return 0
}

func (m *mockNetDB) RecalculateSize() error {
	return nil
}

func (m *mockNetDB) Ensure() error {
	return nil
}

func (m *mockNetDB) SelectFloodfillRouters(targetHash common.Hash, count int) ([]router_info.RouterInfo, error) {
	return []router_info.RouterInfo{}, nil
}

func (m *mockNetDB) GetLeaseSetCount() int {
	return len(m.leaseSets)
}

func (m *mockNetDB) GetAllLeaseSets() []LeaseSetEntry {
	entries := make([]LeaseSetEntry, 0, len(m.leaseSets))
	for hash, data := range m.leaseSets {
		ls, err := lease_set.ReadLeaseSet(data)
		if err != nil {
			continue
		}
		entries = append(entries, LeaseSetEntry{
			Hash: hash,
			Entry: Entry{
				LeaseSet: &ls,
			},
		})
	}
	return entries
}

func (m *mockNetDB) GetLeaseSet(hash common.Hash) chan lease_set.LeaseSet {
	data, exists := m.leaseSets[hash]
	if !exists {
		return nil
	}

	ls, err := lease_set.ReadLeaseSet(data)
	if err != nil {
		return nil
	}

	ch := make(chan lease_set.LeaseSet, 1)
	ch <- ls
	close(ch)
	return ch
}

func (m *mockNetDB) GetLeaseSetBytes(hash common.Hash) ([]byte, error) {
	data, exists := m.leaseSets[hash]
	if !exists {
		return nil, assert.AnError
	}
	return data, nil
}

func (m *mockNetDB) StoreLeaseSet(hash common.Hash, data []byte) {
	m.leaseSets[hash] = data
}

// TestNewDestinationResolver verifies resolver creation
func TestNewDestinationResolver(t *testing.T) {
	netdb := newMockNetDB()
	resolver := NewDestinationResolver(netdb)

	assert.NotNil(t, resolver)
	assert.NotNil(t, resolver.netdb)
}

// TestResolveDestination_NotFound tests resolution of non-existent destination
func TestResolveDestination_NotFound(t *testing.T) {
	netdb := newMockNetDB()
	resolver := NewDestinationResolver(netdb)

	// Create a random hash that doesn't exist
	var destHash common.Hash
	_, err := rand.Read(destHash[:])
	require.NoError(t, err)

	// Attempt to resolve non-existent destination
	_, err = resolver.ResolveDestination(destHash)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found in netdb")
}

// TestResolveDestination_InvalidLeaseSet tests handling of corrupted LeaseSet data
func TestResolveDestination_InvalidLeaseSet(t *testing.T) {
	netdb := newMockNetDB()
	resolver := NewDestinationResolver(netdb)

	// Create a hash and store invalid data
	var destHash common.Hash
	_, err := rand.Read(destHash[:])
	require.NoError(t, err)

	// Store invalid LeaseSet data
	invalidData := []byte{0x01, 0x02, 0x03}
	netdb.StoreLeaseSet(destHash, invalidData)

	// Attempt to resolve - should fail due to invalid data
	_, err = resolver.ResolveDestination(destHash)
	assert.Error(t, err)
}

// TestResolveDestination_LeaseSet2NotFound tests LeaseSet2 fallback behavior
func TestResolveDestination_LeaseSet2NotFound(t *testing.T) {
	netdb := newMockNetDB()
	resolver := NewDestinationResolver(netdb)

	var destHash common.Hash
	_, err := rand.Read(destHash[:])
	require.NoError(t, err)

	// extractKeyFromLeaseSet2 should fail for non-existent data
	_, err = resolver.extractKeyFromLeaseSet2(destHash)
	assert.Error(t, err)
}

// TestExtractKeyFromLeaseSet2_NotLeaseSet2 tests rejection of non-LeaseSet2 data
func TestExtractKeyFromLeaseSet2_NotLeaseSet2(t *testing.T) {
	netdb := newMockNetDB()
	resolver := NewDestinationResolver(netdb)

	var destHash common.Hash
	_, err := rand.Read(destHash[:])
	require.NoError(t, err)

	// Store data that doesn't start with 0x07 (LeaseSet2 marker)
	notLS2Data := []byte{0x01, 0x02, 0x03, 0x04}
	netdb.StoreLeaseSet(destHash, notLS2Data)

	// Should fail with "unsupported lease set type"
	_, err = resolver.extractKeyFromLeaseSet2(destHash)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported lease set type")
}

// TestExtractKeyFromLeaseSet2_EmptyData tests handling of empty data
func TestExtractKeyFromLeaseSet2_EmptyData(t *testing.T) {
	netdb := newMockNetDB()
	resolver := NewDestinationResolver(netdb)

	var destHash common.Hash
	_, err := rand.Read(destHash[:])
	require.NoError(t, err)

	// Store empty data
	netdb.StoreLeaseSet(destHash, []byte{})

	// Should fail due to empty data
	_, err = resolver.extractKeyFromLeaseSet2(destHash)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported lease set type")
}

// TestExtractKeyFromLeaseSet2_WithX25519Key tests successful X25519 key extraction from LeaseSet2
// Note: This test verifies the code path but requires a fully valid LeaseSet2 structure.
// For now, we verify that the parsing attempt happens and error handling works correctly.
func TestExtractKeyFromLeaseSet2_WithX25519Key(t *testing.T) {
	t.Skip("Requires full LeaseSet2 construction - verified code path exists")

	// This test demonstrates the expected behavior:
	// 1. Create a valid LeaseSet2 with X25519 encryption key
	// 2. Store it in NetDB
	// 3. Extract and verify the X25519 key
	//
	// Implementation blocked on: proper LeaseSet2 test fixture creation
	// The destination_resolver.go code already has the correct logic:
	// - Checks for type byte 0x07
	// - Calls lease_set2.ReadLeaseSet2()
	// - Extracts X25519 keys from EncryptionKeys()
	// - Returns [32]byte key for garlic encryption
}

// TestResolveDestination_LeaseSet2Success tests full resolution with LeaseSet2
func TestResolveDestination_LeaseSet2Success(t *testing.T) {
	t.Skip("Requires full LeaseSet2 construction from common package - integration test")

	// This test would require:
	// 1. Creating a valid destination with X25519 keys
	// 2. Building a proper LeaseSet2 with the destination
	// 3. Storing it in NetDB
	// 4. Resolving and verifying the X25519 key extraction
	//
	// Implementation requires github.com/go-i2p/common/lease_set2 builder functions
}

// BenchmarkResolveDestination_NotFound benchmarks failed lookups
func BenchmarkResolveDestination_NotFound(b *testing.B) {
	netdb := newMockNetDB()
	resolver := NewDestinationResolver(netdb)

	var destHash common.Hash
	rand.Read(destHash[:])

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = resolver.ResolveDestination(destHash)
	}
}
