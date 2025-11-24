package netdb

import (
	"crypto/rand"
	"testing"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/lease_set"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockNetDB implements the minimal interface needed for DestinationResolver
type mockNetDB struct {
	leaseSets map[common.Hash][]byte
}

func newMockNetDB() *mockNetDB {
	return &mockNetDB{
		leaseSets: make(map[common.Hash][]byte),
	}
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
	assert.Contains(t, err.Error(), "not found in NetDB")
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

	// Should fail with "not a LeaseSet2"
	_, err = resolver.extractKeyFromLeaseSet2(destHash)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not a LeaseSet2")
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
	assert.Contains(t, err.Error(), "not a LeaseSet2")
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
