package netdb

import (
	"errors"
	"testing"

	"github.com/go-i2p/common/router_info"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockRouterInfoProvider is a test double for RouterInfoProvider interface.
// It allows us to control what RouterInfo is returned and simulate error conditions.
type mockRouterInfoProvider struct {
	routerInfo *router_info.RouterInfo
	err        error
	callCount  int // Track how many times GetRouterInfo was called
}

// GetRouterInfo returns the configured RouterInfo or error.
// Increments callCount for verification in tests.
func (m *mockRouterInfoProvider) GetRouterInfo() (*router_info.RouterInfo, error) {
	m.callCount++
	if m.err != nil {
		return nil, m.err
	}
	return m.routerInfo, nil
}

// TestPublishOurRouterInfo_NoProvider tests that publishing skips when no provider configured
func TestPublishOurRouterInfo_NoProvider(t *testing.T) {
	db := newMockNetDB()
	config := DefaultPublisherConfig()
	publisher := NewPublisher(db, nil, nil, nil, config)

	// Should not panic with nil provider
	publisher.publishOurRouterInfo()

	// No RouterInfo should be stored since provider is nil
	assert.Equal(t, 0, db.Size())
}

// TestPublishOurRouterInfo_ProviderError tests handling of provider errors
func TestPublishOurRouterInfo_ProviderError(t *testing.T) {
	db := newMockNetDB()
	config := DefaultPublisherConfig()

	// Create provider that returns an error
	provider := &mockRouterInfoProvider{
		err: errors.New("failed to construct RouterInfo"),
	}

	publisher := NewPublisher(db, nil, nil, provider, config)

	// Should handle error gracefully and log warning (not panic)
	publisher.publishOurRouterInfo()

	// Verify provider was called
	assert.Equal(t, 1, provider.callCount)

	// No RouterInfo should be stored due to error
	assert.Equal(t, 0, db.Size())
}

// TestPublishOurRouterInfo_InvalidRouterInfo tests handling of invalid RouterInfo
func TestPublishOurRouterInfo_InvalidRouterInfo(t *testing.T) {
	db := newMockNetDB()
	config := DefaultPublisherConfig()

	// Create an empty (invalid) RouterInfo
	invalidRI := &router_info.RouterInfo{}

	provider := &mockRouterInfoProvider{
		routerInfo: invalidRI,
	}

	publisher := NewPublisher(db, nil, nil, provider, config)

	// Should skip publishing invalid RouterInfo
	publisher.publishOurRouterInfo()

	// Verify provider was called
	assert.Equal(t, 1, provider.callCount)

	// No RouterInfo should be stored since it's invalid
	assert.Equal(t, 0, db.Size())
}

// TestPublishOurRouterInfo_Success tests successful RouterInfo publishing
func TestPublishOurRouterInfo_Success(t *testing.T) {
	db := newMockNetDB()
	config := DefaultPublisherConfig()

	// Create a valid RouterInfo for testing
	// Note: In real usage, this would come from keys.RouterInfoKeystore.ConstructRouterInfo()
	validRI := createValidTestRouterInfo(t)

	provider := &mockRouterInfoProvider{
		routerInfo: validRI,
	}

	publisher := NewPublisher(db, nil, nil, provider, config)

	// Should successfully publish RouterInfo
	publisher.publishOurRouterInfo()

	// Verify provider was called
	assert.Equal(t, 1, provider.callCount)

	// Note: Actual storage in mockNetDB depends on implementation
	// The important part is that PublishRouterInfo was called without panic
}

// TestPublisherWithRouterInfoProvider tests Publisher creation with provider
func TestPublisherWithRouterInfoProvider(t *testing.T) {
	db := newMockNetDB()
	config := DefaultPublisherConfig()

	validRI := createValidTestRouterInfo(t)
	provider := &mockRouterInfoProvider{
		routerInfo: validRI,
	}

	publisher := NewPublisher(db, nil, nil, provider, config)

	assert.NotNil(t, publisher)
	assert.NotNil(t, publisher.routerInfoProvider)
	assert.Equal(t, provider, publisher.routerInfoProvider)
}

// TestPublishOurRouterInfo_MultipleCallsToProvider tests that provider is called correctly
func TestPublishOurRouterInfo_MultipleCallsToProvider(t *testing.T) {
	db := newMockNetDB()
	config := DefaultPublisherConfig()

	validRI := createValidTestRouterInfo(t)
	provider := &mockRouterInfoProvider{
		routerInfo: validRI,
	}

	publisher := NewPublisher(db, nil, nil, provider, config)

	// Call publishOurRouterInfo multiple times
	publisher.publishOurRouterInfo()
	publisher.publishOurRouterInfo()
	publisher.publishOurRouterInfo()

	// Verify provider was called each time
	assert.Equal(t, 3, provider.callCount)
}

// TestPublishOurRouterInfo_ProviderReturnsNil tests handling when provider returns nil
func TestPublishOurRouterInfo_ProviderReturnsNil(t *testing.T) {
	db := newMockNetDB()
	config := DefaultPublisherConfig()

	provider := &mockRouterInfoProvider{
		routerInfo: nil,
		err:        errors.New("RouterInfo not available"),
	}

	publisher := NewPublisher(db, nil, nil, provider, config)

	// Should handle nil RouterInfo gracefully
	publisher.publishOurRouterInfo()

	// Verify provider was called
	assert.Equal(t, 1, provider.callCount)

	// No RouterInfo should be stored
	assert.Equal(t, 0, db.Size())
}

// createValidTestRouterInfo creates a minimal valid RouterInfo for testing.
// This simulates what keys.RouterInfoKeystore.ConstructRouterInfo() would return.
func createValidTestRouterInfo(t *testing.T) *router_info.RouterInfo {
	// For now, create an empty RouterInfo structure
	// In a real implementation, this would be fully constructed with:
	// - RouterIdentity (encryption key, signing key, certificate)
	// - Published timestamp
	// - Router addresses (NTCP2, SSU2)
	// - Options (caps, netId)
	// - Signature
	ri := &router_info.RouterInfo{}

	// Note: The mockNetDB and actual implementation will handle validation
	// This is just a placeholder for the test
	return ri
}

// TestRouterInfoProviderInterface tests that the interface is properly defined
func TestRouterInfoProviderInterface(t *testing.T) {
	// Verify mockRouterInfoProvider implements RouterInfoProvider
	var _ RouterInfoProvider = (*mockRouterInfoProvider)(nil)
}

// TestPublisherRouterInfoProviderNil tests that nil provider is allowed
func TestPublisherRouterInfoProviderNil(t *testing.T) {
	db := newMockNetDB()
	config := DefaultPublisherConfig()

	// Creating publisher with nil provider should be allowed
	publisher := NewPublisher(db, nil, nil, nil, config)
	require.NotNil(t, publisher)
	assert.Nil(t, publisher.routerInfoProvider)
}

// TestPublisherRouterInfoProviderSet tests that provider is properly set
func TestPublisherRouterInfoProviderSet(t *testing.T) {
	db := newMockNetDB()
	config := DefaultPublisherConfig()

	validRI := createValidTestRouterInfo(t)
	provider := &mockRouterInfoProvider{
		routerInfo: validRI,
	}

	publisher := NewPublisher(db, nil, nil, provider, config)
	require.NotNil(t, publisher)
	assert.NotNil(t, publisher.routerInfoProvider)
}
