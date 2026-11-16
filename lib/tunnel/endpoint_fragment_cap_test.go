package tunnel

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestSetFragmentCacheSize_ReachesNewEndpoints is the C1 guard for
// performance.fragment_cache_size: the operator's cap must reach newly created
// Endpoints and be enforced. Before this fix every endpoint used the hardcoded
// maxConcurrentAssemblies constant and the knob was dead.
func TestSetFragmentCacheSize_ReachesNewEndpoints(t *testing.T) {
	t.Cleanup(func() { SetFragmentCacheSize(0) })

	SetFragmentCacheSize(2)
	assert.Equal(t, 2, GetFragmentCacheSize())

	decryption := &mockTunnelEncryptor{}
	handler := func(msgBytes []byte) error { return nil }
	ep, err := NewEndpoint(1, decryption, handler)
	assert.NoError(t, err)
	defer ep.Stop()

	assert.Equal(t, 2, ep.maxAssemblies, "endpoint must adopt the configured fragment cache cap")

	// Fill to the cap, then add one more: the cap-enforcing creation must evict
	// so the count never exceeds the configured limit.
	ep.fragmentsMutex.Lock()
	for i := uint32(0); i < 5; i++ {
		ep.createAssemblerWithCapEnforcement(i, DTLocal)
	}
	count := len(ep.fragments)
	ep.fragmentsMutex.Unlock()

	assert.LessOrEqual(t, count, 2, "concurrent assemblies must never exceed the configured cap")
}

// TestSetFragmentCacheSize_ZeroUsesBuiltIn pins that an unset value selects the
// built-in default, so a default-configured router is unchanged.
func TestSetFragmentCacheSize_ZeroUsesBuiltIn(t *testing.T) {
	t.Cleanup(func() { SetFragmentCacheSize(0) })

	SetFragmentCacheSize(0)
	assert.Equal(t, maxConcurrentAssemblies, GetFragmentCacheSize(), "zero must select the built-in default")

	decryption := &mockTunnelEncryptor{}
	handler := func(msgBytes []byte) error { return nil }
	ep, err := NewEndpoint(1, decryption, handler)
	assert.NoError(t, err)
	defer ep.Stop()

	assert.Equal(t, maxConcurrentAssemblies, ep.maxAssemblies)
}
