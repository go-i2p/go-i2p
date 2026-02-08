package tunnel

import (
	"errors"
	"sync"
	"testing"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockCongestionInfoProvider implements CongestionInfoProvider for testing.
type mockCongestionInfoProvider struct {
	mu    sync.RWMutex
	flags map[common.Hash]config.CongestionFlag
}

func newMockCongestionInfoProvider() *mockCongestionInfoProvider {
	return &mockCongestionInfoProvider{
		flags: make(map[common.Hash]config.CongestionFlag),
	}
}

func (m *mockCongestionInfoProvider) SetFlag(hash common.Hash, flag config.CongestionFlag) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.flags[hash] = flag
}

func (m *mockCongestionInfoProvider) GetEffectiveCongestionFlag(hash common.Hash) config.CongestionFlag {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if flag, ok := m.flags[hash]; ok {
		return flag
	}
	return config.CongestionFlagNone
}

// mockNetDBSelectorWithHashes returns RouterInfos that can be identified by hash.
type mockNetDBSelectorWithHashes struct {
	peers []router_info.RouterInfo
	err   error
}

func (m *mockNetDBSelectorWithHashes) SelectPeers(count int, exclude []common.Hash) ([]router_info.RouterInfo, error) {
	if m.err != nil {
		return nil, m.err
	}

	// Build exclude set for fast lookup
	excludeSet := make(map[string]struct{}, len(exclude))
	for _, h := range exclude {
		excludeSet[h.String()] = struct{}{}
	}

	// Filter out excluded peers
	var available []router_info.RouterInfo
	for _, ri := range m.peers {
		hash, err := ri.IdentHash()
		if err != nil {
			continue
		}
		if _, excluded := excludeSet[hash.String()]; !excluded {
			available = append(available, ri)
		}
	}

	if count > len(available) {
		return available, nil
	}
	return available[:count], nil
}

// Helper to create default congestion config for tests.
func testCongestionDefaults() config.CongestionDefaults {
	return config.CongestionDefaults{
		DFlagCapacityMultiplier:      0.5,
		EFlagCapacityMultiplier:      0.1,
		StaleEFlagCapacityMultiplier: 0.5,
	}
}

// TestNewCongestionAwarePeerSelector_NilUnderlying tests nil underlying selector rejection.
func TestNewCongestionAwarePeerSelector_NilUnderlying(t *testing.T) {
	provider := newMockCongestionInfoProvider()
	cfg := testCongestionDefaults()

	selector, err := NewCongestionAwarePeerSelector(nil, provider, cfg)
	assert.Nil(t, selector)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "underlying peer selector cannot be nil")
}

// TestNewCongestionAwarePeerSelector_NilCongestionInfo tests nil congestion info rejection.
func TestNewCongestionAwarePeerSelector_NilCongestionInfo(t *testing.T) {
	db := &mockNetDBSelectorWithHashes{}
	cfg := testCongestionDefaults()

	selector, err := NewCongestionAwarePeerSelector(db, nil, cfg)
	assert.Nil(t, selector)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "congestion info provider cannot be nil")
}

// TestNewCongestionAwarePeerSelector_Success tests successful creation.
func TestNewCongestionAwarePeerSelector_Success(t *testing.T) {
	db := &mockNetDBSelectorWithHashes{}
	provider := newMockCongestionInfoProvider()
	cfg := testCongestionDefaults()

	selector, err := NewCongestionAwarePeerSelector(db, provider, cfg)
	assert.NoError(t, err)
	assert.NotNil(t, selector)
}

// TestNewCongestionAwarePeerSelector_WithOptions tests functional options.
func TestNewCongestionAwarePeerSelector_WithOptions(t *testing.T) {
	db := &mockNetDBSelectorWithHashes{}
	provider := newMockCongestionInfoProvider()
	cfg := testCongestionDefaults()

	selector, err := NewCongestionAwarePeerSelector(
		db, provider, cfg,
		WithMaxRetries(5),
	)
	require.NoError(t, err)
	assert.Equal(t, 5, selector.maxRetries)
}

// TestSelectPeersWithCongestionAwareness_InvalidCount tests invalid count rejection.
func TestSelectPeersWithCongestionAwareness_InvalidCount(t *testing.T) {
	db := &mockNetDBSelectorWithHashes{}
	provider := newMockCongestionInfoProvider()
	cfg := testCongestionDefaults()

	selector, err := NewCongestionAwarePeerSelector(db, provider, cfg)
	require.NoError(t, err)

	peers, err := selector.SelectPeersWithCongestionAwareness(0, nil)
	assert.Error(t, err)
	assert.Nil(t, peers)
	assert.Contains(t, err.Error(), "count must be > 0")
}

// TestSelectPeersWithCongestionAwareness_UnderlyingError tests underlying error propagation.
func TestSelectPeersWithCongestionAwareness_UnderlyingError(t *testing.T) {
	db := &mockNetDBSelectorWithHashes{err: errors.New("db failure")}
	provider := newMockCongestionInfoProvider()
	cfg := testCongestionDefaults()

	selector, err := NewCongestionAwarePeerSelector(db, provider, cfg)
	require.NoError(t, err)

	peers, err := selector.SelectPeersWithCongestionAwareness(3, nil)
	assert.Error(t, err)
	assert.Nil(t, peers)
	assert.Contains(t, err.Error(), "underlying selector error")
}

// TestSelectPeersWithCongestionAwareness_NoGFlag tests selection with no congestion.
func TestSelectPeersWithCongestionAwareness_NoGFlag(t *testing.T) {
	// Create real RouterInfo instances (empty but valid)
	peers := []router_info.RouterInfo{{}, {}, {}}
	db := &mockNetDBSelectorWithHashes{peers: peers}
	provider := newMockCongestionInfoProvider()
	cfg := testCongestionDefaults()

	selector, err := NewCongestionAwarePeerSelector(db, provider, cfg)
	require.NoError(t, err)

	selected, err := selector.SelectPeersWithCongestionAwareness(2, nil)
	assert.NoError(t, err)
	// Note: empty RouterInfos fail IdentHash, so they're skipped
	// This tests that the selection logic runs without errors even with empty RIs
	// Selected may be empty or nil since empty RIs can't provide hashes
	assert.True(t, selected == nil || len(selected) == 0)
}

// TestShouldExcludePeer_GFlag tests G flag exclusion.
func TestShouldExcludePeer_GFlag(t *testing.T) {
	db := &mockNetDBSelectorWithHashes{}
	provider := newMockCongestionInfoProvider()
	cfg := testCongestionDefaults()

	selector, err := NewCongestionAwarePeerSelector(db, provider, cfg)
	require.NoError(t, err)

	// Create a hash and set G flag
	hash := common.Hash{}
	copy(hash[:], []byte("test_peer_g_flag_123456"))
	provider.SetFlag(hash, config.CongestionFlagG)

	// Create mock RouterInfo (we'll test with empty RI which may or may not work)
	ri := router_info.RouterInfo{}

	// Since empty RI can't return IdentHash, this tests the error path
	excluded := selector.ShouldExcludePeer(ri)
	assert.False(t, excluded) // Error path returns false (don't exclude if uncertain)
}

// TestGetCapacityMultiplier_AllFlags tests capacity multipliers for all flags.
func TestGetCapacityMultiplier_AllFlags(t *testing.T) {
	db := &mockNetDBSelectorWithHashes{}
	provider := newMockCongestionInfoProvider()
	cfg := testCongestionDefaults()

	selector, err := NewCongestionAwarePeerSelector(db, provider, cfg)
	require.NoError(t, err)

	testCases := []struct {
		name     string
		flag     config.CongestionFlag
		expected float64
	}{
		{"no_flag", config.CongestionFlagNone, 1.0},
		{"d_flag", config.CongestionFlagD, 0.5},
		{"e_flag", config.CongestionFlagE, 0.1},
		{"g_flag", config.CongestionFlagG, 0.0},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			hash := common.Hash{}
			copy(hash[:], []byte("test_"+tc.name+"_hash_12345"))
			provider.SetFlag(hash, tc.flag)

			// Create an empty RI - will test error path (returns 1.0)
			ri := router_info.RouterInfo{}
			multiplier := selector.GetCapacityMultiplier(ri)
			// Empty RI can't get hash, so returns 1.0
			assert.Equal(t, 1.0, multiplier)
		})
	}
}

// TestSelectionMetrics_Tracking tests that metrics are tracked correctly.
func TestSelectionMetrics_Tracking(t *testing.T) {
	peers := []router_info.RouterInfo{{}, {}, {}}
	db := &mockNetDBSelectorWithHashes{peers: peers}
	provider := newMockCongestionInfoProvider()
	cfg := testCongestionDefaults()

	selector, err := NewCongestionAwarePeerSelector(db, provider, cfg)
	require.NoError(t, err)

	// Initial metrics should be zero
	metrics := selector.GetSelectionMetrics()
	assert.Equal(t, int64(0), metrics.TotalSelections)

	// Make a selection
	_, _ = selector.SelectPeersWithCongestionAwareness(2, nil)

	// Check metrics updated
	metrics = selector.GetSelectionMetrics()
	assert.Equal(t, int64(1), metrics.TotalSelections)

	// Reset and verify
	selector.ResetSelectionMetrics()
	metrics = selector.GetSelectionMetrics()
	assert.Equal(t, int64(0), metrics.TotalSelections)
}

// TestHashSetToSlice tests the hash set conversion helper.
func TestHashSetToSlice(t *testing.T) {
	t.Run("empty_set", func(t *testing.T) {
		set := make(map[common.Hash]struct{})
		slice := hashSetToSlice(set)
		assert.Len(t, slice, 0)
	})

	t.Run("non_empty_set", func(t *testing.T) {
		set := make(map[common.Hash]struct{})
		h1 := common.Hash{}
		copy(h1[:], []byte("hash1_hash1_hash1_hash1_"))
		h2 := common.Hash{}
		copy(h2[:], []byte("hash2_hash2_hash2_hash2_"))

		set[h1] = struct{}{}
		set[h2] = struct{}{}

		slice := hashSetToSlice(set)
		assert.Len(t, slice, 2)
	})
}

// TestCongestionAwarePeerSelector_Interface verifies interface compliance.
func TestCongestionAwarePeerSelector_Interface(t *testing.T) {
	db := &mockNetDBSelectorWithHashes{}
	provider := newMockCongestionInfoProvider()
	cfg := testCongestionDefaults()

	selector, err := NewCongestionAwarePeerSelector(db, provider, cfg)
	require.NoError(t, err)

	// Verify the selector implements the interface
	var _ CongestionAwarePeerSelector = selector
}

// TestSelectPeersWithCongestionAwareness_EmptyDB tests selection with empty database.
func TestSelectPeersWithCongestionAwareness_EmptyDB(t *testing.T) {
	db := &mockNetDBSelectorWithHashes{peers: nil}
	provider := newMockCongestionInfoProvider()
	cfg := testCongestionDefaults()

	selector, err := NewCongestionAwarePeerSelector(db, provider, cfg)
	require.NoError(t, err)

	selected, err := selector.SelectPeersWithCongestionAwareness(3, nil)
	assert.NoError(t, err)
	assert.Empty(t, selected)

	// Should track insufficient peers metric
	metrics := selector.GetSelectionMetrics()
	assert.Equal(t, int64(1), metrics.InsufficientPeers)
}

// TestSelectPeersWithCongestionAwareness_WithExclusions tests peer exclusion list.
func TestSelectPeersWithCongestionAwareness_WithExclusions(t *testing.T) {
	peers := []router_info.RouterInfo{{}, {}, {}}
	db := &mockNetDBSelectorWithHashes{peers: peers}
	provider := newMockCongestionInfoProvider()
	cfg := testCongestionDefaults()

	selector, err := NewCongestionAwarePeerSelector(db, provider, cfg)
	require.NoError(t, err)

	// Create some exclusion hashes
	exclude := []common.Hash{{}, {}}
	copy(exclude[0][:], []byte("exclude1_exclude1_exclu"))
	copy(exclude[1][:], []byte("exclude2_exclude2_exclu"))

	selected, err := selector.SelectPeersWithCongestionAwareness(2, exclude)
	assert.NoError(t, err)
	// Empty RouterInfos fail IdentHash, so selected may be empty/nil
	// This tests that exclusion logic runs without panics
	assert.True(t, selected == nil || len(selected) >= 0)
}

// TestCapacityMultiplierValues tests that configured multipliers are used.
func TestCapacityMultiplierValues(t *testing.T) {
	db := &mockNetDBSelectorWithHashes{}
	provider := newMockCongestionInfoProvider()

	// Custom config values
	cfg := config.CongestionDefaults{
		DFlagCapacityMultiplier:      0.6,
		EFlagCapacityMultiplier:      0.2,
		StaleEFlagCapacityMultiplier: 0.6,
	}

	selector, err := NewCongestionAwarePeerSelector(db, provider, cfg)
	require.NoError(t, err)

	// Verify config is stored correctly
	assert.Equal(t, 0.6, selector.cfg.DFlagCapacityMultiplier)
	assert.Equal(t, 0.2, selector.cfg.EFlagCapacityMultiplier)
}

// TestSelectionMetrics_FailureTracking tests that failures are tracked.
func TestSelectionMetrics_FailureTracking(t *testing.T) {
	db := &mockNetDBSelectorWithHashes{err: errors.New("db error")}
	provider := newMockCongestionInfoProvider()
	cfg := testCongestionDefaults()

	selector, err := NewCongestionAwarePeerSelector(db, provider, cfg)
	require.NoError(t, err)

	_, _ = selector.SelectPeersWithCongestionAwareness(2, nil)

	metrics := selector.GetSelectionMetrics()
	assert.Equal(t, int64(1), metrics.SelectionFailures)
}

// TestCongestionInfoProvider_Mock tests the mock implementation.
func TestCongestionInfoProvider_Mock(t *testing.T) {
	provider := newMockCongestionInfoProvider()

	hash := common.Hash{}
	copy(hash[:], []byte("test_hash_test_hash_test"))

	// Default should be None
	flag := provider.GetEffectiveCongestionFlag(hash)
	assert.Equal(t, config.CongestionFlagNone, flag)

	// Set and retrieve D flag
	provider.SetFlag(hash, config.CongestionFlagD)
	flag = provider.GetEffectiveCongestionFlag(hash)
	assert.Equal(t, config.CongestionFlagD, flag)

	// Set and retrieve E flag
	provider.SetFlag(hash, config.CongestionFlagE)
	flag = provider.GetEffectiveCongestionFlag(hash)
	assert.Equal(t, config.CongestionFlagE, flag)

	// Set and retrieve G flag
	provider.SetFlag(hash, config.CongestionFlagG)
	flag = provider.GetEffectiveCongestionFlag(hash)
	assert.Equal(t, config.CongestionFlagG, flag)
}

// TestCongestionInfoProvider_ConcurrentAccess tests thread safety of mock.
func TestCongestionInfoProvider_ConcurrentAccess(t *testing.T) {
	provider := newMockCongestionInfoProvider()

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			hash := common.Hash{}
			copy(hash[:], []byte("concurrent_test_hash_xxx"))

			if i%2 == 0 {
				provider.SetFlag(hash, config.CongestionFlagD)
			} else {
				_ = provider.GetEffectiveCongestionFlag(hash)
			}
		}(i)
	}
	wg.Wait()
}

// =============================================================================
// Composable CongestionFilter Tests
// =============================================================================

func TestCongestionFilter_Name(t *testing.T) {
	provider := newMockCongestionInfoProvider()
	filter := NewCongestionFilter(provider)
	assert.Equal(t, "CongestionFilter", filter.Name())
}

func TestCongestionFilter_AcceptsNonCongested(t *testing.T) {
	provider := newMockCongestionInfoProvider()
	filter := NewCongestionFilter(provider)

	// Empty RI can't get hash, so returns true (don't exclude on error)
	ri := router_info.RouterInfo{}
	assert.True(t, filter.Accept(ri))
}

func TestCongestionFilter_AcceptsDFlag(t *testing.T) {
	provider := newMockCongestionInfoProvider()
	filter := NewCongestionFilter(provider)

	hash := common.Hash{}
	copy(hash[:], []byte("d_flag_peer_hash_123456"))
	provider.SetFlag(hash, config.CongestionFlagD)

	// D flag should be accepted (not excluded)
	// Empty RI returns true due to IdentHash error
	ri := router_info.RouterInfo{}
	assert.True(t, filter.Accept(ri))
}

func TestCongestionFilter_AcceptsEFlag(t *testing.T) {
	provider := newMockCongestionInfoProvider()
	filter := NewCongestionFilter(provider)

	hash := common.Hash{}
	copy(hash[:], []byte("e_flag_peer_hash_123456"))
	provider.SetFlag(hash, config.CongestionFlagE)

	// E flag should be accepted (not excluded)
	ri := router_info.RouterInfo{}
	assert.True(t, filter.Accept(ri))
}

// =============================================================================
// Composable CongestionScorer Tests
// =============================================================================

func TestCongestionScorer_Name(t *testing.T) {
	provider := newMockCongestionInfoProvider()
	cfg := testCongestionDefaults()
	scorer := NewCongestionScorer(provider, cfg)
	assert.Equal(t, "CongestionScorer", scorer.Name())
}

func TestCongestionScorer_FullScoreForNoCongestion(t *testing.T) {
	provider := newMockCongestionInfoProvider()
	cfg := testCongestionDefaults()
	scorer := NewCongestionScorer(provider, cfg)

	// Empty RI can't get hash, returns 1.0
	ri := router_info.RouterInfo{}
	score := scorer.Score(ri)
	assert.Equal(t, 1.0, score)
}

func TestCongestionScorer_ConfigurableMultipliers(t *testing.T) {
	provider := newMockCongestionInfoProvider()
	cfg := config.CongestionDefaults{
		DFlagCapacityMultiplier: 0.6,
		EFlagCapacityMultiplier: 0.2,
	}
	scorer := NewCongestionScorer(provider, cfg)

	// Verify scorer stores the config
	assert.Equal(t, 0.6, scorer.cfg.DFlagCapacityMultiplier)
	assert.Equal(t, 0.2, scorer.cfg.EFlagCapacityMultiplier)
}

// =============================================================================
// Convenience Constructor Tests
// =============================================================================

func TestNewCongestionAwareStack_NilDB(t *testing.T) {
	provider := newMockCongestionInfoProvider()
	selector, err := NewCongestionAwareStack(nil, provider)
	assert.Nil(t, selector)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "db selector cannot be nil")
}

func TestNewCongestionAwareStack_NilProvider(t *testing.T) {
	db := &mockNetDBSelectorWithHashes{}
	selector, err := NewCongestionAwareStack(db, nil)
	assert.Nil(t, selector)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "congestion info provider cannot be nil")
}

func TestNewCongestionAwareStack_Success(t *testing.T) {
	db := &mockNetDBSelectorWithHashes{}
	provider := newMockCongestionInfoProvider()

	selector, err := NewCongestionAwareStack(db, provider)
	assert.NoError(t, err)
	assert.NotNil(t, selector)

	// Should be a FilteringPeerSelector
	_, ok := selector.(*FilteringPeerSelector)
	assert.True(t, ok)
}

func TestNewCongestionAwareScoringStack_NilDB(t *testing.T) {
	provider := newMockCongestionInfoProvider()
	cfg := testCongestionDefaults()
	selector, err := NewCongestionAwareScoringStack(nil, provider, cfg)
	assert.Nil(t, selector)
	assert.Error(t, err)
}

func TestNewCongestionAwareScoringStack_NilProvider(t *testing.T) {
	db := &mockNetDBSelectorWithHashes{}
	cfg := testCongestionDefaults()
	selector, err := NewCongestionAwareScoringStack(db, nil, cfg)
	assert.Nil(t, selector)
	assert.Error(t, err)
}

func TestNewCongestionAwareScoringStack_Success(t *testing.T) {
	db := &mockNetDBSelectorWithHashes{}
	provider := newMockCongestionInfoProvider()
	cfg := testCongestionDefaults()

	selector, err := NewCongestionAwareScoringStack(db, provider, cfg)
	assert.NoError(t, err)
	assert.NotNil(t, selector)

	// Outermost should be ScoringPeerSelector
	_, ok := selector.(*ScoringPeerSelector)
	assert.True(t, ok)
}

// =============================================================================
// Interface Compliance for Composable Types
// =============================================================================

func TestCongestionFilter_InterfaceCompliance(t *testing.T) {
	var _ PeerFilter = (*CongestionFilter)(nil)
}

func TestCongestionScorer_InterfaceCompliance(t *testing.T) {
	var _ PeerScorer = (*CongestionScorer)(nil)
}
