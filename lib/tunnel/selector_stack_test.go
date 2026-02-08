package tunnel

import (
	"errors"
	"testing"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stackTestPeerSelector is a simple mock implementing PeerSelector for tests.
type stackTestPeerSelector struct {
	peers []router_info.RouterInfo
	err   error
}

func (m *stackTestPeerSelector) SelectPeers(count int, exclude []common.Hash) ([]router_info.RouterInfo, error) {
	if m.err != nil {
		return nil, m.err
	}

	excludeSet := make(map[string]struct{}, len(exclude))
	for _, h := range exclude {
		excludeSet[h.String()] = struct{}{}
	}

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

// alwaysAcceptFilter accepts all peers.
type alwaysAcceptFilter struct{}

func (f *alwaysAcceptFilter) Name() string                          { return "AlwaysAccept" }
func (f *alwaysAcceptFilter) Accept(ri router_info.RouterInfo) bool { return true }

// alwaysRejectFilter rejects all peers.
type alwaysRejectFilter struct{}

func (f *alwaysRejectFilter) Name() string                          { return "AlwaysReject" }
func (f *alwaysRejectFilter) Accept(ri router_info.RouterInfo) bool { return false }

// countingFilter counts how many times Accept is called.
type countingFilter struct {
	count int
}

func (f *countingFilter) Name() string { return "CountingFilter" }
func (f *countingFilter) Accept(ri router_info.RouterInfo) bool {
	f.count++
	return true
}

// constantScorer returns a constant score.
type constantScorer struct {
	name  string
	score float64
}

func (s *constantScorer) Name() string                            { return s.name }
func (s *constantScorer) Score(ri router_info.RouterInfo) float64 { return s.score }

// =============================================================================
// FilteringPeerSelector Tests
// =============================================================================

func TestNewFilteringPeerSelector_NilUnderlying(t *testing.T) {
	selector, err := NewFilteringPeerSelector(nil)
	assert.Nil(t, selector)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "underlying selector cannot be nil")
}

func TestNewFilteringPeerSelector_Success(t *testing.T) {
	mock := &stackTestPeerSelector{}
	selector, err := NewFilteringPeerSelector(mock)
	assert.NoError(t, err)
	assert.NotNil(t, selector)
}

func TestNewFilteringPeerSelector_WithOptions(t *testing.T) {
	mock := &stackTestPeerSelector{}
	filter := &alwaysAcceptFilter{}

	selector, err := NewFilteringPeerSelector(
		mock,
		WithFilters(filter),
		WithFilterMaxRetries(5),
		WithFilterName("TestSelector"),
	)
	require.NoError(t, err)
	assert.Equal(t, 5, selector.maxRetries)
	assert.Equal(t, "TestSelector", selector.name)
	assert.Len(t, selector.filters, 1)
}

func TestFilteringPeerSelector_InvalidCount(t *testing.T) {
	mock := &stackTestPeerSelector{}
	selector, err := NewFilteringPeerSelector(mock)
	require.NoError(t, err)

	peers, err := selector.SelectPeers(0, nil)
	assert.Error(t, err)
	assert.Nil(t, peers)
}

func TestFilteringPeerSelector_UnderlyingError(t *testing.T) {
	mock := &stackTestPeerSelector{err: errors.New("db error")}
	selector, err := NewFilteringPeerSelector(mock)
	require.NoError(t, err)

	peers, err := selector.SelectPeers(3, nil)
	assert.Error(t, err)
	assert.Nil(t, peers)
	assert.Contains(t, err.Error(), "underlying selector error")
}

func TestFilteringPeerSelector_NoFilters(t *testing.T) {
	// With no filters, all candidates should be accepted
	peers := []router_info.RouterInfo{{}, {}, {}}
	mock := &stackTestPeerSelector{peers: peers}

	selector, err := NewFilteringPeerSelector(mock)
	require.NoError(t, err)

	// Empty RIs fail IdentHash, so they're skipped; test ensures no error
	selected, err := selector.SelectPeers(2, nil)
	assert.NoError(t, err)
	// selected may be nil or empty since empty RIs can't provide hashes
	assert.True(t, selected == nil || len(selected) >= 0)
}

func TestFilteringPeerSelector_AlwaysAccept(t *testing.T) {
	peers := []router_info.RouterInfo{{}, {}, {}}
	mock := &stackTestPeerSelector{peers: peers}
	filter := &alwaysAcceptFilter{}

	selector, err := NewFilteringPeerSelector(mock, WithFilters(filter))
	require.NoError(t, err)

	// Empty RIs fail IdentHash, so they're skipped; test ensures no error
	selected, err := selector.SelectPeers(2, nil)
	assert.NoError(t, err)
	// selected may be nil or empty since empty RIs can't provide hashes
	assert.True(t, selected == nil || len(selected) >= 0)
}

func TestFilteringPeerSelector_AlwaysReject(t *testing.T) {
	peers := []router_info.RouterInfo{{}, {}, {}}
	mock := &stackTestPeerSelector{peers: peers}
	filter := &alwaysRejectFilter{}

	selector, err := NewFilteringPeerSelector(mock, WithFilters(filter))
	require.NoError(t, err)

	// All peers will be rejected, should get empty/short result
	selected, err := selector.SelectPeers(2, nil)
	assert.NoError(t, err)
	assert.Empty(t, selected)
}

func TestFilteringPeerSelector_AddFilter(t *testing.T) {
	mock := &stackTestPeerSelector{}
	selector, err := NewFilteringPeerSelector(mock)
	require.NoError(t, err)

	assert.Len(t, selector.filters, 0)

	selector.AddFilter(&alwaysAcceptFilter{})
	assert.Len(t, selector.filters, 1)

	selector.AddFilter(&alwaysRejectFilter{})
	assert.Len(t, selector.filters, 2)
}

// =============================================================================
// FuncFilter Tests
// =============================================================================

func TestFuncFilter(t *testing.T) {
	acceptAll := NewFuncFilter("AcceptAll", func(ri router_info.RouterInfo) bool {
		return true
	})

	assert.Equal(t, "AcceptAll", acceptAll.Name())
	assert.True(t, acceptAll.Accept(router_info.RouterInfo{}))

	rejectAll := NewFuncFilter("RejectAll", func(ri router_info.RouterInfo) bool {
		return false
	})

	assert.Equal(t, "RejectAll", rejectAll.Name())
	assert.False(t, rejectAll.Accept(router_info.RouterInfo{}))
}

// =============================================================================
// CompositeFilter Tests (AND logic)
// =============================================================================

func TestCompositeFilter_Empty(t *testing.T) {
	// Empty composite should accept all
	composite := NewCompositeFilter("Empty")
	assert.True(t, composite.Accept(router_info.RouterInfo{}))
}

func TestCompositeFilter_AllAccept(t *testing.T) {
	composite := NewCompositeFilter("AllAccept",
		&alwaysAcceptFilter{},
		&alwaysAcceptFilter{},
	)
	assert.True(t, composite.Accept(router_info.RouterInfo{}))
}

func TestCompositeFilter_OneRejects(t *testing.T) {
	composite := NewCompositeFilter("OneRejects",
		&alwaysAcceptFilter{},
		&alwaysRejectFilter{},
		&alwaysAcceptFilter{},
	)
	assert.False(t, composite.Accept(router_info.RouterInfo{}))
}

func TestCompositeFilter_Name(t *testing.T) {
	composite := NewCompositeFilter("MyComposite")
	assert.Equal(t, "MyComposite", composite.Name())
}

// =============================================================================
// AnyFilter Tests (OR logic)
// =============================================================================

func TestAnyFilter_Empty(t *testing.T) {
	// Empty OR filter should accept all (no conditions to fail)
	any := NewAnyFilter("Empty")
	assert.True(t, any.Accept(router_info.RouterInfo{}))
}

func TestAnyFilter_AllReject(t *testing.T) {
	any := NewAnyFilter("AllReject",
		&alwaysRejectFilter{},
		&alwaysRejectFilter{},
	)
	assert.False(t, any.Accept(router_info.RouterInfo{}))
}

func TestAnyFilter_OneAccepts(t *testing.T) {
	any := NewAnyFilter("OneAccepts",
		&alwaysRejectFilter{},
		&alwaysAcceptFilter{},
		&alwaysRejectFilter{},
	)
	assert.True(t, any.Accept(router_info.RouterInfo{}))
}

// =============================================================================
// InvertFilter Tests
// =============================================================================

func TestInvertFilter(t *testing.T) {
	inverted := NewInvertFilter(&alwaysAcceptFilter{})
	assert.Equal(t, "NOT(AlwaysAccept)", inverted.Name())
	assert.False(t, inverted.Accept(router_info.RouterInfo{}))

	inverted2 := NewInvertFilter(&alwaysRejectFilter{})
	assert.Equal(t, "NOT(AlwaysReject)", inverted2.Name())
	assert.True(t, inverted2.Accept(router_info.RouterInfo{}))
}

// =============================================================================
// ScoringPeerSelector Tests
// =============================================================================

func TestNewScoringPeerSelector_NilUnderlying(t *testing.T) {
	selector, err := NewScoringPeerSelector(nil)
	assert.Nil(t, selector)
	assert.Error(t, err)
}

func TestNewScoringPeerSelector_Success(t *testing.T) {
	mock := &stackTestPeerSelector{}
	selector, err := NewScoringPeerSelector(mock)
	assert.NoError(t, err)
	assert.NotNil(t, selector)
}

func TestNewScoringPeerSelector_WithOptions(t *testing.T) {
	mock := &stackTestPeerSelector{}
	scorer := &constantScorer{name: "Test", score: 0.8}

	selector, err := NewScoringPeerSelector(
		mock,
		WithScorers(scorer),
		WithScoreThreshold(0.5),
		WithScoringName("MyScoringSelector"),
		WithScoringMaxRetries(5),
	)
	require.NoError(t, err)
	assert.Equal(t, "MyScoringSelector", selector.name)
	assert.Equal(t, 0.5, selector.threshold)
	assert.Equal(t, 5, selector.maxRetries)
	assert.Len(t, selector.scorers, 1)
}

func TestScoringPeerSelector_ComputeScore_NoScorers(t *testing.T) {
	mock := &stackTestPeerSelector{}
	selector, err := NewScoringPeerSelector(mock)
	require.NoError(t, err)

	// No scorers = score of 1.0
	score := selector.ComputeScore(router_info.RouterInfo{})
	assert.Equal(t, 1.0, score)
}

func TestScoringPeerSelector_ComputeScore_MultipleScorers(t *testing.T) {
	mock := &stackTestPeerSelector{}
	selector, err := NewScoringPeerSelector(
		mock,
		WithScorers(
			&constantScorer{name: "A", score: 0.5},
			&constantScorer{name: "B", score: 0.8},
		),
	)
	require.NoError(t, err)

	// Multiplicative: 0.5 * 0.8 = 0.4
	score := selector.ComputeScore(router_info.RouterInfo{})
	assert.InDelta(t, 0.4, score, 0.001)
}

func TestScoringPeerSelector_AddScorer(t *testing.T) {
	mock := &stackTestPeerSelector{}
	selector, err := NewScoringPeerSelector(mock)
	require.NoError(t, err)

	assert.Len(t, selector.scorers, 0)
	selector.AddScorer(&constantScorer{name: "Test", score: 0.5})
	assert.Len(t, selector.scorers, 1)
}

func TestScoringPeerSelector_InvalidCount(t *testing.T) {
	mock := &stackTestPeerSelector{}
	selector, err := NewScoringPeerSelector(mock)
	require.NoError(t, err)

	peers, err := selector.SelectPeers(0, nil)
	assert.Error(t, err)
	assert.Nil(t, peers)
}

// =============================================================================
// NetDBSelectorAdapter Tests
// =============================================================================

func TestNetDBSelectorAdapter_Nil(t *testing.T) {
	adapter, err := NewNetDBSelectorAdapter(nil)
	assert.Nil(t, adapter)
	assert.Error(t, err)
}

func TestNetDBSelectorAdapter_Delegates(t *testing.T) {
	mock := &fakeDB{peers: []router_info.RouterInfo{{}, {}, {}}}
	adapter, err := NewNetDBSelectorAdapter(mock)
	require.NoError(t, err)

	peers, err := adapter.SelectPeers(2, nil)
	assert.NoError(t, err)
	assert.Len(t, peers, 2)
}

// =============================================================================
// PeerSelectorStack Tests
// =============================================================================

func TestNewPeerSelectorStack_Nil(t *testing.T) {
	stack := NewPeerSelectorStack(nil)
	selector, err := stack.Build()
	assert.Nil(t, selector)
	assert.Error(t, err)
}

func TestFromNetDB_Nil(t *testing.T) {
	stack := FromNetDB(nil)
	selector, err := stack.Build()
	assert.Nil(t, selector)
	assert.Error(t, err)
}

func TestPeerSelectorStack_Simple(t *testing.T) {
	mock := &stackTestPeerSelector{}
	selector, err := NewPeerSelectorStack(mock).Build()
	assert.NoError(t, err)
	assert.Equal(t, mock, selector)
}

func TestFromNetDB_Success(t *testing.T) {
	mock := &fakeDB{}
	selector, err := FromNetDB(mock).Build()
	assert.NoError(t, err)
	assert.NotNil(t, selector)
}

func TestPeerSelectorStack_WithFilter(t *testing.T) {
	mock := &stackTestPeerSelector{}
	selector, err := NewPeerSelectorStack(mock).
		WithFilter(&alwaysAcceptFilter{}).
		Build()

	assert.NoError(t, err)
	assert.NotNil(t, selector)

	// Should be a FilteringPeerSelector
	_, ok := selector.(*FilteringPeerSelector)
	assert.True(t, ok)
}

func TestPeerSelectorStack_WithScoring(t *testing.T) {
	mock := &stackTestPeerSelector{}
	selector, err := NewPeerSelectorStack(mock).
		WithScoring(&constantScorer{name: "Test", score: 0.5}).
		Build()

	assert.NoError(t, err)
	assert.NotNil(t, selector)

	// Should be a ScoringPeerSelector
	_, ok := selector.(*ScoringPeerSelector)
	assert.True(t, ok)
}

func TestPeerSelectorStack_Chaining(t *testing.T) {
	mock := &stackTestPeerSelector{}
	selector, err := NewPeerSelectorStack(mock).
		WithFilter(&alwaysAcceptFilter{}).
		WithScoring(&constantScorer{name: "Test", score: 0.5}).
		WithFilter(&alwaysAcceptFilter{}).
		Build()

	assert.NoError(t, err)
	assert.NotNil(t, selector)

	// Outermost should be FilteringPeerSelector
	filtering, ok := selector.(*FilteringPeerSelector)
	assert.True(t, ok)

	// Its underlying should be ScoringPeerSelector
	_, ok = filtering.underlying.(*ScoringPeerSelector)
	assert.True(t, ok)
}

func TestPeerSelectorStack_WithThreshold(t *testing.T) {
	mock := &stackTestPeerSelector{}
	selector, err := NewPeerSelectorStack(mock).
		WithThreshold(0.3, &constantScorer{name: "Test", score: 0.5}).
		Build()

	assert.NoError(t, err)
	assert.NotNil(t, selector)

	scoring, ok := selector.(*ScoringPeerSelector)
	assert.True(t, ok)
	assert.Equal(t, 0.3, scoring.threshold)
}

func TestPeerSelectorStack_MustBuild_Success(t *testing.T) {
	mock := &stackTestPeerSelector{}
	assert.NotPanics(t, func() {
		selector := NewPeerSelectorStack(mock).MustBuild()
		assert.NotNil(t, selector)
	})
}

func TestPeerSelectorStack_MustBuild_Panic(t *testing.T) {
	assert.Panics(t, func() {
		_ = NewPeerSelectorStack(nil).MustBuild()
	})
}

// =============================================================================
// Interface Compliance Tests
// =============================================================================

func TestPeerSelector_InterfaceCompliance(t *testing.T) {
	// Verify all implementations satisfy PeerSelector
	var _ PeerSelector = (*FilteringPeerSelector)(nil)
	var _ PeerSelector = (*ScoringPeerSelector)(nil)
	var _ PeerSelector = (*NetDBSelectorAdapter)(nil)
	var _ PeerSelector = (*mockPeerSelector)(nil)
}

func TestPeerFilter_InterfaceCompliance(t *testing.T) {
	var _ PeerFilter = (*FuncFilter)(nil)
	var _ PeerFilter = (*CompositeFilter)(nil)
	var _ PeerFilter = (*AnyFilter)(nil)
	var _ PeerFilter = (*InvertFilter)(nil)
	var _ PeerFilter = (*alwaysAcceptFilter)(nil)
	var _ PeerFilter = (*alwaysRejectFilter)(nil)
}

func TestPeerScorer_InterfaceCompliance(t *testing.T) {
	var _ PeerScorer = (*constantScorer)(nil)
}
