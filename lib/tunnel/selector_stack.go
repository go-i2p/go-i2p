// Package tunnel provides I2P tunnel management functionality.
package tunnel

import (
	"fmt"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/logger"
)

// =============================================================================
// Core Interfaces
// =============================================================================

// PeerFilter defines a filter that can accept or reject peers during selection.
// Filters can be stacked to create composite selection logic.
type PeerFilter interface {
	// Name returns a descriptive name for this filter (for logging/debugging).
	Name() string

	// Accept returns true if the peer should be included in the selection.
	// Returning false excludes the peer from this selection round.
	Accept(ri router_info.RouterInfo) bool
}

// PeerScorer provides a score or weight for peer selection prioritization.
// Higher scores indicate more preferred peers.
type PeerScorer interface {
	// Name returns a descriptive name for this scorer.
	Name() string

	// Score returns a score for the peer (higher = better, 0.0-1.0 normalized).
	// A score of 0.0 means the peer should be avoided if possible.
	Score(ri router_info.RouterInfo) float64
}

// Note: PeerSelector interface is defined in pool.go as:
// type PeerSelector interface {
//     SelectPeers(count int, exclude []common.Hash) ([]router_info.RouterInfo, error)
// }

// =============================================================================
// Common Selection Logic (eliminates duplication)
// =============================================================================

// PeerEvaluator evaluates whether a peer should be selected.
// Returns true if the peer should be included, false otherwise.
type PeerEvaluator func(ri router_info.RouterInfo, hash common.Hash) bool

// retryingSelectConfig holds configuration for the common selection loop.
type retryingSelectConfig struct {
	underlying PeerSelector
	maxRetries int
	name       string
}

// retryingSelect is the common selection loop used by all selector types.
// It handles the retry logic, exclusion tracking, and candidate evaluation.
func retryingSelect(
	cfg retryingSelectConfig,
	count int,
	exclude []common.Hash,
	evaluator PeerEvaluator,
) ([]router_info.RouterInfo, int, error) {
	if count <= 0 {
		return nil, 0, fmt.Errorf("count must be > 0")
	}

	// Track all excluded hashes (original + rejected)
	allExcluded := make(map[common.Hash]struct{}, len(exclude))
	for _, h := range exclude {
		allExcluded[h] = struct{}{}
	}

	var selectedPeers []router_info.RouterInfo
	retries := 0

	for len(selectedPeers) < count && retries <= cfg.maxRetries {
		needed := count - len(selectedPeers)
		// Request extra to account for potential rejections
		requestCount := needed + (needed / 2) + 1

		excludeList := HashSetToSlice(allExcluded)
		candidates, err := cfg.underlying.SelectPeers(requestCount, excludeList)
		if err != nil {
			return nil, retries, fmt.Errorf("underlying selector error: %w", err)
		}

		if len(candidates) == 0 {
			break // No more peers available
		}

		// Evaluate each candidate
		for _, ri := range candidates {
			if len(selectedPeers) >= count {
				break
			}

			hash, err := ri.IdentHash()
			if err != nil {
				continue
			}

			// Mark as seen to avoid re-selection
			allExcluded[hash] = struct{}{}

			if evaluator(ri, hash) {
				selectedPeers = append(selectedPeers, ri)
			}
		}
		retries++
	}

	return selectedPeers, retries, nil
}

// HashSetToSlice converts a hash set to a slice.
// Exported for use by other selector implementations.
func HashSetToSlice(set map[common.Hash]struct{}) []common.Hash {
	result := make([]common.Hash, 0, len(set))
	for h := range set {
		result = append(result, h)
	}
	return result
}

// =============================================================================
// FilteringPeerSelector
// =============================================================================

// FilteringPeerSelector wraps an underlying selector and applies filters.
// It implements PeerSelector, enabling stacking of multiple filtering layers.
type FilteringPeerSelector struct {
	underlying PeerSelector
	filters    []PeerFilter
	maxRetries int
	name       string
}

// FilteringPeerSelectorOption is a functional option for FilteringPeerSelector.
type FilteringPeerSelectorOption func(*FilteringPeerSelector)

// WithFilters adds filters to the selector.
func WithFilters(filters ...PeerFilter) FilteringPeerSelectorOption {
	return func(s *FilteringPeerSelector) {
		s.filters = append(s.filters, filters...)
	}
}

// WithFilterMaxRetries sets the maximum retry count for finding acceptable peers.
func WithFilterMaxRetries(n int) FilteringPeerSelectorOption {
	return func(s *FilteringPeerSelector) {
		s.maxRetries = n
	}
}

// WithFilterName sets a descriptive name for logging.
func WithFilterName(name string) FilteringPeerSelectorOption {
	return func(s *FilteringPeerSelector) {
		s.name = name
	}
}

// NewFilteringPeerSelector creates a new filtering peer selector.
// The underlying selector provides candidates, filters determine acceptance.
func NewFilteringPeerSelector(
	underlying PeerSelector,
	opts ...FilteringPeerSelectorOption,
) (*FilteringPeerSelector, error) {
	if underlying == nil {
		return nil, fmt.Errorf("underlying selector cannot be nil")
	}

	s := &FilteringPeerSelector{
		underlying: underlying,
		filters:    make([]PeerFilter, 0),
		maxRetries: 3,
		name:       "FilteringPeerSelector",
	}

	for _, opt := range opts {
		opt(s)
	}

	filterNames := make([]string, len(s.filters))
	for i, f := range s.filters {
		filterNames[i] = f.Name()
	}

	log.WithFields(logger.Fields{
		"at":          "NewFilteringPeerSelector",
		"name":        s.name,
		"filters":     filterNames,
		"max_retries": s.maxRetries,
		"reason":      "initialization",
	}).Debug("created filtering peer selector")

	return s, nil
}

// SelectPeers implements PeerSelector by filtering candidates from the underlying selector.
func (s *FilteringPeerSelector) SelectPeers(count int, exclude []common.Hash) ([]router_info.RouterInfo, error) {
	rejectedByFilter := make(map[string]int)

	evaluator := func(ri router_info.RouterInfo, hash common.Hash) bool {
		for _, filter := range s.filters {
			if !filter.Accept(ri) {
				rejectedByFilter[filter.Name()]++
				s.logFilterRejection(hash, filter.Name())
				return false
			}
		}
		return true
	}

	cfg := retryingSelectConfig{
		underlying: s.underlying,
		maxRetries: s.maxRetries,
		name:       s.name,
	}

	selected, retries, err := retryingSelect(cfg, count, exclude, evaluator)
	if err != nil {
		return nil, err
	}

	s.logSelectionSummary(count, len(selected), retries, rejectedByFilter)

	if len(selected) < count {
		log.WithFields(logger.Fields{
			"at":        s.name,
			"requested": count,
			"selected":  len(selected),
			"retries":   retries,
			"rejected":  rejectedByFilter,
			"reason":    "insufficient peers passed filters",
		}).Warn("could not find enough peers matching filter criteria")
	}

	return selected, nil
}

// AddFilter adds a filter to the selector chain.
func (s *FilteringPeerSelector) AddFilter(filter PeerFilter) {
	s.filters = append(s.filters, filter)
}

// logFilterRejection logs a peer rejection by a filter.
func (s *FilteringPeerSelector) logFilterRejection(hash common.Hash, filterName string) {
	hashStr := hash.String()
	if len(hashStr) > 16 {
		hashStr = hashStr[:16]
	}

	log.WithFields(logger.Fields{
		"at":     s.name,
		"hash":   hashStr,
		"filter": filterName,
		"reason": "peer rejected by filter",
	}).Debug("peer filtered out")
}

// logSelectionSummary logs a selection summary.
func (s *FilteringPeerSelector) logSelectionSummary(requested, selected, retries int, rejected map[string]int) {
	log.WithFields(logger.Fields{
		"at":        s.name,
		"requested": requested,
		"selected":  selected,
		"retries":   retries,
		"rejected":  rejected,
		"reason":    "selection complete",
	}).Debug("filtering selector summary")
}

// Compile-time interface check
var _ PeerSelector = (*FilteringPeerSelector)(nil)

// =============================================================================
// Composable Filter Implementations
// =============================================================================

// FuncFilter wraps a simple function as a PeerFilter.
// Useful for quick inline filters.
type FuncFilter struct {
	name     string
	acceptFn func(ri router_info.RouterInfo) bool
}

// NewFuncFilter creates a filter from a function.
func NewFuncFilter(name string, acceptFn func(ri router_info.RouterInfo) bool) *FuncFilter {
	return &FuncFilter{name: name, acceptFn: acceptFn}
}

func (f *FuncFilter) Name() string                          { return f.name }
func (f *FuncFilter) Accept(ri router_info.RouterInfo) bool { return f.acceptFn(ri) }

// CompositeFilter combines multiple filters with AND logic.
// A peer must pass ALL filters to be accepted.
type CompositeFilter struct {
	name    string
	filters []PeerFilter
}

// NewCompositeFilter creates a composite AND filter.
func NewCompositeFilter(name string, filters ...PeerFilter) *CompositeFilter {
	return &CompositeFilter{name: name, filters: filters}
}

func (f *CompositeFilter) Name() string { return f.name }

func (f *CompositeFilter) Accept(ri router_info.RouterInfo) bool {
	for _, filter := range f.filters {
		if !filter.Accept(ri) {
			return false
		}
	}
	return true
}

// AnyFilter combines multiple filters with OR logic.
// A peer passes if ANY filter accepts it.
type AnyFilter struct {
	name    string
	filters []PeerFilter
}

// NewAnyFilter creates a composite OR filter.
func NewAnyFilter(name string, filters ...PeerFilter) *AnyFilter {
	return &AnyFilter{name: name, filters: filters}
}

func (f *AnyFilter) Name() string { return f.name }

func (f *AnyFilter) Accept(ri router_info.RouterInfo) bool {
	if len(f.filters) == 0 {
		return true
	}
	for _, filter := range f.filters {
		if filter.Accept(ri) {
			return true
		}
	}
	return false
}

// InvertFilter negates another filter's result.
type InvertFilter struct {
	inner PeerFilter
}

// NewInvertFilter creates a filter that inverts another filter.
func NewInvertFilter(inner PeerFilter) *InvertFilter {
	return &InvertFilter{inner: inner}
}

func (f *InvertFilter) Name() string { return "NOT(" + f.inner.Name() + ")" }

func (f *InvertFilter) Accept(ri router_info.RouterInfo) bool {
	return !f.inner.Accept(ri)
}

// =============================================================================
// ScoringPeerSelector
// =============================================================================

// ScoringPeerSelector selects peers based on scores from multiple scorers.
// Higher-scoring peers are preferred but not guaranteed (allows for randomness).
type ScoringPeerSelector struct {
	underlying PeerSelector
	scorers    []PeerScorer
	threshold  float64 // Minimum score to be considered (0.0-1.0)
	name       string
	maxRetries int
}

// ScoringPeerSelectorOption is a functional option for ScoringPeerSelector.
type ScoringPeerSelectorOption func(*ScoringPeerSelector)

// WithScorers adds scorers to the selector.
func WithScorers(scorers ...PeerScorer) ScoringPeerSelectorOption {
	return func(s *ScoringPeerSelector) {
		s.scorers = append(s.scorers, scorers...)
	}
}

// WithScoreThreshold sets the minimum acceptable score.
func WithScoreThreshold(threshold float64) ScoringPeerSelectorOption {
	return func(s *ScoringPeerSelector) {
		s.threshold = threshold
	}
}

// WithScoringName sets the selector name for logging.
func WithScoringName(name string) ScoringPeerSelectorOption {
	return func(s *ScoringPeerSelector) {
		s.name = name
	}
}

// WithScoringMaxRetries sets the maximum retry count.
func WithScoringMaxRetries(n int) ScoringPeerSelectorOption {
	return func(s *ScoringPeerSelector) {
		s.maxRetries = n
	}
}

// NewScoringPeerSelector creates a scoring-based peer selector.
func NewScoringPeerSelector(
	underlying PeerSelector,
	opts ...ScoringPeerSelectorOption,
) (*ScoringPeerSelector, error) {
	if underlying == nil {
		return nil, fmt.Errorf("underlying selector cannot be nil")
	}

	s := &ScoringPeerSelector{
		underlying: underlying,
		scorers:    make([]PeerScorer, 0),
		threshold:  0.0, // Accept all by default
		name:       "ScoringPeerSelector",
		maxRetries: 3,
	}

	for _, opt := range opts {
		opt(s)
	}

	scorerNames := make([]string, len(s.scorers))
	for i, scorer := range s.scorers {
		scorerNames[i] = scorer.Name()
	}

	log.WithFields(logger.Fields{
		"at":        "NewScoringPeerSelector",
		"name":      s.name,
		"scorers":   scorerNames,
		"threshold": s.threshold,
		"reason":    "initialization",
	}).Debug("created scoring peer selector")

	return s, nil
}

// SelectPeers implements PeerSelector with scoring logic.
func (s *ScoringPeerSelector) SelectPeers(count int, exclude []common.Hash) ([]router_info.RouterInfo, error) {
	belowThreshold := 0

	evaluator := func(ri router_info.RouterInfo, _ common.Hash) bool {
		score := s.ComputeScore(ri)
		if score >= s.threshold {
			return true
		}
		belowThreshold++
		return false
	}

	cfg := retryingSelectConfig{
		underlying: s.underlying,
		maxRetries: s.maxRetries,
		name:       s.name,
	}

	selected, retries, err := retryingSelect(cfg, count, exclude, evaluator)
	if err != nil {
		return nil, err
	}

	log.WithFields(logger.Fields{
		"at":              s.name,
		"requested":       count,
		"selected":        len(selected),
		"below_threshold": belowThreshold,
		"retries":         retries,
		"reason":          "selection complete",
	}).Debug("scoring selector summary")

	return selected, nil
}

// ComputeScore computes the combined score for a peer from all scorers.
// Returns the product of all scorer scores (multiplicative combination).
func (s *ScoringPeerSelector) ComputeScore(ri router_info.RouterInfo) float64 {
	if len(s.scorers) == 0 {
		return 1.0
	}

	score := 1.0
	for _, scorer := range s.scorers {
		score *= scorer.Score(ri)
	}
	return score
}

// AddScorer adds a scorer to the selector.
func (s *ScoringPeerSelector) AddScorer(scorer PeerScorer) {
	s.scorers = append(s.scorers, scorer)
}

// Compile-time interface check
var _ PeerSelector = (*ScoringPeerSelector)(nil)

// =============================================================================
// Adapter: NetDBSelector to PeerSelector
// =============================================================================

// NetDBSelectorAdapter wraps a NetDBSelector to implement PeerSelector.
// This allows NetDBSelector to be used with composable selectors.
type NetDBSelectorAdapter struct {
	db NetDBSelector
}

// NewNetDBSelectorAdapter creates an adapter from NetDBSelector to PeerSelector.
func NewNetDBSelectorAdapter(db NetDBSelector) (*NetDBSelectorAdapter, error) {
	if db == nil {
		return nil, fmt.Errorf("db selector cannot be nil")
	}
	return &NetDBSelectorAdapter{db: db}, nil
}

// SelectPeers delegates to the underlying NetDBSelector.
func (a *NetDBSelectorAdapter) SelectPeers(count int, exclude []common.Hash) ([]router_info.RouterInfo, error) {
	return a.db.SelectPeers(count, exclude)
}

// Compile-time interface check
var _ PeerSelector = (*NetDBSelectorAdapter)(nil)

// =============================================================================
// Stack Builder for Fluent API
// =============================================================================

// PeerSelectorStack provides a fluent builder for composing peer selectors.
type PeerSelectorStack struct {
	selector PeerSelector
	err      error
}

// NewPeerSelectorStack starts building a selector stack from a base selector.
func NewPeerSelectorStack(base PeerSelector) *PeerSelectorStack {
	if base == nil {
		return &PeerSelectorStack{err: fmt.Errorf("base selector cannot be nil")}
	}
	return &PeerSelectorStack{selector: base}
}

// FromNetDB starts a stack from a NetDBSelector.
func FromNetDB(db NetDBSelector) *PeerSelectorStack {
	adapter, err := NewNetDBSelectorAdapter(db)
	if err != nil {
		return &PeerSelectorStack{err: err}
	}
	return &PeerSelectorStack{selector: adapter}
}

// WithFilter adds a filtering layer to the stack.
func (s *PeerSelectorStack) WithFilter(filters ...PeerFilter) *PeerSelectorStack {
	if s.err != nil {
		return s
	}

	filtered, err := NewFilteringPeerSelector(
		s.selector,
		WithFilters(filters...),
	)
	if err != nil {
		s.err = err
		return s
	}

	s.selector = filtered
	return s
}

// WithScoring adds a scoring layer to the stack.
func (s *PeerSelectorStack) WithScoring(scorers ...PeerScorer) *PeerSelectorStack {
	if s.err != nil {
		return s
	}

	scoring, err := NewScoringPeerSelector(
		s.selector,
		WithScorers(scorers...),
	)
	if err != nil {
		s.err = err
		return s
	}

	s.selector = scoring
	return s
}

// WithThreshold adds scoring with a minimum threshold.
func (s *PeerSelectorStack) WithThreshold(threshold float64, scorers ...PeerScorer) *PeerSelectorStack {
	if s.err != nil {
		return s
	}

	scoring, err := NewScoringPeerSelector(
		s.selector,
		WithScorers(scorers...),
		WithScoreThreshold(threshold),
	)
	if err != nil {
		s.err = err
		return s
	}

	s.selector = scoring
	return s
}

// Build returns the final composed selector, or an error if any step failed.
func (s *PeerSelectorStack) Build() (PeerSelector, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.selector, nil
}

// MustBuild returns the selector or panics on error (for initialization).
func (s *PeerSelectorStack) MustBuild() PeerSelector {
	if s.err != nil {
		panic(s.err)
	}
	return s.selector
}
