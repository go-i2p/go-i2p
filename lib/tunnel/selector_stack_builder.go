package tunnel

import "fmt"

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
