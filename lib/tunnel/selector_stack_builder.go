package tunnel

import (
	"github.com/samber/oops"
)

// PeerSelectorStack provides a fluent builder for composing peer selectors.
type PeerSelectorStack struct {
	selector PeerSelector
	err      error
}

// NewPeerSelectorStack starts building a selector stack from a base selector.
func NewPeerSelectorStack(base PeerSelector) *PeerSelectorStack {
	if base == nil {
		log.Error("NewPeerSelectorStack: base selector cannot be nil")
		return &PeerSelectorStack{err: oops.Errorf("base selector cannot be nil")}
	}
	log.Debug("creating peer selector stack")
	return &PeerSelectorStack{selector: base}
}

// FromNetDB starts a stack from a NetDBSelector.
func FromNetDB(db NetDBSelector) *PeerSelectorStack {
	adapter, err := NewNetDBSelectorAdapter(db)
	if err != nil {
		log.WithError(err).Error("FromNetDB: failed to create netdb selector adapter")
		return &PeerSelectorStack{err: err}
	}
	log.Debug("created peer selector stack from netdb")
	return &PeerSelectorStack{selector: adapter}
}

// addSelector is a generic builder helper that creates a new selector layer,
// handles errors, and updates the stack with the result.
// Returns the updated stack (with error set if fn fails).
func (s *PeerSelectorStack) addSelector(name string, fn func(PeerSelector) (PeerSelector, error)) *PeerSelectorStack {
	if s.err != nil {
		return s
	}

	newSel, err := fn(s.selector)
	if err != nil {
		log.WithError(err).Errorf("addSelector: failed to create %s peer selector", name)
		s.err = err
		return s
	}

	s.selector = newSel
	return s
}

// WithFilter adds a filtering layer to the stack.
func (s *PeerSelectorStack) WithFilter(filters ...PeerFilter) *PeerSelectorStack {
	return s.addSelector("filtering", func(sel PeerSelector) (PeerSelector, error) {
		return NewFilteringPeerSelector(sel, WithFilters(filters...))
	})
}

// WithScoring adds a scoring layer to the stack.
func (s *PeerSelectorStack) WithScoring(scorers ...PeerScorer) *PeerSelectorStack {
	return s.addSelector("scoring", func(sel PeerSelector) (PeerSelector, error) {
		return NewScoringPeerSelector(sel, WithScorers(scorers...))
	})
}

// WithThreshold adds scoring with a minimum threshold.
func (s *PeerSelectorStack) WithThreshold(threshold float64, scorers ...PeerScorer) *PeerSelectorStack {
	return s.addSelector("threshold scoring", func(sel PeerSelector) (PeerSelector, error) {
		return NewScoringPeerSelector(sel, WithScorers(scorers...), WithScoreThreshold(threshold))
	})
}

// Build returns the final composed selector, or an error if any step failed.
func (s *PeerSelectorStack) Build() (PeerSelector, error) {
	if s.err != nil {
		log.WithError(s.err).Error("Build: peer selector stack has accumulated error")
		return nil, s.err
	}
	log.Debug("peer selector stack built successfully")
	return s.selector, nil
}

// MustBuild returns the selector or panics on error (for initialization).
func (s *PeerSelectorStack) MustBuild() PeerSelector {
	if s.err != nil {
		panic(s.err)
	}
	return s.selector
}
