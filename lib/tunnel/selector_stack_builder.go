package tunnel

import (
	"github.com/samber/oops"
)

// PeerSelectorStack provides a fluent builder for composing peer selectors.
// It lets callers layer filtering and scoring on top of a base selector
// (typically a NetDB adapter) without wiring each layer by hand.
type PeerSelectorStack struct {
	selector PeerSelector
	err      error
}

// NewPeerSelectorStack starts building a selector stack from a base selector.
// The base selector supplies the candidate peers; later With* calls wrap it
// with additional selection behavior.
func NewPeerSelectorStack(base PeerSelector) *PeerSelectorStack {
	if base == nil {
		log.Error("NewPeerSelectorStack: base selector cannot be nil")
		return &PeerSelectorStack{err: oops.Errorf("base selector cannot be nil")}
	}
	log.Debug("creating peer selector stack")
	return &PeerSelectorStack{selector: base}
}

// FromNetDB starts a stack from a NetDBSelector.
// This is the common entry point: it adapts the network database into a
// PeerSelector so callers can build on it without knowing the adapter.
// See also [NetDBSelectorAdapter].
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
// Filters drop peers that should never be used (e.g. failed or congested),
// before any scoring happens.
// See also [FilteringPeerSelector].
func (s *PeerSelectorStack) WithFilter(filters ...PeerFilter) *PeerSelectorStack {
	return s.addSelector("filtering", func(sel PeerSelector) (PeerSelector, error) {
		return NewFilteringPeerSelector(sel, WithFilters(filters...))
	})
}

// WithScoring adds a scoring layer to the stack.
// Scoring ranks the surviving peers so the best candidates are picked
// first.
// See also [ScoringPeerSelector].
func (s *PeerSelectorStack) WithScoring(scorers ...PeerScorer) *PeerSelectorStack {
	return s.addSelector("scoring", func(sel PeerSelector) (PeerSelector, error) {
		return NewScoringPeerSelector(sel, WithScorers(scorers...))
	})
}

// WithThreshold adds scoring with a minimum threshold.
// This is a convenience for WithScoring plus WithScoreThreshold in one
// call, for the common case of "score and drop weak peers".
func (s *PeerSelectorStack) WithThreshold(threshold float64, scorers ...PeerScorer) *PeerSelectorStack {
	return s.addSelector("threshold scoring", func(sel PeerSelector) (PeerSelector, error) {
		return NewScoringPeerSelector(sel, WithScorers(scorers...), WithScoreThreshold(threshold))
	})
}

// Build returns the final composed selector, or an error if any step failed.
// Errors from earlier With* calls are remembered and surfaced here, so the
// builder can be used without checking each step.
func (s *PeerSelectorStack) Build() (PeerSelector, error) {
	if s.err != nil {
		log.WithError(s.err).Error("Build: peer selector stack has accumulated error")
		return nil, s.err
	}
	log.Debug("peer selector stack built successfully")
	return s.selector, nil
}

// MustBuild returns the selector or panics on error (for initialization).
// It is intended for program startup, where a misconfigured selector is a
// fatal error rather than a recoverable one.
func (s *PeerSelectorStack) MustBuild() PeerSelector {
	if s.err != nil {
		panic(s.err)
	}
	return s.selector
}
