package tunnel

import (
	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

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
// Options configure how peers are scored and filtered, keeping the
// constructor signature stable as new tuning knobs are added.
type ScoringPeerSelectorOption func(*ScoringPeerSelector)

// WithScorers adds scorers to the selector.
// Each scorer contributes a multiplicative factor to a peer's combined
// score, so adding scorers lets callers layer independent quality signals.
func WithScorers(scorers ...PeerScorer) ScoringPeerSelectorOption {
	return func(s *ScoringPeerSelector) {
		s.scorers = append(s.scorers, scorers...)
	}
}

// WithScoreThreshold sets the minimum acceptable score.
// Peers scoring below the threshold are dropped, so this bounds how much
// the selector degrades when all candidates are weak.
func WithScoreThreshold(threshold float64) ScoringPeerSelectorOption {
	return func(s *ScoringPeerSelector) {
		s.threshold = threshold
	}
}

// WithScoringName sets the selector name for logging.
// A distinct name lets operators tell apart multiple scoring selectors
// that may be active in the same pool.
func WithScoringName(name string) ScoringPeerSelectorOption {
	return func(s *ScoringPeerSelector) {
		s.name = name
	}
}

// WithScoringMaxRetries sets the maximum retry count.
// Retries let the selector re-pick peers when a build attempt fails,
// bounded so a bad candidate set cannot loop forever.
func WithScoringMaxRetries(n int) ScoringPeerSelectorOption {
	return func(s *ScoringPeerSelector) {
		s.maxRetries = n
	}
}

// NewScoringPeerSelector creates a scoring-based peer selector.
// It wraps an underlying selector and ranks the candidate peers it returns
// using the registered scorers, so the best routers are picked first when
// building tunnels.
// See also [ScoringPeerSelector].
func NewScoringPeerSelector(
	underlying PeerSelector,
	opts ...ScoringPeerSelectorOption,
) (*ScoringPeerSelector, error) {
	if underlying == nil {
		return nil, oops.Errorf("underlying selector cannot be nil")
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
// It asks the underlying selector for candidates, scores each one, drops
// peers below the configured threshold, and returns the highest-scoring
// peers first.
// See also [PeerSelector].
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
// Individual scorer outputs are floored at minScorerOutput to prevent a single
// zero-scoring scorer from permanently eliminating a peer regardless of other scores.
const minScorerOutput = 0.01

// ComputeScore computes the multiplicative combined score for a peer from all registered scorers.
func (s *ScoringPeerSelector) ComputeScore(ri router_info.RouterInfo) float64 {
	if len(s.scorers) == 0 {
		return 1.0
	}

	score := 1.0
	for _, scorer := range s.scorers {
		v := scorer.Score(ri)
		if v < minScorerOutput {
			v = minScorerOutput
		}
		score *= v
	}
	return score
}

// AddScorer adds a scorer to the selector.
// Each added scorer contributes one factor to the multiplicative combined
// score, letting callers layer independent quality signals (e.g. latency,
// failure history) on top of each other.
// See also [PeerScorer].
func (s *ScoringPeerSelector) AddScorer(scorer PeerScorer) {
	s.scorers = append(s.scorers, scorer)
}

// Compile-time interface check
var _ PeerSelector = (*ScoringPeerSelector)(nil)
