package tunnel

import (
	"fmt"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/logger"
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
// Individual scorer outputs are floored at minScorerOutput to prevent a single
// zero-scoring scorer from permanently eliminating a peer regardless of other scores.
const minScorerOutput = 0.01

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
func (s *ScoringPeerSelector) AddScorer(scorer PeerScorer) {
	s.scorers = append(s.scorers, scorer)
}

// Compile-time interface check
var _ PeerSelector = (*ScoringPeerSelector)(nil)
