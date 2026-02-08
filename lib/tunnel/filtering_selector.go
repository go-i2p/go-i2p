package tunnel

import (
	"fmt"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/logger"
)

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
