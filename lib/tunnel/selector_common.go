package tunnel

import (
	"fmt"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
)

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
