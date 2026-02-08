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

	allExcluded := buildExclusionSet(exclude)
	selectedPeers, retries, err := executeSelectionLoop(cfg, count, allExcluded, evaluator)

	return selectedPeers, retries, err
}

// buildExclusionSet creates a hash set from the initial exclude list.
func buildExclusionSet(exclude []common.Hash) map[common.Hash]struct{} {
	allExcluded := make(map[common.Hash]struct{}, len(exclude))
	for _, h := range exclude {
		allExcluded[h] = struct{}{}
	}
	return allExcluded
}

// executeSelectionLoop performs the retry loop for peer selection.
func executeSelectionLoop(
	cfg retryingSelectConfig,
	count int,
	allExcluded map[common.Hash]struct{},
	evaluator PeerEvaluator,
) ([]router_info.RouterInfo, int, error) {
	var selectedPeers []router_info.RouterInfo
	retries := 0

	for len(selectedPeers) < count && retries <= cfg.maxRetries {
		candidates, err := fetchPeerCandidates(cfg, count-len(selectedPeers), allExcluded)
		if err != nil {
			return nil, retries, err
		}
		if len(candidates) == 0 {
			break
		}

		selectedPeers = evaluateCandidates(candidates, selectedPeers, count, allExcluded, evaluator)
		retries++
	}

	return selectedPeers, retries, nil
}

// fetchPeerCandidates retrieves candidates from the underlying selector.
func fetchPeerCandidates(
	cfg retryingSelectConfig,
	needed int,
	allExcluded map[common.Hash]struct{},
) ([]router_info.RouterInfo, error) {
	requestCount := needed + (needed / 2) + 1
	excludeList := HashSetToSlice(allExcluded)

	candidates, err := cfg.underlying.SelectPeers(requestCount, excludeList)
	if err != nil {
		return nil, fmt.Errorf("underlying selector error: %w", err)
	}
	return candidates, nil
}

// evaluateCandidates evaluates each candidate and collects accepted peers.
func evaluateCandidates(
	candidates []router_info.RouterInfo,
	selectedPeers []router_info.RouterInfo,
	count int,
	allExcluded map[common.Hash]struct{},
	evaluator PeerEvaluator,
) []router_info.RouterInfo {
	for _, ri := range candidates {
		if len(selectedPeers) >= count {
			break
		}

		hash, err := ri.IdentHash()
		if err != nil {
			continue
		}

		allExcluded[hash] = struct{}{}

		if evaluator(ri, hash) {
			selectedPeers = append(selectedPeers, ri)
		}
	}
	return selectedPeers
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
