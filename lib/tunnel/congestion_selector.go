// Package tunnel provides I2P tunnel management functionality.
package tunnel

import (
	"fmt"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/go-i2p/logger"
)

// CongestionAwarePeerSelector adjusts peer selection based on congestion flags.
// Implements PROP_162 peer selection rules:
//   - G flag: Exclude from selection entirely
//   - E flag: Apply severe capacity multiplier (0.1x default)
//   - D flag: Apply moderate capacity multiplier (0.5x default)
//   - Stale E flag (>15min): Treat as D flag
type CongestionAwarePeerSelector interface {
	// SelectPeersWithCongestionAwareness selects peers, filtering/derating by congestion.
	// Excludes G-flagged peers and applies capacity multipliers to D/E peers.
	SelectPeersWithCongestionAwareness(count int, exclude []common.Hash) ([]router_info.RouterInfo, error)

	// ShouldExcludePeer returns true if peer should be completely excluded (G flag).
	ShouldExcludePeer(ri router_info.RouterInfo) bool

	// GetCapacityMultiplier returns a capacity multiplier for peer derating (0.0-1.0).
	// Returns 1.0 for non-congested peers, 0.0 for G-flagged peers.
	GetCapacityMultiplier(ri router_info.RouterInfo) float64
}

// CongestionInfoProvider provides congestion information about peers.
// This is a subset of netdb.PeerCongestionInfo to avoid import cycles.
type CongestionInfoProvider interface {
	// GetEffectiveCongestionFlag returns the effective congestion flag for a peer.
	// Handles stale E flag → D downgrade automatically.
	GetEffectiveCongestionFlag(hash common.Hash) config.CongestionFlag
}

// DefaultCongestionAwarePeerSelector implements CongestionAwarePeerSelector.
// It wraps an underlying peer selector and applies congestion-based filtering.
type DefaultCongestionAwarePeerSelector struct {
	underlying       NetDBSelector
	congestionInfo   CongestionInfoProvider
	cfg              config.CongestionDefaults
	maxRetries       int           // Max retries when G-flagged peers need replacing
	retryDelay       time.Duration // Delay between retries (for testing)
	selectionMetrics *SelectionMetrics
}

// SelectionMetrics tracks peer selection statistics for monitoring.
type SelectionMetrics struct {
	TotalSelections    int64 // Total selection attempts
	GFlagExclusions    int64 // Peers excluded due to G flag
	DFlagDeratings     int64 // Peers selected with D flag derating
	EFlagDeratings     int64 // Peers selected with E flag derating
	StaleEDowngrades   int64 // E flags downgraded to D due to stale RI
	InsufficientPeers  int64 // Times we couldn't find enough non-G peers
	SelectionFailures  int64 // Total selection failures
	AverageRetries     float64
	lastRetryCount     int
	totalRetryCount    int64
	selectionWithRetry int64
}

// CongestionAwareSelectorOption is a functional option for configuring the selector.
type CongestionAwareSelectorOption func(*DefaultCongestionAwarePeerSelector)

// WithMaxRetries sets the maximum number of retries when replacing G-flagged peers.
func WithMaxRetries(n int) CongestionAwareSelectorOption {
	return func(s *DefaultCongestionAwarePeerSelector) {
		s.maxRetries = n
	}
}

// WithRetryDelay sets the delay between retries (useful for testing).
func WithRetryDelay(d time.Duration) CongestionAwareSelectorOption {
	return func(s *DefaultCongestionAwarePeerSelector) {
		s.retryDelay = d
	}
}

// NewCongestionAwarePeerSelector creates a new congestion-aware peer selector.
// The underlying selector provides base peer selection, and congestionInfo
// provides congestion flags for filtering decisions.
func NewCongestionAwarePeerSelector(
	underlying NetDBSelector,
	congestionInfo CongestionInfoProvider,
	cfg config.CongestionDefaults,
	opts ...CongestionAwareSelectorOption,
) (*DefaultCongestionAwarePeerSelector, error) {
	if underlying == nil {
		return nil, fmt.Errorf("underlying peer selector cannot be nil")
	}
	if congestionInfo == nil {
		return nil, fmt.Errorf("congestion info provider cannot be nil")
	}

	s := &DefaultCongestionAwarePeerSelector{
		underlying:       underlying,
		congestionInfo:   congestionInfo,
		cfg:              cfg,
		maxRetries:       3,
		retryDelay:       0,
		selectionMetrics: &SelectionMetrics{},
	}

	for _, opt := range opts {
		opt(s)
	}

	log.WithFields(logger.Fields{
		"at":                      "NewCongestionAwarePeerSelector",
		"d_flag_multiplier":       cfg.DFlagCapacityMultiplier,
		"e_flag_multiplier":       cfg.EFlagCapacityMultiplier,
		"stale_e_flag_multiplier": cfg.StaleEFlagCapacityMultiplier,
		"max_retries":             s.maxRetries,
		"reason":                  "initialization",
	}).Debug("created congestion-aware peer selector")

	return s, nil
}

// SelectPeersWithCongestionAwareness selects peers with congestion awareness.
// It excludes G-flagged peers and may request additional peers to replace them.
func (s *DefaultCongestionAwarePeerSelector) SelectPeersWithCongestionAwareness(
	count int,
	exclude []common.Hash,
) ([]router_info.RouterInfo, error) {
	if count <= 0 {
		return nil, fmt.Errorf("count must be > 0")
	}

	s.selectionMetrics.TotalSelections++
	allExcluded := s.initExclusionSet(exclude)

	selectedPeers, retries, err := s.selectWithRetries(count, allExcluded)
	if err != nil {
		return nil, err
	}

	s.updateRetryMetrics(retries)
	s.checkInsufficientPeers(count, len(selectedPeers), retries)
	s.logSelectionSummary(count, len(selectedPeers), retries)

	return selectedPeers, nil
}

// initExclusionSet creates a hash set from the initial exclude list.
func (s *DefaultCongestionAwarePeerSelector) initExclusionSet(exclude []common.Hash) map[common.Hash]struct{} {
	allExcluded := make(map[common.Hash]struct{}, len(exclude))
	for _, h := range exclude {
		allExcluded[h] = struct{}{}
	}
	return allExcluded
}

// selectWithRetries performs the retry loop to find non-G-flagged peers.
func (s *DefaultCongestionAwarePeerSelector) selectWithRetries(
	count int,
	allExcluded map[common.Hash]struct{},
) ([]router_info.RouterInfo, int, error) {
	var selectedPeers []router_info.RouterInfo
	retries := 0

	for len(selectedPeers) < count && retries <= s.maxRetries {
		candidates, err := s.fetchCandidates(count-len(selectedPeers), allExcluded)
		if err != nil {
			s.selectionMetrics.SelectionFailures++
			return nil, retries, fmt.Errorf("underlying selector error: %w", err)
		}
		if len(candidates) == 0 {
			break
		}

		selectedPeers = s.filterAndCollectPeers(candidates, selectedPeers, count, allExcluded)
		s.applyRetryDelay(retries)
		retries++
	}

	return selectedPeers, retries, nil
}

// fetchCandidates retrieves candidate peers from the underlying selector.
func (s *DefaultCongestionAwarePeerSelector) fetchCandidates(
	needed int,
	allExcluded map[common.Hash]struct{},
) ([]router_info.RouterInfo, error) {
	requestCount := needed + (needed / 2) + 1
	excludeList := hashSetToSlice(allExcluded)
	return s.underlying.SelectPeers(requestCount, excludeList)
}

// filterAndCollectPeers filters G-flagged peers and collects valid ones.
func (s *DefaultCongestionAwarePeerSelector) filterAndCollectPeers(
	candidates []router_info.RouterInfo,
	selectedPeers []router_info.RouterInfo,
	count int,
	allExcluded map[common.Hash]struct{},
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

		if s.ShouldExcludePeer(ri) {
			s.selectionMetrics.GFlagExclusions++
			s.logPeerExclusion(hash, "G flag - rejecting all tunnels")
			continue
		}

		s.recordDeratingMetrics(hash)
		selectedPeers = append(selectedPeers, ri)
	}
	return selectedPeers
}

// applyRetryDelay applies configured delay between retries.
func (s *DefaultCongestionAwarePeerSelector) applyRetryDelay(retries int) {
	if retries > 0 && s.retryDelay > 0 {
		time.Sleep(s.retryDelay)
	}
}

// updateRetryMetrics updates the retry-related metrics.
func (s *DefaultCongestionAwarePeerSelector) updateRetryMetrics(retries int) {
	if retries > 1 {
		s.selectionMetrics.selectionWithRetry++
		s.selectionMetrics.totalRetryCount += int64(retries - 1)
		s.selectionMetrics.AverageRetries = float64(s.selectionMetrics.totalRetryCount) /
			float64(s.selectionMetrics.selectionWithRetry)
	}
}

// checkInsufficientPeers logs a warning if not enough peers were found.
func (s *DefaultCongestionAwarePeerSelector) checkInsufficientPeers(requested, selected, retries int) {
	if selected < requested {
		s.selectionMetrics.InsufficientPeers++
		log.WithFields(logger.Fields{
			"at":        "SelectPeersWithCongestionAwareness",
			"requested": requested,
			"selected":  selected,
			"retries":   retries,
			"reason":    "insufficient non-congested peers available",
		}).Warn("could not find enough non-G-flagged peers")
	}
}

// ShouldExcludePeer returns true if the peer should be excluded due to G flag.
func (s *DefaultCongestionAwarePeerSelector) ShouldExcludePeer(ri router_info.RouterInfo) bool {
	hash, err := ri.IdentHash()
	if err != nil {
		return false // Can't determine, don't exclude
	}

	flag := s.congestionInfo.GetEffectiveCongestionFlag(hash)
	return flag == config.CongestionFlagG
}

// GetCapacityMultiplier returns the capacity multiplier for a peer.
// Returns:
//   - 1.0 for non-congested peers
//   - 0.5 for D-flagged peers (configurable)
//   - 0.1 for E-flagged peers (configurable)
//   - 0.5 for stale E-flagged peers (treated as D)
//   - 0.0 for G-flagged peers (should be excluded entirely)
func (s *DefaultCongestionAwarePeerSelector) GetCapacityMultiplier(ri router_info.RouterInfo) float64 {
	hash, err := ri.IdentHash()
	if err != nil {
		return 1.0 // Can't determine, use full capacity
	}

	flag := s.congestionInfo.GetEffectiveCongestionFlag(hash)

	switch flag {
	case config.CongestionFlagG:
		return 0.0
	case config.CongestionFlagE:
		return s.cfg.EFlagCapacityMultiplier
	case config.CongestionFlagD:
		return s.cfg.DFlagCapacityMultiplier
	default:
		return 1.0
	}
}

// GetSelectionMetrics returns current selection metrics for monitoring.
func (s *DefaultCongestionAwarePeerSelector) GetSelectionMetrics() SelectionMetrics {
	return *s.selectionMetrics
}

// ResetSelectionMetrics resets all selection metrics to zero.
func (s *DefaultCongestionAwarePeerSelector) ResetSelectionMetrics() {
	s.selectionMetrics = &SelectionMetrics{}
}

// recordDeratingMetrics records derating metrics for a selected peer.
func (s *DefaultCongestionAwarePeerSelector) recordDeratingMetrics(hash common.Hash) {
	flag := s.congestionInfo.GetEffectiveCongestionFlag(hash)

	switch flag {
	case config.CongestionFlagD:
		s.selectionMetrics.DFlagDeratings++
	case config.CongestionFlagE:
		s.selectionMetrics.EFlagDeratings++
	}
}

// logPeerExclusion logs a peer exclusion event with details.
func (s *DefaultCongestionAwarePeerSelector) logPeerExclusion(hash common.Hash, reason string) {
	hashStr := hash.String()
	if len(hashStr) > 16 {
		hashStr = hashStr[:16]
	}

	log.WithFields(logger.Fields{
		"at":     "SelectPeersWithCongestionAwareness",
		"hash":   hashStr,
		"reason": reason,
	}).Debug("excluded peer from selection")
}

// logSelectionSummary logs a summary of the selection operation.
func (s *DefaultCongestionAwarePeerSelector) logSelectionSummary(requested, selected, retries int) {
	log.WithFields(logger.Fields{
		"at":           "SelectPeersWithCongestionAwareness",
		"requested":    requested,
		"selected":     selected,
		"retries":      retries,
		"g_exclusions": s.selectionMetrics.GFlagExclusions,
		"d_deratings":  s.selectionMetrics.DFlagDeratings,
		"e_deratings":  s.selectionMetrics.EFlagDeratings,
		"reason":       "selection complete",
	}).Debug("peer selection summary")
}

// hashSetToSlice is a local alias for HashSetToSlice (for backward compatibility).
// New code should use HashSetToSlice directly.
func hashSetToSlice(set map[common.Hash]struct{}) []common.Hash {
	return HashSetToSlice(set)
}

// Compile-time interface check
var _ CongestionAwarePeerSelector = (*DefaultCongestionAwarePeerSelector)(nil)

// =============================================================================
// Composable Filters and Scorers for Selector Stacking
// =============================================================================

// CongestionFilter is a PeerFilter that excludes G-flagged peers.
// Use with FilteringPeerSelector for composable congestion filtering.
type CongestionFilter struct {
	congestionInfo CongestionInfoProvider
}

// NewCongestionFilter creates a filter that excludes G-flagged peers.
func NewCongestionFilter(congestionInfo CongestionInfoProvider) *CongestionFilter {
	return &CongestionFilter{congestionInfo: congestionInfo}
}

func (f *CongestionFilter) Name() string { return "CongestionFilter" }

func (f *CongestionFilter) Accept(ri router_info.RouterInfo) bool {
	hash, err := ri.IdentHash()
	if err != nil {
		return true // Can't determine, don't exclude
	}

	flag := f.congestionInfo.GetEffectiveCongestionFlag(hash)
	// Reject G-flagged peers (rejecting all tunnels)
	return flag != config.CongestionFlagG
}

// CongestionScorer is a PeerScorer that derates peers based on congestion flags.
// Use with ScoringPeerSelector for composable congestion scoring.
type CongestionScorer struct {
	congestionInfo CongestionInfoProvider
	cfg            config.CongestionDefaults
}

// NewCongestionScorer creates a scorer that derates congested peers.
func NewCongestionScorer(congestionInfo CongestionInfoProvider, cfg config.CongestionDefaults) *CongestionScorer {
	return &CongestionScorer{
		congestionInfo: congestionInfo,
		cfg:            cfg,
	}
}

func (s *CongestionScorer) Name() string { return "CongestionScorer" }

func (s *CongestionScorer) Score(ri router_info.RouterInfo) float64 {
	hash, err := ri.IdentHash()
	if err != nil {
		return 1.0 // Can't determine, use full score
	}

	flag := s.congestionInfo.GetEffectiveCongestionFlag(hash)

	switch flag {
	case config.CongestionFlagG:
		return 0.0 // Should be filtered out, but score 0 if reached
	case config.CongestionFlagE:
		return s.cfg.EFlagCapacityMultiplier
	case config.CongestionFlagD:
		return s.cfg.DFlagCapacityMultiplier
	default:
		return 1.0
	}
}

// Compile-time interface checks for composable types
var _ PeerFilter = (*CongestionFilter)(nil)
var _ PeerScorer = (*CongestionScorer)(nil)

// =============================================================================
// Convenience Constructors for Stacked Selectors
// =============================================================================

// NewCongestionAwareStack creates a stacked selector with congestion filtering.
// This is equivalent to:
//
//	FromNetDB(db).WithFilter(NewCongestionFilter(info)).Build()
//
// For more complex stacking, use PeerSelectorStack directly.
func NewCongestionAwareStack(
	db NetDBSelector,
	congestionInfo CongestionInfoProvider,
) (PeerSelector, error) {
	if db == nil {
		return nil, fmt.Errorf("db selector cannot be nil")
	}
	if congestionInfo == nil {
		return nil, fmt.Errorf("congestion info provider cannot be nil")
	}

	return FromNetDB(db).
		WithFilter(NewCongestionFilter(congestionInfo)).
		Build()
}

// NewCongestionAwareScoringStack creates a stacked selector with both
// congestion filtering (excludes G) and scoring (derates D/E).
func NewCongestionAwareScoringStack(
	db NetDBSelector,
	congestionInfo CongestionInfoProvider,
	cfg config.CongestionDefaults,
) (PeerSelector, error) {
	if db == nil {
		return nil, fmt.Errorf("db selector cannot be nil")
	}
	if congestionInfo == nil {
		return nil, fmt.Errorf("congestion info provider cannot be nil")
	}

	return FromNetDB(db).
		WithFilter(NewCongestionFilter(congestionInfo)).
		WithScoring(NewCongestionScorer(congestionInfo, cfg)).
		Build()
}
