// Package tunnel provides I2P tunnel management functionality.
package tunnel

import "github.com/go-i2p/common/router_info"

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
