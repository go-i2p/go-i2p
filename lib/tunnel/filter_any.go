package tunnel

import "github.com/go-i2p/common/router_info"

// AnyFilter combines multiple filters with OR logic.
// A peer passes if ANY filter accepts it.
type AnyFilter struct {
	name    string
	filters []PeerFilter
}

// NewAnyFilter creates a composite OR filter.
// It is useful when a peer is acceptable if it matches any of several
// independent criteria.
func NewAnyFilter(name string, filters ...PeerFilter) *AnyFilter {
	return &AnyFilter{name: name, filters: filters}
}

// Name returns the filter name.
// The name is used in logs and diagnostics to identify this filter.
func (f *AnyFilter) Name() string { return f.name }

// Accept returns true if any inner filter accepts the peer.
// Returns true if there are no filters (empty OR = accept all).
func (f *AnyFilter) Accept(ri router_info.RouterInfo) bool {
	if len(f.filters) == 0 {
		return true
	}
	for _, filter := range f.filters {
		if filter.Accept(ri) {
			return true
		}
	}
	return false
}

// Compile-time interface check
var _ PeerFilter = (*AnyFilter)(nil)
