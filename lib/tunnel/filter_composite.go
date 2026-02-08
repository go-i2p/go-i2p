package tunnel

import "github.com/go-i2p/common/router_info"

// CompositeFilter combines multiple filters with AND logic.
// A peer must pass ALL filters to be accepted.
type CompositeFilter struct {
	name    string
	filters []PeerFilter
}

// NewCompositeFilter creates a composite AND filter.
func NewCompositeFilter(name string, filters ...PeerFilter) *CompositeFilter {
	return &CompositeFilter{name: name, filters: filters}
}

// Name returns the filter name.
func (f *CompositeFilter) Name() string { return f.name }

// Accept returns true only if all inner filters accept the peer.
func (f *CompositeFilter) Accept(ri router_info.RouterInfo) bool {
	for _, filter := range f.filters {
		if !filter.Accept(ri) {
			return false
		}
	}
	return true
}

// Compile-time interface check
var _ PeerFilter = (*CompositeFilter)(nil)
