package tunnel

import "github.com/go-i2p/common/router_info"

// CompositeFilter combines multiple filters with AND logic.
// A peer must pass ALL filters to be accepted.
type CompositeFilter struct {
	name    string
	filters []PeerFilter
}

// NewCompositeFilter creates a composite AND filter.
// It is useful when a peer must satisfy several independent criteria
// before it is eligible for tunnel building.
func NewCompositeFilter(name string, filters ...PeerFilter) *CompositeFilter {
	return &CompositeFilter{name: name, filters: filters}
}

// Name returns the filter name.
// The name is used in logs and diagnostics to identify this filter.
func (f *CompositeFilter) Name() string { return f.name }

// Accept returns true only if all inner filters accept the peer.
// A single failing filter rejects the peer, so the composite is only as
// permissive as its strictest member.
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
