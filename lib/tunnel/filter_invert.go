package tunnel

import "github.com/go-i2p/common/router_info"

// InvertFilter negates another filter's result.
type InvertFilter struct {
	inner PeerFilter
}

// NewInvertFilter creates a filter that inverts another filter.
// It is useful for reusing an existing "bad peer" filter as a "good peer"
// filter, or vice versa, without duplicating the logic.
func NewInvertFilter(inner PeerFilter) *InvertFilter {
	return &InvertFilter{inner: inner}
}

// Name returns a descriptive name indicating the negation.
// The NOT(...) form makes it obvious in logs that this filter inverts the
// inner one.
func (f *InvertFilter) Name() string { return "NOT(" + f.inner.Name() + ")" }

// Accept returns the opposite of the inner filter's result.
// A peer the inner filter rejects is accepted here, and vice versa.
func (f *InvertFilter) Accept(ri router_info.RouterInfo) bool {
	return !f.inner.Accept(ri)
}

// Compile-time interface check
var _ PeerFilter = (*InvertFilter)(nil)
