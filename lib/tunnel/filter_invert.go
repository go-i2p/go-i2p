package tunnel

import "github.com/go-i2p/common/router_info"

// InvertFilter negates another filter's result.
type InvertFilter struct {
	inner PeerFilter
}

// NewInvertFilter creates a filter that inverts another filter.
func NewInvertFilter(inner PeerFilter) *InvertFilter {
	return &InvertFilter{inner: inner}
}

// Name returns a descriptive name indicating the negation.
func (f *InvertFilter) Name() string { return "NOT(" + f.inner.Name() + ")" }

// Accept returns the opposite of the inner filter's result.
func (f *InvertFilter) Accept(ri router_info.RouterInfo) bool {
	return !f.inner.Accept(ri)
}

// Compile-time interface check
var _ PeerFilter = (*InvertFilter)(nil)
