package tunnel

import "github.com/go-i2p/common/router_info"

// FuncFilter wraps a simple function as a PeerFilter.
// Useful for quick inline filters.
type FuncFilter struct {
	name     string
	acceptFn func(ri router_info.RouterInfo) bool
}

// NewFuncFilter creates a filter from a function.
func NewFuncFilter(name string, acceptFn func(ri router_info.RouterInfo) bool) *FuncFilter {
	return &FuncFilter{name: name, acceptFn: acceptFn}
}

// Name returns the filter name.
func (f *FuncFilter) Name() string { return f.name }

// Accept returns whether the peer passes the filter function.
func (f *FuncFilter) Accept(ri router_info.RouterInfo) bool { return f.acceptFn(ri) }

// Compile-time interface check
var _ PeerFilter = (*FuncFilter)(nil)
