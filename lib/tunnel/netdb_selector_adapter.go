package tunnel

import (
	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	"github.com/samber/oops"
)

// NetDBSelectorAdapter wraps a NetDBSelector to implement PeerSelector.
// This allows NetDBSelector to be used with composable selectors.
type NetDBSelectorAdapter struct {
	db NetDBSelector
}

// NewNetDBSelectorAdapter creates an adapter from NetDBSelector to PeerSelector.
func NewNetDBSelectorAdapter(db NetDBSelector) (*NetDBSelectorAdapter, error) {
	if db == nil {
		return nil, oops.Errorf("db selector cannot be nil")
	}
	return &NetDBSelectorAdapter{db: db}, nil
}

// SelectPeers delegates to the underlying NetDBSelector.
func (a *NetDBSelectorAdapter) SelectPeers(count int, exclude []common.Hash) ([]router_info.RouterInfo, error) {
	return a.db.SelectPeers(count, exclude)
}

// Compile-time interface check
var _ PeerSelector = (*NetDBSelectorAdapter)(nil)
