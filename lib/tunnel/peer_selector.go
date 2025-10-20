package tunnel

import (
	"fmt"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
)

// NetDBSelector is a minimal interface used by DefaultPeerSelector to
// delegate peer selection. Any component that implements
// SelectPeers(count int, exclude []common.Hash) ([]router_info.RouterInfo, error)
// can be used. This avoids a hard dependency on a concrete netdb type.
type NetDBSelector interface {
	SelectPeers(count int, exclude []common.Hash) ([]router_info.RouterInfo, error)
}

// DefaultPeerSelector is a simple implementation of PeerSelector that
// delegates peer selection to a NetDB-like component (for example
// lib/netdb.StdNetDB). It performs basic argument validation and
// propagates errors from the underlying selector.
type DefaultPeerSelector struct {
	db NetDBSelector
}

// NewDefaultPeerSelector creates a new DefaultPeerSelector backed by the
// provided db. The db must implement SelectPeers with the same signature.
// Returns an error if db is nil.
func NewDefaultPeerSelector(db NetDBSelector) (*DefaultPeerSelector, error) {
	if db == nil {
		return nil, fmt.Errorf("db selector cannot be nil")
	}
	return &DefaultPeerSelector{db: db}, nil
}

// SelectPeers selects peers by delegating to the underlying db selector.
// Returns an error for invalid arguments or if the underlying selector fails.
func (s *DefaultPeerSelector) SelectPeers(count int, exclude []common.Hash) ([]router_info.RouterInfo, error) {
	if count <= 0 {
		return nil, fmt.Errorf("count must be > 0")
	}
	peers, err := s.db.SelectPeers(count, exclude)
	if err != nil {
		return nil, fmt.Errorf("underlying selector error: %w", err)
	}
	return peers, nil
}
