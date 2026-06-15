package bootstrap

import (
	"context"

	"github.com/go-i2p/common/router_info"
	"github.com/samber/oops"
)

// Bootstrap defines a way to bootstrap into the i2p network.
type Bootstrap interface {
	// get more peers for bootstrap
	// try obtaining at most n router infos
	// if n is 0 then try obtaining as many router infos as possible
	// returns nil and error if we cannot fetch ANY router infos
	// returns a slice of router infos containing n or fewer router infos
	GetPeers(ctx context.Context, n int) ([]router_info.RouterInfo, error)
}

// tryBootstrapSource is a generic helper that attempts to obtain peers from any Bootstrap implementation.
// Consolidation for H-8: consolidates triplicated try*Bootstrap patterns.
// Callers pass the bootstrap object and should handle source-specific logging.
// Returns peers and nil on success (no error + len > 0).
// Returns nil and a wrapped error if GetPeers fails or returns no peers.
func tryBootstrapSource(b Bootstrap, ctx context.Context, n int, sourceName string) ([]router_info.RouterInfo, error) {
	peers, err := b.GetPeers(ctx, n)
	if err == nil && len(peers) > 0 {
		return peers, nil
	}
	if err != nil {
		return nil, oops.Wrapf(err, "%s bootstrap failed", sourceName)
	}
	return nil, oops.Errorf("%s bootstrap returned no peers", sourceName)
}
