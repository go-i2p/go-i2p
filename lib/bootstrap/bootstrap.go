package bootstrap

import (
	"context"

	"github.com/go-i2p/common/router_info"
)

// interface defining a way to bootstrap into the i2p network
type Bootstrap interface {
	// get more peers for bootstrap
	// try obtaining at most n router infos
	// if n is 0 then try obtaining as many router infos as possible
	// returns nil and error if we cannot fetch ANY router infos
	// returns a slice of router infos containing n or fewer router infos
	GetPeers(ctx context.Context, n int) ([]router_info.RouterInfo, error)
}
