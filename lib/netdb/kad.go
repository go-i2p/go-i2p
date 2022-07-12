package netdb

import (
	"time"

	common "github.com/go-i2p/go-i2p/lib/common/data"
	"github.com/go-i2p/go-i2p/lib/common/router_info"
	"github.com/go-i2p/go-i2p/lib/tunnel"
)

// resolves router infos with recursive kademlia lookup
type kadResolver struct {
	// netdb to store result into
	netDB NetworkDatabase
	// what tunnel pool to use when doing lookup
	// if nil the lookup will be done directly
	pool *tunnel.Pool
}

// TODO: implement
func (kr *kadResolver) Lookup(h common.Hash, timeout time.Duration) (chnl chan router_info.RouterInfo) {
	return
}

// create a new resolver that stores result into a NetworkDatabase and uses a tunnel pool for the lookup
func KademliaResolver(netDb NetworkDatabase, pool *tunnel.Pool) (r Resolver) {
	if pool != nil && netDb != nil {
		r = &kadResolver{
			netDB: netDb,
			pool:  pool,
		}
	}
	return
}
