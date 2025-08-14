package netdb

import (
	"github.com/go-i2p/go-i2p/lib/tunnel"
)

// Moved from: kad.go
// NewKademliaResolver creates a new resolver that stores result into a NetworkDatabase and uses a tunnel pool for the lookup
func NewKademliaResolver(netDb NetworkDatabase, pool *tunnel.Pool) (r Resolver) {
	if pool != nil && netDb != nil {
		r = &KademliaResolver{
			NetworkDatabase: netDb,
			pool:            pool,
		}
	}
	return
}
