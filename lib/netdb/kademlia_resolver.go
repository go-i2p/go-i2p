package netdb

import (
	"github.com/go-i2p/go-i2p/lib/tunnel"
)

// Moved from: kad.go
// NewKademliaResolver creates a new resolver that stores result into a NetworkDatabase and uses a tunnel pool for the lookup
func NewKademliaResolver(netDb NetworkDatabase, pool *tunnel.Pool) (r Resolver) {
	if pool != nil && netDb != nil {
		log.WithField("at", "NewKademliaResolver").Debug("Creating Kademlia resolver")
		r = &KademliaResolver{
			NetworkDatabase: netDb,
			pool:            pool,
		}
	} else {
		log.WithField("at", "NewKademliaResolver").Warn("Cannot create resolver: pool or netDb is nil")
	}
	return
}
