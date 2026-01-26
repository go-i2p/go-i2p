package netdb

import (
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/go-i2p/logger"
)

// Moved from: kad.go
// NewKademliaResolver creates a new resolver that stores result into a NetworkDatabase and uses a tunnel pool for the lookup
func NewKademliaResolver(netDb NetworkDatabase, pool *tunnel.Pool) (r Resolver) {
	if pool != nil && netDb != nil {
		log.WithFields(logger.Fields{
			"at":     "NewKademliaResolver",
			"reason": "initialization",
		}).Debug("creating Kademlia resolver")
		r = &KademliaResolver{
			NetworkDatabase: netDb,
			pool:            pool,
		}
	} else {
		log.WithFields(logger.Fields{
			"at":     "NewKademliaResolver",
			"reason": "nil_dependencies",
		}).Warn("cannot create resolver: pool or netDb is nil")
	}
	return r
}
