package netdb

import (
	common "github.com/go-i2p/common/data"
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
			responseHandler: NewLookupResponseHandler(),
		}
	} else {
		log.WithFields(logger.Fields{
			"at":     "NewKademliaResolver",
			"reason": "nil_dependencies",
		}).Warn("cannot create resolver: pool or netDb is nil")
	}
	return r
}

// NewKademliaResolverWithTransport creates a resolver with transport capability for network lookups.
// This enables the resolver to send DatabaseLookup messages to peers and receive responses.
//
// Parameters:
//   - netDb: The network database to store discovered RouterInfos
//   - pool: The tunnel pool for sending messages (used for privacy)
//   - transport: The transport interface for sending DatabaseLookup messages
//   - ourHash: Our router's identity hash for constructing lookup messages
func NewKademliaResolverWithTransport(netDb NetworkDatabase, pool *tunnel.Pool, transport LookupTransport, ourHash common.Hash) *KademliaResolver {
	if netDb == nil {
		log.WithFields(logger.Fields{
			"at":     "NewKademliaResolverWithTransport",
			"reason": "nil_netdb",
		}).Warn("cannot create resolver: netDb is nil")
		return nil
	}

	log.WithFields(logger.Fields{
		"at":            "NewKademliaResolverWithTransport",
		"reason":        "initialization",
		"has_pool":      pool != nil,
		"has_transport": transport != nil,
	}).Debug("creating Kademlia resolver with transport")

	return &KademliaResolver{
		NetworkDatabase: netDb,
		pool:            pool,
		transport:       transport,
		ourHash:         ourHash,
		responseHandler: NewLookupResponseHandler(),
	}
}

// SetTransport sets the lookup transport for network-based DHT lookups.
// This must be called before performing remote lookups if not set via constructor.
func (kr *KademliaResolver) SetTransport(transport LookupTransport) {
	kr.mu.Lock()
	kr.transport = transport
	kr.mu.Unlock()
	log.WithFields(logger.Fields{
		"at":     "KademliaResolver.SetTransport",
		"reason": "transport_configured",
	}).Debug("lookup transport set")
}

// SetOurHash sets our router's identity hash for constructing lookup messages.
func (kr *KademliaResolver) SetOurHash(hash common.Hash) {
	kr.mu.Lock()
	kr.ourHash = hash
	kr.mu.Unlock()
	log.WithFields(logger.Fields{
		"at":     "KademliaResolver.SetOurHash",
		"reason": "our_hash_configured",
	}).Debug("our router hash set")
}

// GetResponseHandler returns the response handler for registering incoming responses.
// This should be called by the message processor to deliver DatabaseStore and
// DatabaseSearchReply messages to waiting lookups.
func (kr *KademliaResolver) GetResponseHandler() *LookupResponseHandler {
	return kr.responseHandler
}
