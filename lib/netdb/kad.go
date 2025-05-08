package netdb

import (
	"context"
	"fmt"
	"time"

	common "github.com/go-i2p/go-i2p/lib/common/data"
	"github.com/go-i2p/go-i2p/lib/common/router_info"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/sirupsen/logrus"
)

// resolves router infos with recursive kademlia lookup
type kadResolver struct {
	// netdb to store result into
	NetworkDatabase
	// what tunnel pool to use when doing lookup
	// if nil the lookup will be done directly
	pool *tunnel.Pool
}

func (kr *kadResolver) Lookup(h common.Hash, timeout time.Duration) (*router_info.RouterInfo, error) {
	log.WithFields(logrus.Fields{
		"hash":    h,
		"timeout": timeout,
	}).Debug("Starting Kademlia lookup")

	// Create a context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Try local lookup first
	ri := kr.NetworkDatabase.GetRouterInfo(h)
	if &ri == nil {
		log.WithField("hash", h).Debug("RouterInfo found locally")
		return &ri, nil
	}

	// If we don't have a tunnel pool, we can't do remote lookups
	// Technically, we could do a direct lookup, but that would require
	// the transport anyway which is what I'm working on now.
	if kr.pool == nil {
		return nil, fmt.Errorf("tunnel pool required for remote lookups")
	}

	// Set up channels for the result and errors
	resultChan := make(chan *router_info.RouterInfo, 1)
	errChan := make(chan error, 1)

	// Start the Kademlia lookup in a goroutine
	go func() {
		// Find the closest peers we know to the target hash
		closestPeers := kr.findClosestPeers(h)
		if len(closestPeers) == 0 {
			errChan <- fmt.Errorf("no peers available for lookup")
			return
		}

		// Query each closest peer in parallel
		for _, peer := range closestPeers {
			go func(p common.Hash) {
				ri, err := kr.queryPeer(ctx, p, h)
				if err != nil {
					log.WithFields(logrus.Fields{
						"peer":  p,
						"error": err,
					}).Debug("Peer query failed")
					return
				}

				if ri != nil {
					resultChan <- ri
				}
			}(peer)
		}

		// Allow some time for queries to complete, but eventually give up
		select {
		case <-time.After(timeout - time.Second): // Leave 1s buffer for the main select
			errChan <- fmt.Errorf("kademlia lookup failed to find router info")
		case <-ctx.Done():
			// Context was already canceled, main select will handle it
		}
	}()

	// Wait for result, error, or timeout
	select {
	case result := <-resultChan:
		// Store the result in our local database
		kr.NetworkDatabase.StoreRouterInfo(*result)
		return result, nil
	case err := <-errChan:
		return nil, err
	case <-ctx.Done():
		return nil, fmt.Errorf("lookup timed out after %s", timeout)
	}
}

// findClosestPeers returns peers closest to the target hash using XOR distance
func (kr *kadResolver) findClosestPeers(target common.Hash) []common.Hash {
	// This would be implemented to find the closest peers by XOR distance
	// For now return a simplified implementation that just returns some known peers

	// In a real implementation, we would:
	// 1. Get all known peers from the netDB
	// 2. Calculate XOR distance between target and all peers
	// 3. Sort by XOR distance
	// 4. Return the K closest peers (where K is typically 8 or 16)

	// Placeholder implementation that would need to be completed
	return []common.Hash{}
}

// queryPeer sends a lookup request to a specific peer through the tunnel
func (kr *kadResolver) queryPeer(ctx context.Context, peer common.Hash, target common.Hash) (*router_info.RouterInfo, error) {
	// This would send a DatabaseLookup message through the tunnel to the peer
	// The implementation would:
	// 1. Create an I2NP DatabaseLookup message
	// 2. Send it through the tunnel pool to the peer
	// 3. Wait for and process the response

	// Placeholder implementation that would need to be completed
	return nil, fmt.Errorf("peer query not implemented")
}

// create a new resolver that stores result into a NetworkDatabase and uses a tunnel pool for the lookup
func KademliaResolver(netDb NetworkDatabase, pool *tunnel.Pool) (r Resolver) {
	if pool != nil && netDb != nil {
		r = &kadResolver{
			NetworkDatabase: netDb,
			pool:            pool,
		}
	}
	return
}
