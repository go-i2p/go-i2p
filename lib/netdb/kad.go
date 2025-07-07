package netdb

import (
	"context"
	"fmt"
	"sort"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/sirupsen/logrus"
)

// resolves router infos with recursive kademlia lookup
type KademliaResolver struct {
	// netdb to store result into
	NetworkDatabase
	// what tunnel pool to use when doing lookup
	// if nil the lookup will be done directly
	pool *tunnel.Pool
}

func (kr *KademliaResolver) Lookup(h common.Hash, timeout time.Duration) (*router_info.RouterInfo, error) {
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
func (kr *KademliaResolver) findClosestPeers(target common.Hash) []common.Hash {
	const K = 8 // Standard Kademlia parameter for number of closest peers to return

	// Get all known router infos from the network database
	allRouterInfos := kr.NetworkDatabase.GetAllRouterInfos()
	if len(allRouterInfos) == 0 {
		log.Debug("No peers available in network database")
		return []common.Hash{}
	}

	// Calculate XOR distance for each peer
	type peerDistance struct {
		hash     common.Hash
		distance []byte
	}

	peers := make([]peerDistance, 0, len(allRouterInfos))

	for _, ri := range allRouterInfos {
		peerHash := ri.IdentHash()

		// Skip self or target if it's in our database
		if peerHash == target {
			continue
		}

		// Calculate XOR distance between target and peer
		distance := make([]byte, len(target))
		for i := 0; i < len(target); i++ {
			distance[i] = target[i] ^ peerHash[i]
		}

		peers = append(peers, peerDistance{
			hash:     peerHash,
			distance: distance,
		})
	}

	if len(peers) == 0 {
		log.Debug("No suitable peers found after filtering")
		return []common.Hash{}
	}

	// Sort peers by XOR distance (closest first)
	sort.Slice(peers, func(i, j int) bool {
		// Compare distances byte by byte (big endian comparison)
		for k := 0; k < len(peers[i].distance); k++ {
			if peers[i].distance[k] < peers[j].distance[k] {
				return true
			}
			if peers[i].distance[k] > peers[j].distance[k] {
				return false
			}
		}
		return false // Equal distances
	})

	// Take up to K closest peers
	count := K
	if len(peers) < count {
		count = len(peers)
	}

	result := make([]common.Hash, count)
	for i := 0; i < count; i++ {
		result[i] = peers[i].hash
	}

	log.WithFields(logrus.Fields{
		"target":        target,
		"total_peers":   len(peers),
		"closest_peers": len(result),
	}).Debug("Found closest peers by XOR distance")

	return result
}

// queryPeer sends a lookup request to a specific peer through the tunnel
func (kr *KademliaResolver) queryPeer(ctx context.Context, peer common.Hash, target common.Hash) (*router_info.RouterInfo, error) {
	// This would send a DatabaseLookup message through the tunnel to the peer
	// The implementation would:
	// 1. Create an I2NP DatabaseLookup message
	// 2. Send it through the tunnel pool to the peer
	// 3. Wait for and process the response

	// Placeholder implementation that would need to be completed
	return nil, fmt.Errorf("peer query not implemented")
}

// create a new resolver that stores result into a NetworkDatabase and uses a tunnel pool for the lookup
func NewKademliaResolver(netDb NetworkDatabase, pool *tunnel.Pool) (r Resolver) {
	if pool != nil && netDb != nil {
		r = &KademliaResolver{
			NetworkDatabase: netDb,
			pool:            pool,
		}
	}
	return
}
