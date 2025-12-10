package netdb

import (
	"context"
	"fmt"
	"sort"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/go-i2p/logger"
)

// resolves router infos with recursive kademlia lookup
type KademliaResolver struct {
	// netdb to store result into
	NetworkDatabase
	// what tunnel pool to use when doing lookup
	// if nil the lookup will be done directly
	pool *tunnel.Pool
}

// peerDistance represents a peer with its calculated XOR distance
type peerDistance struct {
	hash     common.Hash
	distance []byte
}

func (kr *KademliaResolver) Lookup(h common.Hash, timeout time.Duration) (*router_info.RouterInfo, error) {
	log.WithFields(logger.Fields{
		"at":      "(KademliaResolver) Lookup",
		"reason":  "starting kademlia lookup",
		"hash":    fmt.Sprintf("%x...", h[:8]),
		"timeout": timeout,
	}).Debug("starting Kademlia lookup")

	// Create a context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Try local lookup first
	if ri := kr.attemptLocalLookup(h); ri != nil {
		return ri, nil
	}

	// Validate remote lookup capability
	if err := kr.validateRemoteLookupCapability(); err != nil {
		return nil, err
	}

	// Set up channels for the result and errors
	resultChan := make(chan *router_info.RouterInfo, 1)
	errChan := make(chan error, 1)

	// Start the remote lookup process
	kr.performRemoteLookup(ctx, h, timeout, resultChan, errChan)

	// Wait for result, error, or timeout
	return kr.collectLookupResult(resultChan, errChan, ctx, timeout)
}

// attemptLocalLookup tries to find the RouterInfo locally first.
func (kr *KademliaResolver) attemptLocalLookup(h common.Hash) *router_info.RouterInfo {
	riChan := kr.NetworkDatabase.GetRouterInfo(h)
	ri, ok := <-riChan
	if !ok {
		log.WithFields(logger.Fields{
			"at":     "(KademliaResolver) attemptLocalLookup",
			"reason": "channel closed without result",
			"hash":   fmt.Sprintf("%x...", h[:8]),
		}).Debug("channel closed, no RouterInfo available")
		return nil
	}
	// Check if the RouterInfo is valid by comparing with an empty hash
	var emptyHash common.Hash
	identHash, err := ri.IdentHash()
	if err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"at":     "(KademliaResolver) attemptLocalLookup",
			"reason": "failed to extract router hash",
			"hash":   fmt.Sprintf("%x...", h[:8]),
		}).Debug("failed to get router hash from local lookup")
		return nil
	}
	if identHash != emptyHash {
		log.WithFields(logger.Fields{
			"at":     "(KademliaResolver) attemptLocalLookup",
			"reason": "local cache hit",
			"hash":   fmt.Sprintf("%x...", h[:8]),
		}).Debug("routerInfo found locally")
		return &ri
	}
	return nil
}

// validateRemoteLookupCapability checks if remote lookups are possible.
func (kr *KademliaResolver) validateRemoteLookupCapability() error {
	if kr.pool == nil {
		log.WithFields(logger.Fields{
			"at":     "validateRemoteLookupCapability",
			"reason": "tunnel pool not configured",
		}).Error("Cannot perform remote lookup")
		return fmt.Errorf("tunnel pool required for remote lookups")
	}
	return nil
}

// performRemoteLookup starts the Kademlia lookup process in a goroutine.
func (kr *KademliaResolver) performRemoteLookup(ctx context.Context, h common.Hash, timeout time.Duration, resultChan chan *router_info.RouterInfo, errChan chan error) {
	log.WithFields(logger.Fields{
		"at":      "performRemoteLookup",
		"hash":    fmt.Sprintf("%x", h[:8]),
		"timeout": timeout,
	}).Debug("Starting remote Kademlia lookup")
	go func() {
		// Find the closest peers we know to the target hash
		closestPeers := kr.findClosestPeers(h)
		if len(closestPeers) == 0 {
			log.WithFields(logger.Fields{
				"at":     "performRemoteLookup",
				"hash":   fmt.Sprintf("%x", h[:8]),
				"reason": "no peers available",
			}).Error("Kademlia lookup failed")
			errChan <- fmt.Errorf("insufficient peers available for lookup")
			return
		}

		log.WithFields(logger.Fields{
			"at":         "performRemoteLookup",
			"hash":       fmt.Sprintf("%x", h[:8]),
			"peer_count": len(closestPeers),
		}).Debug("Found closest peers for lookup")

		// Query each closest peer in parallel
		kr.queryClosestPeers(ctx, closestPeers, h, resultChan)

		// Allow some time for queries to complete, but eventually give up
		kr.handleLookupTimeout(ctx, timeout, errChan)
	}()
}

// queryClosestPeers queries each of the closest peers in parallel.
func (kr *KademliaResolver) queryClosestPeers(ctx context.Context, peers []common.Hash, target common.Hash, resultChan chan *router_info.RouterInfo) {
	for _, peer := range peers {
		go func(p common.Hash) {
			ri, err := kr.queryPeer(ctx, p, target)
			if err != nil {
				log.WithFields(logger.Fields{
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
}

// handleLookupTimeout manages the timeout for the lookup operation.
func (kr *KademliaResolver) handleLookupTimeout(ctx context.Context, timeout time.Duration, errChan chan error) {
	select {
	case <-time.After(timeout - time.Second): // Leave 1s buffer for the main select
		errChan <- fmt.Errorf("router info not found in kademlia lookup")
	case <-ctx.Done():
		// Context was already canceled, main select will handle it
	}
}

// collectLookupResult waits for and processes the lookup result.
func (kr *KademliaResolver) collectLookupResult(resultChan chan *router_info.RouterInfo, errChan chan error, ctx context.Context, timeout time.Duration) (*router_info.RouterInfo, error) {
	select {
	case result := <-resultChan:
		// Store the result in our local database
		kr.NetworkDatabase.StoreRouterInfo(*result)
		log.WithFields(logger.Fields{
			"at":   "collectLookupResult",
			"hash": fmt.Sprintf("%x", result),
		}).Debug("Kademlia lookup successful, stored RouterInfo")
		return result, nil
	case err := <-errChan:
		log.WithFields(logger.Fields{
			"at": "collectLookupResult",
		}).WithError(err).Error("Kademlia lookup failed")
		return nil, err
	case <-ctx.Done():
		log.WithFields(logger.Fields{
			"at":      "collectLookupResult",
			"timeout": timeout,
		}).Error("Kademlia lookup timed out")
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

	// Calculate XOR distances for all peers
	peers := kr.calculatePeerDistances(allRouterInfos, target)
	if len(peers) == 0 {
		log.Debug("No suitable peers found after filtering")
		return []common.Hash{}
	}

	// Sort and select closest peers
	return kr.selectClosestPeers(peers, target, K)
}

// calculatePeerDistances calculates XOR distances for all router infos.
func (kr *KademliaResolver) calculatePeerDistances(allRouterInfos []router_info.RouterInfo, target common.Hash) []peerDistance {
	peers := make([]peerDistance, 0, len(allRouterInfos))

	for _, ri := range allRouterInfos {
		peerHash, err := ri.IdentHash()
		if err != nil {
			log.WithError(err).Warn("Failed to get peer hash for distance calculation, skipping")
			continue
		}

		// Skip self or target if it's in our database
		if peerHash == target {
			continue
		}

		// Calculate XOR distance between target and peer
		distance := kr.calculateXORDistance(target, peerHash)

		peers = append(peers, peerDistance{
			hash:     peerHash,
			distance: distance,
		})
	}

	return peers
}

// calculateXORDistance calculates the XOR distance between two hashes.
func (kr *KademliaResolver) calculateXORDistance(target, peer common.Hash) []byte {
	distance := make([]byte, len(target))
	for i := 0; i < len(target); i++ {
		distance[i] = target[i] ^ peer[i]
	}
	return distance
}

// selectClosestPeers sorts peers by distance and returns the K closest ones.
func (kr *KademliaResolver) selectClosestPeers(peers []peerDistance, target common.Hash, K int) []common.Hash {
	// Sort peers by XOR distance (closest first)
	sort.Slice(peers, func(i, j int) bool {
		return kr.compareDistances(peers[i].distance, peers[j].distance)
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

	log.WithFields(logger.Fields{
		"target":        target,
		"total_peers":   len(peers),
		"closest_peers": len(result),
	}).Debug("Found closest peers by XOR distance")

	return result
}

// compareDistances compares two distance byte arrays (big endian comparison).
func (kr *KademliaResolver) compareDistances(dist1, dist2 []byte) bool {
	for k := 0; k < len(dist1); k++ {
		if dist1[k] < dist2[k] {
			return true
		}
		if dist1[k] > dist2[k] {
			return false
		}
	}
	return false // Equal distances
}

// queryPeer sends a lookup request to a specific peer through the tunnel
func (kr *KademliaResolver) queryPeer(ctx context.Context, peer, target common.Hash) (*router_info.RouterInfo, error) {
	// This would send a DatabaseLookup message through the tunnel to the peer
	// The implementation would:
	// 1. Create an I2NP DatabaseLookup message
	// 2. Send it through the tunnel pool to the peer
	// 3. Wait for and process the response

	log.WithFields(logger.Fields{
		"at":     "queryPeer",
		"peer":   fmt.Sprintf("%x", peer[:8]),
		"target": fmt.Sprintf("%x", target[:8]),
		"reason": "not implemented",
	}).Debug("Peer query placeholder")

	// Placeholder implementation that would need to be completed
	return nil, fmt.Errorf("peer query not implemented")
}
