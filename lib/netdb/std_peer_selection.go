package netdb

import (
	"fmt"
	"sort"

	"github.com/go-i2p/crypto/rand"
	"github.com/samber/oops"

	"github.com/go-i2p/logger"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/bootstrap"
)

// GetAllRouterInfos returns all cached RouterInfos as a slice.
func (db *StdNetDB) GetAllRouterInfos() (ri []router_info.RouterInfo) {
	log.WithFields(logger.Fields{
		"at":     "StdNetDB.GetAllRouterInfos",
		"reason": "bulk_retrieval",
	}).Debug("getting all RouterInfos")
	db.riMutex.RLock()
	ri = make([]router_info.RouterInfo, 0, len(db.RouterInfos))
	for _, e := range db.RouterInfos {
		if e.RouterInfo != nil {
			ri = append(ri, *e.RouterInfo)
		}
	}
	db.riMutex.RUnlock()
	return ri
}

// buildExcludeMap creates a map for fast hash lookup during peer filtering
func (db *StdNetDB) buildExcludeMap(exclude []common.Hash) map[common.Hash]bool {
	excludeMap := make(map[common.Hash]bool)
	for _, hash := range exclude {
		excludeMap[hash] = true
	}
	return excludeMap
}

// hasReachableAddress checks if a router is reachable via any supported transport:
// - Direct NTCP2 or SSU2 (host+port present)
// - SSU2 via introducers (ih0 key set)
// Returns (direct bool, viaIntroducer bool). Both false means no reachable address.
func hasReachableAddress(ri *router_info.RouterInfo) (direct bool, viaIntroducer bool) {
	if ri == nil {
		return false, false
	}
	if bootstrap.HasDirectConnectivity(*ri) {
		return true, false
	}
	if bootstrap.HasSSU2IntroducerConnectivity(*ri) {
		return false, true
	}
	return false, false
}

// filterAvailablePeers filters router infos excluding specified hashes and checking reachability.
// Results are sorted by PeerTracker reliability score (reliable peers first).
func (db *StdNetDB) filterAvailablePeers(allRouterInfos []router_info.RouterInfo, excludeMap map[common.Hash]bool) []router_info.RouterInfo {
	stats := &peerFilterStats{}
	available := db.collectAvailablePeers(allRouterInfos, excludeMap, stats)
	logPeerFilteringResults(allRouterInfos, available, stats)
	db.sortPeersByReliability(available)
	return available
}

// sortPeersByReliability sorts peers in descending order of PeerTracker reliability score.
// Reliable peers (high success rate) appear first, unknown peers in the middle,
// and less reliable peers last.
func (db *StdNetDB) sortPeersByReliability(peers []router_info.RouterInfo) {
	if db.PeerTracker == nil || len(peers) < 2 {
		return
	}
	sort.SliceStable(peers, func(i, j int) bool {
		hashI, errI := peers[i].IdentHash()
		hashJ, errJ := peers[j].IdentHash()
		if errI != nil || errJ != nil {
			return errI == nil // peers with valid hashes first
		}
		return db.PeerTracker.ScorePeer(hashI) > db.PeerTracker.ScorePeer(hashJ)
	})
}

// peerFilterStats tracks filtering statistics for peer selection.
type peerFilterStats struct {
	skippedExcluded     int
	skippedNoAddresses  int
	skippedNotReachable int // no NTCP2/SSU2 direct address and no SSU2 introducer
	skippedHashError    int
	skippedStale        int
	directCount         int // accepted with direct NTCP2 or SSU2 connectivity
	viaIntroducer       int // accepted via SSU2 introducers
}

// collectAvailablePeers iterates through router infos and filters out invalid or excluded peers.
// Accepted peers are those reachable directly (NTCP2 or SSU2 with host+port) or
// via SSU2 introducers.
func (db *StdNetDB) collectAvailablePeers(allRouterInfos []router_info.RouterInfo, excludeMap map[common.Hash]bool, stats *peerFilterStats) []router_info.RouterInfo {
	var available []router_info.RouterInfo

	for _, ri := range allRouterInfos {
		if shouldSkipPeer(ri, excludeMap, db.PeerTracker, stats) {
			continue
		}
		direct, viaIntro := hasReachableAddress(&ri)
		switch {
		case direct:
			stats.directCount++
			available = append(available, ri)
		case viaIntro:
			stats.viaIntroducer++
			available = append(available, ri)
		default:
			stats.skippedNotReachable++
		}
	}

	return available
}

// shouldSkipPeer determines if a peer should be filtered out based on various criteria.
func shouldSkipPeer(ri router_info.RouterInfo, excludeMap map[common.Hash]bool, tracker *PeerTracker, stats *peerFilterStats) bool {
	riHash, err := ri.IdentHash()
	if err != nil {
		log.WithError(err).Debug("Failed to get router hash, skipping router")
		stats.skippedHashError++
		return true
	}
	if excludeMap[riHash] {
		stats.skippedExcluded++
		return true
	}
	if len(ri.RouterAddresses()) == 0 {
		stats.skippedNoAddresses++
		return true
	}
	if tracker.IsLikelyStale(riHash) {
		log.WithFields(logger.Fields{
			"peer_hash": fmt.Sprintf("%x", riHash[:8]),
			"reason":    "peer_marked_stale_by_tracker",
		}).Debug("Skipping stale peer")
		stats.skippedStale++
		return true
	}
	return false
}

// logPeerFilteringResults logs detailed peer filtering statistics.
func logPeerFilteringResults(allRouterInfos, available []router_info.RouterInfo, stats *peerFilterStats) {
	log.WithFields(logger.Fields{
		"at":                    "filterAvailablePeers",
		"phase":                 "peer_filtering",
		"total":                 len(allRouterInfos),
		"available":             len(available),
		"direct":                stats.directCount,
		"via_introducer":        stats.viaIntroducer,
		"skipped_excluded":      stats.skippedExcluded,
		"skipped_no_addresses":  stats.skippedNoAddresses,
		"skipped_not_reachable": stats.skippedNotReachable,
		"skipped_stale":         stats.skippedStale,
		"skipped_hash_error":    stats.skippedHashError,
		"usability_ratio":       fmt.Sprintf("%.1f%%", float64(len(available))*100.0/float64(len(allRouterInfos))),
	}).Info("Peer filtering complete")
}

// selectRandomPeers randomly selects the requested number of peers from available pool.
// Uses Fisher-Yates shuffle to avoid degenerate O(n²) behavior of rejection sampling
// when count approaches len(available).
func (db *StdNetDB) selectRandomPeers(available []router_info.RouterInfo, count int) []router_info.RouterInfo {
	if count > len(available) {
		count = len(available)
	}
	if count <= 0 || len(available) == 0 {
		return nil
	}

	// Create index slice and Fisher-Yates shuffle the first 'count' elements
	indices := make([]int, len(available))
	for i := range indices {
		indices[i] = i
	}
	rand.Shuffle(len(indices), func(i, j int) {
		indices[i], indices[j] = indices[j], indices[i]
	})

	selected := make([]router_info.RouterInfo, count)
	for i := 0; i < count; i++ {
		selected[i] = available[indices[i]]
	}
	return selected
}

// SelectPeers selects a random subset of peers for tunnel building
// Filters out unreachable routers and excludes specified hashes
func (db *StdNetDB) SelectPeers(count int, exclude []common.Hash) ([]router_info.RouterInfo, error) {
	log.WithFields(logger.Fields{
		"count":   count,
		"exclude": len(exclude),
	}).Debug("Selecting peers for tunnel building")

	allRouterInfos := db.GetAllRouterInfos()
	if len(allRouterInfos) == 0 {
		return nil, oops.Errorf("insufficient router infos available for peer selection")
	}

	excludeMap := db.buildExcludeMap(exclude)
	available := db.filterAvailablePeers(allRouterInfos, excludeMap)

	if len(available) == 0 {
		// Enhanced metrics for Critical Priority Issue #2: Peer Selection Diagnostics
		// This provides operators with actionable information about NetDB composition
		log.WithFields(logger.Fields{
			"at":              "StdNetDB.SelectPeers",
			"phase":           "peer_selection",
			"total_peers":     len(allRouterInfos),
			"excluded_peers":  len(exclude),
			"filtered_peers":  len(available),
			"requested_count": count,
			"diagnosis":       "no reachable peers: all lack direct NTCP2/SSU2 addresses and SSU2 introducer addresses",
			"impact":          "tunnel building will fail until reachable peers are available",
		}).Error("No reachable peers available after filtering")
		return nil, oops.Errorf("insufficient suitable peers after filtering: need %d reachable peers, but 0 available from %d total peers (%d excluded)", count, len(allRouterInfos), len(exclude))
	}

	// If we have fewer available peers than requested, return all
	if len(available) <= count {
		log.WithFields(logger.Fields{
			"at":              "StdNetDB.SelectPeers",
			"reason":          "requested_exceeds_available",
			"available_peers": len(available),
		}).Debug("returning all available peers")
		return available, nil
	}

	selected := db.selectRandomPeers(available, count)
	log.WithFields(logger.Fields{
		"at":             "StdNetDB.SelectPeers",
		"reason":         "selection_complete",
		"selected_peers": count,
	}).Debug("peer selection completed")
	return selected, nil
}

// SelectFloodfillRouters selects the closest floodfill routers to a target hash
// using XOR distance metric (Kademlia-style selection).
//
// This method:
// 1. Filters all RouterInfos to find only floodfill routers (caps contains 'f')
// 2. Calculates XOR distance between target hash and each floodfill router
// 3. Returns up to 'count' closest floodfill routers sorted by distance
//
// Parameters:
//   - targetHash: The hash to find closest floodfill routers to (e.g., LeaseSet hash)
//   - count: Maximum number of floodfill routers to return
//
// Returns:
//   - Slice of RouterInfo for closest floodfill routers (may be less than count if insufficient floodfills available)
//   - Error if no floodfill routers are available in NetDB
func (db *StdNetDB) SelectFloodfillRouters(targetHash common.Hash, count int) ([]router_info.RouterInfo, error) {
	log.WithFields(logger.Fields{
		"target_hash": fmt.Sprintf("%x", targetHash[:8]),
		"count":       count,
	}).Debug("Selecting closest floodfill routers")

	// Get all router infos
	allRouterInfos := db.GetAllRouterInfos()
	if len(allRouterInfos) == 0 {
		return nil, oops.Errorf("no router infos available in NetDB")
	}

	// Filter for floodfill routers
	floodfills := db.filterFloodfillRouters(allRouterInfos)
	if len(floodfills) == 0 {
		return nil, oops.Errorf("no floodfill routers available in NetDB")
	}

	log.WithFields(logger.Fields{
		"at":              "StdNetDB.SelectFloodfillRouters",
		"reason":          "floodfill_selection_complete",
		"floodfill_count": len(floodfills),
	}).Debug("found floodfill routers")

	// Calculate XOR distances and select closest
	return db.selectClosestByXORDistance(floodfills, targetHash, count), nil
}

// filterFloodfillRouters filters RouterInfos to return only floodfill routers
// that are not marked stale by PeerTracker.
// A router is considered floodfill if its "caps" option contains the character 'f'.
func (db *StdNetDB) filterFloodfillRouters(routers []router_info.RouterInfo) []router_info.RouterInfo {
	var floodfills []router_info.RouterInfo

	for _, ri := range routers {
		if !db.isFloodfillRouter(ri) {
			continue
		}
		if db.PeerTracker != nil {
			if riHash, err := ri.IdentHash(); err == nil && db.PeerTracker.IsLikelyStale(riHash) {
				log.WithField("peer_hash", fmt.Sprintf("%x", riHash[:8])).
					Debug("Skipping stale floodfill router")
				continue
			}
		}
		floodfills = append(floodfills, ri)
	}

	return floodfills
}

// isFloodfillRouter checks if a RouterInfo represents a floodfill router.
// Delegates to the shared IsFloodfillRouter function.
func (db *StdNetDB) isFloodfillRouter(ri router_info.RouterInfo) bool {
	return IsFloodfillRouter(ri)
}

// routerDistance represents a router with its calculated XOR distance from target.
type routerDistance struct {
	routerInfo router_info.RouterInfo
	distance   []byte // XOR distance as byte array for comparison
}

// selectClosestByXORDistance selects up to 'count' routers closest to targetHash
// using XOR distance metric (Kademlia).
func (db *StdNetDB) selectClosestByXORDistance(routers []router_info.RouterInfo, targetHash common.Hash, count int) []router_info.RouterInfo {
	// Calculate distances for all routers
	distances := make([]routerDistance, 0, len(routers))
	for _, ri := range routers {
		riHash, err := ri.IdentHash()
		if err != nil {
			log.WithError(err).Warn("Failed to get router hash for XOR distance calculation, skipping")
			continue
		}
		distance := CalculateXORDistance(targetHash, riHash)
		distances = append(distances, routerDistance{
			routerInfo: ri,
			distance:   distance,
		})
	}

	// Sort by XOR distance (ascending)
	sort.Slice(distances, func(i, j int) bool {
		return CompareXORDistances(distances[i].distance, distances[j].distance)
	})

	// Take up to count closest routers
	resultCount := count
	if len(distances) < count {
		resultCount = len(distances)
	}

	result := make([]router_info.RouterInfo, resultCount)
	for i := 0; i < resultCount; i++ {
		result[i] = distances[i].routerInfo
	}

	log.WithFields(logger.Fields{
		"requested": count,
		"available": len(distances),
		"selected":  resultCount,
	}).Debug("Selected closest floodfill routers by XOR distance")

	return result
}
