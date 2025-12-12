package tunnel

import (
	"fmt"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_address"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/logger"
)

// NetDBSelector is a minimal interface used by DefaultPeerSelector to
// delegate peer selection. Any component that implements
// SelectPeers(count int, exclude []common.Hash) ([]router_info.RouterInfo, error)
// can be used. This avoids a hard dependency on a concrete netdb type.
type NetDBSelector interface {
	SelectPeers(count int, exclude []common.Hash) ([]router_info.RouterInfo, error)
}

// DefaultPeerSelector is a simple implementation of PeerSelector that
// delegates peer selection to a NetDB-like component (for example
// lib/netdb.StdNetDB). It performs basic argument validation and
// propagates errors from the underlying selector.
type DefaultPeerSelector struct {
	db NetDBSelector
}

// NewDefaultPeerSelector creates a new DefaultPeerSelector backed by the
// provided db. The db must implement SelectPeers with the same signature.
// Returns an error if db is nil.
func NewDefaultPeerSelector(db NetDBSelector) (*DefaultPeerSelector, error) {
	log.WithFields(logger.Fields{
		"at":     "NewDefaultPeerSelector",
		"reason": "initialization",
	}).Debug("creating default peer selector")
	if db == nil {
		log.WithFields(logger.Fields{
			"at":     "NewDefaultPeerSelector",
			"reason": "nil_db_selector",
		}).Error("DB selector is nil")
		return nil, fmt.Errorf("db selector cannot be nil")
	}
	log.WithFields(logger.Fields{
		"at":     "NewDefaultPeerSelector",
		"reason": "created_successfully",
	}).Debug("default peer selector created")
	return &DefaultPeerSelector{db: db}, nil
}

// SelectPeers selects peers by delegating to the underlying db selector.
// Returns an error for invalid arguments or if the underlying selector fails.
func (s *DefaultPeerSelector) SelectPeers(count int, exclude []common.Hash) ([]router_info.RouterInfo, error) {
	log.WithFields(logger.Fields{
		"at":            "SelectPeers",
		"count":         count,
		"exclude_count": len(exclude),
	}).Debug("Selecting peers for tunnel")

	if err := validatePeerCount(count); err != nil {
		return nil, err
	}

	peers, err := s.db.SelectPeers(count, exclude)
	if err != nil {
		log.WithFields(logger.Fields{
			"at":     "(DefaultPeerSelector) SelectPeers",
			"reason": "db_selector_failed",
			"error":  err.Error(),
		}).Error("underlying selector failed")
		return nil, fmt.Errorf("underlying selector error: %w", err)
	}

	log.WithFields(logger.Fields{
		"at":         "SelectPeers",
		"peer_count": len(peers),
	}).Debug("Successfully selected peers")

	analyzePeerCharacteristics(peers)
	return peers, nil
}

// validatePeerCount checks if the peer count is valid and logs errors for invalid counts.
// Returns an error if count is less than or equal to 0.
func validatePeerCount(count int) error {
	if count <= 0 {
		log.WithFields(logger.Fields{
			"at":     "validatePeerCount",
			"count":  count,
			"reason": "count must be positive",
		}).Error("Invalid peer count")
		return fmt.Errorf("count must be > 0")
	}
	return nil
}

// analyzePeerCharacteristics examines selected peers for reachability characteristics
// and logs diagnostic information about NTCP2 connectivity and dialability.
func analyzePeerCharacteristics(peers []router_info.RouterInfo) {
	ntcp2Count, directlyDialableCount, introducerOnlyCount := countPeerTypes(peers)

	log.WithFields(logger.Fields{
		"at":                  "analyzePeerCharacteristics",
		"total_peers":         len(peers),
		"ntcp2_addresses":     ntcp2Count,
		"directly_dialable":   directlyDialableCount,
		"introducer_only":     introducerOnlyCount,
		"dialable_percentage": fmt.Sprintf("%.1f%%", float64(directlyDialableCount)/float64(len(peers))*100),
	}).Info("Peer selection characteristics for tunnel building")

	warnIfNoDialablePeers(directlyDialableCount, len(peers))
}

// countPeerTypes iterates through peers and counts NTCP2 addresses, directly dialable peers,
// and introducer-only peers based on their router address configuration.
func countPeerTypes(peers []router_info.RouterInfo) (ntcp2Count, directlyDialableCount, introducerOnlyCount int) {
	for _, peer := range peers {
		hasDirectNTCP2, peerNTCP2Count := checkPeerAddresses(peer.RouterAddresses())
		ntcp2Count += peerNTCP2Count
		updateDialabilityCounters(&directlyDialableCount, &introducerOnlyCount, hasDirectNTCP2, peerNTCP2Count)
	}
	return ntcp2Count, directlyDialableCount, introducerOnlyCount
}

// checkPeerAddresses examines all addresses for a peer and determines if it has directly dialable NTCP2.
// Returns whether the peer has direct NTCP2 connectivity and the count of NTCP2 addresses found.
func checkPeerAddresses(addresses []*router_address.RouterAddress) (hasDirectNTCP2 bool, ntcp2Count int) {
	for _, addr := range addresses {
		if isNTCP2Address(addr) {
			ntcp2Count++
			if hasHostKey(addr) {
				hasDirectNTCP2 = true
			}
		}
	}
	return hasDirectNTCP2, ntcp2Count
}

// updateDialabilityCounters increments the appropriate dialability counter based on peer characteristics.
// Updates directlyDialableCount if the peer has direct NTCP2, or introducerOnlyCount if it only has introducers.
func updateDialabilityCounters(directlyDialableCount, introducerOnlyCount *int, hasDirectNTCP2 bool, ntcp2Count int) {
	if hasDirectNTCP2 {
		*directlyDialableCount++
	} else if ntcp2Count > 0 {
		*introducerOnlyCount++
	}
}

// isNTCP2Address checks if a router address is an NTCP2 transport (case-insensitive).
// Returns true if the transport style is NTCP2.
func isNTCP2Address(addr *router_address.RouterAddress) bool {
	style := addr.TransportStyle()
	styleStr, err := style.Data()
	if err != nil {
		return false
	}
	return styleStr == "NTCP2" || styleStr == "ntcp2"
}

// hasHostKey checks if a router address has a 'host' key indicating it is directly dialable.
// Returns true if the host key exists without error.
func hasHostKey(addr *router_address.RouterAddress) bool {
	_, hostErr := addr.Host()
	return hostErr == nil
}

// warnIfNoDialablePeers logs a warning if no directly dialable NTCP2 peers were selected,
// which may cause tunnel building failures.
func warnIfNoDialablePeers(directlyDialableCount, totalPeers int) {
	if directlyDialableCount == 0 && totalPeers > 0 {
		log.WithFields(logger.Fields{
			"at":                "warnIfNoDialablePeers",
			"total_peers":       totalPeers,
			"directly_dialable": directlyDialableCount,
			"reason":            "no directly dialable peers selected",
		}).Warn("WARNING: No directly dialable NTCP2 peers selected - tunnel building may fail")
	}
}
