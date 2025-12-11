package tunnel

import (
	"fmt"

	common "github.com/go-i2p/common/data"
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

	if count <= 0 {
		log.WithFields(logger.Fields{
			"at":     "SelectPeers",
			"count":  count,
			"reason": "count must be positive",
		}).Error("Invalid peer count")
		return nil, fmt.Errorf("count must be > 0")
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

	// PRIORITY 4: Enhanced peer diagnostics to understand what peers are selected
	log.WithFields(logger.Fields{
		"at":         "SelectPeers",
		"peer_count": len(peers),
	}).Debug("Successfully selected peers")

	// Analyze selected peers for reachability characteristics
	ntcp2Count := 0
	introducerOnlyCount := 0
	directlyDialableCount := 0

	for _, peer := range peers {
		hasDirectNTCP2 := false
		addresses := peer.RouterAddresses()

		for _, addr := range addresses {
			style := addr.TransportStyle()
			styleStr, err := style.Data()
			if err != nil {
				continue
			}

			// Check if this is NTCP2 (case-insensitive)
			if styleStr == "NTCP2" || styleStr == "ntcp2" {
				ntcp2Count++
				// Check if address has 'host' key (directly dialable) vs introducer-only
				_, hostErr := addr.Host()
				if hostErr == nil {
					hasDirectNTCP2 = true
				}
			}
		}

		if hasDirectNTCP2 {
			directlyDialableCount++
		} else if ntcp2Count > 0 {
			// Has NTCP2 but no direct address - introducer only
			introducerOnlyCount++
		}
	}

	log.WithFields(logger.Fields{
		"at":                  "SelectPeers",
		"total_peers":         len(peers),
		"ntcp2_addresses":     ntcp2Count,
		"directly_dialable":   directlyDialableCount,
		"introducer_only":     introducerOnlyCount,
		"dialable_percentage": fmt.Sprintf("%.1f%%", float64(directlyDialableCount)/float64(len(peers))*100),
	}).Info("Peer selection characteristics for tunnel building")

	if directlyDialableCount == 0 && len(peers) > 0 {
		log.WithFields(logger.Fields{
			"at":                "SelectPeers",
			"total_peers":       len(peers),
			"directly_dialable": directlyDialableCount,
			"reason":            "no directly dialable peers selected",
		}).Warn("WARNING: No directly dialable NTCP2 peers selected - tunnel building may fail")
	}

	return peers, nil
}
