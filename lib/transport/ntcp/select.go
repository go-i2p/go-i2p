package ntcp

import (
	"context"
	"time"

	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/netdb"
)

func (t *NTCP2Transport) selectPeersToConnect(netdb netdb.NetworkDatabase, count int) []router_info.RouterInfo {
	// Select suitable RouterInfos from NetDB based on capabilities, freshness, etc.
	peers := netdb.GetAllRouterInfos()
	var selectedPeers []router_info.RouterInfo
	for _, peer := range peers {
		if t.Compatible(peer) {
			selectedPeers = append(selectedPeers, peer)
		}
	}
	if len(selectedPeers) > count {
		selectedPeers = selectedPeers[:count]
	}
	return selectedPeers
}

func (t *NTCP2Transport) maintainConnections(ctx context.Context, netdb netdb.NetworkDatabase) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			currentCount := t.getActiveSessionCount()
			if currentCount < t.minDesiredSessions {
				// Find suitable peers and connect
				peers := t.selectPeersToConnect(netdb, t.minDesiredSessions-currentCount)
				for _, peer := range peers {
					log.Debugf("Connecting to peer: %s", peer.IdentHash())
					// TODO: Implement connection logic
					// Example: t.establishSession(peer)
					// This is a placeholder for the actual connection logic
					//go t.establishSession(peer)
				}
			}
		}
	}
}

func (t *NTCP2Transport) getActiveSessionCount() int {
	t.activeSessionsLock.RLock()
	defer t.activeSessionsLock.RUnlock()
	return len(t.activeSessions)
}
