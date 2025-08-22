package tunnel

import (
	"sync"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
)

// TunnelState represents the current state of a tunnel during building
type TunnelState struct {
	ID            TunnelID
	Hops          []common.Hash    // Router hashes for each hop
	State         TunnelBuildState // Current build state
	CreatedAt     time.Time        // When tunnel building started
	ResponseCount int              // Number of responses received
	Responses     []BuildResponse  // Responses from each hop
}

// TunnelBuildState represents different states during tunnel building
type TunnelBuildState int

const (
	TunnelBuilding TunnelBuildState = iota // Tunnel is being built
	TunnelReady                            // Tunnel is ready for use
	TunnelFailed                           // Tunnel build failed
)

// BuildResponse represents a response from a tunnel hop
type BuildResponse struct {
	HopIndex int    // Index of the hop that responded
	Success  bool   // Whether the hop accepted the tunnel
	Reply    []byte // Raw response data
}

// PeerSelector defines interface for selecting peers for tunnel building
type PeerSelector interface {
	SelectPeers(count int, exclude []common.Hash) ([]router_info.RouterInfo, error)
}

// Pool manages a collection of tunnels
type Pool struct {
	tunnels      map[TunnelID]*TunnelState
	mutex        sync.RWMutex
	peerSelector PeerSelector
}

// NewTunnelPool creates a new tunnel pool with the given peer selector
func NewTunnelPool(selector PeerSelector) *Pool {
	return &Pool{
		tunnels:      make(map[TunnelID]*TunnelState),
		peerSelector: selector,
	}
}

// GetTunnel retrieves a tunnel by ID
func (p *Pool) GetTunnel(id TunnelID) (*TunnelState, bool) {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	tunnel, exists := p.tunnels[id]
	return tunnel, exists
}

// AddTunnel adds a new tunnel to the pool
func (p *Pool) AddTunnel(tunnel *TunnelState) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.tunnels[tunnel.ID] = tunnel
	log.WithField("tunnel_id", tunnel.ID).Debug("Added tunnel to pool")
}

// RemoveTunnel removes a tunnel from the pool
func (p *Pool) RemoveTunnel(id TunnelID) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	delete(p.tunnels, id)
	log.WithField("tunnel_id", id).Debug("Removed tunnel from pool")
}

// GetActiveTunnels returns all active tunnels
func (p *Pool) GetActiveTunnels() []*TunnelState {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	var active []*TunnelState
	for _, tunnel := range p.tunnels {
		if tunnel.State == TunnelReady {
			active = append(active, tunnel)
		}
	}
	log.WithField("active_count", len(active)).Debug("Retrieved active tunnels")
	return active
}

// CleanupExpiredTunnels removes tunnels that have been building for too long
func (p *Pool) CleanupExpiredTunnels(maxAge time.Duration) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	now := time.Now()
	var expired []TunnelID

	for id, tunnel := range p.tunnels {
		if tunnel.State == TunnelBuilding && now.Sub(tunnel.CreatedAt) > maxAge {
			expired = append(expired, id)
		}
	}

	for _, id := range expired {
		delete(p.tunnels, id)
	}

	if len(expired) > 0 {
		log.WithField("expired_count", len(expired)).Warn("Cleaned up expired tunnels")
	}
}
