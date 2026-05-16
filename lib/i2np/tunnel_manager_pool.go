package i2np

import (
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/samber/oops"
)

// GetPool returns the outbound tunnel pool for backward compatibility.
// Deprecated: Use GetInboundPool() or GetOutboundPool() for specific pools. Will be removed in v0.2.0.
func (tm *TunnelManager) GetPool() *tunnel.Pool {
	return tm.outboundPool
}

// GetInboundPool returns the inbound tunnel pool.
func (tm *TunnelManager) GetInboundPool() *tunnel.Pool {
	return tm.inboundPool
}

// GetOutboundPool returns the outbound tunnel pool.
func (tm *TunnelManager) GetOutboundPool() *tunnel.Pool {
	return tm.outboundPool
}

// getPoolForTunnel returns the appropriate pool based on tunnel direction.
func (tm *TunnelManager) getPoolForTunnel(isInbound bool) *tunnel.Pool {
	if isInbound {
		return tm.inboundPool
	}
	return tm.outboundPool
}

// retryTunnelBuild routes retry requests to the appropriate pool.
// This wrapper is used by the ReplyProcessor for automatic tunnel build retries.
func (tm *TunnelManager) retryTunnelBuild(tunnelID tunnel.TunnelID, isInbound bool, hopCount int) error {
	pool := tm.getPoolForTunnel(isInbound)
	if pool == nil {
		return oops.Errorf("pool not initialized for isInbound=%v", isInbound)
	}
	return pool.RetryTunnelBuild(tunnelID, isInbound, hopCount)
}
