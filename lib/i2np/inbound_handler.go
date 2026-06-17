package i2np

import "github.com/go-i2p/go-i2p/lib/tunnel"

// InboundHandlerRegistrar is implemented by InboundMessageHandler (lib/router)
// and allows the TunnelManager to register/unregister newly-active inbound tunnels
// as control-plane (exploratory) endpoints without importing lib/router, which
// would create an import cycle.
//
// When an inbound tunnel build succeeds, the TunnelManager calls
// RegisterExploratoryTunnel so that subsequent TunnelData messages addressed
// to that tunnel ID (e.g. build replies sent via TUNNEL delivery mode) are
// forwarded to the MessageProcessor rather than silently dropped.
//
// When an inbound tunnel fails or expires, the TunnelManager calls
// UnregisterTunnel to clean up the endpoint so the tunnel ID can be safely
// reused without receiving stale messages.
type InboundHandlerRegistrar interface {
	RegisterExploratoryTunnel(tunnelID tunnel.TunnelID) error
	UnregisterTunnel(tunnelID tunnel.TunnelID)
}
