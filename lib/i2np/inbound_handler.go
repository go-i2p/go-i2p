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
	// RegisterExploratoryTunnel registers an inbound tunnel as a control-plane
	// endpoint so that TunnelData messages addressed to it (e.g. build replies
	// sent via TUNNEL delivery mode) reach the MessageProcessor instead of
	// being dropped.
	RegisterExploratoryTunnel(tunnelID tunnel.TunnelID) error
	// RegisterClientTunnel registers an inbound client tunnel endpoint for message delivery to an I2CP session.
	// sessionID identifies the owning I2CP session.
	// The inbound handler implementation is responsible for creating the endpoint with proper session context.
	RegisterClientTunnel(tunnelID tunnel.TunnelID, sessionID uint16) error
	// UnregisterTunnel removes a previously registered inbound tunnel endpoint.
	// It is called when a tunnel fails or expires so the tunnel ID can be
	// safely reused without receiving stale messages.
	UnregisterTunnel(tunnelID tunnel.TunnelID)
}
