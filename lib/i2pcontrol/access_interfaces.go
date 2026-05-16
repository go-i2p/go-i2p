package i2pcontrol

import (
	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/go-i2p/go-i2p/lib/netdb"
	"github.com/go-i2p/go-i2p/lib/tunnel"
)

// RouterInfoReader provides access to router configuration and component information.
// This interface is used by handlers that need router metadata, configuration, and subsystem access.
type RouterInfoReader interface {
	// GetConfig returns the router configuration.
	GetConfig() *config.RouterConfig

	// GetNetDB returns the network database.
	GetNetDB() *netdb.StdNetDB

	// GetTunnelManager returns the tunnel manager for tunnel statistics.
	GetTunnelManager() i2np.TunnelOrchestrator

	// GetParticipantManager returns the participant manager for transit tunnel statistics.
	GetParticipantManager() *tunnel.Manager

	// GetTransportAddr returns the listening address of the first available transport.
	// Returns nil if no transports are available.
	GetTransportAddr() interface{}

	// GetSSU2Addr returns the listening UDP address of the SSU2 transport.
	// Returns nil if SSU2 is not available.
	GetSSU2Addr() interface{}

	// IsRunning returns whether the router is currently operational.
	IsRunning() bool

	// IsReseeding returns whether the router is currently performing a NetDB reseed operation.
	IsReseeding() bool
}

// BandwidthReader provides access to current bandwidth statistics.
// This interface is used by handlers that report bandwidth metrics.
type BandwidthReader interface {
	// GetBandwidthRates returns the current 15-second inbound and outbound bandwidth rates in bytes per second.
	GetBandwidthRates() (inbound, outbound uint64)

	// GetBandwidthRates1s returns the most recent 1-second inbound and outbound bandwidth rates in bytes per second.
	GetBandwidthRates1s() (inbound, outbound uint64)
}

// NetworkStatusReader provides access to network status and session statistics.
// This interface is used by handlers that report network connectivity and session counts.
type NetworkStatusReader interface {
	// GetNetworkStatus returns the I2PControl network status code (0–14).
	GetNetworkStatus() int

	// GetActiveSessionCount returns the number of active transport sessions (connected peers).
	GetActiveSessionCount() int

	// GetNTCP2SessionCount returns the number of active NTCP2 (TCP) sessions.
	GetNTCP2SessionCount() int

	// GetSSU2SessionCount returns the number of active SSU2 (UDP) sessions.
	GetSSU2SessionCount() int
}

// RouterController provides access to router control operations.
// This interface is used by handlers that perform router administration.
type RouterController interface {
	// Stop initiates graceful shutdown of the router.
	Stop()

	// Reseed triggers a manual NetDB reseed operation.
	Reseed() error
}
