package i2pcontrol

import (
	"net"

	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/go-i2p/go-i2p/lib/i2np"
)

// NetDBStatsReader provides read-only access to network database statistics.
// This narrow interface decouples I2PControl stats collection from the full NetDB API.
type NetDBStatsReader interface {
	// GetRouterInfoCount returns the number of RouterInfo entries in the database.
	GetRouterInfoCount() int

	// GetActivePeerCount returns the number of active peers.
	GetActivePeerCount() int

	// GetFastPeerCount returns the number of fast-tier peers.
	GetFastPeerCount() int

	// GetHighCapacityPeerCount returns the number of high-capacity peers.
	GetHighCapacityPeerCount() int

	// GetLeaseSetCount returns the number of LeaseSets in the database.
	GetLeaseSetCount() int

	// IsFloodfill returns whether this router is a floodfill router.
	IsFloodfill() bool
}

// ParticipantStatsReader provides read-only access to tunnel participant statistics.
// This narrow interface decouples I2PControl stats collection from the full tunnel manager API.
type ParticipantStatsReader interface {
	// ParticipantCount returns the number of tunnels this router is currently participating in.
	ParticipantCount() int
}

// RouterInfoReader provides access to router configuration and component information.
// This interface is used by handlers that need router metadata, configuration, and subsystem access.
// Decouples I2PControl from router internals by returning narrow, use-case-specific interfaces
// rather than full subsystem types.
type RouterInfoReader interface {
	// GetConfig returns the router configuration.
	GetConfig() *config.RouterConfig

	// GetNetDB returns a read-only network database stats interface.
	GetNetDB() NetDBStatsReader

	// GetTunnelManager returns a read-only tunnel stats interface.
	// Callers that need build operations should use i2np.TunnelBuildCoordinator directly.
	GetTunnelManager() i2np.TunnelStatsReader

	// GetParticipantManager returns a read-only participant stats interface.
	GetParticipantManager() ParticipantStatsReader

	// GetTransportAddr returns the listening address of the first available transport.
	// Returns nil if no transports are available.
	GetTransportAddr() net.Addr

	// GetSSU2Addr returns the listening UDP address of the SSU2 transport.
	// Returns nil if SSU2 is not available.
	GetSSU2Addr() net.Addr

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

// RouterAccess defines the minimal interface needed to collect router statistics.
// This allows the stats provider to work with the real Router or test mocks.
//
// Design rationale:
//   - Minimal interface (only what we actually need)
//   - Read-only operations (stats collection doesn't modify router)
//   - Allows easy mocking for tests
type RouterAccess interface {
	// RouterInfoReader provides access to router configuration and components
	RouterInfoReader

	// BandwidthReader provides access to bandwidth statistics
	BandwidthReader

	// NetworkStatusReader provides access to network status and session counts
	NetworkStatusReader

	// RouterController provides access to router control operations
	RouterController
}
