package i2pcontrol

import (
	"time"

	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/go-i2p/go-i2p/lib/netdb"
	"github.com/go-i2p/go-i2p/lib/tunnel"
)

// RouterStatsProvider provides access to router statistics for I2PControl RPC.
// This interface abstracts router statistics collection, allowing for testing
// with mock implementations while providing real router stats in production.
//
// Design rationale:
//   - Decouples I2PControl from router internals
//   - Enables testing without full router initialization
//   - Provides stable interface even if router structure changes
type RouterStatsProvider interface {
	// GetBandwidthStats returns current bandwidth statistics
	// Returns inbound/outbound bytes per second
	GetBandwidthStats() BandwidthStats

	// GetRouterInfo returns general router status information
	// Includes uptime, version, peer counts, and tunnel counts
	GetRouterInfo() RouterInfoStats

	// GetTunnelStats returns detailed tunnel statistics
	// Includes participating, inbound, and outbound tunnel counts
	GetTunnelStats() TunnelStats

	// GetNetDBStats returns network database statistics
	// Includes RouterInfo count, LeaseSet count, and floodfill status
	GetNetDBStats() NetDBStats

	// GetNetworkConfig returns network configuration settings
	// Includes NTCP2 port and address information
	GetNetworkConfig() NetworkConfig

	// IsRunning returns whether the router is currently running
	IsRunning() bool

	// GetRouterControl returns the underlying router control interface
	// This is used by RouterManagerHandler to perform control operations (shutdown, restart, etc.)
	GetRouterControl() interface{ Stop() }
}

// BandwidthStats contains bandwidth usage statistics.
// Rates are measured in bytes per second.
type BandwidthStats struct {
	// InboundRate is the current inbound data rate (bytes/sec)
	// Currently returns 0.0 as bandwidth tracking is not yet implemented
	InboundRate float64

	// OutboundRate is the current outbound data rate (bytes/sec)
	// Currently returns 0.0 as bandwidth tracking is not yet implemented
	OutboundRate float64
}

// RouterInfoStats contains general router status information.
// This maps to I2PControl RouterInfo method responses.
type RouterInfoStats struct {
	// Uptime is router uptime in milliseconds
	Uptime int64

	// Version is the router version string
	Version string

	// Status is the router status string (e.g., "OK", "TESTING", "ERROR")
	Status string

	// ActivePeers is the number of currently active transport connections
	// Currently returns 0 as session tracking is not yet exposed
	ActivePeers int

	// KnownPeers is the number of RouterInfos in the NetDB
	KnownPeers int

	// ActivePeers is the number of peers with successful connections in the last hour
	ActivePeersCount int

	// FastPeers is the number of peers with low latency (< 500ms average response time)
	FastPeersCount int

	// HighCapacityPeers is the number of reliable, high-performance peers
	HighCapacityPeersCount int

	// IsReseeding indicates if the router is currently performing a NetDB reseed operation
	IsReseeding bool

	// ParticipatingTunnels is the count of tunnels we're participating in
	ParticipatingTunnels int

	// InboundTunnels is the number of active inbound tunnels
	InboundTunnels int

	// OutboundTunnels is the number of active outbound tunnels
	OutboundTunnels int
}

// TunnelStats contains detailed tunnel statistics.
// This provides a breakdown of tunnel states and types.
type TunnelStats struct {
	// Participating is the number of transit tunnels we're participating in
	// (tunnels where we're a hop but not the endpoint)
	Participating int

	// InboundActive is the number of our active inbound tunnels
	InboundActive int

	// OutboundActive is the number of our active outbound tunnels
	OutboundActive int

	// InboundBuilding is the number of inbound tunnels currently building
	InboundBuilding int

	// OutboundBuilding is the number of outbound tunnels currently building
	OutboundBuilding int
}

// NetDBStats contains network database statistics.
// This provides information about the local database size and role.
type NetDBStats struct {
	// RouterInfos is the count of RouterInfo entries in NetDB
	RouterInfos int

	// LeaseSets is the count of LeaseSet entries in NetDB
	// Currently returns 0 as LeaseSet counting is not implemented
	LeaseSets int

	// Floodfill indicates if we're operating as a floodfill router
	// Currently returns false as floodfill status is not exposed
	Floodfill bool
}

// NetworkConfig contains network configuration settings.
// This maps to I2PControl NetworkSetting method responses.
type NetworkConfig struct {
	// NTCP2Port is the port number the NTCP2 transport is listening on
	// Returns 0 if NTCP2 is not available
	NTCP2Port int

	// NTCP2Address is the full address string (IP:port) the NTCP2 transport is listening on
	// Returns empty string if NTCP2 is not available
	NTCP2Address string

	// NTCP2Hostname is the hostname/IP address (without port) that NTCP2 is listening on
	// Extracted from NTCP2Address
	NTCP2Hostname string

	// BandwidthLimitIn is the inbound bandwidth limit in KB/s
	// Returns 0 if no limit is configured (unlimited)
	BandwidthLimitIn int

	// BandwidthLimitOut is the outbound bandwidth limit in KB/s
	// Returns 0 if no limit is configured (unlimited)
	BandwidthLimitOut int
}

// routerStatsProvider implements RouterStatsProvider by wrapping the actual Router.
// Uses interface types to minimize coupling with router internals.
//
// Design notes:
//   - Uses minimal interface requirements (duck typing)
//   - Tracks start time for uptime calculation
//   - Returns mock data for unimplemented features (bandwidth, active peers)
//   - Safe to call concurrently (uses read-only access patterns)
type routerStatsProvider struct {
	// router provides access to router subsystems
	// Uses minimal interface to allow testing with mocks
	router RouterAccess

	// startTime is when the router statistics provider was created
	// Used to calculate uptime
	startTime time.Time

	// version is the router version string
	// Hardcoded for now as version is not tracked in router
	version string
}

// RouterAccess defines the minimal interface needed to collect router statistics.
// This allows the stats provider to work with the real Router or test mocks.
//
// Design rationale:
//   - Minimal interface (only what we actually need)
//   - Read-only operations (stats collection doesn't modify router)
//   - Allows easy mocking for tests
type RouterAccess interface {
	// GetNetDB returns the network database
	// In real Router, this is embedded so accessed directly via *netdb.StdNetDB methods
	GetNetDB() *netdb.StdNetDB

	// GetTunnelManager returns the tunnel manager for tunnel statistics
	GetTunnelManager() *i2np.TunnelManager

	// GetParticipantManager returns the participant manager for transit tunnel statistics
	GetParticipantManager() *tunnel.Manager

	// GetConfig returns the router configuration
	GetConfig() *config.RouterConfig

	// GetTransportAddr returns the listening address of the first available transport
	// Returns nil if no transports are available
	// This is used to extract NTCP2 port and address for NetworkSetting RPC method
	GetTransportAddr() interface{}

	// IsRunning returns whether the router is currently operational
	IsRunning() bool

	// IsReseeding returns whether the router is currently performing a NetDB reseed operation
	IsReseeding() bool

	// GetBandwidthRates returns the current 1-second and 15-second bandwidth rates in bytes per second
	GetBandwidthRates() (rate1s, rate15s uint64)

	// Stop initiates graceful shutdown of the router
	Stop()
}

// NewRouterStatsProvider creates a new statistics provider for the given router.
// The router parameter must implement the RouterAccess interface (or be a *router.Router).
//
// Parameters:
//   - router: The router to collect statistics from (must implement RouterAccess)
//   - version: The router version string (e.g., "0.1.0-go")
//
// Returns:
//   - RouterStatsProvider: The statistics provider
func NewRouterStatsProvider(router RouterAccess, version string) RouterStatsProvider {
	return &routerStatsProvider{
		router:    router,
		startTime: time.Now(),
		version:   version,
	}
}

// GetBandwidthStats returns current bandwidth statistics.
// Returns the 1-second rolling average bandwidth rate from the router's bandwidth tracker.
// Rates are in bytes per second.
func (rsp *routerStatsProvider) GetBandwidthStats() BandwidthStats {
	// Get the 1-second rolling average rate (we ignore 15s for now)
	rate1s, _ := rsp.router.GetBandwidthRates()

	// Convert from bytes per second to the format expected by I2PControl
	// The rate represents total bandwidth (inbound + outbound combined)
	// For simplicity, we return it as outbound rate (Java I2P behavior)
	return BandwidthStats{
		InboundRate:  0.0,             // Not tracked separately yet
		OutboundRate: float64(rate1s), // 1-second average in bytes/sec
	}
}

// GetRouterInfo returns general router status information.
// Collects statistics from NetDB and tunnel manager.
func (rsp *routerStatsProvider) GetRouterInfo() RouterInfoStats {
	// Determine status string based on whether router is running
	statusStr := "ERROR"
	if rsp.router.IsRunning() {
		statusStr = "OK"
	}

	stats := RouterInfoStats{
		Uptime:      rsp.calculateUptime(),
		Version:     rsp.version,
		Status:      statusStr,
		ActivePeers: 0, // Active session tracking not yet exposed
	}

	// Collect NetDB statistics if available
	if netdb := rsp.router.GetNetDB(); netdb != nil {
		stats.KnownPeers = netdb.GetRouterInfoCount()
		stats.ActivePeersCount = netdb.GetActivePeerCount()
		stats.FastPeersCount = netdb.GetFastPeerCount()
		stats.HighCapacityPeersCount = netdb.GetHighCapacityPeerCount()
	}

	// Collect reseed status from router
	stats.IsReseeding = rsp.router.IsReseeding()

	// Collect participating tunnel statistics from participant manager
	if pm := rsp.router.GetParticipantManager(); pm != nil {
		stats.ParticipatingTunnels = pm.ParticipantCount()
	}

	// Collect tunnel statistics if available
	if tm := rsp.router.GetTunnelManager(); tm != nil {
		// Currently TunnelManager only has one pool (GetPool())
		// Separate inbound/outbound tracking not yet implemented
		if pool := tm.GetPool(); pool != nil {
			poolStats := pool.GetPoolStats()
			// Total active tunnels (not separated by direction yet)
			stats.InboundTunnels = poolStats.Active / 2  // Estimate
			stats.OutboundTunnels = poolStats.Active / 2 // Estimate
		}
	}

	return stats
}

// GetTunnelStats returns detailed tunnel statistics.
// Collects statistics from separate inbound and outbound tunnel manager pools.
func (rsp *routerStatsProvider) GetTunnelStats() TunnelStats {
	stats := TunnelStats{}

	// Collect from tunnel manager if available
	tm := rsp.router.GetTunnelManager()
	if tm == nil {
		return stats
	}

	// Get statistics from separate inbound and outbound pools
	if inboundPool := tm.GetInboundPool(); inboundPool != nil {
		inboundStats := inboundPool.GetPoolStats()
		stats.InboundActive = inboundStats.Active
		stats.InboundBuilding = inboundStats.Building
	}

	if outboundPool := tm.GetOutboundPool(); outboundPool != nil {
		outboundStats := outboundPool.GetPoolStats()
		stats.OutboundActive = outboundStats.Active
		stats.OutboundBuilding = outboundStats.Building
	}

	return stats
}

// GetNetDBStats returns network database statistics.
// Collects statistics from NetDB.
func (rsp *routerStatsProvider) GetNetDBStats() NetDBStats {
	stats := NetDBStats{
		LeaseSets: 0,     // LeaseSet counting not implemented
		Floodfill: false, // Floodfill status not exposed
	}

	// Collect NetDB statistics if available
	if netdb := rsp.router.GetNetDB(); netdb != nil {
		stats.RouterInfos = netdb.GetRouterInfoCount()
	}

	return stats
}

// GetNetworkConfig returns network configuration settings.
// Extracts NTCP2 port, hostname, and bandwidth limits from the router.
// Returns zero values if transport is not available or not NTCP2.
func (rsp *routerStatsProvider) GetNetworkConfig() NetworkConfig {
	config := NetworkConfig{
		NTCP2Port:         0,
		NTCP2Address:      "",
		NTCP2Hostname:     "",
		BandwidthLimitIn:  0, // 0 means unlimited
		BandwidthLimitOut: 0, // 0 means unlimited
	}

	// Get transport address from router
	addr := rsp.router.GetTransportAddr()
	if addr == nil {
		return config
	}

	// Extract address string (format is typically "ip:port")
	addrStr := ""
	if netAddr, ok := addr.(interface{ String() string }); ok {
		addrStr = netAddr.String()
	}

	if addrStr == "" {
		return config
	}

	config.NTCP2Address = addrStr

	// Parse hostname and port from address string
	// Expected format: "127.0.0.1:12345" or "[::1]:12345" or "[2001:db8::1]:12345"
	hostname, port := rsp.parseHostPort(addrStr)
	config.NTCP2Hostname = hostname
	config.NTCP2Port = port

	// Bandwidth limits are not yet configurable in the router
	// Return 0 (unlimited) for now
	// TODO: Add bandwidth limit configuration to RouterConfig
	config.BandwidthLimitIn = 0
	config.BandwidthLimitOut = 0

	return config
}

// parseHostPort extracts hostname and port from an address string.
// Handles both IPv4 (host:port) and IPv6 ([host]:port) formats.
// Returns empty string and 0 if parsing fails.
func (rsp *routerStatsProvider) parseHostPort(addrStr string) (hostname string, port int) {
	// Handle IPv6 addresses with brackets: [2001:db8::1]:12345
	if len(addrStr) > 0 && addrStr[0] == '[' {
		// Find closing bracket
		closeBracket := -1
		for i := 1; i < len(addrStr); i++ {
			if addrStr[i] == ']' {
				closeBracket = i
				break
			}
		}
		if closeBracket > 0 {
			hostname = addrStr[1:closeBracket] // Extract IPv6 address without brackets
			// Port comes after ]:
			if closeBracket+1 < len(addrStr) && addrStr[closeBracket+1] == ':' {
				port = rsp.parsePort(addrStr[closeBracket+2:])
			}
			return hostname, port
		}
	}

	// Handle IPv4 addresses: 127.0.0.1:12345
	// Find the last colon (in case of IPv6 without brackets, this handles the port)
	lastColon := -1
	for i := len(addrStr) - 1; i >= 0; i-- {
		if addrStr[i] == ':' {
			lastColon = i
			break
		}
	}

	if lastColon > 0 {
		hostname = addrStr[:lastColon]
		port = rsp.parsePort(addrStr[lastColon+1:])
	} else {
		// No colon found, entire string is hostname
		hostname = addrStr
	}

	return hostname, port
}

// parsePort converts a port string to an integer.
// Returns 0 if the string is not a valid port number.
func (rsp *routerStatsProvider) parsePort(portStr string) int {
	port := 0
	for _, ch := range portStr {
		if ch >= '0' && ch <= '9' {
			port = port*10 + int(ch-'0')
		} else {
			// Invalid character
			return 0
		}
	}
	return port
} // IsRunning returns whether the router is currently running.
func (rsp *routerStatsProvider) IsRunning() bool {
	return rsp.router.IsRunning()
}

// GetRouterControl returns the underlying router control interface.
// This allows RouterManagerHandler to perform control operations like shutdown.
func (rsp *routerStatsProvider) GetRouterControl() interface{ Stop() } {
	return rsp.router
}

// calculateUptime returns router uptime in milliseconds.
// Calculated from the time the stats provider was created.
func (rsp *routerStatsProvider) calculateUptime() int64 {
	duration := time.Since(rsp.startTime)
	return duration.Milliseconds()
}

// RealRouter is an adapter that makes *router.Router implement RouterAccess.
// This bridges the gap between the stats provider's minimal interface
// and the actual Router implementation.
//
// Usage:
//
//	import "github.com/go-i2p/go-i2p/lib/router"
//	r, _ := router.CreateRouter(cfg)
//	statsProvider := i2pcontrol.NewRouterStatsProvider(
//	    i2pcontrol.RealRouter{Router: r},
//	    "0.1.0-go",
//	)
type RealRouter struct {
	// Router is the actual router instance
	// Must be a pointer to avoid copying the router
	Router interface {
		GetNetDB() *netdb.StdNetDB
		GetTunnelManager() *i2np.TunnelManager
		GetParticipantManager() *tunnel.Manager
		GetConfig() *config.RouterConfig
		IsRunning() bool
	}
}

// GetNetDB returns the NetDB (implements RouterAccess)
func (rr RealRouter) GetNetDB() *netdb.StdNetDB {
	return rr.Router.GetNetDB()
}

// GetTunnelManager returns the tunnel manager (implements RouterAccess)
func (rr RealRouter) GetTunnelManager() *i2np.TunnelManager {
	return rr.Router.GetTunnelManager()
}

// GetParticipantManager returns the participant manager (implements RouterAccess)
func (rr RealRouter) GetParticipantManager() *tunnel.Manager {
	return rr.Router.GetParticipantManager()
}

// GetConfig returns the router configuration (implements RouterAccess)
func (rr RealRouter) GetConfig() *config.RouterConfig {
	return rr.Router.GetConfig()
}

// IsRunning returns whether the router is running (implements RouterAccess)
func (rr RealRouter) IsRunning() bool {
	return rr.Router.IsRunning()
}
