package i2pcontrol

import (
	"sync"
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
	GetRouterControl() interface {
		Stop()
		Reseed() error
	}

	// GetNetworkStatus returns the I2PControl network status code (0–14).
	// 0=OK, 1=TESTING, 2=FIREWALLED, 3=HIDDEN, 4=WARN_FIREWALLED_AND_FAST,
	// 5=WARN_FIREWALLED_AND_FLOODFILL, 6=WARN_FIREWALLED_AND_INBOUND_TCP,
	// 7=WARN_SLOW_FOREIGN_SEEDNODES, 8=ERROR_I2CP,
	// 9=ERROR_CLOCK_SKEW, 10=ERROR_PRIVATE_TCP_ADDRESS,
	// 11=ERROR_SYMMETRIC_NAT, 12=ERROR_UDP_PORT_IN_USE,
	// 13=ERROR_NO_ACTIVE_PEERS_CHECK_CONNECTION_AND_FIREWALL,
	// 14=ERROR_UDP_DISABLED_AND_TCP_UNSET
	GetNetworkStatus() int

	// GetRateForPeriod returns the windowed average or event count for a named stat over
	// the most recent periodMs milliseconds. It mirrors the Java I2P StatManager.getRate()
	// semantic used by the I2PControl GetRate RPC.
	//
	// Supported stat names:
	//   bw.sendBps, bw.receiveBps, bw.combined         — bandwidth in bytes/sec
	//   tunnel.participatingTunnels                     — participating tunnel count
	//   tunnel.buildExploratorySuccess                  — count of successful exploratory builds
	//   tunnel.buildExploratoryReject                   — count of rejected exploratory builds
	//   tunnel.buildExploratoryExpire                   — count of timed-out exploratory builds
	//   tunnel.buildClientSuccess                       — count of successful client builds (0 until client tunnels are implemented)
	//   tunnel.buildRequestTime                         — average build duration in milliseconds
	GetRateForPeriod(stat string, periodMs int64) float64
}

// BandwidthStats contains bandwidth usage statistics.
type BandwidthStats struct {
	// InboundRate is the 15-second rolling average inbound data rate (bytes/sec).
	InboundRate float64

	// OutboundRate is the 15-second rolling average outbound data rate (bytes/sec).
	OutboundRate float64

	// InboundRate1s is the most recent 1-second inbound sample (bytes/sec).
	InboundRate1s float64

	// OutboundRate1s is the most recent 1-second outbound sample (bytes/sec).
	OutboundRate1s float64
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
	LeaseSets int

	// Floodfill indicates if we're operating as a floodfill router
	Floodfill bool
}

// NetworkConfig contains network configuration settings.
// This maps to I2PControl NetworkSetting method responses.
type NetworkConfig struct {
	// NTCP2Port is the port number the NTCP2 transport is listening on.
	// Returns 0 if NTCP2 is not available.
	NTCP2Port int

	// NTCP2Address is the full address string (IP:port) the NTCP2 transport is listening on.
	// Returns empty string if NTCP2 is not available.
	NTCP2Address string

	// NTCP2Hostname is the hostname/IP address (without port) that NTCP2 is listening on.
	// Extracted from NTCP2Address.
	NTCP2Hostname string

	// BandwidthLimitIn is the inbound bandwidth limit in KB/s.
	// Returns 0 if no limit is configured (unlimited).
	BandwidthLimitIn int

	// BandwidthLimitOut is the outbound bandwidth limit in KB/s.
	// Returns 0 if no limit is configured (unlimited).
	BandwidthLimitOut int

	// SSU2Port is the UDP port number the SSU2 transport is listening on.
	// Returns 0 if SSU2 is disabled or the port is not yet known.
	SSU2Port int

	// SSU2Address is the full UDP address string (IP:port) the SSU2 transport is listening on.
	// Returns empty string if SSU2 is not available.
	SSU2Address string

	// SSU2Hostname is the hostname/IP address (without port) that SSU2 is listening on.
	// Extracted from SSU2Address.
	SSU2Hostname string

	// SharePercentage is the configured percentage (0–100) of bandwidth shared for transit tunnels.
	SharePercentage int
}

// routerStatsProvider implements RouterStatsProvider by wrapping the actual Router.
// Uses interface types to minimize coupling with router internals.
//
// Design notes:
//   - Uses minimal interface requirements (duck typing)
//   - Tracks start time for uptime calculation
//   - Collects live router statistics including bandwidth, peer counts, and tunnel information via RouterAccess interface
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

	// Sliding-window samples for period-aware GetRate responses (kept for 2 hours).
	// Samples are recorded lazily (rate-limited to once per sampleInterval) the first
	// time GetRateForPeriod is called after the interval has elapsed.
	bwInWindow  *RateWindow // inbound bytes/sec samples
	bwOutWindow *RateWindow // outbound bytes/sec samples
	partWindow  *RateWindow // participating tunnel count samples

	// sampleMu protects lastSampleAt to avoid concurrent double-sampling.
	sampleMu     sync.Mutex
	lastSampleAt time.Time
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

	// GetTransportAddr returns the listening address of the first available transport.
	// Returns nil if no transports are available.
	// This is used to extract NTCP2 port and address for NetworkSetting RPC method.
	GetTransportAddr() interface{}

	// GetSSU2Addr returns the listening UDP address of the SSU2 transport.
	// Returns nil if SSU2 is not available.
	GetSSU2Addr() interface{}

	// IsRunning returns whether the router is currently operational.
	IsRunning() bool

	// IsReseeding returns whether the router is currently performing a NetDB reseed operation.
	IsReseeding() bool

	// GetBandwidthRates returns the current 15-second inbound and outbound bandwidth rates in bytes per second.
	GetBandwidthRates() (inbound, outbound uint64)

	// GetBandwidthRates1s returns the most recent 1-second inbound and outbound bandwidth rates in bytes per second.
	GetBandwidthRates1s() (inbound, outbound uint64)

	// GetNetworkStatus returns the I2PControl network status code (0–14).
	GetNetworkStatus() int

	// GetActiveSessionCount returns the number of active transport sessions (connected peers).
	GetActiveSessionCount() int

	// Stop initiates graceful shutdown of the router.
	Stop()

	// Reseed triggers a manual NetDB reseed operation.
	Reseed() error
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
	const sampleWindowMaxAge = 2 * time.Hour
	log.WithField("version", version).Debug("creating router stats provider")
	return &routerStatsProvider{
		router:      router,
		startTime:   time.Now(),
		version:     version,
		bwInWindow:  newRateWindow(sampleWindowMaxAge),
		bwOutWindow: newRateWindow(sampleWindowMaxAge),
		partWindow:  newRateWindow(sampleWindowMaxAge),
	}
}

// GetBandwidthStats returns current bandwidth statistics.
// Returns both 15-second rolling average and 1-second instantaneous rates.
// Rates are in bytes per second.
func (rsp *routerStatsProvider) GetBandwidthStats() BandwidthStats {
	inbound15s, outbound15s := rsp.router.GetBandwidthRates()
	inbound1s, outbound1s := rsp.router.GetBandwidthRates1s()

	log.WithFields(map[string]interface{}{
		"inbound_15s":  inbound15s,
		"outbound_15s": outbound15s,
		"inbound_1s":   inbound1s,
		"outbound_1s":  outbound1s,
	}).Debug("collected bandwidth stats")

	return BandwidthStats{
		InboundRate:    float64(inbound15s),
		OutboundRate:   float64(outbound15s),
		InboundRate1s:  float64(inbound1s),
		OutboundRate1s: float64(outbound1s),
	}
}

// GetNetworkStatus returns the I2PControl network status code (0–14).
func (rsp *routerStatsProvider) GetNetworkStatus() int {
	return rsp.router.GetNetworkStatus()
}

// GetRouterInfo returns general router status information.
// Collects statistics from NetDB and tunnel manager.
func (rsp *routerStatsProvider) GetRouterInfo() RouterInfoStats {
	stats := RouterInfoStats{
		Uptime:      rsp.calculateUptime(),
		Version:     rsp.version,
		Status:      rsp.determineRouterStatus(),
		ActivePeers: rsp.router.GetActiveSessionCount(),
	}

	rsp.collectNetDBStats(&stats)
	stats.IsReseeding = rsp.router.IsReseeding()
	rsp.collectParticipatingTunnelStats(&stats)
	rsp.collectTunnelStats(&stats)

	return stats
}

// determineRouterStatus returns the router status string based on whether the router is running.
// Returns "OK" if the router is running, "ERROR" otherwise.
func (rsp *routerStatsProvider) determineRouterStatus() string {
	if rsp.router.IsRunning() {
		return "OK"
	}
	return "ERROR"
}

// collectNetDBStats populates NetDB statistics in the provided RouterInfoStats.
// Collects peer counts including known, active, fast, and high-capacity peers.
func (rsp *routerStatsProvider) collectNetDBStats(stats *RouterInfoStats) {
	netdb := rsp.router.GetNetDB()
	if netdb == nil {
		return
	}

	stats.KnownPeers = netdb.GetRouterInfoCount()
	stats.ActivePeersCount = netdb.GetActivePeerCount()
	stats.FastPeersCount = netdb.GetFastPeerCount()
	stats.HighCapacityPeersCount = netdb.GetHighCapacityPeerCount()
}

// collectParticipatingTunnelStats populates participating tunnel count in the provided RouterInfoStats.
// Collects the count of tunnels this router is participating in from the participant manager.
func (rsp *routerStatsProvider) collectParticipatingTunnelStats(stats *RouterInfoStats) {
	pm := rsp.router.GetParticipantManager()
	if pm == nil {
		return
	}

	stats.ParticipatingTunnels = pm.ParticipantCount()
}

// collectTunnelStats populates tunnel statistics in the provided RouterInfoStats.
// Collects active inbound and outbound tunnel counts from separate tunnel pools.
func (rsp *routerStatsProvider) collectTunnelStats(stats *RouterInfoStats) {
	tm := rsp.router.GetTunnelManager()
	if tm == nil {
		return
	}

	if inboundPool := tm.GetInboundPool(); inboundPool != nil {
		inboundStats := inboundPool.GetPoolStats()
		stats.InboundTunnels = inboundStats.Active
	}

	if outboundPool := tm.GetOutboundPool(); outboundPool != nil {
		outboundStats := outboundPool.GetPoolStats()
		stats.OutboundTunnels = outboundStats.Active
	}
}

// GetTunnelStats returns detailed tunnel statistics.
// Collects statistics from separate inbound and outbound tunnel manager pools.
func (rsp *routerStatsProvider) GetTunnelStats() TunnelStats {
	stats := TunnelStats{}
	log.Debug("collecting tunnel stats")

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
// Collects statistics from NetDB including RouterInfo count, LeaseSet count,
// and floodfill status.
func (rsp *routerStatsProvider) GetNetDBStats() NetDBStats {
	stats := NetDBStats{}

	// Collect NetDB statistics if available
	if netdb := rsp.router.GetNetDB(); netdb != nil {
		stats.RouterInfos = netdb.GetRouterInfoCount()
		stats.LeaseSets = netdb.GetLeaseSetCount()
		stats.Floodfill = netdb.IsFloodfill()
		log.WithFields(map[string]interface{}{
			"router_infos": stats.RouterInfos,
			"lease_sets":   stats.LeaseSets,
			"floodfill":    stats.Floodfill,
		}).Debug("collected NetDB stats")
	}

	return stats
}

// GetNetworkConfig returns network configuration settings.
// Extracts NTCP2/SSU2 ports, hostnames, and bandwidth limits from the router.
// Returns zero values if transport is not available.
func (rsp *routerStatsProvider) GetNetworkConfig() NetworkConfig {
	netConfig := NetworkConfig{}

	// Report configured bandwidth limits from RouterConfig.
	// Bandwidth limits are in KB/s for the I2PControl protocol.
	cfg := rsp.router.GetConfig()
	if cfg != nil {
		if cfg.MaxBandwidthIn > 0 {
			netConfig.BandwidthLimitIn = int(cfg.MaxBandwidthIn / 1024)
		} else if cfg.MaxBandwidth > 0 {
			netConfig.BandwidthLimitIn = int(cfg.MaxBandwidth / 1024)
		}
		if cfg.MaxBandwidthOut > 0 {
			netConfig.BandwidthLimitOut = int(cfg.MaxBandwidthOut / 1024)
		} else if cfg.MaxBandwidth > 0 {
			netConfig.BandwidthLimitOut = int(cfg.MaxBandwidth / 1024)
		}
		netConfig.SharePercentage = cfg.SharePercentage
	}

	// Populate NTCP2 address info.
	addr := rsp.router.GetTransportAddr()
	if addr == nil {
		return netConfig
	}

	// Extract address string (format is typically "ip:port")
	addrStr := ""
	if netAddr, ok := addr.(interface{ String() string }); ok {
		addrStr = netAddr.String()
	}

	if addrStr == "" {
		return netConfig
	}

	netConfig.NTCP2Address = addrStr

	// Parse hostname and port from address string
	// Expected format: "127.0.0.1:12345" or "[::1]:12345" or "[2001:db8::1]:12345"
	hostname, port := rsp.parseHostPort(addrStr)
	netConfig.NTCP2Hostname = hostname
	netConfig.NTCP2Port = port

	// Populate SSU2 address info.
	ssu2Addr := rsp.router.GetSSU2Addr()
	if ssu2Addr != nil {
		ssu2AddrStr := ""
		if netAddr, ok := ssu2Addr.(interface{ String() string }); ok {
			ssu2AddrStr = netAddr.String()
		}
		if ssu2AddrStr != "" {
			netConfig.SSU2Address = ssu2AddrStr
			ssu2Host, ssu2Port := rsp.parseHostPort(ssu2AddrStr)
			netConfig.SSU2Hostname = ssu2Host
			netConfig.SSU2Port = ssu2Port
		}
	}

	return netConfig
}

// parseHostPort extracts hostname and port from an address string.
// Handles both IPv4 (host:port) and IPv6 ([host]:port) formats.
// Returns empty string and 0 if parsing fails.
func (rsp *routerStatsProvider) parseHostPort(addrStr string) (hostname string, port int) {
	if rsp.isIPv6WithBrackets(addrStr) {
		return rsp.parseIPv6Address(addrStr)
	}
	return rsp.parseIPv4Address(addrStr)
}

// isIPv6WithBrackets checks if the address string starts with a bracket indicating IPv6 format.
func (rsp *routerStatsProvider) isIPv6WithBrackets(addrStr string) bool {
	return len(addrStr) > 0 && addrStr[0] == '['
}

// parseIPv6Address extracts hostname and port from an IPv6 address string with brackets.
// Expected format: [2001:db8::1]:12345
func (rsp *routerStatsProvider) parseIPv6Address(addrStr string) (hostname string, port int) {
	closeBracket := rsp.findClosingBracket(addrStr)
	if closeBracket <= 0 {
		return "", 0
	}

	hostname = addrStr[1:closeBracket]
	port = rsp.extractPortAfterBracket(addrStr, closeBracket)
	return hostname, port
}

// findClosingBracket locates the position of the closing bracket in an address string.
func (rsp *routerStatsProvider) findClosingBracket(addrStr string) int {
	for i := 1; i < len(addrStr); i++ {
		if addrStr[i] == ']' {
			return i
		}
	}
	return -1
}

// extractPortAfterBracket extracts the port number after the closing bracket and colon.
func (rsp *routerStatsProvider) extractPortAfterBracket(addrStr string, closeBracket int) int {
	if closeBracket+1 < len(addrStr) && addrStr[closeBracket+1] == ':' {
		return rsp.parsePort(addrStr[closeBracket+2:])
	}
	return 0
}

// parseIPv4Address extracts hostname and port from an IPv4 address string.
// Expected format: 127.0.0.1:12345
func (rsp *routerStatsProvider) parseIPv4Address(addrStr string) (hostname string, port int) {
	lastColon := rsp.findLastColon(addrStr)
	if lastColon > 0 {
		hostname = addrStr[:lastColon]
		port = rsp.parsePort(addrStr[lastColon+1:])
	} else {
		hostname = addrStr
	}
	return hostname, port
}

// findLastColon locates the position of the last colon in an address string.
func (rsp *routerStatsProvider) findLastColon(addrStr string) int {
	for i := len(addrStr) - 1; i >= 0; i-- {
		if addrStr[i] == ':' {
			return i
		}
	}
	return -1
}

// parsePort converts a port string to an integer.
// Returns 0 if the string is empty, contains non-digit characters,
// or the result is outside the valid port range (1–65535).
func (rsp *routerStatsProvider) parsePort(portStr string) int {
	if len(portStr) == 0 {
		return 0
	}
	port := 0
	for _, ch := range portStr {
		if ch >= '0' && ch <= '9' {
			port = port*10 + int(ch-'0')
			if port > 65535 {
				return 0
			}
		} else {
			// Invalid character
			return 0
		}
	}
	return port
}

// IsRunning returns whether the router is currently running.
func (rsp *routerStatsProvider) IsRunning() bool {
	return rsp.router.IsRunning()
}

// GetRouterControl returns the underlying router control interface.
// This allows RouterManagerHandler to perform control operations like shutdown and reseed.
func (rsp *routerStatsProvider) GetRouterControl() interface {
	Stop()
	Reseed() error
} {
	return rsp.router
}

// calculateUptime returns router uptime in milliseconds.
// Calculated from the time the stats provider was created.
func (rsp *routerStatsProvider) calculateUptime() int64 {
	duration := time.Since(rsp.startTime)
	return duration.Milliseconds()
}

// sampleInterval is the minimum time between successive bandwidth/participating-tunnel samples.
// Balances measurement accuracy against the overhead of calling GetBandwidthRates.
const sampleInterval = 5 * time.Second

// maybeRecordSample records a bandwidth and participating-tunnel sample if sampleInterval has
// elapsed since the last sample. Safe to call concurrently from multiple goroutines.
func (rsp *routerStatsProvider) maybeRecordSample() {
	rsp.sampleMu.Lock()
	defer rsp.sampleMu.Unlock()
	if time.Since(rsp.lastSampleAt) < sampleInterval {
		return
	}
	rsp.lastSampleAt = time.Now()

	inbound, outbound := rsp.router.GetBandwidthRates()
	rsp.bwInWindow.Record(float64(inbound))
	rsp.bwOutWindow.Record(float64(outbound))

	if pm := rsp.router.GetParticipantManager(); pm != nil {
		rsp.partWindow.Record(float64(pm.ParticipantCount()))
	}
}

// GetRateForPeriod returns the windowed average or event count for the named stat over
// the most recent periodMs milliseconds. It mirrors the Java I2P StatManager.getRate()
// semantic used by the I2PControl GetRate RPC.
//
// For bandwidth stats, returns the mean bytes/sec over the window (falling back to the
// current 15-second rate when fewer than two samples have been recorded).
// For count stats (tunnel build success/reject/expire), returns the total event count
// within the window.
func (rsp *routerStatsProvider) GetRateForPeriod(stat string, periodMs int64) float64 {
	rsp.maybeRecordSample()

	switch stat {
	// Bandwidth — windowed average. Return 0 until at least 2 samples have been
	// collected so that callers (e.g. the hourly average TUI row) receive a neutral
	// placeholder during the warm-up period rather than the instantaneous 15-second rate.
	case "bw.sendBps":
		if rsp.bwOutWindow.Len(periodMs) >= 2 {
			return rsp.bwOutWindow.Average(periodMs)
		}
		return 0
	case "bw.receiveBps":
		if rsp.bwInWindow.Len(periodMs) >= 2 {
			return rsp.bwInWindow.Average(periodMs)
		}
		return 0
	case "bw.combined":
		inLen := rsp.bwInWindow.Len(periodMs)
		outLen := rsp.bwOutWindow.Len(periodMs)
		if inLen >= 2 || outLen >= 2 {
			return rsp.bwInWindow.Average(periodMs) + rsp.bwOutWindow.Average(periodMs)
		}
		return 0

	// Participating tunnels — windowed average, with fallback to instantaneous count
	case "tunnel.participatingTunnels":
		if avg := rsp.partWindow.Average(periodMs); avg > 0 {
			return avg
		}
		ri := rsp.GetRouterInfo()
		return float64(ri.ParticipatingTunnels)

	// Tunnel build stats — event counts within the requested window
	case "tunnel.buildExploratorySuccess":
		if tm := rsp.router.GetTunnelManager(); tm != nil {
			return tm.GetBuildSuccessCount(periodMs)
		}
		return 0
	case "tunnel.buildExploratoryReject":
		if tm := rsp.router.GetTunnelManager(); tm != nil {
			return tm.GetBuildRejectCount(periodMs)
		}
		return 0
	case "tunnel.buildExploratoryExpire":
		if tm := rsp.router.GetTunnelManager(); tm != nil {
			return tm.GetBuildExpireCount(periodMs)
		}
		return 0
	case "tunnel.buildClientSuccess":
		if tm := rsp.router.GetTunnelManager(); tm != nil {
			return tm.GetClientBuildSuccessCount(periodMs)
		}
		return 0
	case "tunnel.buildRequestTime":
		if tm := rsp.router.GetTunnelManager(); tm != nil {
			return tm.GetBuildAvgTimeMs(periodMs)
		}
		return 0

	default:
		log.WithField("stat", stat).Debug("i2pcontrol: GetRateForPeriod unknown stat name, returning 0")
		return 0
	}
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
		IsReseeding() bool
		GetBandwidthRates() (inbound, outbound uint64)
		GetBandwidthRates1s() (inbound, outbound uint64)
		GetNetworkStatus() int
		GetActiveSessionCount() int
		Stop()
		Reseed() error
		GetTransportAddr() interface{}
		GetSSU2Addr() interface{}
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

// IsReseeding returns whether the router is currently reseeding (implements RouterAccess)
func (rr RealRouter) IsReseeding() bool {
	return rr.Router.IsReseeding()
}

// GetBandwidthRates returns current bandwidth rates (implements RouterAccess)
func (rr RealRouter) GetBandwidthRates() (inbound, outbound uint64) {
	return rr.Router.GetBandwidthRates()
}

// GetActiveSessionCount returns active transport session count (implements RouterAccess)
func (rr RealRouter) GetActiveSessionCount() int {
	return rr.Router.GetActiveSessionCount()
}

// Stop initiates graceful shutdown (implements RouterAccess)
func (rr RealRouter) Stop() {
	rr.Router.Stop()
}

// Reseed triggers a manual NetDB reseed (implements RouterAccess)
func (rr RealRouter) Reseed() error {
	return rr.Router.Reseed()
}

// GetTransportAddr returns the listening address of the first transport (implements RouterAccess)
func (rr RealRouter) GetTransportAddr() interface{} {
	return rr.Router.GetTransportAddr()
}

// GetSSU2Addr returns the listening UDP address of the SSU2 transport (implements RouterAccess)
func (rr RealRouter) GetSSU2Addr() interface{} {
	return rr.Router.GetSSU2Addr()
}

// GetBandwidthRates1s returns 1-second inbound and outbound bandwidth rates (implements RouterAccess)
func (rr RealRouter) GetBandwidthRates1s() (inbound, outbound uint64) {
	return rr.Router.GetBandwidthRates1s()
}

// GetNetworkStatus returns the I2PControl network status code (implements RouterAccess)
func (rr RealRouter) GetNetworkStatus() int {
	return rr.Router.GetNetworkStatus()
}

// Compile-time interface satisfaction check
var _ RouterAccess = RealRouter{}
