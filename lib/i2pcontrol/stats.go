package i2pcontrol

import (
	"net"
	"sync"
	"time"

	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/go-i2p/go-i2p/lib/netdb"
	"github.com/go-i2p/go-i2p/lib/transport"
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
	//   netdb.routerinfo.accepted                       — cumulative accepted RouterInfo count
	//   netdb.routerinfo.rejected                       — cumulative rejected RouterInfo count
	//   netdb.routerinfo.rejected.datatype              — cumulative invalid data-type rejects
	//   netdb.routerinfo.rejected.parse                 — cumulative parse/decompression rejects
	//   netdb.routerinfo.rejected.validation            — cumulative validation rejects
	//   netdb.routerinfo.rejected.hash                  — cumulative identity-hash rejects
	//   netdb.routerinfo.rejected.signature             — cumulative signature rejects
	//   netdb.routerinfo.rejected.network               — cumulative netId/version policy rejects
	//   netdb.routerinfo.rejected.admission             — cumulative admission-limit rejects
	//   tunnel.buildExploratorySuccess                  — count of successful exploratory builds
	//   tunnel.buildExploratoryReject                   — count of rejected exploratory builds
	//   tunnel.buildExploratoryExpire                   — count of timed-out exploratory builds
	//   tunnel.buildClientSuccess                       — count of successful client builds
	//   tunnel.buildClientReject                        — count of rejected client builds
	//   tunnel.buildClientExpire                        — count of timed-out client builds
	//   tunnel.buildRequestTime                         — average build duration in milliseconds
	GetRateForPeriod(stat string, periodMs int64) float64

	// GetLocalRouterIdentityHash returns the base64-encoded identity hash of this router.
	// Used by I2PControl extensions for self-identification (e.g., i2p.router.hash).
	// Returns an error if the hash cannot be computed.
	GetLocalRouterIdentityHash() (string, error)
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

	// ActivePeers is the currently active transport session count,
	// sourced from Router.GetActiveSessionCount()
	ActivePeers int

	// KnownPeers is the number of RouterInfos in the NetDB
	KnownPeers int

	// ActivePeers is the number of peers with successful connections in the last hour
	ActivePeersCount int

	// FastPeers is the number of peers with low latency (< 500ms average response time)
	FastPeersCount int

	// HighCapacityPeers is the number of reliable, high-performance peers
	HighCapacityPeersCount int

	// RouterInfoAcceptCount is the number of RouterInfos accepted into memory.
	RouterInfoAcceptCount uint64

	// RouterInfoRejectCount is the total number of rejected RouterInfo ingest attempts.
	RouterInfoRejectCount uint64

	// RouterInfoRejectDataTypeCount is the number of RouterInfo rejects due to invalid store type.
	RouterInfoRejectDataTypeCount uint64

	// RouterInfoRejectParseCount is the number of RouterInfo rejects due to parse/decompression failures.
	RouterInfoRejectParseCount uint64

	// RouterInfoRejectValidationCount is the number of RouterInfo rejects due to hash/signature/network validation failures.
	RouterInfoRejectValidationCount uint64

	// RouterInfoRejectHashCount is the number of RouterInfo rejects due to identity-hash mismatches.
	RouterInfoRejectHashCount uint64

	// RouterInfoRejectSignatureCount is the number of RouterInfo rejects due to invalid signatures.
	RouterInfoRejectSignatureCount uint64

	// RouterInfoRejectNetworkCount is the number of RouterInfo rejects due to netId/router.version network policy checks.
	RouterInfoRejectNetworkCount uint64

	// RouterInfoRejectAdmissionCount is the number of RouterInfo rejects due to admission limits.
	RouterInfoRejectAdmissionCount uint64

	// RouterInfoPersistDeferredCount is the number of accepted RouterInfos whose
	// initial filesystem persistence was deferred.
	RouterInfoPersistDeferredCount uint64

	// RouterInfoPersistPendingCount is the number of RouterInfos awaiting
	// filesystem persistence retry.
	RouterInfoPersistPendingCount uint64

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

// determineRouterStatus returns the router process-health status string.
// It reports only whether the router process is running (OK) or not (ERROR).
// It is intentionally independent of network reachability — for detailed
// reachability state (TESTING / FIREWALLED / HIDDEN / OK) operators must
// consult the i2p.router.net.status I2PControl field, which is backed by
// Router.GetNetworkStatus().
func (rsp *routerStatsProvider) determineRouterStatus() string {
	if rsp.router.IsRunning() {
		return "OK"
	}
	return "ERROR"
}

// collectNetDBStats populates NetDB statistics in the provided RouterInfoStats.
// Collects peer counts including known, active, fast, and high-capacity peers.
func (rsp *routerStatsProvider) collectNetDBStats(stats *RouterInfoStats) {
	netdbReader := rsp.router.GetNetDB()
	if netdbReader == nil {
		return
	}

	// Type-assert to check for nil pointer wrapped in interface
	concreteNetDB, ok := netdbReader.(*netdb.StdNetDB)
	if !ok || concreteNetDB == nil {
		return
	}

	stats.KnownPeers = netdbReader.GetRouterInfoCount()
	stats.ActivePeersCount = netdbReader.GetActivePeerCount()
	stats.FastPeersCount = netdbReader.GetFastPeerCount()
	stats.HighCapacityPeersCount = netdbReader.GetHighCapacityPeerCount()

	storeStats := concreteNetDB.GetRouterInfoStoreStats()
	stats.RouterInfoAcceptCount = storeStats.AcceptedCount
	stats.RouterInfoRejectDataTypeCount = storeStats.RejectedDataTypeCount
	stats.RouterInfoRejectParseCount = storeStats.RejectedParseCount
	stats.RouterInfoRejectValidationCount = storeStats.RejectedValidationCount
	stats.RouterInfoRejectHashCount = storeStats.RejectedHashCount
	stats.RouterInfoRejectSignatureCount = storeStats.RejectedSignatureCount
	stats.RouterInfoRejectNetworkCount = storeStats.RejectedNetworkCount
	stats.RouterInfoRejectAdmissionCount = storeStats.RejectedAdmissionCount
	stats.RouterInfoRejectCount =
		stats.RouterInfoRejectDataTypeCount +
			stats.RouterInfoRejectParseCount +
			stats.RouterInfoRejectValidationCount +
			stats.RouterInfoRejectAdmissionCount
	stats.RouterInfoPersistDeferredCount = storeStats.PersistDeferredCount
	stats.RouterInfoPersistPendingCount = storeStats.PersistPendingCount
}

// collectParticipatingTunnelStats populates participating tunnel count in the provided RouterInfoStats.
// Collects the count of tunnels this router is participating in from the participant manager.
func (rsp *routerStatsProvider) collectParticipatingTunnelStats(stats *RouterInfoStats) {
	pmReader := rsp.router.GetParticipantManager()
	if pmReader == nil {
		return
	}

	// Type-assert to check for nil pointer wrapped in interface
	concretePM, ok := pmReader.(*tunnel.ParticipantManager)
	if !ok || concretePM == nil {
		return
	}

	stats.ParticipatingTunnels = pmReader.ParticipantCount()
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
	netdbReader := rsp.router.GetNetDB()
	if netdbReader == nil {
		return stats
	}

	// Type-assert to check for nil pointer wrapped in interface
	concreteNetDB, ok := netdbReader.(*netdb.StdNetDB)
	if !ok || concreteNetDB == nil {
		return stats
	}

	stats.RouterInfos = netdbReader.GetRouterInfoCount()
	stats.LeaseSets = netdbReader.GetLeaseSetCount()
	stats.Floodfill = netdbReader.IsFloodfill()
	log.WithFields(map[string]interface{}{
		"router_infos": stats.RouterInfos,
		"lease_sets":   stats.LeaseSets,
		"floodfill":    stats.Floodfill,
	}).Debug("collected NetDB stats")

	return stats
}

// GetNetworkConfig returns network configuration settings.
// Extracts NTCP2/SSU2 ports, hostnames, and bandwidth limits from the router.
// Returns zero values if transport is not available.
func (rsp *routerStatsProvider) GetNetworkConfig() NetworkConfig {
	netConfig := NetworkConfig{}

	rsp.populateBandwidthLimits(&netConfig)
	rsp.populateNTCP2Config(&netConfig)
	rsp.populateSSU2Config(&netConfig)

	return netConfig
}

// populateBandwidthLimits sets bandwidth limit fields from router config (in KB/s).
func (rsp *routerStatsProvider) populateBandwidthLimits(netConfig *NetworkConfig) {
	cfg := rsp.router.GetConfig()
	if cfg == nil {
		return
	}

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

// populateNTCP2Config sets NTCP2 address, hostname, and port fields.
func (rsp *routerStatsProvider) populateNTCP2Config(netConfig *NetworkConfig) {
	addr := rsp.router.GetTransportAddr()
	if addr == nil {
		return
	}

	addrStr := rsp.extractAddressString(addr)
	if addrStr == "" {
		return
	}

	netConfig.NTCP2Address = addrStr
	hostname, port := rsp.parseHostPort(addrStr)
	netConfig.NTCP2Hostname = hostname
	netConfig.NTCP2Port = port
}

// populateSSU2Config sets SSU2 address, hostname, and port fields.
func (rsp *routerStatsProvider) populateSSU2Config(netConfig *NetworkConfig) {
	ssu2Addr := rsp.router.GetSSU2Addr()
	if ssu2Addr == nil {
		return
	}

	ssu2AddrStr := rsp.extractAddressString(ssu2Addr)
	if ssu2AddrStr == "" {
		return
	}

	netConfig.SSU2Address = ssu2AddrStr
	ssu2Host, ssu2Port := rsp.parseHostPort(ssu2AddrStr)
	netConfig.SSU2Hostname = ssu2Host
	netConfig.SSU2Port = ssu2Port
}

// extractAddressString extracts the string representation from a network address.
func (rsp *routerStatsProvider) extractAddressString(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	return addr.String()
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

	pmReader := rsp.router.GetParticipantManager()
	if pmReader != nil {
		// Type-assert to check for nil pointer wrapped in interface
		concretePM, ok := pmReader.(*tunnel.ParticipantManager)
		if ok && concretePM != nil {
			rsp.partWindow.Record(float64(pmReader.ParticipantCount()))
		}
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

	switch {
	case stat == "bw.sendBps" || stat == "bw.receiveBps" || stat == "bw.combined":
		return rsp.getBandwidthRate(stat, periodMs)
	case stat == "tunnel.participatingTunnels":
		return rsp.getParticipatingTunnelsRate(periodMs)
	case rsp.isNetDBRouterInfoStat(stat):
		return rsp.getNetDBRouterInfoRateStat(stat)
	case rsp.isTunnelBuildStat(stat):
		return rsp.getTunnelBuildRate(stat, periodMs)
	case stat == "tcp.activePeers" || stat == "udp.activePeers":
		return rsp.getTransportPeersCount(stat)
	case rsp.isTransportSessionFailureStat(stat):
		return rsp.getTransportSessionFailureCount(stat)
	default:
		log.WithField("stat", stat).Debug("i2pcontrol: GetRateForPeriod unknown stat name, returning 0")
		return 0
	}
}

// getBandwidthRate returns windowed average bandwidth (bytes/sec) or 0 until 2+ samples.
func (rsp *routerStatsProvider) getBandwidthRate(stat string, periodMs int64) float64 {
	switch stat {
	case "bw.sendBps":
		if rsp.bwOutWindow.Len(periodMs) >= 2 {
			return rsp.bwOutWindow.Average(periodMs)
		}
	case "bw.receiveBps":
		if rsp.bwInWindow.Len(periodMs) >= 2 {
			return rsp.bwInWindow.Average(periodMs)
		}
	case "bw.combined":
		inLen := rsp.bwInWindow.Len(periodMs)
		outLen := rsp.bwOutWindow.Len(periodMs)
		if inLen >= 2 || outLen >= 2 {
			return rsp.bwInWindow.Average(periodMs) + rsp.bwOutWindow.Average(periodMs)
		}
	}
	return 0
}

// getParticipatingTunnelsRate returns windowed average or falls back to instantaneous count.
func (rsp *routerStatsProvider) getParticipatingTunnelsRate(periodMs int64) float64 {
	if avg := rsp.partWindow.Average(periodMs); avg > 0 {
		return avg
	}
	ri := rsp.GetRouterInfo()
	return float64(ri.ParticipatingTunnels)
}

// isTunnelBuildStat checks if the stat is a tunnel build metric.
func (rsp *routerStatsProvider) isTunnelBuildStat(stat string) bool {
	return stat == "tunnel.buildExploratorySuccess" ||
		stat == "tunnel.buildExploratoryReject" ||
		stat == "tunnel.buildExploratoryExpire" ||
		stat == "tunnel.buildClientSuccess" ||
		stat == "tunnel.buildClientReject" ||
		stat == "tunnel.buildClientExpire" ||
		stat == "tunnel.buildRequestTime"
}

// getTunnelBuildRate returns tunnel build event counts or average time within the window.
func (rsp *routerStatsProvider) getTunnelBuildRate(stat string, periodMs int64) float64 {
	tm := rsp.router.GetTunnelManager()
	if tm == nil {
		return 0
	}

	switch stat {
	case "tunnel.buildExploratorySuccess":
		return tm.GetBuildSuccessCount(periodMs)
	case "tunnel.buildExploratoryReject":
		return tm.GetBuildRejectCount(periodMs)
	case "tunnel.buildExploratoryExpire":
		return tm.GetBuildExpireCount(periodMs)
	case "tunnel.buildClientSuccess":
		return tm.GetClientBuildSuccessCount(periodMs)
	case "tunnel.buildClientReject":
		return tm.GetClientBuildRejectCount(periodMs)
	case "tunnel.buildClientExpire":
		return tm.GetClientBuildExpireCount(periodMs)
	case "tunnel.buildRequestTime":
		return tm.GetBuildAvgTimeMs(periodMs)
	default:
		return 0
	}
}

// getTransportPeersCount returns instantaneous transport session counts.
func (rsp *routerStatsProvider) getTransportPeersCount(stat string) float64 {
	switch stat {
	case "tcp.activePeers":
		return float64(rsp.router.GetNTCP2SessionCount())
	case "udp.activePeers":
		return float64(rsp.router.GetSSU2SessionCount())
	default:
		return 0
	}
}

func (rsp *routerStatsProvider) isTransportSessionFailureStat(stat string) bool {
	return stat == "transport.session.attempts" ||
		stat == "transport.session.fail.noCompatible" ||
		stat == "transport.session.fail.allFailed" ||
		stat == "transport.session.skip.cooldown" ||
		stat == "transport.session.fail.poolFull"
}

type transportSessionFailureStatsReader interface {
	GetTransportSessionFailureStats() transport.MuxSessionFailureStats
}

func (rsp *routerStatsProvider) getTransportSessionFailureCount(stat string) float64 {
	reader, ok := rsp.router.(transportSessionFailureStatsReader)
	if !ok {
		return 0
	}

	stats := reader.GetTransportSessionFailureStats()
	switch stat {
	case "transport.session.attempts":
		return float64(stats.SessionAttempts)
	case "transport.session.fail.noCompatible":
		return float64(stats.NoCompatibleTransport)
	case "transport.session.fail.allFailed":
		return float64(stats.AllTransportsFailed)
	case "transport.session.skip.cooldown":
		return float64(stats.PeerCooldownSkipped)
	case "transport.session.fail.poolFull":
		return float64(stats.ConnectionPoolFull)
	default:
		return 0
	}
}

func (rsp *routerStatsProvider) isNetDBRouterInfoStat(stat string) bool {
	return stat == "netdb.routerinfo.accepted" ||
		stat == "netdb.routerinfo.rejected" ||
		stat == "netdb.routerinfo.rejected.datatype" ||
		stat == "netdb.routerinfo.rejected.parse" ||
		stat == "netdb.routerinfo.rejected.validation" ||
		stat == "netdb.routerinfo.rejected.hash" ||
		stat == "netdb.routerinfo.rejected.signature" ||
		stat == "netdb.routerinfo.rejected.network" ||
		stat == "netdb.routerinfo.rejected.admission"
}

func (rsp *routerStatsProvider) getNetDBRouterInfoRateStat(stat string) float64 {
	netdbReader := rsp.router.GetNetDB()
	if netdbReader == nil {
		return 0
	}

	concreteNetDB, ok := netdbReader.(*netdb.StdNetDB)
	if !ok || concreteNetDB == nil {
		return 0
	}

	storeStats := concreteNetDB.GetRouterInfoStoreStats()

	switch stat {
	case "netdb.routerinfo.accepted":
		return float64(storeStats.AcceptedCount)
	case "netdb.routerinfo.rejected":
		return float64(
			storeStats.RejectedDataTypeCount +
				storeStats.RejectedParseCount +
				storeStats.RejectedValidationCount +
				storeStats.RejectedAdmissionCount,
		)
	case "netdb.routerinfo.rejected.datatype":
		return float64(storeStats.RejectedDataTypeCount)
	case "netdb.routerinfo.rejected.parse":
		return float64(storeStats.RejectedParseCount)
	case "netdb.routerinfo.rejected.validation":
		return float64(storeStats.RejectedValidationCount)
	case "netdb.routerinfo.rejected.hash":
		return float64(storeStats.RejectedHashCount)
	case "netdb.routerinfo.rejected.signature":
		return float64(storeStats.RejectedSignatureCount)
	case "netdb.routerinfo.rejected.network":
		return float64(storeStats.RejectedNetworkCount)
	case "netdb.routerinfo.rejected.admission":
		return float64(storeStats.RejectedAdmissionCount)
	default:
		return 0
	}
}

// GetLocalRouterIdentityHash returns the base64-encoded identity hash of this router.
// Used by I2PControl extensions for self-identification (e.g., i2p.router.hash).
func (rsp *routerStatsProvider) GetLocalRouterIdentityHash() (string, error) {
	return rsp.router.GetLocalRouterIdentityHash()
}

// RouterBackend is the concrete router contract that RealRouter wraps.
// It uses the real implementation types (*netdb.StdNetDB, *tunnel.ParticipantManager)
// that *router.Router provides, which RealRouter adapts to the RouterAccess interface.
// This named interface replaces the anonymous inline contract previously embedded
// in RealRouter so there is a single named definition to evolve and document.
type RouterBackend interface {
	GetNetDB() *netdb.StdNetDB
	GetTunnelManager() i2np.TunnelOrchestrator
	GetParticipantManager() *tunnel.ParticipantManager
	GetConfig() *config.RouterConfig
	IsRunning() bool
	IsReseeding() bool
	GetBandwidthRates() (inbound, outbound uint64)
	GetBandwidthRates1s() (inbound, outbound uint64)
	GetNetworkStatus() int
	GetActiveSessionCount() int
	GetNTCP2SessionCount() int
	GetSSU2SessionCount() int
	Stop()
	Reseed() error
	GetTransportAddr() net.Addr
	GetSSU2Addr() net.Addr
	GetLocalRouterIdentityHash() (string, error)
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
	// Router is the actual router instance.
	// Must be a pointer to avoid copying the router.
	Router RouterBackend
}

// GetNetDB returns the NetDB stats reader (implements RouterInfoReader)
func (rr RealRouter) GetNetDB() NetDBStatsReader {
	return rr.Router.GetNetDB()
}

// GetTunnelManager returns the tunnel stats reader (implements RouterInfoReader)
func (rr RealRouter) GetTunnelManager() i2np.TunnelStatsReader {
	return rr.Router.GetTunnelManager()
}

// GetParticipantManager returns the participant stats reader (implements RouterInfoReader)
func (rr RealRouter) GetParticipantManager() ParticipantStatsReader {
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

// GetNTCP2SessionCount returns active NTCP2 (TCP) session count (implements RouterAccess)
func (rr RealRouter) GetNTCP2SessionCount() int {
	return rr.Router.GetNTCP2SessionCount()
}

// GetSSU2SessionCount returns active SSU2 (UDP) session count (implements RouterAccess)
func (rr RealRouter) GetSSU2SessionCount() int {
	return rr.Router.GetSSU2SessionCount()
}

// GetTransportSessionFailureStats returns transport mux session-attempt outcome counters.
func (rr RealRouter) GetTransportSessionFailureStats() transport.MuxSessionFailureStats {
	typed, ok := rr.Router.(interface {
		GetTransportSessionFailureStats() transport.MuxSessionFailureStats
	})
	if !ok {
		return transport.MuxSessionFailureStats{}
	}
	return typed.GetTransportSessionFailureStats()
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
func (rr RealRouter) GetTransportAddr() net.Addr {
	return rr.Router.GetTransportAddr()
}

// GetSSU2Addr returns the listening UDP address of the SSU2 transport (implements RouterAccess)
func (rr RealRouter) GetSSU2Addr() net.Addr {
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

// GetLocalRouterIdentityHash returns the local router identity hash (implements RouterAccess)
func (rr RealRouter) GetLocalRouterIdentityHash() (string, error) {
	return rr.Router.GetLocalRouterIdentityHash()
}

// Compile-time interface satisfaction check
var _ RouterAccess = RealRouter{}
