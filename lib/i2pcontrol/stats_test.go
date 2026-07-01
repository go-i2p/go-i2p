package i2pcontrol

import (
	"net"
	"os"
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/crypto/tunnel"
	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/go-i2p/go-i2p/lib/netdb"
	tunnelpkg "github.com/go-i2p/go-i2p/lib/tunnel"
)

// mockTunnelEncryptor is a simple mock for testing participant tunnels
type mockTunnelEncryptor struct{}

func (m *mockTunnelEncryptor) Encrypt(data []byte) ([]byte, error) {
	return data, nil
}

func (m *mockTunnelEncryptor) Decrypt(data []byte) ([]byte, error) {
	return data, nil
}

func (m *mockTunnelEncryptor) Type() tunnel.TunnelEncryptionType {
	return tunnel.TunnelEncryptionECIES
}

// mockRouterAccess provides a simple mock for testing
type mockRouterAccess struct {
	netdb              *netdb.StdNetDB
	tunnelManager      i2np.TunnelStatsReader
	participantManager *tunnelpkg.ParticipantManager
	cfg                *config.RouterConfig
	running            bool
}

func (m *mockRouterAccess) GetNetDB() NetDBStatsReader {
	return m.netdb
}

func (m *mockRouterAccess) GetTunnelManager() i2np.TunnelStatsReader {
	return m.tunnelManager
}

func (m *mockRouterAccess) GetParticipantManager() ParticipantStatsReader {
	return m.participantManager
}

func (m *mockRouterAccess) GetConfig() *config.RouterConfig {
	return m.cfg
}

func (m *mockRouterAccess) IsRunning() bool {
	return m.running
}

func (m *mockRouterAccess) IsReseeding() bool {
	return false // Mock always returns false for testing
}

func (m *mockRouterAccess) GetBandwidthRates() (inbound, outbound uint64) {
	// Return test values (inbound, outbound in bytes/sec)
	// Mock returns 0 for inbound and 1024 for outbound as test data
	return 0, 1024
}

func (m *mockRouterAccess) GetBandwidthRates1s() (inbound, outbound uint64) {
	return 0, 512
}

func (m *mockRouterAccess) GetNetworkStatus() int {
	if !m.running {
		return 8
	}
	return 0
}

func (m *mockRouterAccess) GetActiveSessionCount() int {
	return 0
}

func (m *mockRouterAccess) GetNTCP2SessionCount() int {
	return 0
}

func (m *mockRouterAccess) GetSSU2SessionCount() int {
	return 0
}

func (m *mockRouterAccess) GetTransportAddr() net.Addr {
	return nil
}

func (m *mockRouterAccess) GetSSU2Addr() net.Addr {
	return nil
}

func (m *mockRouterAccess) Stop() {
	// Mock implementation - sets running to false
	m.running = false
}

func (m *mockRouterAccess) Reseed() error {
	return nil
}

func (m *mockRouterAccess) GetLocalRouterIdentityHash() (string, error) {
	// Return a base64-encoded test hash (32 bytes encoded in base64)
	return "dGVzdC1yb3V0ZXItaWRlbnRpdHktaGFzaA==", nil
}

// TestNewRouterStatsProvider tests stats provider creation
func TestNewRouterStatsProvider(t *testing.T) {
	router := &mockRouterAccess{running: true}
	version := "0.1.0-test"

	provider := NewRouterStatsProvider(router, version)

	if provider == nil {
		t.Fatal("NewRouterStatsProvider returned nil")
	}

	// Verify it's the right type
	rsp, ok := provider.(*routerStatsProvider)
	if !ok {
		t.Fatalf("NewRouterStatsProvider returned wrong type: %T", provider)
	}

	// Verify fields are set
	if rsp.version != version {
		t.Errorf("version = %q, want %q", rsp.version, version)
	}
	if rsp.startTime.IsZero() {
		t.Error("startTime not initialized")
	}

	// Verify startTime is recent (within 1 second)
	now := time.Now()
	if now.Sub(rsp.startTime) > time.Second {
		t.Errorf("startTime %v is not recent (now: %v)", rsp.startTime, now)
	}
}

// TestGetBandwidthStats tests bandwidth statistics retrieval
func TestGetBandwidthStats(t *testing.T) {
	router := &mockRouterAccess{running: true}
	provider := NewRouterStatsProvider(router, "0.1.0")

	stats := provider.GetBandwidthStats()

	// Should return bandwidth from mock (1024 bytes/sec 1s rate, 2048 bytes/sec 15s rate)
	if stats.InboundRate != 0.0 {
		t.Errorf("InboundRate = %f, want 0.0", stats.InboundRate)
	}
	if stats.OutboundRate != 1024.0 {
		t.Errorf("OutboundRate = %f, want 1024.0", stats.OutboundRate)
	}
}

// TestGetRouterInfo_NilNetDB tests router info with nil NetDB
func TestGetRouterInfo_NilNetDB(t *testing.T) {
	router := &mockRouterAccess{
		netdb:   nil, // Nil NetDB
		running: true,
	}

	provider := NewRouterStatsProvider(router, "0.1.0")

	// Wait a bit to ensure measurable uptime
	time.Sleep(2 * time.Millisecond)

	stats := provider.GetRouterInfo()

	// Should not panic and should return zero for NetDB stats
	if stats.KnownPeers != 0 {
		t.Errorf("KnownPeers = %d, want 0 (nil NetDB)", stats.KnownPeers)
	}

	// Other fields should still work
	if stats.Uptime < 0 {
		t.Errorf("Uptime = %d, want >= 0", stats.Uptime)
	}
	if stats.Version != "0.1.0" {
		t.Errorf("Version = %q, want %q", stats.Version, "0.1.0")
	}
}

// TestGetRouterInfo_NilTunnelManager tests router info with nil tunnel manager
func TestGetRouterInfo_NilTunnelManager(t *testing.T) {
	router := &mockRouterAccess{
		netdb:         nil,
		tunnelManager: nil, // Nil tunnel manager
		running:       true,
	}

	provider := NewRouterStatsProvider(router, "0.1.0")
	stats := provider.GetRouterInfo()

	// Should not panic and should return zero for tunnel stats
	if stats.ParticipatingTunnels != 0 {
		t.Errorf("ParticipatingTunnels = %d, want 0 (nil TunnelManager)", stats.ParticipatingTunnels)
	}
	if stats.InboundTunnels != 0 {
		t.Errorf("InboundTunnels = %d, want 0 (nil TunnelManager)", stats.InboundTunnels)
	}
	if stats.OutboundTunnels != 0 {
		t.Errorf("OutboundTunnels = %d, want 0 (nil TunnelManager)", stats.OutboundTunnels)
	}
}

// TestGetRouterInfo_WithParticipatingTunnels tests that participating tunnel count is collected
func TestGetRouterInfo_WithParticipatingTunnels(t *testing.T) {
	// Create a participant manager with some tunnels
	pm := tunnelpkg.NewManager()
	defer pm.Stop()

	// Add some mock participants (we need a mock encryptor)
	for i := tunnelpkg.TunnelID(1); i <= 5; i++ {
		p, err := tunnelpkg.NewParticipant(i, &mockTunnelEncryptor{})
		if err != nil {
			t.Fatalf("Failed to create participant: %v", err)
		}
		if err := pm.AddParticipant(p); err != nil {
			t.Fatalf("Failed to add participant: %v", err)
		}
	}

	// Verify participant count is 5
	if pm.ParticipantCount() != 5 {
		t.Fatalf("Expected 5 participants, got %d", pm.ParticipantCount())
	}

	router := &mockRouterAccess{
		participantManager: pm,
		running:            true,
	}

	provider := NewRouterStatsProvider(router, "0.1.0")
	stats := provider.GetRouterInfo()

	// Should return the actual participating tunnel count
	if stats.ParticipatingTunnels != 5 {
		t.Errorf("ParticipatingTunnels = %d, want 5", stats.ParticipatingTunnels)
	}
}

// TestGetTunnelStats_NilTunnelManager tests with nil tunnel manager
func TestGetTunnelStats_NilTunnelManager(t *testing.T) {
	router := &mockRouterAccess{
		tunnelManager: nil,
		running:       true,
	}

	provider := NewRouterStatsProvider(router, "0.1.0")
	stats := provider.GetTunnelStats()

	// Should return zero-value struct (no panic)
	if stats.Participating != 0 {
		t.Errorf("Participating = %d, want 0", stats.Participating)
	}
	if stats.InboundActive != 0 {
		t.Errorf("InboundActive = %d, want 0", stats.InboundActive)
	}
	if stats.OutboundActive != 0 {
		t.Errorf("OutboundActive = %d, want 0", stats.OutboundActive)
	}
	if stats.InboundBuilding != 0 {
		t.Errorf("InboundBuilding = %d, want 0", stats.InboundBuilding)
	}
	if stats.OutboundBuilding != 0 {
		t.Errorf("OutboundBuilding = %d, want 0", stats.OutboundBuilding)
	}
}

// TestGetNetDBStats_NilNetDB tests with nil NetDB
func TestGetNetDBStats_NilNetDB(t *testing.T) {
	router := &mockRouterAccess{
		netdb:   nil,
		running: true,
	}

	provider := NewRouterStatsProvider(router, "0.1.0")
	stats := provider.GetNetDBStats()

	// Should not panic and should return zero values
	if stats.RouterInfos != 0 {
		t.Errorf("RouterInfos = %d, want 0", stats.RouterInfos)
	}
	if stats.LeaseSets != 0 {
		t.Errorf("LeaseSets = %d, want 0", stats.LeaseSets)
	}
	if stats.Floodfill != false {
		t.Errorf("Floodfill = %v, want false", stats.Floodfill)
	}
}

// TestIsRunning tests router running status
func TestIsRunning(t *testing.T) {
	tests := []struct {
		name    string
		running bool
	}{
		{"running", true},
		{"stopped", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := &mockRouterAccess{running: tt.running}
			provider := NewRouterStatsProvider(router, "0.1.0")

			if got := provider.IsRunning(); got != tt.running {
				t.Errorf("IsRunning() = %v, want %v", got, tt.running)
			}
		})
	}
}

// TestCalculateUptime tests uptime calculation accuracy
func TestCalculateUptime(t *testing.T) {
	router := &mockRouterAccess{running: true}
	provider := NewRouterStatsProvider(router, "0.1.0")

	// Get provider as concrete type to access calculateUptime
	rsp := provider.(*routerStatsProvider)

	// Initial uptime should be very small (< 100ms)
	uptime1 := rsp.calculateUptime()
	if uptime1 < 0 || uptime1 > 100 {
		t.Errorf("Initial uptime = %d ms, want 0-100 ms", uptime1)
	}

	// Wait a known duration
	time.Sleep(50 * time.Millisecond)

	// Uptime should have increased by approximately that duration
	uptime2 := rsp.calculateUptime()
	delta := uptime2 - uptime1

	// Allow some margin for scheduling jitter (±20ms)
	if delta < 30 || delta > 70 {
		t.Errorf("Uptime delta = %d ms, want 30-70 ms (50ms ±20ms)", delta)
	}
}

// TestConcurrentAccess tests concurrent access to stats provider
func TestConcurrentAccess(t *testing.T) {
	router := &mockRouterAccess{
		netdb:   nil,
		running: true,
	}

	provider := NewRouterStatsProvider(router, "0.1.0")

	// Spawn multiple goroutines accessing stats concurrently
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			defer func() { done <- true }()

			for j := 0; j < 100; j++ {
				_ = provider.GetBandwidthStats()
				_ = provider.GetRouterInfo()
				_ = provider.GetTunnelStats()
				_ = provider.GetNetDBStats()
				_ = provider.IsRunning()
			}
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}

	// If we get here without panic, concurrent access is safe
}

// BenchmarkGetRouterInfo benchmarks router info collection
func BenchmarkGetRouterInfo(b *testing.B) {
	router := &mockRouterAccess{
		netdb:   nil,
		running: true,
	}

	provider := NewRouterStatsProvider(router, "0.1.0")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = provider.GetRouterInfo()
	}
}

// BenchmarkGetTunnelStats benchmarks tunnel stats collection
func BenchmarkGetTunnelStats(b *testing.B) {
	router := &mockRouterAccess{
		tunnelManager: nil,
		running:       true,
	}

	provider := NewRouterStatsProvider(router, "0.1.0")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = provider.GetTunnelStats()
	}
}

// BenchmarkGetNetDBStats benchmarks NetDB stats collection
func BenchmarkGetNetDBStats(b *testing.B) {
	router := &mockRouterAccess{
		netdb:   nil,
		running: true,
	}

	provider := NewRouterStatsProvider(router, "0.1.0")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = provider.GetNetDBStats()
	}
}

// TestGetNetworkConfig_BandwidthLimitsFromConfig verifies that bandwidth limits
// are reported from RouterConfig when configured.
func TestGetNetworkConfig_BandwidthLimitsFromConfig(t *testing.T) {
	tests := []struct {
		name             string
		maxBandwidth     uint64
		wantBandwidthIn  int
		wantBandwidthOut int
	}{
		{
			name:             "default 1 MB/s",
			maxBandwidth:     1024 * 1024,
			wantBandwidthIn:  1024, // 1024 KB/s
			wantBandwidthOut: 1024,
		},
		{
			name:             "unlimited (zero)",
			maxBandwidth:     0,
			wantBandwidthIn:  0,
			wantBandwidthOut: 0,
		},
		{
			name:             "custom 5 MB/s",
			maxBandwidth:     5 * 1024 * 1024,
			wantBandwidthIn:  5120, // 5120 KB/s
			wantBandwidthOut: 5120,
		},
		{
			name:             "small 100 KB/s",
			maxBandwidth:     100 * 1024,
			wantBandwidthIn:  100,
			wantBandwidthOut: 100,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := &mockRouterAccess{
				cfg: &config.RouterConfig{
					MaxBandwidth: tt.maxBandwidth,
				},
				running: true,
			}

			provider := NewRouterStatsProvider(router, "0.1.0")
			netCfg := provider.GetNetworkConfig()

			if netCfg.BandwidthLimitIn != tt.wantBandwidthIn {
				t.Errorf("BandwidthLimitIn = %d, want %d", netCfg.BandwidthLimitIn, tt.wantBandwidthIn)
			}
			if netCfg.BandwidthLimitOut != tt.wantBandwidthOut {
				t.Errorf("BandwidthLimitOut = %d, want %d", netCfg.BandwidthLimitOut, tt.wantBandwidthOut)
			}
		})
	}
}

// TestGetNetworkConfig_NilConfigReportsUnlimited verifies that a nil config
// reports unlimited (0) bandwidth.
func TestGetNetworkConfig_NilConfigReportsUnlimited(t *testing.T) {
	router := &mockRouterAccess{
		cfg:     nil,
		running: true,
	}

	provider := NewRouterStatsProvider(router, "0.1.0")
	netCfg := provider.GetNetworkConfig()

	if netCfg.BandwidthLimitIn != 0 {
		t.Errorf("BandwidthLimitIn = %d, want 0 (unlimited)", netCfg.BandwidthLimitIn)
	}
	if netCfg.BandwidthLimitOut != 0 {
		t.Errorf("BandwidthLimitOut = %d, want 0 (unlimited)", netCfg.BandwidthLimitOut)
	}
}

// mockRouterAccessWithSessions wraps mockRouterAccess with a configurable session count.
type mockRouterAccessWithSessions struct {
	mockRouterAccess
	sessionCount int
}

func (m *mockRouterAccessWithSessions) GetActiveSessionCount() int {
	return m.sessionCount
}

// TestStatsActivePeers verifies ActivePeers reflects the router's active session count.
func TestStatsActivePeers(t *testing.T) {
	tests := []struct {
		name     string
		sessions int
	}{
		{"no sessions", 0},
		{"one session", 1},
		{"many sessions", 42},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := &mockRouterAccessWithSessions{
				mockRouterAccess: mockRouterAccess{running: true},
				sessionCount:     tt.sessions,
			}
			provider := NewRouterStatsProvider(router, "0.1.0-test")
			stats := provider.GetRouterInfo()

			if stats.ActivePeers != tt.sessions {
				t.Errorf("ActivePeers = %d, want %d", stats.ActivePeers, tt.sessions)
			}
		})
	}
}

// mockRouterAccessWithTransportSessions wraps mockRouterAccess with configurable
// per-transport session counts for testing tcp.activePeers and udp.activePeers stats.
type mockRouterAccessWithTransportSessions struct {
	mockRouterAccess
	ntcp2Count int
	ssu2Count  int
}

func (m *mockRouterAccessWithTransportSessions) GetNTCP2SessionCount() int {
	return m.ntcp2Count
}

func (m *mockRouterAccessWithTransportSessions) GetSSU2SessionCount() int {
	return m.ssu2Count
}

// TestStatsTransportActivePeers verifies that tcp.activePeers and udp.activePeers
// stats correctly return the per-transport session counts.
func TestStatsTransportActivePeers(t *testing.T) {
	tests := []struct {
		name       string
		ntcp2Count int
		ssu2Count  int
	}{
		{"no sessions", 0, 0},
		{"only ntcp2", 5, 0},
		{"only ssu2", 0, 3},
		{"both transports", 10, 7},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := &mockRouterAccessWithTransportSessions{
				mockRouterAccess: mockRouterAccess{running: true},
				ntcp2Count:       tt.ntcp2Count,
				ssu2Count:        tt.ssu2Count,
			}
			provider := NewRouterStatsProvider(router, "0.1.0-test")

			// Test tcp.activePeers (NTCP2)
			tcpPeers := provider.GetRateForPeriod("tcp.activePeers", 60000)
			if tcpPeers != float64(tt.ntcp2Count) {
				t.Errorf("tcp.activePeers = %v, want %d", tcpPeers, tt.ntcp2Count)
			}

			// Test udp.activePeers (SSU2)
			udpPeers := provider.GetRateForPeriod("udp.activePeers", 60000)
			if udpPeers != float64(tt.ssu2Count) {
				t.Errorf("udp.activePeers = %v, want %d", udpPeers, tt.ssu2Count)
			}
		})
	}
}

// mockRouterWithNetworkStatus is a minimal RouterAccess that lets tests control
// both the process-running flag and the detailed network-status code.
type mockRouterWithNetworkStatus struct {
	mockRouterAccess
	netStatus int
}

func (m *mockRouterWithNetworkStatus) GetNetworkStatus() int { return m.netStatus }

// TestStatusFieldCoherence verifies the Audit #3 invariant: the "Status" field
// in RouterInfoStats reflects only process-health (OK / ERROR), while
// GetNetworkStatus() can independently report detailed reachability codes such
// as FIREWALLED (2), HIDDEN (3), or TESTING (1). The two fields must never be
// conflated.
func TestStatusFieldCoherence(t *testing.T) {
	cases := []struct {
		name          string
		running       bool
		netStatus     int
		wantStatus    string // process-health only: "OK" or "ERROR"
		wantNetStatus int
	}{
		{"running-ok", true, 0, "OK", 0},
		{"running-firewalled", true, 2, "OK", 2}, // FIREWALLED → Status still OK
		{"running-hidden", true, 3, "OK", 3},     // HIDDEN     → Status still OK
		{"running-testing", true, 1, "OK", 1},    // TESTING    → Status still OK
		{"not-running", false, 8, "ERROR", 8},    // process down → ERROR
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			router := &mockRouterWithNetworkStatus{
				mockRouterAccess: mockRouterAccess{running: c.running},
				netStatus:        c.netStatus,
			}
			provider := NewRouterStatsProvider(router, "0.1.0-test")

			info := provider.GetRouterInfo()
			if info.Status != c.wantStatus {
				t.Errorf("Status = %q, want %q", info.Status, c.wantStatus)
			}
			if got := provider.GetNetworkStatus(); got != c.wantNetStatus {
				t.Errorf("GetNetworkStatus() = %d, want %d", got, c.wantNetStatus)
			}
		})
	}
}

func TestGetRateForPeriod_ClientBuildRejectExpireStats(t *testing.T) {
	router := &mockRouterAccess{
		tunnelManager: i2np.NewTunnelManager(nil),
		running:       true,
	}
	provider := NewRouterStatsProvider(router, "0.1.0-test")

	reject := provider.GetRateForPeriod("tunnel.buildClientReject", 60000)
	expire := provider.GetRateForPeriod("tunnel.buildClientExpire", 60000)

	if reject != 0 {
		t.Errorf("tunnel.buildClientReject = %v, want 0", reject)
	}
	if expire != 0 {
		t.Errorf("tunnel.buildClientExpire = %v, want 0", expire)
	}
}

func TestGetRateForPeriod_NetDBRouterInfoRejectParseStat(t *testing.T) {
	dbDir := t.TempDir()
	db := netdb.NewStdNetDB(dbDir)
	t.Cleanup(func() {
		db.Stop()
		_ = os.RemoveAll(dbDir)
	})

	router := &mockRouterAccess{
		netdb:   db,
		running: true,
	}
	provider := NewRouterStatsProvider(router, "0.1.0-test")

	var key common.Hash
	// Invalid DatabaseStore RouterInfo payload (too short to decode) to trigger parse rejection.
	if err := db.Store(key, []byte{0x00}, 0); err == nil {
		t.Fatalf("expected parse failure storing invalid RouterInfo payload")
	}

	if got := provider.GetRateForPeriod("netdb.routerinfo.rejected.parse", 60000); got < 1 {
		t.Fatalf("netdb.routerinfo.rejected.parse = %v, want >= 1", got)
	}

	if got := provider.GetRateForPeriod("netdb.routerinfo.rejected", 60000); got < 1 {
		t.Fatalf("netdb.routerinfo.rejected = %v, want >= 1", got)
	}
}
