package i2pcontrol

import (
	"testing"
	"time"

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
	tunnelManager      *i2np.TunnelManager
	participantManager *tunnelpkg.Manager
	cfg                *config.RouterConfig
	running            bool
}

func (m *mockRouterAccess) GetNetDB() *netdb.StdNetDB {
	return m.netdb
}

func (m *mockRouterAccess) GetTunnelManager() *i2np.TunnelManager {
	return m.tunnelManager
}

func (m *mockRouterAccess) GetParticipantManager() *tunnelpkg.Manager {
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

func (m *mockRouterAccess) GetBandwidthRates() (rate1s, rate15s uint64) {
	// Return test values
	return 1024, 2048
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
