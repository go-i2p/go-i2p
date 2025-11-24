package i2cp

import (
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/tunnel"
)

func TestDefaultSessionConfig(t *testing.T) {
	config := DefaultSessionConfig()

	if config.InboundTunnelLength != 3 {
		t.Errorf("InboundTunnelLength = %d, want 3", config.InboundTunnelLength)
	}
	if config.OutboundTunnelLength != 3 {
		t.Errorf("OutboundTunnelLength = %d, want 3", config.OutboundTunnelLength)
	}
	if config.InboundTunnelCount != 5 {
		t.Errorf("InboundTunnelCount = %d, want 5", config.InboundTunnelCount)
	}
	if config.OutboundTunnelCount != 5 {
		t.Errorf("OutboundTunnelCount = %d, want 5", config.OutboundTunnelCount)
	}
	if config.TunnelLifetime != 10*time.Minute {
		t.Errorf("TunnelLifetime = %v, want 10m", config.TunnelLifetime)
	}
}

func TestSessionGetters(t *testing.T) {
	session, err := NewSession(1, nil, nil)
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}
	defer session.Stop()

	// Test Destination getter
	if session.Destination() == nil {
		t.Error("Destination() should not be nil")
	}

	// Test CreatedAt getter
	createdAt := session.CreatedAt()
	if createdAt.IsZero() {
		t.Error("CreatedAt() should not be zero")
	}
	if time.Since(createdAt) > time.Second {
		t.Error("CreatedAt() should be recent")
	}

	// Test pool getters
	if session.InboundPool() != nil {
		t.Error("InboundPool() should be nil for new session")
	}
	if session.OutboundPool() != nil {
		t.Error("OutboundPool() should be nil for new session")
	}

	// Test SetOutboundPool
	pool := &tunnel.Pool{}
	session.SetOutboundPool(pool)
	if session.OutboundPool() != pool {
		t.Error("OutboundPool() should return the set pool")
	}
}

func TestNewSession(t *testing.T) {
	config := DefaultSessionConfig()
	config.Nickname = "test-session"

	session, err := NewSession(1, nil, config)
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}

	if session.ID() != 1 {
		t.Errorf("ID() = %d, want 1", session.ID())
	}
	if !session.IsActive() {
		t.Error("Session should be active after creation")
	}
	if session.Config().Nickname != "test-session" {
		t.Errorf("Config().Nickname = %q, want %q", session.Config().Nickname, "test-session")
	}

	// Clean up
	session.Stop()
}

func TestSessionQueueMessage(t *testing.T) {
	session, err := NewSession(1, nil, nil)
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}
	defer session.Stop()

	// Queue a message
	payload := []byte("test message")
	if err := session.QueueIncomingMessage(payload); err != nil {
		t.Fatalf("QueueIncomingMessage() error = %v", err)
	}

	// Receive the message (with timeout)
	done := make(chan struct{})
	var msg *IncomingMessage
	go func() {
		msg, _ = session.ReceiveMessage()
		close(done)
	}()

	select {
	case <-done:
		if msg == nil {
			t.Fatal("ReceiveMessage() returned nil")
		}
		if string(msg.Payload) != string(payload) {
			t.Errorf("Payload = %q, want %q", msg.Payload, payload)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("ReceiveMessage() timeout")
	}
}

func TestSessionQueueFull(t *testing.T) {
	session, err := NewSession(1, nil, nil)
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}
	defer session.Stop()

	// Fill the queue (buffer size is 100)
	for i := 0; i < 100; i++ {
		if err := session.QueueIncomingMessage([]byte("msg")); err != nil {
			t.Fatalf("QueueIncomingMessage() error at %d: %v", i, err)
		}
	}

	// Next message should fail
	if err := session.QueueIncomingMessage([]byte("overflow")); err == nil {
		t.Error("Expected error when queue is full, got nil")
	}
}

func TestSessionStop(t *testing.T) {
	session, err := NewSession(1, nil, nil)
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}

	session.Stop()

	if session.IsActive() {
		t.Error("Session should not be active after Stop()")
	}

	// Queuing to stopped session should fail
	if err := session.QueueIncomingMessage([]byte("msg")); err == nil {
		t.Error("Expected error queuing to stopped session, got nil")
	}

	// ReceiveMessage should return immediately
	msg, err := session.ReceiveMessage()
	if msg != nil {
		t.Errorf("ReceiveMessage() from stopped session = %v, want nil", msg)
	}
}

func TestSessionReconfigure(t *testing.T) {
	session, err := NewSession(1, nil, nil)
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}
	defer session.Stop()

	newConfig := DefaultSessionConfig()
	newConfig.InboundTunnelCount = 10
	newConfig.Nickname = "updated"

	if err := session.Reconfigure(newConfig); err != nil {
		t.Fatalf("Reconfigure() error = %v", err)
	}

	if session.Config().InboundTunnelCount != 10 {
		t.Errorf("InboundTunnelCount = %d, want 10", session.Config().InboundTunnelCount)
	}
	if session.Config().Nickname != "updated" {
		t.Errorf("Nickname = %q, want %q", session.Config().Nickname, "updated")
	}
}

func TestSessionManager(t *testing.T) {
	manager := NewSessionManager()

	// Create first session
	session1, err := manager.CreateSession(nil, nil)
	if err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}

	// Verify session is registered
	if manager.SessionCount() != 1 {
		t.Errorf("SessionCount() = %d, want 1", manager.SessionCount())
	}

	// Retrieve session
	retrieved, ok := manager.GetSession(session1.ID())
	if !ok {
		t.Error("GetSession() returned false")
	}
	if retrieved.ID() != session1.ID() {
		t.Errorf("Retrieved session ID = %d, want %d", retrieved.ID(), session1.ID())
	}

	// Create second session
	session2, err := manager.CreateSession(nil, nil)
	if err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}

	if session1.ID() == session2.ID() {
		t.Error("Sessions should have different IDs")
	}

	if manager.SessionCount() != 2 {
		t.Errorf("SessionCount() = %d, want 2", manager.SessionCount())
	}

	// Destroy first session
	if err := manager.DestroySession(session1.ID()); err != nil {
		t.Fatalf("DestroySession() error = %v", err)
	}

	if manager.SessionCount() != 1 {
		t.Errorf("SessionCount() = %d, want 1", manager.SessionCount())
	}

	// First session should not be retrievable
	if _, ok := manager.GetSession(session1.ID()); ok {
		t.Error("Destroyed session should not be retrievable")
	}

	// Clean up
	manager.StopAll()

	if manager.SessionCount() != 0 {
		t.Errorf("SessionCount() after StopAll() = %d, want 0", manager.SessionCount())
	}
}

func TestSessionManagerDestroy_NotFound(t *testing.T) {
	manager := NewSessionManager()

	err := manager.DestroySession(9999)
	if err == nil {
		t.Error("Expected error destroying non-existent session, got nil")
	}
}

func TestSessionManager_MultipleCreatesAndDestroys(t *testing.T) {
	manager := NewSessionManager()

	// Create and destroy multiple sessions
	for i := 0; i < 10; i++ {
		session, err := manager.CreateSession(nil, nil)
		if err != nil {
			t.Fatalf("CreateSession() iteration %d error = %v", i, err)
		}

		if err := manager.DestroySession(session.ID()); err != nil {
			t.Fatalf("DestroySession() iteration %d error = %v", i, err)
		}
	}

	if manager.SessionCount() != 0 {
		t.Errorf("SessionCount() = %d, want 0", manager.SessionCount())
	}
}

func BenchmarkSessionQueueMessage(b *testing.B) {
	session, _ := NewSession(1, nil, nil)
	defer session.Stop()

	payload := []byte("benchmark message")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = session.QueueIncomingMessage(payload)
		// Drain to prevent queue full
		<-session.incomingMessages
	}
}

func BenchmarkSessionManagerCreateDestroy(b *testing.B) {
	manager := NewSessionManager()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		session, _ := manager.CreateSession(nil, nil)
		_ = manager.DestroySession(session.ID())
	}
}

// TestSessionCreateLeaseSetNoInboundPool tests CreateLeaseSet with no inbound pool
func TestSessionCreateLeaseSetNoInboundPool(t *testing.T) {
	session, err := NewSession(1, nil, nil)
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}
	defer session.Stop()

	// Should fail because there's no inbound pool
	_, err = session.CreateLeaseSet()
	if err == nil {
		t.Error("Expected error when no inbound pool, got nil")
	}
	if err != nil && err.Error() != "session 1 has no inbound tunnel pool" {
		t.Errorf("Unexpected error message: %v", err)
	}
}

// TestSessionCreateLeaseSetInactiveSession tests CreateLeaseSet on inactive session
func TestSessionCreateLeaseSetInactiveSession(t *testing.T) {
	session, err := NewSession(1, nil, nil)
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}

	// Stop the session to make it inactive
	session.Stop()

	// Should fail because session is not active
	_, err = session.CreateLeaseSet()
	if err == nil {
		t.Error("Expected error when session inactive, got nil")
	}
	if err != nil && err.Error() != "session 1 is not active" {
		t.Errorf("Unexpected error message: %v", err)
	}
}

// TestSessionCreateLeaseSetNoActiveTunnels tests CreateLeaseSet with empty pool
func TestSessionCreateLeaseSetNoActiveTunnels(t *testing.T) {
	session, err := NewSession(1, nil, nil)
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}
	defer session.Stop()

	// Create an empty tunnel pool using mock peer selector
	selector := &mockPeerSelector{}
	pool := tunnel.NewTunnelPool(selector)
	session.SetInboundPool(pool)

	// Should fail because there are no active tunnels
	_, err = session.CreateLeaseSet()
	if err == nil {
		t.Error("Expected error when no active tunnels, got nil")
	}
}

// TestSessionCreateLeaseSetWithActiveTunnels tests successful LeaseSet creation
func TestSessionCreateLeaseSetWithActiveTunnels(t *testing.T) {
	session, err := NewSession(1, nil, nil)
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}
	defer session.Stop()

	// Create a tunnel pool with active tunnels
	selector := &mockPeerSelector{}
	pool := tunnel.NewTunnelPool(selector)
	session.SetInboundPool(pool)

	// Add a mock active tunnel to the pool
	// Create router hash for gateway
	var gatewayHash common.Hash
	copy(gatewayHash[:], []byte("gateway-router-hash-12345678"))

	tunnelState := &tunnel.TunnelState{
		ID:        tunnel.TunnelID(12345),
		Hops:      []common.Hash{gatewayHash},
		State:     tunnel.TunnelReady,
		CreatedAt: time.Now(),
	}
	pool.AddTunnel(tunnelState)

	// Should successfully create LeaseSet
	leaseSetBytes, err := session.CreateLeaseSet()
	if err != nil {
		t.Errorf("CreateLeaseSet() error = %v", err)
	}
	if len(leaseSetBytes) == 0 {
		t.Error("Expected non-empty LeaseSet bytes")
	}
}

// mockPeerSelector is a simple peer selector for testing
type mockPeerSelector struct{}

func (m *mockPeerSelector) SelectPeers(count int, exclude []common.Hash) ([]router_info.RouterInfo, error) {
	return []router_info.RouterInfo{}, nil
}

// TestSessionCurrentLeaseSet tests CurrentLeaseSet getter
func TestSessionCurrentLeaseSet(t *testing.T) {
	session, err := NewSession(1, nil, nil)
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}
	defer session.Stop()

	// Initially should be nil
	if ls := session.CurrentLeaseSet(); ls != nil {
		t.Error("CurrentLeaseSet() should be nil for new session")
	}

	// Create a tunnel pool with active tunnel
	selector := &mockPeerSelector{}
	pool := tunnel.NewTunnelPool(selector)
	session.SetInboundPool(pool)

	var gatewayHash common.Hash
	copy(gatewayHash[:], []byte("gateway-router-hash-12345678"))

	tunnelState := &tunnel.TunnelState{
		ID:        tunnel.TunnelID(12345),
		Hops:      []common.Hash{gatewayHash},
		State:     tunnel.TunnelReady,
		CreatedAt: time.Now(),
	}
	pool.AddTunnel(tunnelState)

	// Create LeaseSet
	leaseSetBytes, err := session.CreateLeaseSet()
	if err != nil {
		t.Fatalf("CreateLeaseSet() error = %v", err)
	}

	// Now CurrentLeaseSet should return the cached value
	cachedLS := session.CurrentLeaseSet()
	if cachedLS == nil {
		t.Error("CurrentLeaseSet() should not be nil after creation")
	}
	if string(cachedLS) != string(leaseSetBytes) {
		t.Error("CurrentLeaseSet() should match created LeaseSet")
	}
}

// TestSessionLeaseSetAge tests LeaseSetAge getter
func TestSessionLeaseSetAge(t *testing.T) {
	session, err := NewSession(1, nil, nil)
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}
	defer session.Stop()

	// Initially should be zero
	if age := session.LeaseSetAge(); age != 0 {
		t.Errorf("LeaseSetAge() = %v, want 0 for new session", age)
	}

	// Create a tunnel pool with active tunnel
	selector := &mockPeerSelector{}
	pool := tunnel.NewTunnelPool(selector)
	session.SetInboundPool(pool)

	var gatewayHash common.Hash
	copy(gatewayHash[:], []byte("gateway-router-hash-12345678"))

	tunnelState := &tunnel.TunnelState{
		ID:        tunnel.TunnelID(12345),
		Hops:      []common.Hash{gatewayHash},
		State:     tunnel.TunnelReady,
		CreatedAt: time.Now(),
	}
	pool.AddTunnel(tunnelState)

	// Create LeaseSet
	_, err = session.CreateLeaseSet()
	if err != nil {
		t.Fatalf("CreateLeaseSet() error = %v", err)
	}

	// Age should be very small (just created)
	age := session.LeaseSetAge()
	if age < 0 || age > time.Second {
		t.Errorf("LeaseSetAge() = %v, expected small positive duration", age)
	}

	// Wait a bit and check age increases
	time.Sleep(100 * time.Millisecond)
	age2 := session.LeaseSetAge()
	if age2 <= age {
		t.Errorf("LeaseSetAge() should increase over time: %v <= %v", age2, age)
	}
}

// TestStartLeaseSetMaintenanceNoInboundPool tests maintenance start without pool
func TestStartLeaseSetMaintenanceNoInboundPool(t *testing.T) {
	session, err := NewSession(1, nil, nil)
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}
	defer session.Stop()

	// Should fail because there's no inbound pool
	err = session.StartLeaseSetMaintenance()
	if err == nil {
		t.Error("Expected error when no inbound pool, got nil")
	}
}

// TestStartLeaseSetMaintenanceInactiveSession tests maintenance on inactive session
func TestStartLeaseSetMaintenanceInactiveSession(t *testing.T) {
	session, err := NewSession(1, nil, nil)
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}

	// Stop the session to make it inactive
	session.Stop()

	// Should fail because session is not active
	err = session.StartLeaseSetMaintenance()
	if err == nil {
		t.Error("Expected error when session inactive, got nil")
	}
}

// TestStartLeaseSetMaintenanceSuccess tests successful maintenance start
func TestStartLeaseSetMaintenanceSuccess(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping maintenance test in short mode")
	}

	session, err := NewSession(1, nil, DefaultSessionConfig())
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}
	defer session.Stop()

	// Create a tunnel pool with active tunnel
	selector := &mockPeerSelector{}
	pool := tunnel.NewTunnelPool(selector)
	session.SetInboundPool(pool)

	var gatewayHash common.Hash
	copy(gatewayHash[:], []byte("gateway-router-hash-12345678"))

	tunnelState := &tunnel.TunnelState{
		ID:        tunnel.TunnelID(12345),
		Hops:      []common.Hash{gatewayHash},
		State:     tunnel.TunnelReady,
		CreatedAt: time.Now(),
	}
	pool.AddTunnel(tunnelState)

	// Start maintenance
	err = session.StartLeaseSetMaintenance()
	if err != nil {
		t.Fatalf("StartLeaseSetMaintenance() error = %v", err)
	}

	// Wait a bit for initial LeaseSet generation
	time.Sleep(200 * time.Millisecond)

	// Verify LeaseSet was created
	if session.CurrentLeaseSet() == nil {
		t.Error("LeaseSet should be created by maintenance")
	}

	// Verify age is recent
	age := session.LeaseSetAge()
	if age < 0 || age > 2*time.Second {
		t.Errorf("LeaseSetAge() = %v, expected small duration", age)
	}
}

// TestLeaseSetMaintenanceRegeneration tests that LeaseSet is regenerated
func TestLeaseSetMaintenanceRegeneration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping maintenance regeneration test in short mode")
	}

	// Use short tunnel lifetime for faster testing
	config := DefaultSessionConfig()
	config.TunnelLifetime = 2 * time.Second // Very short for testing

	session, err := NewSession(1, nil, nil)
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}
	defer session.Stop()

	// Create a tunnel pool with active tunnel
	selector := &mockPeerSelector{}
	pool := tunnel.NewTunnelPool(selector)
	session.SetInboundPool(pool)

	var gatewayHash common.Hash
	copy(gatewayHash[:], []byte("gateway-router-hash-12345678"))

	tunnelState := &tunnel.TunnelState{
		ID:        tunnel.TunnelID(12345),
		Hops:      []common.Hash{gatewayHash},
		State:     tunnel.TunnelReady,
		CreatedAt: time.Now(),
	}
	pool.AddTunnel(tunnelState)

	// Start maintenance
	err = session.StartLeaseSetMaintenance()
	if err != nil {
		t.Fatalf("StartLeaseSetMaintenance() error = %v", err)
	}

	// Wait for initial generation
	time.Sleep(200 * time.Millisecond)

	firstLS := session.CurrentLeaseSet()
	if firstLS == nil {
		t.Fatal("First LeaseSet should be created")
	}

	// Wait for regeneration threshold (lifetime/2 = 1 second)
	// Plus a bit more for the maintenance check interval (lifetime/4 = 0.5 seconds)
	time.Sleep(1500 * time.Millisecond)

	secondLS := session.CurrentLeaseSet()
	if secondLS == nil {
		t.Fatal("Second LeaseSet should be created")
	}

	// LeaseSets should be different (different timestamps)
	if string(firstLS) == string(secondLS) {
		t.Error("LeaseSet should be regenerated with different data")
	}
}

// TestLeaseSetMaintenanceStopCleanup tests maintenance cleanup on stop
func TestLeaseSetMaintenanceStopCleanup(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping maintenance cleanup test in short mode")
	}

	session, err := NewSession(1, nil, DefaultSessionConfig())
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}

	// Create a tunnel pool with active tunnel
	selector := &mockPeerSelector{}
	pool := tunnel.NewTunnelPool(selector)
	session.SetInboundPool(pool)

	var gatewayHash common.Hash
	copy(gatewayHash[:], []byte("gateway-router-hash-12345678"))

	tunnelState := &tunnel.TunnelState{
		ID:        tunnel.TunnelID(12345),
		Hops:      []common.Hash{gatewayHash},
		State:     tunnel.TunnelReady,
		CreatedAt: time.Now(),
	}
	pool.AddTunnel(tunnelState)

	// Start maintenance
	err = session.StartLeaseSetMaintenance()
	if err != nil {
		t.Fatalf("StartLeaseSetMaintenance() error = %v", err)
	}

	// Wait for initial generation
	time.Sleep(200 * time.Millisecond)

	// Stop session - should cleanly shut down maintenance
	session.Stop()

	// Verify session is no longer active
	if session.IsActive() {
		t.Error("Session should not be active after Stop()")
	}
}

// TestMaintainLeaseSetDirectCall tests direct call to maintainLeaseSet
func TestMaintainLeaseSetDirectCall(t *testing.T) {
	session, err := NewSession(1, nil, nil)
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}
	defer session.Stop()

	// Create a tunnel pool with active tunnel
	selector := &mockPeerSelector{}
	pool := tunnel.NewTunnelPool(selector)
	session.SetInboundPool(pool)

	var gatewayHash common.Hash
	copy(gatewayHash[:], []byte("gateway-router-hash-12345678"))

	tunnelState := &tunnel.TunnelState{
		ID:        tunnel.TunnelID(12345),
		Hops:      []common.Hash{gatewayHash},
		State:     tunnel.TunnelReady,
		CreatedAt: time.Now(),
	}
	pool.AddTunnel(tunnelState)

	// Call maintainLeaseSet directly
	err = session.maintainLeaseSet()
	if err != nil {
		t.Errorf("maintainLeaseSet() error = %v", err)
	}

	// Verify LeaseSet was created
	if session.CurrentLeaseSet() == nil {
		t.Error("LeaseSet should be created")
	}

	// Call again - should not regenerate (not enough time passed)
	firstLS := session.CurrentLeaseSet()
	err = session.maintainLeaseSet()
	if err != nil {
		t.Errorf("maintainLeaseSet() second call error = %v", err)
	}

	secondLS := session.CurrentLeaseSet()
	if string(firstLS) != string(secondLS) {
		t.Error("LeaseSet should not change when below regeneration threshold")
	}
}

// TestLeaseSetRegenerationThreshold tests regeneration based on age
func TestLeaseSetRegenerationThreshold(t *testing.T) {
	// Use very short tunnel lifetime for testing
	config := DefaultSessionConfig()
	config.TunnelLifetime = 1 * time.Second

	session, err := NewSession(1, nil, nil)
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}
	defer session.Stop()

	// Create a tunnel pool with active tunnel
	selector := &mockPeerSelector{}
	pool := tunnel.NewTunnelPool(selector)
	session.SetInboundPool(pool)

	var gatewayHash common.Hash
	copy(gatewayHash[:], []byte("gateway-router-hash-12345678"))

	tunnelState := &tunnel.TunnelState{
		ID:        tunnel.TunnelID(12345),
		Hops:      []common.Hash{gatewayHash},
		State:     tunnel.TunnelReady,
		CreatedAt: time.Now(),
	}
	pool.AddTunnel(tunnelState)

	// Generate initial LeaseSet
	err = session.maintainLeaseSet()
	if err != nil {
		t.Fatalf("maintainLeaseSet() error = %v", err)
	}

	firstLS := session.CurrentLeaseSet()
	if firstLS == nil {
		t.Fatal("First LeaseSet should be created")
	}
	firstAge := session.LeaseSetAge()

	// Wait for regeneration threshold (lifetime/2 = 0.5 seconds)
	time.Sleep(600 * time.Millisecond)

	// Call maintainLeaseSet again - should regenerate
	err = session.maintainLeaseSet()
	if err != nil {
		t.Errorf("maintainLeaseSet() regeneration error = %v", err)
	}

	secondLS := session.CurrentLeaseSet()
	secondAge := session.LeaseSetAge()

	// Verify a new LeaseSet was generated by checking that age reset
	if secondAge >= firstAge+500*time.Millisecond {
		t.Errorf("LeaseSet age should reset after regeneration: first=%v second=%v", firstAge, secondAge)
	}

	// Age should be very recent (less than 100ms old)
	if secondAge > 100*time.Millisecond {
		t.Errorf("New LeaseSet age should be very small: %v", secondAge)
	}

	// Just verify we still have a valid LeaseSet
	if secondLS == nil {
		t.Error("Second LeaseSet should exist")
	}
}
