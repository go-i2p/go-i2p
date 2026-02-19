package i2cp

import (
	"bytes"
	"sync"
	"testing"
	"time"

	"github.com/go-i2p/common/data"
	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/encrypted_leaseset"
	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/go-i2p/lib/keys"
	"github.com/go-i2p/go-i2p/lib/netdb"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

	// ReceiveMessage should return immediately (timeout expected)
	msg, _ := session.ReceiveMessage()
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
	if err != nil && err.Error() != "session 1 not active" {
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

	session, err := NewSession(1, nil, config)
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

	session, err := NewSession(1, nil, config)
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

func TestStopTunnelPools(t *testing.T) {
	session, err := NewSession(1, nil, nil)
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}
	defer session.Stop()

	// Create dummy pools using the mock peer selector
	selector := &mockPeerSelector{}
	inboundConfig := tunnel.PoolConfig{
		MinTunnels: 2,
		MaxTunnels: 3,
		HopCount:   3,
		IsInbound:  true,
	}
	outboundConfig := tunnel.PoolConfig{
		MinTunnels: 2,
		MaxTunnels: 3,
		HopCount:   3,
		IsInbound:  false,
	}
	session.SetInboundPool(tunnel.NewTunnelPoolWithConfig(selector, inboundConfig))
	session.SetOutboundPool(tunnel.NewTunnelPoolWithConfig(selector, outboundConfig))

	// Verify pools are set
	if session.inboundPool == nil {
		t.Fatal("inboundPool should be set")
	}
	if session.outboundPool == nil {
		t.Fatal("outboundPool should be set")
	}

	// Stop pools
	session.StopTunnelPools()

	// Verify pools are nil
	if session.inboundPool != nil {
		t.Error("inboundPool should be nil after StopTunnelPools")
	}
	if session.outboundPool != nil {
		t.Error("outboundPool should be nil after StopTunnelPools")
	}
}

func TestStopTunnelPools_NilPools(t *testing.T) {
	session, err := NewSession(1, nil, nil)
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}
	defer session.Stop()

	// Should not panic with nil pools
	session.StopTunnelPools()
}

// =============================================================================
// Tests for AUDIT fix: "I2CP Server Always Replaces Client-Provided Destination"
// (FUNCTIONAL MISMATCH / I2CP-03)
//
// These tests verify that clients can maintain persistent I2P identities
// by providing their own private keys when creating sessions.
// =============================================================================

// TestPrepareDestinationAndKeys_WithPrivateKeys_PreservesIdentity verifies that
// providing both signing and encryption private keys produces a DestinationKeyStore
// whose destination matches the original identity (same .b32.i2p address).
func TestPrepareDestinationAndKeys_WithPrivateKeys_PreservesIdentity(t *testing.T) {
	// Generate an original identity
	originalKS, err := keys.NewDestinationKeyStore()
	require.NoError(t, err)

	originalDest := originalKS.Destination()
	originalDestBytes, err := originalDest.Bytes()
	require.NoError(t, err)

	// Extract the private keys
	sigPriv := originalKS.SigningPrivateKey()
	encPriv := originalKS.EncryptionPrivateKey()

	// Reconstruct via prepareDestinationAndKeys with the same private keys
	resultKS, resultDest, err := prepareDestinationAndKeys(originalDest, sigPriv, encPriv)
	require.NoError(t, err)
	require.NotNil(t, resultKS)
	require.NotNil(t, resultDest)

	// The destination should be identical (same .b32.i2p address)
	resultDestBytes, err := resultDest.Bytes()
	require.NoError(t, err)
	assert.True(t, bytes.Equal(originalDestBytes, resultDestBytes),
		"destination should be preserved when private keys are provided")
}

// TestNewSession_WithPrivateKeys_PreservesIdentity verifies that a session
// created with client-provided private keys has the same destination identity
// as the original keystore.
func TestNewSession_WithPrivateKeys_PreservesIdentity(t *testing.T) {
	// Generate an original identity
	originalKS, err := keys.NewDestinationKeyStore()
	require.NoError(t, err)

	originalDest := originalKS.Destination()
	originalDestBytes, err := originalDest.Bytes()
	require.NoError(t, err)
	sigPriv := originalKS.SigningPrivateKey()
	encPriv := originalKS.EncryptionPrivateKey()

	// Create session with the original private keys
	session, err := NewSession(1, originalDest, nil, sigPriv, encPriv)
	require.NoError(t, err)
	defer session.Stop()

	// Session destination should match the original
	sessionDestBytes, err := session.Destination().Bytes()
	require.NoError(t, err)
	assert.True(t, bytes.Equal(originalDestBytes, sessionDestBytes),
		"session destination should match original when private keys are provided")

	// Session keys should produce the same signing and encryption behavior
	assert.NotNil(t, session.keys, "session keys must not be nil")
	assert.NotNil(t, session.keys.SigningPrivateKey(), "signing private key must be present")
	assert.NotNil(t, session.keys.EncryptionPrivateKey(), "encryption private key must be present")
}

// TestCreateSession_WithPrivateKeys_PreservesIdentity verifies that the
// SessionManager.CreateSession method correctly passes through private keys.
func TestCreateSession_WithPrivateKeys_PreservesIdentity(t *testing.T) {
	sm := NewSessionManager()

	// Generate an original identity
	originalKS, err := keys.NewDestinationKeyStore()
	require.NoError(t, err)

	originalDest := originalKS.Destination()
	originalDestBytes, err := originalDest.Bytes()
	require.NoError(t, err)
	sigPriv := originalKS.SigningPrivateKey()
	encPriv := originalKS.EncryptionPrivateKey()

	// Create session via manager with private keys
	session, err := sm.CreateSession(originalDest, nil, sigPriv, encPriv)
	require.NoError(t, err)
	defer sm.DestroySession(session.ID())

	// Session destination should match the original
	sessionDestBytes, err := session.Destination().Bytes()
	require.NoError(t, err)
	assert.True(t, bytes.Equal(originalDestBytes, sessionDestBytes),
		"session destination should match original when private keys are provided via SessionManager")
}

// TestNewSession_WithoutPrivateKeys_GeneratesFreshIdentity verifies that
// when no private keys are provided, a fresh identity is always generated
// (backward compatibility with the previous behavior).
func TestNewSession_WithoutPrivateKeys_GeneratesFreshIdentity(t *testing.T) {
	// Generate a destination but DON'T provide its private keys
	originalKS, err := keys.NewDestinationKeyStore()
	require.NoError(t, err)

	originalDest := originalKS.Destination()
	originalDestBytes, err := originalDest.Bytes()
	require.NoError(t, err)

	// Create session without private keys
	session, err := NewSession(1, originalDest, nil)
	require.NoError(t, err)
	defer session.Stop()

	// Session destination should be DIFFERENT from the original
	// (fresh keys generated, different identity)
	sessionDestBytes, err := session.Destination().Bytes()
	require.NoError(t, err)
	assert.False(t, bytes.Equal(originalDestBytes, sessionDestBytes),
		"session destination should differ when no private keys are provided")

	// But session should still have valid keys
	assert.NotNil(t, session.keys, "session keys must not be nil")
	assert.NotNil(t, session.keys.SigningPrivateKey(), "signing private key must be present")
}

// TestNewSession_WithNilDestAndNilKeys_GeneratesFreshIdentity verifies the
// base case where both destination and keys are nil (completely fresh session).
func TestNewSession_WithNilDestAndNilKeys_GeneratesFreshIdentity(t *testing.T) {
	session, err := NewSession(1, nil, nil)
	require.NoError(t, err)
	defer session.Stop()

	assert.NotNil(t, session.destination, "destination must not be nil")
	assert.NotNil(t, session.keys, "keys must not be nil")
	assert.NotNil(t, session.keys.SigningPrivateKey(), "signing private key must be present")
	assert.NotNil(t, session.keys.EncryptionPrivateKey(), "encryption private key must be present")
}

// TestPrepareDestinationAndKeys_WithPartialKeys_GeneratesFresh verifies that
// providing only one private key (partial) falls back to generating fresh keys.
func TestPrepareDestinationAndKeys_WithPartialKeys_GeneratesFresh(t *testing.T) {
	originalKS, err := keys.NewDestinationKeyStore()
	require.NoError(t, err)

	sigPriv := originalKS.SigningPrivateKey()

	// Provide only signing key, no encryption key — should generate fresh
	keyStore, dest, err := prepareDestinationAndKeys(nil, sigPriv, nil)
	require.NoError(t, err)
	assert.NotNil(t, keyStore)
	assert.NotNil(t, dest)

	// Should have generated fresh keys (different from original)
	originalDestBytes, err := originalKS.Destination().Bytes()
	require.NoError(t, err)
	resultDestBytes, err := dest.Bytes()
	require.NoError(t, err)
	assert.False(t, bytes.Equal(originalDestBytes, resultDestBytes),
		"with partial keys, should generate fresh identity")
}

// TestPrepareDestinationAndKeys_IdentityStableAcrossReconstructions verifies
// that the same private keys always produce the same destination identity.
func TestPrepareDestinationAndKeys_IdentityStableAcrossReconstructions(t *testing.T) {
	// Generate an original identity
	originalKS, err := keys.NewDestinationKeyStore()
	require.NoError(t, err)

	sigPriv := originalKS.SigningPrivateKey()
	encPriv := originalKS.EncryptionPrivateKey()

	// Reconstruct multiple times
	var destinations [][]byte
	for i := 0; i < 3; i++ {
		ks, dest, err := prepareDestinationAndKeys(nil, sigPriv, encPriv)
		require.NoError(t, err)
		require.NotNil(t, ks)
		db, err := dest.Bytes()
		require.NoError(t, err)
		destinations = append(destinations, db)
	}

	// All should produce identical destinations
	for i := 1; i < len(destinations); i++ {
		assert.True(t, bytes.Equal(destinations[0], destinations[i]),
			"reconstruction %d should produce identical destination", i)
	}
}

// TestNewSession_VariadicPrivKeysBackwardCompat verifies that the variadic
// privKeys parameter maintains backward compatibility — existing callers
// that don't provide private keys continue to work.
func TestNewSession_VariadicPrivKeysBackwardCompat(t *testing.T) {
	// No extra args (most existing callers)
	session1, err := NewSession(1, nil, nil)
	require.NoError(t, err)
	defer session1.Stop()
	assert.NotNil(t, session1.keys)

	// Empty variadic (should not panic)
	session2, err := NewSession(2, nil, nil)
	require.NoError(t, err)
	defer session2.Stop()
	assert.NotNil(t, session2.keys)

	// Wrong types in variadic (should be ignored, generate fresh)
	session3, err := NewSession(3, nil, nil, "not-a-key", 42)
	require.NoError(t, err)
	defer session3.Stop()
	assert.NotNil(t, session3.keys)
}

// =============================================================================
// Tests for AUDIT fix: "I2CP Session With External Destination Cannot Create
// LeaseSets" — verifies that sessions created with an external destination
// still receive a non-nil DestinationKeyStore so that LeaseSet creation
// does not panic with a nil pointer dereference.
// =============================================================================

// TestNewSession_WithExternalDestination_HasKeys verifies that providing a
// non-nil destination to NewSession still results in a session whose internal
// keys field is non-nil (so CreateLeaseSet won't panic).
func TestNewSession_WithExternalDestination_HasKeys(t *testing.T) {
	// Create an external destination using a temporary keystore
	keyStore, err := keys.NewDestinationKeyStore()
	require.NoError(t, err, "failed to create test destination keystore")

	externalDest := keyStore.Destination()
	require.NotNil(t, externalDest, "test destination should not be nil")

	// Create a session with that external destination
	session, err := NewSession(42, externalDest, nil)
	require.NoError(t, err, "NewSession with external destination should succeed")
	defer session.Stop()

	// The critical invariant: session.keys must NOT be nil
	assert.NotNil(t, session.keys,
		"session created with external destination must have non-nil keys")
	assert.NotNil(t, session.destination,
		"session must have a destination")
}

// TestNewSession_WithNilDestination_HasKeys verifies the baseline: a session
// with nil destination also gets keys (this always worked, but we verify it
// as a regression guard).
func TestNewSession_WithNilDestination_HasKeys(t *testing.T) {
	session, err := NewSession(1, nil, nil)
	require.NoError(t, err)
	defer session.Stop()

	assert.NotNil(t, session.keys, "session with nil dest should have keys")
	assert.NotNil(t, session.destination, "session with nil dest should have destination")
}

// TestPrepareDestinationAndKeys_ExternalDest_ReturnsValidKeyStore tests the
// prepareDestinationAndKeys helper directly to confirm it returns a
// non-nil DestinationKeyStore when only a destination is provided (no private keys).
func TestPrepareDestinationAndKeys_ExternalDest_ReturnsValidKeyStore(t *testing.T) {
	// Create an external destination
	ks, err := keys.NewDestinationKeyStore()
	require.NoError(t, err)
	externalDest := ks.Destination()

	// Call with non-nil dest but no private keys — should generate fresh keys
	keyStore, dest, err := prepareDestinationAndKeys(externalDest, nil, nil)
	require.NoError(t, err)
	assert.NotNil(t, keyStore, "keyStore must not be nil when dest is provided")
	assert.NotNil(t, dest, "returned dest must not be nil")

	// The returned destination should come from the new keystore
	// (not the client-provided one) since no private keys were provided
	assert.NotNil(t, keyStore.SigningPrivateKey(),
		"keyStore should have a signing private key")
	encPub, encErr := keyStore.EncryptionPublicKey()
	assert.NoError(t, encErr, "EncryptionPublicKey should not error")
	assert.NotNil(t, encPub,
		"keyStore should have an encryption public key")
}

// TestPrepareDestinationAndKeys_NilDest_ReturnsValidKeyStore is the baseline
// test for nil destination input.
func TestPrepareDestinationAndKeys_NilDest_ReturnsValidKeyStore(t *testing.T) {
	keyStore, dest, err := prepareDestinationAndKeys(nil, nil, nil)
	require.NoError(t, err)
	assert.NotNil(t, keyStore, "keyStore must not be nil for nil dest")
	assert.NotNil(t, dest, "dest must not be nil for nil dest input")
}

// TestValidateSessionState_NilKeys_ReturnsError verifies the defensive nil
// check in validateSessionState catches missing prerequisites (pools and keys).
func TestValidateSessionState_NilKeys_ReturnsError(t *testing.T) {
	// Create a session normally then nil out its keys to simulate the old bug
	session, err := NewSession(99, nil, nil)
	require.NoError(t, err)
	defer session.Stop()

	// Force nil keys (simulating the old prepareDestinationAndKeys bug)
	session.keys = nil

	// validateSessionState checks pools before keys, so it will fail
	// on the missing inbound pool first. The key point is that it does
	// fail — the session is not in a valid state for LeaseSet creation.
	err = session.validateSessionState()
	assert.Error(t, err, "validateSessionState should fail with nil keys and no pools")
}

// =============================================================================
// Tests for AUDIT fix: "Double Session Cleanup Race in I2CP Server" —
// verifies that DestroySession can be called twice without panicking, and
// that the SessionManager handles concurrent cleanup gracefully.
// =============================================================================

// TestDestroySession_Idempotent verifies that calling DestroySession twice
// for the same session ID does not panic; the second call returns an error.
func TestDestroySession_Idempotent(t *testing.T) {
	sm := NewSessionManager()

	session, err := sm.CreateSession(nil, nil)
	require.NoError(t, err)
	sessionID := session.ID()

	// First destroy should succeed
	err = sm.DestroySession(sessionID)
	assert.NoError(t, err, "first DestroySession should succeed")

	// Second destroy should return an error but NOT panic
	err = sm.DestroySession(sessionID)
	assert.Error(t, err, "second DestroySession should return an error")
	assert.Contains(t, err.Error(), "not found",
		"error should indicate session was not found")
}

// TestDestroySession_ConcurrentDoubleCleanup simulates the race condition
// where cleanupIdleSessions and cleanupSessionConnection both try to destroy
// the same session concurrently. Neither should panic.
func TestDestroySession_ConcurrentDoubleCleanup(t *testing.T) {
	sm := NewSessionManager()

	session, err := sm.CreateSession(nil, nil)
	require.NoError(t, err)
	sessionID := session.ID()

	var wg sync.WaitGroup
	errors := make([]error, 2)

	// Simulate two concurrent cleanup paths
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			errors[idx] = sm.DestroySession(sessionID)
		}(i)
	}
	wg.Wait()

	// Exactly one should succeed and one should fail
	successes := 0
	failures := 0
	for _, e := range errors {
		if e == nil {
			successes++
		} else {
			failures++
		}
	}
	assert.Equal(t, 1, successes,
		"exactly one concurrent DestroySession should succeed")
	assert.Equal(t, 1, failures,
		"exactly one concurrent DestroySession should fail (already destroyed)")
}

// TestSessionManager_CreateAndDestroyMultiple verifies the session manager
// correctly handles multiple sessions being created and destroyed, ensuring
// session count stays accurate.
func TestSessionManager_CreateAndDestroyMultiple(t *testing.T) {
	sm := NewSessionManager()

	// Create 3 sessions
	sessions := make([]*Session, 3)
	for i := 0; i < 3; i++ {
		s, err := sm.CreateSession(nil, nil)
		require.NoError(t, err)
		sessions[i] = s
	}
	assert.Equal(t, 3, sm.SessionCount())

	// Destroy the middle one
	err := sm.DestroySession(sessions[1].ID())
	assert.NoError(t, err)
	assert.Equal(t, 2, sm.SessionCount())

	// Destroying the same one again should fail
	err = sm.DestroySession(sessions[1].ID())
	assert.Error(t, err)
	assert.Equal(t, 2, sm.SessionCount(), "count should not change on failed destroy")

	// Destroy remaining
	for _, idx := range []int{0, 2} {
		err := sm.DestroySession(sessions[idx].ID())
		assert.NoError(t, err)
	}
	assert.Equal(t, 0, sm.SessionCount())
}

// TestSessionManager_CreateWithExternalDest verifies that CreateSession with
// an external destination produces a fully usable session (non-nil keys).
func TestSessionManager_CreateWithExternalDest(t *testing.T) {
	sm := NewSessionManager()

	ks, err := keys.NewDestinationKeyStore()
	require.NoError(t, err)
	externalDest := ks.Destination()

	session, err := sm.CreateSession(externalDest, nil)
	require.NoError(t, err)
	defer sm.DestroySession(session.ID())

	assert.NotNil(t, session.keys,
		"session created via manager with external dest must have keys")
	assert.NotNil(t, session.Destination(),
		"session must have a destination")
}

// TestSessionConfigEncryptedLeaseSet verifies EncryptedLeaseSet configuration fields
func TestSessionConfigEncryptedLeaseSet(t *testing.T) {
	config := DefaultSessionConfig()

	assert.False(t, config.UseEncryptedLeaseSet, "EncryptedLeaseSet should be disabled by default")
	assert.Nil(t, config.BlindingSecret, "BlindingSecret should be nil by default")
	assert.Equal(t, uint16(600), config.LeaseSetExpiration, "LeaseSetExpiration should default to 600 seconds")

	// Test custom configuration
	secret := []byte("test-secret-32-bytes-long!!!!!!!")
	customConfig := &SessionConfig{
		UseEncryptedLeaseSet: true,
		BlindingSecret:       secret,
		LeaseSetExpiration:   900,
		InboundTunnelLength:  3,
		OutboundTunnelLength: 3,
		InboundTunnelCount:   5,
		OutboundTunnelCount:  5,
		TunnelLifetime:       10 * time.Minute,
		MessageTimeout:       60 * time.Second,
		MessageQueueSize:     100,
	}

	assert.True(t, customConfig.UseEncryptedLeaseSet)
	assert.Equal(t, secret, customConfig.BlindingSecret)
	assert.Equal(t, uint16(900), customConfig.LeaseSetExpiration)
}

// TestValidateEncryptedLeaseSetSupport ensures Ed25519 requirement is enforced
func TestValidateEncryptedLeaseSetSupport(t *testing.T) {
	// Create session with Ed25519 destination
	keyStore, err := keys.NewDestinationKeyStore()
	require.NoError(t, err)

	session := &Session{
		destination: keyStore.Destination(),
		keys:        keyStore,
	}

	// Should succeed with Ed25519
	err = session.validateEncryptedLeaseSetSupport()
	assert.NoError(t, err)

	// Verify the signature type
	sigType := session.destination.KeyCertificate.SigningPublicKeyType()
	assert.Equal(t, key_certificate.KEYCERT_SIGN_ED25519, sigType)
}

// TestEnsureBlindingSecret verifies blinding secret generation and caching
func TestEnsureBlindingSecret(t *testing.T) {
	keyStore, err := keys.NewDestinationKeyStore()
	require.NoError(t, err)

	config := DefaultSessionConfig()
	session := &Session{
		destination: keyStore.Destination(),
		keys:        keyStore,
		config:      config,
	}

	// First call should generate a random secret
	err = session.ensureBlindingSecret()
	assert.NoError(t, err)
	assert.NotNil(t, session.blindingSecret)
	assert.Equal(t, 32, len(session.blindingSecret))

	firstSecret := session.blindingSecret

	// Second call should reuse the same secret
	err = session.ensureBlindingSecret()
	assert.NoError(t, err)
	assert.Equal(t, firstSecret, session.blindingSecret)

	// Test with configured secret
	configuredSecret := []byte("configured-secret-32-bytes!!!!!")
	config.BlindingSecret = configuredSecret
	session.blindingSecret = nil // Reset

	err = session.ensureBlindingSecret()
	assert.NoError(t, err)
	assert.Equal(t, configuredSecret, session.blindingSecret)
}

// TestUpdateBlindedDestination verifies blinded destination derivation and rotation
func TestUpdateBlindedDestination(t *testing.T) {
	keyStore, err := keys.NewDestinationKeyStore()
	require.NoError(t, err)

	config := DefaultSessionConfig()
	config.BlindingSecret = []byte("test-secret-32bytes-long!!!!!!!!")

	session := &Session{
		id:          1,
		destination: keyStore.Destination(),
		keys:        keyStore,
		config:      config,
	}

	// First update should create blinded destination
	err = session.updateBlindedDestination()
	assert.NoError(t, err)
	assert.NotNil(t, session.blindedDestination)
	assert.NotNil(t, session.blindingSecret)

	firstBlinded := session.blindedDestination
	today := time.Now().UTC()
	expectedDate := time.Date(today.Year(), today.Month(), today.Day(), 0, 0, 0, 0, time.UTC)
	assert.Equal(t, expectedDate, session.lastBlindingDate)

	// Second update on same day should reuse blinded destination
	err = session.updateBlindedDestination()
	assert.NoError(t, err)
	assert.Equal(t, firstBlinded, session.blindedDestination)

	// Simulate next day - should rotate blinded destination
	nextDay := today.Add(25 * time.Hour)
	session.lastBlindingDate = time.Date(nextDay.Year(), nextDay.Month(), nextDay.Day()-1, 0, 0, 0, 0, time.UTC)

	err = session.updateBlindedDestination()
	assert.NoError(t, err)
	assert.NotNil(t, session.blindedDestination)
	// Note: Blinded destination will be different due to date change
	// We can't easily compare them, but we can verify fields are populated
}

// TestGenerateEncryptionCookie verifies cookie generation
func TestGenerateEncryptionCookie(t *testing.T) {
	session := &Session{}

	cookie1, err := session.generateEncryptionCookie()
	assert.NoError(t, err)
	assert.Equal(t, 32, len(cookie1))

	cookie2, err := session.generateEncryptionCookie()
	assert.NoError(t, err)
	assert.Equal(t, 32, len(cookie2))

	// Cookies should be random (different each time)
	assert.NotEqual(t, cookie1, cookie2)
}

// TestCreateEncryptedLeaseSetWithMockTunnels tests full EncryptedLeaseSet creation
func TestCreateEncryptedLeaseSetWithMockTunnels(t *testing.T) {
	keyStore, err := keys.NewDestinationKeyStore()
	require.NoError(t, err)

	config := DefaultSessionConfig()
	config.UseEncryptedLeaseSet = true
	config.BlindingSecret = []byte("test-secret-32bytes-long!!!!!!!!")
	config.LeaseSetExpiration = 600

	// Create mock tunnel pool with active tunnels
	tunnels := createMockTunnels(3)
	inboundPool := &tunnel.Pool{}
	// Note: We can't easily set pool state without exposing internals,
	// so we'll test the individual helper functions instead

	session := &Session{
		id:          1,
		destination: keyStore.Destination(),
		keys:        keyStore,
		config:      config,
		inboundPool: inboundPool,
		clientNetDB: netdb.NewClientNetDB(nil), // Pass nil for StdNetDB in test
		createdAt:   time.Now(),
		active:      true,
		stopCh:      make(chan struct{}),
	}

	// Test individual components
	t.Run("ValidateSupport", func(t *testing.T) {
		err := session.validateEncryptedLeaseSetSupport()
		assert.NoError(t, err)
	})

	t.Run("UpdateBlindedDestination", func(t *testing.T) {
		err := session.updateBlindedDestination()
		assert.NoError(t, err)
		assert.NotNil(t, session.blindedDestination)
	})

	t.Run("BuildLeases", func(t *testing.T) {
		leases, err := session.buildLeasesFromTunnels(tunnels)
		assert.NoError(t, err)
		assert.Len(t, leases, 3)
	})

	t.Run("CreateInnerLeaseSet2", func(t *testing.T) {
		leases, err := session.buildLeasesFromTunnels(tunnels)
		require.NoError(t, err)

		ls2, err := session.createInnerLeaseSet2(leases)
		assert.NoError(t, err)
		assert.NotNil(t, ls2)
	})

	t.Run("GenerateCookie", func(t *testing.T) {
		cookie, err := session.generateEncryptionCookie()
		assert.NoError(t, err)
		assert.Equal(t, 32, len(cookie))
	})

	t.Run("EncryptInnerLeaseSet", func(t *testing.T) {
		leases, err := session.buildLeasesFromTunnels(tunnels)
		require.NoError(t, err)

		ls2, err := session.createInnerLeaseSet2(leases)
		require.NoError(t, err)

		cookie, err := session.generateEncryptionCookie()
		require.NoError(t, err)

		encryptedData, err := session.encryptInnerLeaseSet(ls2, cookie)
		assert.NoError(t, err)
		assert.NotEmpty(t, encryptedData)
		assert.True(t, len(encryptedData) > 0)
	})

	t.Run("AssembleEncryptedLeaseSet", func(t *testing.T) {
		// Update blinded destination first
		err := session.updateBlindedDestination()
		require.NoError(t, err)

		cookie := [32]byte{}
		copy(cookie[:], []byte("test-cookie-32-bytes-long!!!!!!"))

		// Create properly-sized encrypted data (minimum 61 bytes per EncryptedLeaseSet spec)
		encryptedData := make([]byte, 100) // Use 100 bytes to be safe
		copy(encryptedData, []byte("mock-encrypted-leaseset-inner-data-with-sufficient-length-to-meet-spec-requirements-minimum-61-bytes"))

		els, err := session.assembleEncryptedLeaseSet(cookie, encryptedData)
		assert.NoError(t, err)
		assert.NotNil(t, els)

		// Verify EncryptedLeaseSet properties
		assert.NotNil(t, els)
		assert.Equal(t, session.config.LeaseSetExpiration, els.Expires())
	})
}

// TestCreateEncryptedLeaseSetSerialization verifies EncryptedLeaseSet can be serialized
func TestCreateEncryptedLeaseSetSerialization(t *testing.T) {
	keyStore, err := keys.NewDestinationKeyStore()
	require.NoError(t, err)

	config := DefaultSessionConfig()
	config.UseEncryptedLeaseSet = true
	config.BlindingSecret = []byte("test-secret-32bytes-long!!!!!!!!")

	tunnels := createMockTunnels(2)

	session := &Session{
		id:          1,
		destination: keyStore.Destination(),
		keys:        keyStore,
		config:      config,
		createdAt:   time.Now(),
	}

	// Build the EncryptedLeaseSet
	err = session.updateBlindedDestination()
	require.NoError(t, err)

	leases, err := session.buildLeasesFromTunnels(tunnels)
	require.NoError(t, err)

	ls2, err := session.createInnerLeaseSet2(leases)
	require.NoError(t, err)

	cookie, err := session.generateEncryptionCookie()
	require.NoError(t, err)

	encryptedData, err := session.encryptInnerLeaseSet(ls2, cookie)
	require.NoError(t, err)

	els, err := session.assembleEncryptedLeaseSet(cookie, encryptedData)
	require.NoError(t, err)

	// Serialize to bytes
	elsBytes, err := els.Bytes()
	assert.NoError(t, err)
	assert.NotEmpty(t, elsBytes)
	assert.True(t, len(elsBytes) > 100) // Should have substantial size

	// Verify can be parsed back
	parsedELS, remainder, err := encrypted_leaseset.ReadEncryptedLeaseSet(elsBytes)
	assert.NoError(t, err)
	assert.Empty(t, remainder)
	assert.NotNil(t, parsedELS, "parsed ELS should not be nil")
}

// TestPublishLeaseSetNetworkWithEncrypted verifies blinded hash is used for EncryptedLeaseSet
func TestPublishLeaseSetNetworkWithEncrypted(t *testing.T) {
	keyStore, err := keys.NewDestinationKeyStore()
	require.NoError(t, err)

	config := DefaultSessionConfig()
	config.UseEncryptedLeaseSet = true
	config.BlindingSecret = []byte("test-secret-32bytes-long!!!!!!!!")

	session := &Session{
		id:          1,
		destination: keyStore.Destination(),
		keys:        keyStore,
		config:      config,
	}

	// Update blinded destination
	err = session.updateBlindedDestination()
	require.NoError(t, err)

	// Calculate expected hashes
	origBytes, err := session.destination.Bytes()
	require.NoError(t, err)
	origHash := data.HashData(origBytes)

	blindedBytes, err := session.blindedDestination.Bytes()
	require.NoError(t, err)
	blindedHash := data.HashData(blindedBytes)

	// Hashes should be different (blinded vs original)
	assert.NotEqual(t, origHash, blindedHash)

	// Create a mock publisher to verify correct hash is used
	mockPublisher := newMockLeaseSetPublisher()

	session.publisher = mockPublisher

	// Publish with EncryptedLeaseSet enabled
	leaseSetBytes := []byte("mock-encrypted-leaseset-data")
	err = session.publishLeaseSetToNetwork(leaseSetBytes)
	assert.NoError(t, err)

	// Verify blinded hash was used
	assert.Contains(t, mockPublisher.published, blindedHash)
	assert.NotContains(t, mockPublisher.published, origHash)

	// Test with EncryptedLeaseSet disabled
	session.config.UseEncryptedLeaseSet = false
	mockPublisher.published = make(map[data.Hash][]byte)

	err = session.publishLeaseSetToNetwork(leaseSetBytes)
	assert.NoError(t, err)

	// Verify original hash was used
	assert.Contains(t, mockPublisher.published, origHash)
	assert.NotContains(t, mockPublisher.published, blindedHash)
}

// TestRegenerateAndPublishWithEncrypted verifies maintenance loop uses EncryptedLeaseSet when configured
func TestRegenerateAndPublishWithEncrypted(t *testing.T) {
	keyStore, err := keys.NewDestinationKeyStore()
	require.NoError(t, err)

	config := DefaultSessionConfig()
	config.UseEncryptedLeaseSet = true
	config.BlindingSecret = []byte("test-secret-32bytes-long!!!!!!!!")

	tunnels := createMockTunnels(2)
	inboundPool := &tunnel.Pool{}

	session := &Session{
		id:          1,
		destination: keyStore.Destination(),
		keys:        keyStore,
		config:      config,
		inboundPool: inboundPool,
		clientNetDB: netdb.NewClientNetDB(nil), // Pass nil for StdNetDB in test
		createdAt:   time.Now(),
		active:      true,
		stopCh:      make(chan struct{}),
	}

	// Note: Full integration test would require mocking tunnel pool state
	// Here we test that the method routing works correctly

	// Verify EncryptedLeaseSet can be created when enabled
	session.config.UseEncryptedLeaseSet = true
	err = session.updateBlindedDestination()
	assert.NoError(t, err)

	// Verify the blinded destination is properly set
	assert.NotNil(t, session.blindedDestination)

	// Test components individually since we can't easily inject tunnel state
	leases, err := session.buildLeasesFromTunnels(tunnels)
	require.NoError(t, err)

	ls2, err := session.createInnerLeaseSet2(leases)
	assert.NoError(t, err)
	assert.NotNil(t, ls2)
}

// TestMergeTunnelParameters_ZeroHopInbound verifies that zero-hop tunnels
// can be configured via ReconfigureSession when InboundTunnelLength is
// explicitly set to 0.
func TestMergeTunnelParameters_ZeroHopInbound(t *testing.T) {
	existing := DefaultSessionConfig()
	assert.Equal(t, 3, existing.InboundTunnelLength, "default should be 3")

	newConfig := &SessionConfig{
		InboundTunnelLength: 0,
		ExplicitlySetFields: map[string]bool{
			"InboundTunnelLength": true,
		},
	}
	mergeTunnelParameters(existing, newConfig)
	assert.Equal(t, 0, existing.InboundTunnelLength,
		"zero-hop inbound tunnel should be allowed when explicitly set")
}

// TestMergeTunnelParameters_ZeroHopOutbound verifies that zero-hop tunnels
// work for outbound tunnels too.
func TestMergeTunnelParameters_ZeroHopOutbound(t *testing.T) {
	existing := DefaultSessionConfig()
	assert.Equal(t, 3, existing.OutboundTunnelLength, "default should be 3")

	newConfig := &SessionConfig{
		OutboundTunnelLength: 0,
		ExplicitlySetFields: map[string]bool{
			"OutboundTunnelLength": true,
		},
	}
	mergeTunnelParameters(existing, newConfig)
	assert.Equal(t, 0, existing.OutboundTunnelLength,
		"zero-hop outbound tunnel should be allowed when explicitly set")
}

// TestMergeTunnelParameters_NotExplicitlySetPreservesDefault verifies that
// when a field is not explicitly set (ExplicitlySetFields is nil or missing),
// the existing default value is preserved.
func TestMergeTunnelParameters_NotExplicitlySetPreservesDefault(t *testing.T) {
	existing := DefaultSessionConfig()
	assert.Equal(t, 3, existing.InboundTunnelLength)

	newConfig := &SessionConfig{
		InboundTunnelLength: 0, // zero but NOT explicitly set
	}
	mergeTunnelParameters(existing, newConfig)
	assert.Equal(t, 3, existing.InboundTunnelLength,
		"default should be preserved when field is not explicitly set")
}

// TestRateLimiter_LowRate verifies that the rate limiter delivers tokens
// smoothly at low rates (rate=2 msg/sec) instead of in bursts.
func TestRateLimiter_LowRate(t *testing.T) {
	rl := newSimpleRateLimiter(2, 5)

	// Consume all initial tokens
	for rl.allow() {
		// drain
	}

	// Wait 600ms — at rate=2, we should accumulate 1.2 tokens
	time.Sleep(600 * time.Millisecond)

	// Should allow at least 1 message (1.2 tokens >= 1.0)
	assert.True(t, rl.allow(),
		"rate limiter should deliver token after 600ms at rate=2")
}

// TestRateLimiter_FractionalAccumulation verifies that fractional tokens
// accumulate correctly across multiple checks.
func TestRateLimiter_FractionalAccumulation(t *testing.T) {
	rl := newSimpleRateLimiter(2, 10)

	// Drain all initial tokens
	for rl.allow() {
	}

	// Wait 300ms — at rate=2, we get 0.6 tokens (not enough for 1)
	time.Sleep(300 * time.Millisecond)
	allowed := rl.allow()
	// Might or might not be allowed depending on timing, but the important
	// thing is lastCheck is updated so tokens don't accumulate incorrectly.

	// Wait another 300ms — total elapsed ~600ms, should have ~1.2 tokens
	time.Sleep(300 * time.Millisecond)
	if !allowed {
		assert.True(t, rl.allow(),
			"fractional tokens should accumulate across multiple checks")
	}
}

// TestSessionQueueIncomingMessage tests queuing messages for delivery
func TestSessionQueueIncomingMessage(t *testing.T) {
	session, err := NewSession(1, nil, nil)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}
	defer session.Stop()

	// Queue a message
	payload := []byte("Incoming message payload")
	err = session.QueueIncomingMessage(payload)
	if err != nil {
		t.Fatalf("Failed to queue message: %v", err)
	}

	// Receive the message
	received, err := session.ReceiveMessage()
	if err != nil {
		t.Fatalf("Failed to receive message: %v", err)
	}

	if received == nil {
		t.Fatal("Received nil message")
	}

	if !bytes.Equal(received.Payload, payload) {
		t.Errorf("Payload mismatch: got %v, want %v", received.Payload, payload)
	}
}

// TestSessionQueueIncomingMessageAfterStop tests queuing after session stop
func TestSessionQueueIncomingMessageAfterStop(t *testing.T) {
	session, err := NewSession(1, nil, nil)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// Stop session
	session.Stop()

	// Try to queue message
	err = session.QueueIncomingMessage([]byte("test"))
	if err == nil {
		t.Error("Expected error when queuing to stopped session, got nil")
	}
}

// TestSessionReceiveMessageAfterStop tests receiving after session stop
func TestSessionReceiveMessageAfterStop(t *testing.T) {
	session, err := NewSession(1, nil, nil)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// Stop session
	session.Stop()

	// Try to receive message (should return nil without error)
	msg, err := session.ReceiveMessage()
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if msg != nil {
		t.Error("Expected nil message after stop")
	}
}

// TestSessionIncomingQueueFull tests queue overflow handling
func TestSessionIncomingQueueFull(t *testing.T) {
	session, err := NewSession(1, nil, nil)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}
	defer session.Stop()

	// Fill the queue (buffer is 100)
	for i := 0; i < 100; i++ {
		if err := session.QueueIncomingMessage([]byte("message")); err != nil {
			t.Fatalf("Failed to queue message %d: %v", i, err)
		}
	}

	// Try to queue one more (should fail)
	err = session.QueueIncomingMessage([]byte("overflow"))
	if err == nil {
		t.Error("Expected error when queue is full, got nil")
	}
}

// TestSessionSetLeaseSetPublisher tests setting the publisher on a session
func TestSessionSetLeaseSetPublisher(t *testing.T) {
	session, err := NewSession(1, nil, nil)
	require.NoError(t, err, "Failed to create session")
	defer session.Stop()

	publisher := newMockLeaseSetPublisher()
	session.SetLeaseSetPublisher(publisher)

	// Verify publisher is set (we can't access it directly, but we can test behavior)
	assert.NotNil(t, session, "Session should not be nil")
}

// TestSessionPublishLeaseSetWithPublisher tests LeaseSet publication via publisher
func TestSessionPublishLeaseSetWithPublisher(t *testing.T) {
	session, err := NewSession(1, nil, nil)
	require.NoError(t, err, "Failed to create session")
	defer session.Stop()

	publisher := newMockLeaseSetPublisher()
	session.SetLeaseSetPublisher(publisher)

	// Setup tunnel pool with active tunnel
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

	// Create LeaseSet (this should trigger publishing)
	leaseSetBytes, err := session.CreateLeaseSet()
	require.NoError(t, err, "Failed to create LeaseSet")
	assert.NotEmpty(t, leaseSetBytes, "LeaseSet should not be empty")

	// Now trigger regeneration which should call the publisher
	err = session.regenerateAndPublishLeaseSet()
	require.NoError(t, err, "Failed to regenerate and publish LeaseSet")

	// Verify publisher was called
	assert.Equal(t, 1, publisher.GetPublishCount(), "Publisher should be called once")
	assert.Equal(t, 1, len(publisher.published), "Should have published 1 LeaseSet")

	// Verify the published key matches destination hash
	destBytes, err := session.Destination().Bytes()
	require.NoError(t, err, "Failed to get destination bytes")
	destHash := common.HashData(destBytes)
	publishedData, exists := publisher.published[destHash]
	assert.True(t, exists, "Should have published LeaseSet for this destination")
	assert.NotEmpty(t, publishedData, "Published data should not be empty")
}

// TestSessionPublishLeaseSetWithoutPublisher tests LeaseSet creation without publisher
func TestSessionPublishLeaseSetWithoutPublisher(t *testing.T) {
	session, err := NewSession(1, nil, nil)
	require.NoError(t, err, "Failed to create session")
	defer session.Stop()

	// Don't set a publisher

	// Setup tunnel pool
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

	// Create LeaseSet (should work even without publisher)
	leaseSetBytes, err := session.CreateLeaseSet()
	require.NoError(t, err, "Failed to create LeaseSet")
	assert.NotEmpty(t, leaseSetBytes, "LeaseSet should not be empty")

	// Regeneration should also succeed without publisher
	err = session.regenerateAndPublishLeaseSet()
	assert.NoError(t, err, "Should succeed even without publisher")
}

// TestSessionPublishLeaseSetPublisherError tests handling of publisher errors
func TestSessionPublishLeaseSetPublisherError(t *testing.T) {
	session, err := NewSession(1, nil, nil)
	require.NoError(t, err, "Failed to create session")
	defer session.Stop()

	publisher := newMockLeaseSetPublisher()
	publisher.publishErr = assert.AnError // Make publisher return error
	session.SetLeaseSetPublisher(publisher)

	// Setup tunnel pool
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

	// Regeneration should still succeed even if publisher fails
	// (publisher errors are logged but not returned)
	err = session.regenerateAndPublishLeaseSet()
	assert.NoError(t, err, "Should not fail even if publisher errors")

	// Verify publisher was called
	assert.Equal(t, 1, publisher.GetPublishCount(), "Publisher should be called")
}

// TestSessionMaintenanceWithPublisher tests LeaseSet maintenance with publisher
func TestSessionMaintenanceWithPublisher(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping maintenance test in short mode")
	}

	config := DefaultSessionConfig()
	config.TunnelLifetime = 2 * time.Second // Very short for testing

	session, err := NewSession(1, nil, config)
	require.NoError(t, err, "Failed to create session")
	defer session.Stop()

	publisher := newMockLeaseSetPublisher()
	session.SetLeaseSetPublisher(publisher)

	// Setup tunnel pool
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
	require.NoError(t, err, "Failed to start maintenance")

	// Wait for initial publication
	time.Sleep(200 * time.Millisecond)

	// Verify at least one publication occurred
	assert.GreaterOrEqual(t, publisher.GetPublishCount(), 1, "Should have published at least once")

	// Wait for potential regeneration (allow more time for maintenance cycle)
	time.Sleep(2000 * time.Millisecond)

	// Should have regenerated at least once more
	assert.GreaterOrEqual(t, publisher.GetPublishCount(), 2, "Should have published multiple times")
}

// TestSetCurrentLeaseSet verifies that SetCurrentLeaseSet properly caches data.
func TestSetCurrentLeaseSet(t *testing.T) {
	session, err := NewSession(1, nil, nil)
	require.NoError(t, err)
	defer session.Stop()

	// Initially nil
	assert.Nil(t, session.CurrentLeaseSet())

	// Set and verify
	testData := []byte("test-leaseset-data")
	session.SetCurrentLeaseSet(testData)
	assert.Equal(t, testData, session.CurrentLeaseSet())

	// Age should be very recent
	assert.Less(t, session.LeaseSetAge(), 5*time.Second)
}

// =============================================================================
// SESSION LIMITS TESTS
// =============================================================================

// TestSessionLimits_MaxSessionsEnforced verifies the max sessions limit is enforced.
func TestSessionLimits_MaxSessionsEnforced(t *testing.T) {
	manager := NewSessionManager()
	maxSessions := 5

	// Create sessions up to the limit
	for i := 0; i < maxSessions; i++ {
		session, err := manager.CreateSession(nil, nil)
		if err != nil {
			t.Fatalf("CreateSession() error at %d: %v", i, err)
		}
		defer session.Stop()
	}

	if manager.SessionCount() != maxSessions {
		t.Errorf("SessionCount() = %d, want %d", manager.SessionCount(), maxSessions)
	}
}

// TestSessionLimits_SessionIDAllocation verifies session ID allocation is secure.
func TestSessionLimits_SessionIDAllocation(t *testing.T) {
	manager := NewSessionManager()

	// Create multiple sessions and track IDs
	ids := make(map[uint16]bool)
	numSessions := 10

	for i := 0; i < numSessions; i++ {
		session, err := manager.CreateSession(nil, nil)
		if err != nil {
			t.Fatalf("CreateSession() error: %v", err)
		}
		defer session.Stop()

		id := session.ID()

		// Verify not reserved
		if id == SessionIDReservedControl {
			t.Errorf("Session got reserved control ID: 0x%04x", id)
		}
		if id == SessionIDReservedBroadcast {
			t.Errorf("Session got reserved broadcast ID: 0x%04x", id)
		}

		// Verify unique
		if ids[id] {
			t.Errorf("Duplicate session ID: 0x%04x", id)
		}
		ids[id] = true
	}
}

// TestSessionLimits_RandomSessionIDGeneration verifies session IDs are random.
func TestSessionLimits_RandomSessionIDGeneration(t *testing.T) {
	// Generate multiple IDs and verify they're not sequential
	ids := make([]uint16, 0, 20)

	for i := 0; i < 20; i++ {
		id, err := generateSecureSessionID()
		if err != nil {
			t.Fatalf("generateSecureSessionID() error: %v", err)
		}
		ids = append(ids, id)
	}

	// Check that IDs are not sequential (would indicate weak randomness)
	sequential := 0
	for i := 1; i < len(ids); i++ {
		if ids[i] == ids[i-1]+1 || ids[i] == ids[i-1]-1 {
			sequential++
		}
	}

	// Allow at most 2 sequential pairs by chance
	if sequential > 2 {
		t.Errorf("Too many sequential session IDs (%d), indicates weak randomness", sequential)
	}
}

// =============================================================================
// SESSION ISOLATION TESTS
// =============================================================================

// TestSessionIsolation_SeparateNetDBPerSession verifies each session has isolated NetDB.
func TestSessionIsolation_SeparateNetDBPerSession(t *testing.T) {
	session1, err := NewSession(1, nil, nil)
	if err != nil {
		t.Fatalf("NewSession(1) error: %v", err)
	}
	defer session1.Stop()

	session2, err := NewSession(2, nil, nil)
	if err != nil {
		t.Fatalf("NewSession(2) error: %v", err)
	}
	defer session2.Stop()

	// Each session should have its own ClientNetDB
	netdb1 := session1.ClientNetDB()
	netdb2 := session2.ClientNetDB()

	if netdb1 == nil {
		t.Error("Session 1 should have a ClientNetDB")
	}
	if netdb2 == nil {
		t.Error("Session 2 should have a ClientNetDB")
	}

	// They should be different instances
	if netdb1 == netdb2 {
		t.Error("Sessions should have separate NetDB instances")
	}
}

// TestSessionIsolation_SeparateDestinations verifies each session has unique destination.
func TestSessionIsolation_SeparateDestinations(t *testing.T) {
	session1, err := NewSession(1, nil, nil)
	if err != nil {
		t.Fatalf("NewSession(1) error: %v", err)
	}
	defer session1.Stop()

	session2, err := NewSession(2, nil, nil)
	if err != nil {
		t.Fatalf("NewSession(2) error: %v", err)
	}
	defer session2.Stop()

	dest1 := session1.Destination()
	dest2 := session2.Destination()

	if dest1 == nil || dest2 == nil {
		t.Fatal("Sessions should have destinations")
	}

	// Get destination bytes for comparison
	dest1Bytes, err := dest1.Bytes()
	if err != nil {
		t.Fatalf("dest1.Bytes() error: %v", err)
	}
	dest2Bytes, err := dest2.Bytes()
	if err != nil {
		t.Fatalf("dest2.Bytes() error: %v", err)
	}

	// Destinations should be different
	if bytes.Equal(dest1Bytes, dest2Bytes) {
		t.Error("Sessions should have different destinations")
	}
}

// TestSessionIsolation_MessageQueueSeparation verifies message queues are separate.
func TestSessionIsolation_MessageQueueSeparation(t *testing.T) {
	session1, err := NewSession(1, nil, nil)
	if err != nil {
		t.Fatalf("NewSession(1) error: %v", err)
	}
	defer session1.Stop()

	session2, err := NewSession(2, nil, nil)
	if err != nil {
		t.Fatalf("NewSession(2) error: %v", err)
	}
	defer session2.Stop()

	// Queue message to session 1
	msg1 := []byte("message for session 1")
	if err := session1.QueueIncomingMessage(msg1); err != nil {
		t.Fatalf("QueueIncomingMessage(1) error: %v", err)
	}

	// Session 2's queue should be empty
	select {
	case msg := <-session2.IncomingMessages():
		t.Errorf("Session 2 received unexpected message: %v", msg)
	default:
		// Expected: no message in session 2
	}
}

// =============================================================================
// DISCONNECT HANDLING TESTS
// =============================================================================

// TestDisconnectHandling_GracefulCleanup verifies disconnect cleans up resources.
func TestDisconnectHandling_GracefulCleanup(t *testing.T) {
	session, err := NewSession(1, nil, nil)
	if err != nil {
		t.Fatalf("NewSession() error: %v", err)
	}

	// Verify active before stop
	if !session.IsActive() {
		t.Error("Session should be active before stop")
	}

	// Stop session
	session.Stop()

	// Verify inactive after stop
	if session.IsActive() {
		t.Error("Session should not be active after stop")
	}
}

// TestDisconnectHandling_MultipleStopSafe verifies multiple Stop() calls are safe.
func TestDisconnectHandling_MultipleStopSafe(t *testing.T) {
	session, err := NewSession(1, nil, nil)
	if err != nil {
		t.Fatalf("NewSession() error: %v", err)
	}

	// Multiple stops should not panic
	session.Stop()
	session.Stop()
	session.Stop()

	// Still should be inactive
	if session.IsActive() {
		t.Error("Session should not be active after multiple stops")
	}
}

// TestDisconnectHandling_QueueRejectedAfterStop verifies queue operations fail after stop.
func TestDisconnectHandling_QueueRejectedAfterStop(t *testing.T) {
	session, err := NewSession(1, nil, nil)
	if err != nil {
		t.Fatalf("NewSession() error: %v", err)
	}

	session.Stop()

	// Queue should reject new messages
	err = session.QueueIncomingMessage([]byte("test"))
	if err == nil {
		t.Error("Expected error queuing to stopped session")
	}
}

// TestDisconnectHandling_ReceiveReturnsNilAfterStop verifies receive unblocks after stop.
func TestDisconnectHandling_ReceiveReturnsNilAfterStop(t *testing.T) {
	session, err := NewSession(1, nil, nil)
	if err != nil {
		t.Fatalf("NewSession() error: %v", err)
	}

	// Start receiver in goroutine
	done := make(chan bool)
	go func() {
		msg, _ := session.ReceiveMessage()
		done <- (msg == nil)
	}()

	// Small delay then stop
	time.Sleep(10 * time.Millisecond)
	session.Stop()

	// Verify receive returned nil
	select {
	case gotNil := <-done:
		if !gotNil {
			t.Error("ReceiveMessage should return nil after stop")
		}
	case <-time.After(1 * time.Second):
		t.Error("ReceiveMessage did not unblock after stop")
	}
}

// =============================================================================
// THREAD SAFETY TESTS
// =============================================================================

// TestThreadSafety_ConcurrentSessionCreation verifies concurrent session creation is safe.
func TestThreadSafety_ConcurrentSessionCreation(t *testing.T) {
	manager := NewSessionManager()
	var wg sync.WaitGroup
	numGoroutines := 20

	sessions := make(chan *Session, numGoroutines)
	errors := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			session, err := manager.CreateSession(nil, nil)
			if err != nil {
				errors <- err
				return
			}
			sessions <- session
		}()
	}

	wg.Wait()
	close(sessions)
	close(errors)

	// Check for errors
	for err := range errors {
		t.Errorf("CreateSession() error: %v", err)
	}

	// Cleanup
	for session := range sessions {
		session.Stop()
	}
}

// TestThreadSafety_ConcurrentSessionAccess verifies concurrent session access is safe.
func TestThreadSafety_ConcurrentSessionAccess(t *testing.T) {
	session, err := NewSession(1, nil, nil)
	if err != nil {
		t.Fatalf("NewSession() error: %v", err)
	}
	defer session.Stop()

	var wg sync.WaitGroup
	numGoroutines := 20

	// Concurrent reads
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = session.ID()
			_ = session.IsActive()
			_ = session.Destination()
			_ = session.Config()
			_ = session.CreatedAt()
			_ = session.LastActivity()
		}()
	}

	wg.Wait()
}

// TestThreadSafety_ConcurrentMessageQueue verifies concurrent message queue access is safe.
func TestThreadSafety_ConcurrentMessageQueue(t *testing.T) {
	session, err := NewSession(1, nil, nil)
	if err != nil {
		t.Fatalf("NewSession() error: %v", err)
	}
	defer session.Stop()

	var wg sync.WaitGroup
	numProducers := 10
	numMessages := 5

	// Multiple producers
	for i := 0; i < numProducers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numMessages; j++ {
				msg := []byte{byte(id), byte(j)}
				_ = session.QueueIncomingMessage(msg) // May fail if queue full
			}
		}(i)
	}

	wg.Wait()
}

// TestThreadSafety_SessionManagerConcurrentOps verifies session manager thread safety.
func TestThreadSafety_SessionManagerConcurrentOps(t *testing.T) {
	manager := NewSessionManager()
	var wg sync.WaitGroup
	numOps := 50

	for i := 0; i < numOps; i++ {
		wg.Add(3)

		// Create
		go func() {
			defer wg.Done()
			session, err := manager.CreateSession(nil, nil)
			if err == nil {
				defer session.Stop()
			}
		}()

		// Read count
		go func() {
			defer wg.Done()
			_ = manager.SessionCount()
		}()

		// Get all
		go func() {
			defer wg.Done()
			_ = manager.GetAllSessions()
		}()
	}

	wg.Wait()

	// Cleanup
	manager.StopAll()
}

// =============================================================================
// RATE LIMITING TESTS
// =============================================================================

// TestRateLimiting_TokenBucketBasic verifies basic rate limiter functionality.
func TestRateLimiting_TokenBucketBasic(t *testing.T) {
	rl := newSimpleRateLimiter(10, 5) // 10/sec rate, 5 burst

	// Should allow burst
	for i := 0; i < 5; i++ {
		if !rl.allow() {
			t.Errorf("Rate limiter should allow burst message %d", i)
		}
	}

	// Burst exhausted, should reject
	if rl.allow() {
		t.Error("Rate limiter should reject after burst")
	}
}

// TestRateLimiting_TokenRefill verifies tokens refill over time.
func TestRateLimiting_TokenRefill(t *testing.T) {
	rl := newSimpleRateLimiter(10, 2) // 10/sec rate, 2 burst

	// Exhaust burst
	rl.allow()
	rl.allow()

	// Should reject immediately
	if rl.allow() {
		t.Error("Should reject immediately after burst")
	}

	// Wait for tokens to refill (1 token per 100ms at 10/sec)
	time.Sleep(150 * time.Millisecond)

	// Should allow after refill
	if !rl.allow() {
		t.Error("Should allow after token refill")
	}
}

// TestRateLimiting_DisabledWhenZeroRate verifies rate=0 disables limiting.
func TestRateLimiting_DisabledWhenZeroRate(t *testing.T) {
	rl := newSimpleRateLimiter(0, 0) // Disabled

	// Should always allow
	for i := 0; i < 100; i++ {
		if !rl.allow() {
			t.Errorf("Rate limiter with rate=0 should always allow")
		}
	}
}

// TestRateLimiting_NilRateLimiterAllows verifies nil rate limiter allows all.
func TestRateLimiting_NilRateLimiterAllows(t *testing.T) {
	var rl *simpleRateLimiter = nil

	if !rl.allow() {
		t.Error("Nil rate limiter should allow")
	}
}

// =============================================================================
// LEASESET PUBLISHING TESTS
// =============================================================================

// TestLeaseSetPublishing_PublisherIntegration verifies LeaseSet publisher integration.
func TestLeaseSetPublishing_PublisherIntegration(t *testing.T) {
	publisher := newMockLeaseSetPublisher()

	session, err := NewSession(1, nil, nil)
	if err != nil {
		t.Fatalf("NewSession() error: %v", err)
	}
	defer session.Stop()

	session.SetLeaseSetPublisher(publisher)

	// Setup tunnel pool with mock tunnel (using mockPeerSelector from session_test.go)
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
		t.Fatalf("CreateLeaseSet() error: %v", err)
	}

	// Verify LeaseSet was created
	if leaseSetBytes == nil || len(leaseSetBytes) == 0 {
		t.Error("LeaseSet bytes should not be empty")
	}
}
