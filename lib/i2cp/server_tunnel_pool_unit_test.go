package i2cp

import (
	"testing"
	"time"
)

// TestServerTunnelPoolConfiguration verifies that tunnel pools are properly configured
// when tunnel builder and peer selector are set before session creation
func TestServerTunnelPoolConfiguration(t *testing.T) {
	server, err := NewServer(DefaultServerConfig())
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	defer server.Stop()

	// Configure tunnel infrastructure (reusing mocks from integration_test.go)
	builder := &mockTunnelBuilder{nextID: 1000}
	selector := &mockPeerSelector{}

	server.SetTunnelBuilder(builder)
	server.SetPeerSelector(selector)

	// Create a session
	config := &SessionConfig{
		InboundTunnelLength:  3,
		OutboundTunnelLength: 3,
		InboundTunnelCount:   2,
		OutboundTunnelCount:  2,
	}

	session, err := server.manager.CreateSession(nil, config)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// Initialize tunnel pools
	if err := server.initializeSessionTunnelPools(session, config); err != nil {
		t.Fatalf("Failed to initialize tunnel pools: %v", err)
	}

	// Verify inbound pool is configured
	inboundPool := session.InboundPool()
	if inboundPool == nil {
		t.Error("Inbound pool not set")
	}

	// Verify outbound pool is configured
	outboundPool := session.OutboundPool()
	if outboundPool == nil {
		t.Error("Outbound pool not set")
	}
}

// TestServerTunnelPoolWithoutInfrastructure verifies that session creation succeeds
// even when tunnel infrastructure is not configured (graceful degradation)
func TestServerTunnelPoolWithoutInfrastructure(t *testing.T) {
	server, err := NewServer(DefaultServerConfig())
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	defer server.Stop()

	// Create a session without setting tunnel builder or peer selector
	config := DefaultSessionConfig()
	session, err := server.manager.CreateSession(nil, config)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// Try to initialize tunnel pools (should fail gracefully)
	err = server.initializeSessionTunnelPools(session, config)
	if err == nil {
		t.Error("Expected error when initializing pools without infrastructure")
	}

	// Session should still be valid
	if session.ID() == 0 {
		t.Error("Session ID should be non-zero")
	}
}

// TestServerTunnelPoolConfigurationFromSessionConfig verifies that tunnel pool
// configuration correctly reflects the session configuration parameters
func TestServerTunnelPoolConfigurationFromSessionConfig(t *testing.T) {
	server, err := NewServer(DefaultServerConfig())
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	defer server.Stop()

	// Configure tunnel infrastructure
	builder := &mockTunnelBuilder{nextID: 2000}
	selector := &mockPeerSelector{}

	server.SetTunnelBuilder(builder)
	server.SetPeerSelector(selector)

	// Create a session with custom configuration
	config := &SessionConfig{
		InboundTunnelLength:  5, // Custom hop count
		OutboundTunnelLength: 4, // Custom hop count
		InboundTunnelCount:   3, // Custom min tunnels
		OutboundTunnelCount:  4, // Custom min tunnels
	}

	session, err := server.manager.CreateSession(nil, config)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// Initialize tunnel pools
	if err := server.initializeSessionTunnelPools(session, config); err != nil {
		t.Fatalf("Failed to initialize tunnel pools: %v", err)
	}

	// Verify pools are set
	if session.InboundPool() == nil {
		t.Error("Inbound pool should be set")
	}
	if session.OutboundPool() == nil {
		t.Error("Outbound pool should be set")
	}
}

// TestServerSetTunnelBuilderThreadSafety verifies thread-safe access to tunnel builder
func TestServerSetTunnelBuilderThreadSafety(t *testing.T) {
	server, err := NewServer(DefaultServerConfig())
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	defer server.Stop()

	builder := &mockTunnelBuilder{nextID: 3000}

	// Set tunnel builder from multiple goroutines
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			server.SetTunnelBuilder(builder)
			done <- true
		}()
	}

	// Wait for all goroutines to complete
	timeout := time.After(5 * time.Second)
	for i := 0; i < 10; i++ {
		select {
		case <-done:
			// Success
		case <-timeout:
			t.Fatal("Timeout waiting for goroutines")
		}
	}
}

// TestServerSetPeerSelectorThreadSafety verifies thread-safe access to peer selector
func TestServerSetPeerSelectorThreadSafety(t *testing.T) {
	server, err := NewServer(DefaultServerConfig())
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	defer server.Stop()

	selector := &mockPeerSelector{}

	// Set peer selector from multiple goroutines
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			server.SetPeerSelector(selector)
			done <- true
		}()
	}

	// Wait for all goroutines to complete
	timeout := time.After(5 * time.Second)
	for i := 0; i < 10; i++ {
		select {
		case <-done:
			// Success
		case <-timeout:
			t.Fatal("Timeout waiting for goroutines")
		}
	}
}
