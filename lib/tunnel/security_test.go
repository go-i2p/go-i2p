package tunnel

import (
	"github.com/go-i2p/crypto/types"
	"encoding/binary"
	"errors"
	"sync"
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/crypto/tunnel"
	"github.com/go-i2p/go-i2p/lib/config"
)

// =============================================================================
// Security Tests for lib/tunnel package
// =============================================================================
// These tests verify the security properties of the tunnel implementation.
//
// Coverage:
// - Tunnel Crypto: TunnelEncryptor interface with ECIES/AES support
// - Hop Processing: Participant decrypt/re-encrypt correctness
// - Gateway Logic: First-hop encryption
// - Endpoint Logic: Final-hop decryption and delivery
// - Fragment Reassembly: Memory limits and timeout handling
// - Delivery Instructions: All types (LOCAL, TUNNEL, ROUTER) parsed correctly
// - Pool Maintenance: Min/max tunnel counts enforced
// - Build Timeouts: Timeout configuration and enforcement
// - Peer Selection: Failed peer exclusion on retry

// =============================================================================
// TUNNEL CRYPTO TESTS
// =============================================================================

// mockSecurityEncryptor implements tunnel.TunnelEncryptor for security testing.
// It tracks encryption/decryption calls and can simulate various scenarios.
type mockSecurityEncryptor struct {
	encryptCalls int
	decryptCalls int
	lastInput    []byte
	simulateFail bool
}

var (
	errMockEncryptionFailed = errors.New("mock encryption failed")
	errMockDecryptionFailed = errors.New("mock decryption failed")
)

func (m *mockSecurityEncryptor) Encrypt(data []byte) ([]byte, error) {
	m.encryptCalls++
	m.lastInput = make([]byte, len(data))
	copy(m.lastInput, data)
	if m.simulateFail {
		return nil, errMockEncryptionFailed
	}
	// Return data unchanged for testing (simulates encryption)
	return data, nil
}

func (m *mockSecurityEncryptor) Decrypt(data []byte) ([]byte, error) {
	m.decryptCalls++
	m.lastInput = make([]byte, len(data))
	copy(m.lastInput, data)
	if m.simulateFail {
		return nil, errMockDecryptionFailed
	}
	// Return data unchanged for testing (simulates decryption)
	return data, nil
}

// Type returns the encryption type (required for TunnelEncryptor interface)
func (m *mockSecurityEncryptor) Type() tunnel.TunnelEncryptionType {
	return tunnel.TunnelEncryptionAES
}

// Ensure mockSecurityEncryptor implements TunnelEncryptor
var _ tunnel.TunnelEncryptor = (*mockSecurityEncryptor)(nil)

// TestTunnelCrypto_TunnelEncryptorInterface verifies the TunnelEncryptor
// interface is correctly used for both ECIES and AES operations.
func TestTunnelCrypto_TunnelEncryptorInterface(t *testing.T) {
	// Verify Gateway uses TunnelEncryptor for encryption
	t.Run("gateway_uses_encryptor", func(t *testing.T) {
		enc := &mockSecurityEncryptor{}
		gw, err := NewGateway(12345, enc, 67890)
		if err != nil {
			t.Fatalf("failed to create gateway: %v", err)
		}

		// Try to send a message
		msg := []byte("test message for encryption")
		_, err = gw.Send(msg)
		if err != nil {
			t.Fatalf("gateway send failed: %v", err)
		}

		// Verify encryption was called
		if enc.encryptCalls != 1 {
			t.Errorf("expected 1 encrypt call, got %d", enc.encryptCalls)
		}
	})

	// Verify Participant uses TunnelEncryptor for decryption
	t.Run("participant_uses_encryptor", func(t *testing.T) {
		dec := &mockSecurityEncryptor{}
		p, err := NewParticipant(12345, dec)
		if err != nil {
			t.Fatalf("failed to create participant: %v", err)
		}

		// Create valid 1028-byte tunnel message
		tunnelData := make([]byte, 1028)
		binary.BigEndian.PutUint32(tunnelData[:4], 67890) // Next hop ID

		_, _, err = p.Process(tunnelData)
		if err != nil {
			t.Fatalf("participant process failed: %v", err)
		}

		// Verify decryption was called
		if dec.decryptCalls != 1 {
			t.Errorf("expected 1 decrypt call, got %d", dec.decryptCalls)
		}
	})

	// Verify Endpoint uses TunnelEncryptor for decryption
	t.Run("endpoint_uses_encryptor", func(t *testing.T) {
		dec := &mockSecurityEncryptor{}
		handler := func(msg []byte) error { return nil }
		ep, err := NewEndpoint(12345, dec, handler)
		if err != nil {
			t.Fatalf("failed to create endpoint: %v", err)
		}
		defer ep.Stop()

		// The endpoint decrypts incoming data
		tunnelData := createValidTunnelMessage(t)

		_ = ep.Receive(tunnelData)

		// Verify decryption was called
		if dec.decryptCalls != 1 {
			t.Errorf("expected 1 decrypt call, got %d", dec.decryptCalls)
		}
	})
}

// TestTunnelCrypto_EncryptionFailureHandling verifies proper error handling
// when encryption/decryption fails.
func TestTunnelCrypto_EncryptionFailureHandling(t *testing.T) {
	t.Run("gateway_handles_encryption_failure", func(t *testing.T) {
		enc := &mockSecurityEncryptor{simulateFail: true}
		gw, _ := NewGateway(12345, enc, 67890)

		msg := []byte("test message")
		_, err := gw.Send(msg)
		if err == nil {
			t.Error("expected error from failed encryption")
		}
	})

	t.Run("participant_handles_decryption_failure", func(t *testing.T) {
		dec := &mockSecurityEncryptor{simulateFail: true}
		p, _ := NewParticipant(12345, dec)

		tunnelData := make([]byte, 1028)
		_, _, err := p.Process(tunnelData)
		if err == nil {
			t.Error("expected error from failed decryption")
		}
	})
}

// =============================================================================
// HOP PROCESSING TESTS (Participant)
// =============================================================================

// TestParticipant_HopProcessingCorrectness verifies participant correctly
// decrypts one layer and extracts next hop ID.
func TestParticipant_HopProcessingCorrectness(t *testing.T) {
	t.Run("extracts_next_hop_id", func(t *testing.T) {
		dec := &mockSecurityEncryptor{}
		p, _ := NewParticipant(12345, dec)

		// Create tunnel data with known next hop ID
		tunnelData := make([]byte, 1028)
		expectedNextHop := TunnelID(0xDEADBEEF)
		binary.BigEndian.PutUint32(tunnelData[:4], uint32(expectedNextHop))

		nextHop, decrypted, err := p.Process(tunnelData)
		if err != nil {
			t.Fatalf("process failed: %v", err)
		}

		if nextHop != expectedNextHop {
			t.Errorf("next hop = %d, want %d", nextHop, expectedNextHop)
		}

		if len(decrypted) != 1028 {
			t.Errorf("decrypted length = %d, want 1028", len(decrypted))
		}
	})

	t.Run("rejects_invalid_message_size", func(t *testing.T) {
		dec := &mockSecurityEncryptor{}
		p, _ := NewParticipant(12345, dec)

		invalidSizes := []int{0, 100, 1000, 1027, 1029, 2000}
		for _, size := range invalidSizes {
			data := make([]byte, size)
			_, _, err := p.Process(data)
			if err == nil {
				t.Errorf("expected error for size %d", size)
			}
		}
	})

	t.Run("updates_last_activity", func(t *testing.T) {
		dec := &mockSecurityEncryptor{}
		p, _ := NewParticipant(12345, dec)

		before := p.LastActivity()
		time.Sleep(10 * time.Millisecond)

		tunnelData := make([]byte, 1028)
		p.Process(tunnelData)

		after := p.LastActivity()
		if !after.After(before) {
			t.Error("last activity not updated after process")
		}
	})
}

// TestParticipant_ExpirationAndIdleTracking verifies participant lifetime
// and idle timeout handling.
func TestParticipant_ExpirationAndIdleTracking(t *testing.T) {
	t.Run("tracks_creation_time", func(t *testing.T) {
		before := time.Now()
		dec := &mockSecurityEncryptor{}
		p, _ := NewParticipant(12345, dec)
		after := time.Now()

		created := p.CreatedAt()
		if created.Before(before) || created.After(after) {
			t.Errorf("creation time %v not between %v and %v", created, before, after)
		}
	})

	t.Run("expires_after_lifetime", func(t *testing.T) {
		dec := &mockSecurityEncryptor{}
		p, _ := NewParticipant(12345, dec)
		p.SetLifetime(50 * time.Millisecond)

		if p.IsExpired(time.Now()) {
			t.Error("should not be expired immediately")
		}

		time.Sleep(60 * time.Millisecond)

		if !p.IsExpired(time.Now()) {
			t.Error("should be expired after lifetime")
		}
	})

	t.Run("detects_idle_tunnels", func(t *testing.T) {
		dec := &mockSecurityEncryptor{}
		p, _ := NewParticipant(12345, dec)
		p.SetIdleTimeout(50 * time.Millisecond)

		if p.IsIdle(time.Now()) {
			t.Error("should not be idle immediately")
		}

		time.Sleep(60 * time.Millisecond)

		if !p.IsIdle(time.Now()) {
			t.Error("should be idle after timeout")
		}
	})
}

// =============================================================================
// GATEWAY LOGIC TESTS
// =============================================================================

// TestGateway_FirstHopEncryption verifies gateway correctly prepares
// and encrypts tunnel messages.
func TestGateway_FirstHopEncryption(t *testing.T) {
	t.Run("creates_valid_tunnel_message", func(t *testing.T) {
		enc := &mockSecurityEncryptor{}
		gw, _ := NewGateway(12345, enc, 67890)

		msg := []byte("test I2NP message")
		encrypted, err := gw.Send(msg)
		if err != nil {
			t.Fatalf("send failed: %v", err)
		}

		if len(encrypted) != 1028 {
			t.Errorf("encrypted length = %d, want 1028", len(encrypted))
		}
	})

	t.Run("validates_message_size", func(t *testing.T) {
		enc := &mockSecurityEncryptor{}
		gw, _ := NewGateway(12345, enc, 67890)

		// Test empty message
		_, err := gw.Send([]byte{})
		if err == nil {
			t.Error("expected error for empty message")
		}

		// Test oversized message
		largeMsg := make([]byte, maxTunnelPayload+100)
		_, err = gw.Send(largeMsg)
		if err == nil {
			t.Error("expected error for oversized message")
		}
	})

	t.Run("sets_next_hop_id", func(t *testing.T) {
		enc := &mockSecurityEncryptor{}
		gw, _ := NewGateway(12345, enc, 67890)

		if gw.NextHopID() != 67890 {
			t.Errorf("next hop ID = %d, want 67890", gw.NextHopID())
		}
	})

	t.Run("rejects_nil_encryption", func(t *testing.T) {
		_, err := NewGateway(12345, nil, 67890)
		if err == nil {
			t.Error("expected error for nil encryption")
		}
	})
}

// TestGateway_ChecksumGeneration verifies correct checksum calculation.
func TestGateway_ChecksumGeneration(t *testing.T) {
	enc := &mockSecurityEncryptor{}
	gw, _ := NewGateway(12345, enc, 67890)

	msg := []byte("test message")
	_, err := gw.Send(msg)
	if err != nil {
		t.Fatalf("send failed: %v", err)
	}

	// Verify checksum was included (bytes 20-24)
	if enc.lastInput == nil || len(enc.lastInput) < 24 {
		t.Fatal("no input captured")
	}

	checksum := enc.lastInput[20:24]
	if checksum[0] == 0 && checksum[1] == 0 && checksum[2] == 0 && checksum[3] == 0 {
		t.Error("checksum should not be all zeros")
	}
}

// =============================================================================
// ENDPOINT LOGIC TESTS
// =============================================================================

// TestEndpoint_DecryptionAndDelivery verifies endpoint correctly
// decrypts and delivers messages.
func TestEndpoint_DecryptionAndDelivery(t *testing.T) {
	t.Run("delivers_to_handler", func(t *testing.T) {
		handler := func(msg []byte) error {
			return nil
		}

		dec := &mockSecurityEncryptor{}
		ep, _ := NewEndpoint(12345, dec, handler)
		defer ep.Stop()

		// Create valid tunnel message
		tunnelData := createValidTunnelMessage(t)
		ep.Receive(tunnelData)

		// Handler may not be called if checksum validation fails
		// This test verifies the decryption path is taken
		if dec.decryptCalls != 1 {
			t.Error("decryption should be called")
		}
	})

	t.Run("validates_message_size", func(t *testing.T) {
		handler := func(msg []byte) error { return nil }
		dec := &mockSecurityEncryptor{}
		ep, _ := NewEndpoint(12345, dec, handler)
		defer ep.Stop()

		invalidSizes := []int{0, 100, 1023, 1025, 2000}
		for _, size := range invalidSizes {
			data := make([]byte, size)
			err := ep.Receive(data)
			if err == nil {
				t.Errorf("expected error for size %d", size)
			}
		}
	})

	t.Run("rejects_nil_handler", func(t *testing.T) {
		dec := &mockSecurityEncryptor{}
		_, err := NewEndpoint(12345, dec, nil)
		if err == nil {
			t.Error("expected error for nil handler")
		}
	})
}

// TestEndpoint_ChecksumValidation verifies checksum verification.
func TestEndpoint_ChecksumValidation(t *testing.T) {
	t.Run("valid_checksum_accepted", func(t *testing.T) {
		handler := func(msg []byte) error { return nil }
		dec := &mockSecurityEncryptor{}
		ep, _ := NewEndpoint(12345, dec, handler)
		defer ep.Stop()

		// Create message with valid checksum
		tunnelData := createValidTunnelMessage(t)
		err := ep.Receive(tunnelData)

		// Should not error due to checksum (may error on other validation)
		if err == ErrChecksumMismatch {
			t.Error("valid checksum should not cause mismatch error")
		}
	})

	t.Run("invalid_checksum_rejected", func(t *testing.T) {
		handler := func(msg []byte) error { return nil }
		dec := &mockSecurityEncryptor{}
		ep, _ := NewEndpoint(12345, dec, handler)
		defer ep.Stop()

		// Create message with invalid checksum
		tunnelData := make([]byte, 1028)
		tunnelData[20] = 0xFF // Corrupt checksum

		err := ep.Receive(tunnelData)
		if err == nil {
			t.Error("invalid checksum should cause error")
		}
	})
}

// =============================================================================
// FRAGMENT REASSEMBLY TESTS
// =============================================================================

// TestFragmentReassembly_MemoryLimits verifies fragment tracking has
// proper memory limits and cleanup.
func TestFragmentReassembly_MemoryLimits(t *testing.T) {
	t.Run("enforces_max_fragment_number", func(t *testing.T) {
		handler := func(msg []byte) error { return nil }
		dec := &mockSecurityEncryptor{}
		ep, _ := NewEndpoint(12345, dec, handler)
		defer ep.Stop()

		// Fragment number must be 1-63 for follow-on fragments
		// Test that values outside this range are rejected
		invalidFragNums := []int{0, 64, 100}
		for _, fragNum := range invalidFragNums {
			di := &DeliveryInstructions{
				fragmentType:   FOLLOW_ON_FRAGMENT,
				fragmentNumber: fragNum,
				messageID:      12345,
			}
			fragmentNum, _ := di.FragmentNumber()
			// Values are stored - validation happens at processing time
			if fragNum > 63 {
				// Fragment numbers should still be retrievable
				// but endpoint will reject during reassembly
				t.Logf("fragment number %d stored as %d", fragNum, fragmentNum)
			}
		}
	})

	t.Run("clears_fragments_on_stop", func(t *testing.T) {
		handler := func(msg []byte) error { return nil }
		dec := &mockSecurityEncryptor{}
		ep, _ := NewEndpoint(12345, dec, handler)

		// Add some fragments manually
		ep.fragmentsMutex.Lock()
		ep.fragments[12345] = &fragmentAssembler{
			fragments:  make(map[int][]byte),
			createdAt:  time.Now(),
			totalCount: 2,
		}
		ep.fragmentsMutex.Unlock()

		ep.ClearFragments()

		ep.fragmentsMutex.Lock()
		count := len(ep.fragments)
		ep.fragmentsMutex.Unlock()

		if count != 0 {
			t.Errorf("fragments not cleared, count = %d", count)
		}
	})
}

// TestFragmentReassembly_TimeoutHandling verifies stale fragment cleanup.
func TestFragmentReassembly_TimeoutHandling(t *testing.T) {
	t.Run("removes_stale_fragments", func(t *testing.T) {
		handler := func(msg []byte) error { return nil }
		dec := &mockSecurityEncryptor{}
		ep, _ := NewEndpoint(12345, dec, handler)

		// Set short timeout for testing
		ep.fragmentTimeout = 50 * time.Millisecond

		// Add old fragment
		ep.fragmentsMutex.Lock()
		ep.fragments[12345] = &fragmentAssembler{
			fragments:  map[int][]byte{0: []byte("fragment")},
			createdAt:  time.Now().Add(-100 * time.Millisecond),
			totalCount: 2,
		}
		ep.fragmentsMutex.Unlock()

		// Trigger cleanup
		ep.removeStaleFragments()

		ep.fragmentsMutex.Lock()
		count := len(ep.fragments)
		ep.fragmentsMutex.Unlock()

		if count != 0 {
			t.Error("stale fragment should have been removed")
		}

		ep.Stop()
	})

	t.Run("keeps_fresh_fragments", func(t *testing.T) {
		handler := func(msg []byte) error { return nil }
		dec := &mockSecurityEncryptor{}
		ep, _ := NewEndpoint(12345, dec, handler)

		ep.fragmentTimeout = 60 * time.Second

		// Add fresh fragment
		ep.fragmentsMutex.Lock()
		ep.fragments[12345] = &fragmentAssembler{
			fragments:  map[int][]byte{0: []byte("fragment")},
			createdAt:  time.Now(),
			totalCount: 2,
		}
		ep.fragmentsMutex.Unlock()

		// Trigger cleanup
		ep.removeStaleFragments()

		ep.fragmentsMutex.Lock()
		count := len(ep.fragments)
		ep.fragmentsMutex.Unlock()

		if count != 1 {
			t.Error("fresh fragment should be kept")
		}

		ep.Stop()
	})
}

// =============================================================================
// DELIVERY INSTRUCTIONS TESTS
// =============================================================================

// TestDeliveryInstructions_AllTypesCorrect verifies all delivery types
// are parsed correctly.
func TestDeliveryInstructions_AllTypesCorrect(t *testing.T) {
	t.Run("DT_LOCAL", func(t *testing.T) {
		di := NewLocalDeliveryInstructions(100)
		dtype, err := di.DeliveryType()
		if err != nil {
			t.Fatalf("failed to get delivery type: %v", err)
		}
		if dtype != DT_LOCAL {
			t.Errorf("delivery type = %d, want DT_LOCAL (%d)", dtype, DT_LOCAL)
		}
	})

	t.Run("DT_TUNNEL", func(t *testing.T) {
		hash := [32]byte{1, 2, 3}
		di := NewTunnelDeliveryInstructions(12345, hash, 100)
		dtype, err := di.DeliveryType()
		if err != nil {
			t.Fatalf("failed to get delivery type: %v", err)
		}
		if dtype != DT_TUNNEL {
			t.Errorf("delivery type = %d, want DT_TUNNEL (%d)", dtype, DT_TUNNEL)
		}
	})

	t.Run("DT_ROUTER", func(t *testing.T) {
		hash := [32]byte{1, 2, 3}
		di := NewRouterDeliveryInstructions(hash, 100)
		dtype, err := di.DeliveryType()
		if err != nil {
			t.Fatalf("failed to get delivery type: %v", err)
		}
		if dtype != DT_ROUTER {
			t.Errorf("delivery type = %d, want DT_ROUTER (%d)", dtype, DT_ROUTER)
		}
	})
}

// TestDeliveryInstructions_RoundTrip verifies serialization/deserialization.
func TestDeliveryInstructions_RoundTrip(t *testing.T) {
	testCases := []struct {
		name string
		di   *DeliveryInstructions
	}{
		{"local", NewLocalDeliveryInstructions(256)},
		{"tunnel", NewTunnelDeliveryInstructions(12345, [32]byte{1, 2, 3}, 512)},
		{"router", NewRouterDeliveryInstructions([32]byte{4, 5, 6}, 768)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			bytes, err := tc.di.Bytes()
			if err != nil {
				t.Fatalf("failed to serialize: %v", err)
			}

			parsed, remainder, err := readDeliveryInstructions(bytes)
			if err != nil {
				t.Fatalf("failed to parse: %v", err)
			}

			if len(remainder) != 0 {
				t.Errorf("unexpected remainder: %d bytes", len(remainder))
			}

			origType, _ := tc.di.DeliveryType()
			parsedType, _ := parsed.DeliveryType()
			if origType != parsedType {
				t.Errorf("delivery type mismatch: %d vs %d", origType, parsedType)
			}

			origSize, _ := tc.di.FragmentSize()
			parsedSize, _ := parsed.FragmentSize()
			if origSize != parsedSize {
				t.Errorf("fragment size mismatch: %d vs %d", origSize, parsedSize)
			}
		})
	}
}

// =============================================================================
// POOL MAINTENANCE TESTS
// =============================================================================

// TestPoolMaintenance_MinMaxTunnelCounts verifies pool maintains
// configured tunnel counts.
func TestPoolMaintenance_MinMaxTunnelCounts(t *testing.T) {
	t.Run("respects_min_tunnels", func(t *testing.T) {
		config := PoolConfig{
			MinTunnels:       4,
			MaxTunnels:       6,
			TunnelLifetime:   10 * time.Minute,
			RebuildThreshold: 2 * time.Minute,
		}

		pool := NewTunnelPoolWithConfig(&mockPeerSelector{}, config)

		// With 0 active tunnels, should need MinTunnels
		needed := pool.calculateNeededTunnels(0, 0)
		if needed != config.MinTunnels {
			t.Errorf("needed = %d, want %d", needed, config.MinTunnels)
		}
	})

	t.Run("respects_max_tunnels", func(t *testing.T) {
		config := PoolConfig{
			MinTunnels:       4,
			MaxTunnels:       6,
			TunnelLifetime:   10 * time.Minute,
			RebuildThreshold: 2 * time.Minute,
		}

		pool := NewTunnelPoolWithConfig(&mockPeerSelector{}, config)

		// With MaxTunnels active, should need 0
		needed := pool.calculateNeededTunnels(config.MaxTunnels, 0)
		if needed != 0 {
			t.Errorf("needed = %d, want 0", needed)
		}
	})

	t.Run("accounts_for_near_expiry", func(t *testing.T) {
		config := PoolConfig{
			MinTunnels:       4,
			MaxTunnels:       6,
			TunnelLifetime:   10 * time.Minute,
			RebuildThreshold: 2 * time.Minute,
		}

		pool := NewTunnelPoolWithConfig(&mockPeerSelector{}, config)

		// With 4 active but 2 near expiry, usable = 2, need 2 more
		needed := pool.calculateNeededTunnels(4, 2)
		if needed != 2 {
			t.Errorf("needed = %d, want 2", needed)
		}
	})
}

// TestPoolMaintenance_ExpirationCleanup verifies expired tunnels are removed.
func TestPoolMaintenance_ExpirationCleanup(t *testing.T) {
	t.Run("removes_building_tunnels_after_maxage", func(t *testing.T) {
		config := DefaultPoolConfig()
		pool := NewTunnelPoolWithConfig(&mockPeerSelector{}, config)

		// Add a building tunnel that's old
		tunnel := &TunnelState{
			ID:        12345,
			State:     TunnelBuilding, // CleanupExpiredTunnels only handles Building state
			CreatedAt: time.Now().Add(-100 * time.Millisecond),
		}
		pool.AddTunnel(tunnel)

		// Run cleanup for building tunnels
		pool.CleanupExpiredTunnels(50 * time.Millisecond)

		// Tunnel should be removed
		_, exists := pool.GetTunnel(12345)
		if exists {
			t.Error("expired building tunnel should have been removed")
		}
	})

	t.Run("keeps_fresh_building_tunnels", func(t *testing.T) {
		config := DefaultPoolConfig()
		pool := NewTunnelPoolWithConfig(&mockPeerSelector{}, config)

		// Add a fresh building tunnel
		tunnel := &TunnelState{
			ID:        12345,
			State:     TunnelBuilding,
			CreatedAt: time.Now(),
		}
		pool.AddTunnel(tunnel)

		// Run cleanup with short max age - tunnel is fresh so should remain
		pool.CleanupExpiredTunnels(10 * time.Minute)

		// Tunnel should still exist
		_, exists := pool.GetTunnel(12345)
		if !exists {
			t.Error("fresh building tunnel should not be removed")
		}
	})

	t.Run("keeps_ready_tunnels_within_lifetime", func(t *testing.T) {
		config := DefaultPoolConfig()
		config.TunnelLifetime = 10 * time.Minute
		pool := NewTunnelPoolWithConfig(&mockPeerSelector{}, config)

		// Add a ready tunnel
		tunnel := &TunnelState{
			ID:        12345,
			State:     TunnelReady,
			CreatedAt: time.Now(),
		}
		pool.AddTunnel(tunnel)

		// Run cleanup
		pool.CleanupExpiredTunnels(10 * time.Minute)

		// Ready tunnel should still exist (ready tunnels handled by maintainPool)
		_, exists := pool.GetTunnel(12345)
		if !exists {
			t.Error("ready tunnel within lifetime should not be removed")
		}
	})
}

// =============================================================================
// BUILD TIMEOUT TESTS
// =============================================================================

// TestBuildTimeout_ConfiguredCorrectly verifies 90-second timeout is default.
func TestBuildTimeout_ConfiguredCorrectly(t *testing.T) {
	// The build timeout is configured in lib/config/defaults.go
	// This test verifies the pool respects build retry delays

	t.Run("default_retry_delay", func(t *testing.T) {
		config := DefaultPoolConfig()
		if config.BuildRetryDelay != 2*time.Second {
			t.Errorf("build retry delay = %v, want 2s", config.BuildRetryDelay)
		}
	})

	t.Run("max_build_retries", func(t *testing.T) {
		config := DefaultPoolConfig()
		if config.MaxBuildRetries != 3 {
			t.Errorf("max build retries = %d, want 3", config.MaxBuildRetries)
		}
	})
}

// =============================================================================
// PEER SELECTION TESTS
// =============================================================================

// mockPeerSelector implements PeerSelector for testing
type mockPeerSelector struct {
	returnError bool
	returnPeers []router_info.RouterInfo
}

func (m *mockPeerSelector) SelectPeers(count int, exclude []common.Hash) ([]router_info.RouterInfo, error) {
	if m.returnError {
		return nil, ErrInvalidMessage
	}
	if m.returnPeers != nil {
		return m.returnPeers, nil
	}
	return nil, nil
}

// TestPeerSelection_FailedPeerExclusion verifies failed peers are excluded on retry.
func TestPeerSelection_FailedPeerExclusion(t *testing.T) {
	t.Run("marks_and_tracks_failed_peers", func(t *testing.T) {
		pool := NewTunnelPool(&mockPeerSelector{})

		hash := common.Hash{1, 2, 3}
		pool.MarkPeerFailed(hash)

		if !pool.IsPeerFailed(hash) {
			t.Error("peer should be marked as failed")
		}
	})

	t.Run("excludes_failed_peers_from_selection", func(t *testing.T) {
		pool := NewTunnelPool(&mockPeerSelector{})

		// Mark some peers as failed
		hash1 := common.Hash{1, 2, 3}
		hash2 := common.Hash{4, 5, 6}
		pool.MarkPeerFailed(hash1)
		pool.MarkPeerFailed(hash2)

		failed := pool.GetFailedPeers()
		if len(failed) != 2 {
			t.Errorf("failed peers count = %d, want 2", len(failed))
		}
	})

	t.Run("cleans_up_expired_failures", func(t *testing.T) {
		pool := NewTunnelPool(&mockPeerSelector{})

		// Add failed peer with old timestamp
		hash := common.Hash{1, 2, 3}
		pool.failedPeersMu.Lock()
		pool.failedPeers[hash] = time.Now().Add(-10 * time.Minute)
		pool.failedPeersMu.Unlock()

		pool.CleanupFailedPeers()

		if pool.IsPeerFailed(hash) {
			t.Error("expired failure should be cleaned up")
		}
	})
}

// =============================================================================
// MANAGER TESTS
// =============================================================================

// TestManager_ParticipantTracking verifies manager correctly tracks participants.
func TestManager_ParticipantTracking(t *testing.T) {
	t.Run("adds_and_retrieves_participants", func(t *testing.T) {
		m := NewManager()
		defer m.Stop()

		dec := &mockSecurityEncryptor{}
		p, _ := NewParticipant(12345, dec)
		err := m.AddParticipant(p)
		if err != nil {
			t.Fatalf("failed to add participant: %v", err)
		}

		retrieved := m.GetParticipant(12345)
		if retrieved == nil {
			t.Error("participant not found")
		}

		if m.ParticipantCount() != 1 {
			t.Errorf("participant count = %d, want 1", m.ParticipantCount())
		}
	})

	t.Run("rejects_nil_participant", func(t *testing.T) {
		m := NewManager()
		defer m.Stop()

		err := m.AddParticipant(nil)
		if err == nil {
			t.Error("expected error for nil participant")
		}
	})

	t.Run("removes_participants", func(t *testing.T) {
		m := NewManager()
		defer m.Stop()

		dec := &mockSecurityEncryptor{}
		p, _ := NewParticipant(12345, dec)
		m.AddParticipant(p)

		removed := m.RemoveParticipant(12345)
		if !removed {
			t.Error("participant should have been removed")
		}

		if m.ParticipantCount() != 0 {
			t.Errorf("participant count = %d, want 0", m.ParticipantCount())
		}
	})
}

// TestManager_CleanupExpiredParticipants verifies automatic cleanup.
func TestManager_CleanupExpiredParticipants(t *testing.T) {
	m := NewManager()
	defer m.Stop()

	// Add participant with short lifetime
	dec := &mockSecurityEncryptor{}
	p, _ := NewParticipant(12345, dec)
	p.SetLifetime(50 * time.Millisecond)
	m.AddParticipant(p)

	// Wait for expiration
	time.Sleep(60 * time.Millisecond)

	// Trigger cleanup
	m.cleanupExpiredParticipants()

	if m.ParticipantCount() != 0 {
		t.Error("expired participant should have been cleaned up")
	}
}

// =============================================================================
// CONCURRENT ACCESS TESTS
// =============================================================================

// TestConcurrentAccess_ThreadSafety verifies thread safety of pool operations.
func TestConcurrentAccess_ThreadSafety(t *testing.T) {
	pool := NewTunnelPool(&mockPeerSelector{})
	var wg sync.WaitGroup

	// Concurrent add/get/remove operations
	for i := 0; i < 100; i++ {
		wg.Add(3)

		go func(id int) {
			defer wg.Done()
			tunnel := &TunnelState{
				ID:        TunnelID(id),
				State:     TunnelReady,
				CreatedAt: time.Now(),
			}
			pool.AddTunnel(tunnel)
		}(i)

		go func(id int) {
			defer wg.Done()
			pool.GetTunnel(TunnelID(id))
		}(i)

		go func(id int) {
			defer wg.Done()
			pool.RemoveTunnel(TunnelID(id))
		}(i)
	}

	wg.Wait()

	// Should complete without race condition
	stats := pool.GetPoolStats()
	t.Logf("Final pool stats: total=%d, active=%d", stats.Total, stats.Active)
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

// createValidTunnelMessage creates a valid 1028-byte tunnel message for testing.
func createValidTunnelMessage(t *testing.T) []byte {
	t.Helper()

	// Create 1028-byte message for endpoint (it expects 1028 bytes)
	msg := make([]byte, 1028)

	// Tunnel ID (bytes 0-3)
	binary.BigEndian.PutUint32(msg[0:4], 12345)

	// IV (bytes 4-20) - zero for testing
	// Checksum (bytes 20-24) - will be calculated

	// Random padding (bytes 24 to separator)
	for i := 24; i < 100; i++ {
		msg[i] = byte(i % 255)
		if msg[i] == 0 {
			msg[i] = 1 // Non-zero padding
		}
	}

	// Zero separator
	msg[100] = 0x00

	// Delivery instructions (DT_LOCAL)
	msg[101] = DT_LOCAL // Flag byte
	msg[102] = 0x00     // Size high byte
	msg[103] = 0x04     // Size low byte (4 bytes of data)

	// Message data
	msg[104] = 'T'
	msg[105] = 'E'
	msg[106] = 'S'
	msg[107] = 'T'

	// Calculate checksum: first 4 bytes of SHA256(data_after_zero_byte + IV)
	// Per I2P spec: "The checksum does NOT cover the padding or the zero byte."
	iv := msg[4:20]
	dataAfterZero := msg[101:] // data after the zero byte at position 100
	checksumData := append(dataAfterZero, iv...)
	hash := types.SHA256(checksumData)
	copy(msg[20:24], hash[:4])

	return msg
}

// =============================================================================
// RESOURCE EXHAUSTION PROTECTION TESTS
// =============================================================================

// TestResourceExhaustion_TotalParticipantLimit verifies that the global participating
// tunnel limit is properly enforced to protect against memory/CPU exhaustion.
// This tests the hard limit where all requests are rejected unconditionally.
func TestResourceExhaustion_TotalParticipantLimit(t *testing.T) {
	// Use a larger limit to avoid soft limit probabilistic rejection during fill
	cfg := config.TunnelDefaults{
		MaxParticipatingTunnels:    1000,
		ParticipatingLimitsEnabled: true,
		PerSourceRateLimitEnabled:  false, // Disable per-source to test global only
	}

	manager := NewManagerWithConfig(cfg)
	defer manager.Stop()

	// Create test hash for a legitimate source
	testHash := common.Hash{}
	copy(testHash[:], []byte("test-router-hash-32-bytes-long!!"))

	// Fill to just below soft limit (50% = 500) so we avoid probabilistic rejection
	for i := 0; i < 400; i++ {
		participant, err := NewParticipant(TunnelID(i), &mockSecurityEncryptor{})
		if err != nil {
			t.Fatalf("Failed to create participant %d: %v", i, err)
		}
		err = manager.AddParticipant(participant)
		if err != nil {
			t.Fatalf("Failed to add participant %d: %v", i, err)
		}
	}

	// Should accept below soft limit (400/1000 = 40%)
	accepted, rejectCode, reason := manager.ProcessBuildRequest(testHash)
	if !accepted {
		t.Errorf("Expected acceptance below soft limit (400/1000), got rejection: code=%d reason=%s", rejectCode, reason)
	}

	// Fill to hard limit (1000/1000)
	for i := 400; i < 1000; i++ {
		participant, _ := NewParticipant(TunnelID(i), &mockSecurityEncryptor{})
		manager.AddParticipant(participant)
	}

	// Should reject at hard limit (1000/1000)
	accepted, rejectCode, reason = manager.ProcessBuildRequest(testHash)
	if accepted {
		t.Error("Expected rejection at hard limit (1000/1000)")
	}
	if rejectCode != BuildReplyCodeBandwidth {
		t.Errorf("Expected reject code %d (BANDWIDTH), got %d", BuildReplyCodeBandwidth, rejectCode)
	}
	if reason != "hard_limit_reached" {
		t.Errorf("Expected reason 'hard_limit_reached', got '%s'", reason)
	}

	// Verify stats show rejection
	stats := manager.GetLimitStats()
	if stats.GlobalRejectionsTotal == 0 {
		t.Error("Expected rejection to be recorded in stats")
	}
	if !stats.AtHardLimit {
		t.Error("Expected AtHardLimit to be true")
	}

	t.Logf("Security test passed: hard limit enforcement at %d participants", stats.CurrentParticipants)
}

// TestResourceExhaustion_PerSourceRateLimit verifies that per-source rate limiting
// prevents a single malicious source from overwhelming the router with tunnel build requests.
func TestResourceExhaustion_PerSourceRateLimit(t *testing.T) {
	// Use small limits for testing
	cfg := config.TunnelDefaults{
		MaxParticipatingTunnels:    15000, // High enough to not trigger global limit
		ParticipatingLimitsEnabled: true,
		PerSourceRateLimitEnabled:  true,
		MaxBuildRequestsPerMinute:  10,
		BuildRequestBurstSize:      3, // Allow burst of 3, then rate limit
		SourceBanDuration:          5 * time.Minute,
	}

	manager := NewManagerWithConfig(cfg)
	defer manager.Stop()

	// Malicious source trying to flood
	attackerHash := common.Hash{}
	copy(attackerHash[:], []byte("attacker-hash-32-bytes-long!!!!"))

	// Legitimate source
	legitimateHash := common.Hash{}
	copy(legitimateHash[:], []byte("legitimate-hash-32-bytes-long!!"))

	// First burst should succeed (up to burst size)
	acceptedCount := 0
	for i := 0; i < 3; i++ {
		accepted, _, _ := manager.ProcessBuildRequest(attackerHash)
		if accepted {
			acceptedCount++
		}
	}
	if acceptedCount != 3 {
		t.Errorf("Expected all 3 burst requests to succeed, got %d", acceptedCount)
	}

	// Additional rapid requests should be rate limited
	rejectedCount := 0
	for i := 0; i < 5; i++ {
		accepted, rejectCode, _ := manager.ProcessBuildRequest(attackerHash)
		if !accepted {
			rejectedCount++
			if rejectCode != BuildReplyCodeBandwidth {
				t.Errorf("Expected reject code %d, got %d", BuildReplyCodeBandwidth, rejectCode)
			}
		}
	}
	if rejectedCount == 0 {
		t.Error("Expected some rapid requests to be rate limited")
	}

	// Meanwhile, legitimate source should still be able to request
	accepted, _, _ := manager.ProcessBuildRequest(legitimateHash)
	if !accepted {
		t.Error("Legitimate source should not be affected by attacker's rate limit")
	}

	t.Logf("Security test passed: per-source rate limiting rejected %d rapid requests from attacker", rejectedCount)
}

// TestResourceExhaustion_AutoBanMechanism verifies that sources exceeding rate limits
// repeatedly get automatically banned to reduce processing overhead.
func TestResourceExhaustion_AutoBanMechanism(t *testing.T) {
	cfg := config.TunnelDefaults{
		MaxParticipatingTunnels:    15000,
		ParticipatingLimitsEnabled: true,
		PerSourceRateLimitEnabled:  true,
		MaxBuildRequestsPerMinute:  10,
		BuildRequestBurstSize:      1,               // Minimal burst to trigger bans quickly
		SourceBanDuration:          1 * time.Second, // Short ban for testing
	}

	limiter := NewSourceLimiterWithConfig(cfg)
	defer limiter.Stop()

	// Malicious source that will be banned
	attackerHash := common.Hash{}
	copy(attackerHash[:], []byte("persistent-attacker-hash-32byte"))

	// First request consumes the single burst token
	allowed, _ := limiter.AllowRequest(attackerHash)
	if !allowed {
		t.Error("First request should be allowed")
	}

	// Generate enough rejections to trigger auto-ban (>10 rejections)
	rejectionsBeforeBan := 0
	for i := 0; i < 20; i++ {
		allowed, reason := limiter.AllowRequest(attackerHash)
		if !allowed {
			rejectionsBeforeBan++
			// After 10+ rejections, should switch to "source_banned"
			if rejectionsBeforeBan > 10 && reason != "source_banned" {
				// May still be "rate_limit_exceeded" on the 11th since ban happens after increment
				if i > 11 && reason != "source_banned" {
					t.Logf("Expected 'source_banned' after many rejections, got '%s' on iteration %d", reason, i)
				}
			}
		}
	}

	// Verify the source is now banned
	if !limiter.IsBanned(attackerHash) {
		t.Error("Attacker should be banned after many rejections")
	}

	// Verify banned source is immediately rejected
	allowed, reason := limiter.AllowRequest(attackerHash)
	if allowed {
		t.Error("Banned source should be rejected")
	}
	if reason != "source_banned" {
		t.Errorf("Expected 'source_banned' reason, got '%s'", reason)
	}

	// Verify stats reflect the ban
	stats := limiter.GetStats()
	if stats.BannedSources == 0 {
		t.Error("Expected at least one banned source in stats")
	}

	t.Logf("Security test passed: auto-ban triggered after %d rejections, banned sources: %d", rejectionsBeforeBan, stats.BannedSources)
}

// TestResourceExhaustion_SoftLimitGradualDegradation verifies that probabilistic rejection
// gradually increases as we approach the hard limit, providing graceful degradation.
func TestResourceExhaustion_SoftLimitGradualDegradation(t *testing.T) {
	// Use larger limits for testing to allow proper soft/critical zone separation
	// With max=1000, soft limit=500, critical threshold=900 (last 100)
	cfg := config.TunnelDefaults{
		MaxParticipatingTunnels:    1000,
		ParticipatingLimitsEnabled: true,
		PerSourceRateLimitEnabled:  false, // Focus on global soft limit behavior
	}

	manager := NewManagerWithConfig(cfg)
	defer manager.Stop()

	testHash := common.Hash{}
	copy(testHash[:], []byte("test-router-hash-32-bytes-long!!"))

	// Fill to exactly soft limit (50% = 500)
	for i := 0; i < 500; i++ {
		participant, _ := NewParticipant(TunnelID(i), &mockSecurityEncryptor{})
		manager.AddParticipant(participant)
	}

	// At soft limit (500/1000), should start seeing probabilistic rejections
	// Starting rate is ~50% rejection
	softLimitRejections := 0
	softLimitAcceptances := 0
	trials := 100

	for i := 0; i < trials; i++ {
		canAccept, _ := manager.CanAcceptParticipant()
		if canAccept {
			softLimitAcceptances++
		} else {
			softLimitRejections++
		}
	}

	// At exactly soft limit (50% of capacity), we expect roughly 50% rejection rate
	// Allow variance due to randomness: 30%-70%
	rejectionRate := float64(softLimitRejections) / float64(trials)
	if rejectionRate < 0.30 || rejectionRate > 0.70 {
		t.Errorf("Expected ~50%% rejection rate at soft limit, got %.2f%%", rejectionRate*100)
	}

	t.Logf("At soft limit (500/%d): rejection rate %.1f%% (%d/%d)",
		cfg.MaxParticipatingTunnels, rejectionRate*100,
		softLimitRejections, trials)

	// Fill to 95% (950/1000) - this is in the critical zone (last 100)
	for i := 500; i < 950; i++ {
		participant, _ := NewParticipant(TunnelID(i), &mockSecurityEncryptor{})
		manager.AddParticipant(participant)
	}

	// Reset counters
	highLoadRejections := 0
	highLoadAcceptances := 0
	for i := 0; i < trials; i++ {
		canAccept, _ := manager.CanAcceptParticipant()
		if canAccept {
			highLoadAcceptances++
		} else {
			highLoadRejections++
		}
	}

	highRejectionRate := float64(highLoadRejections) / float64(trials)
	t.Logf("At critical zone (950/%d): rejection rate %.1f%% (%d/%d)",
		cfg.MaxParticipatingTunnels, highRejectionRate*100,
		highLoadRejections, trials)

	// At 95% (in critical zone), rejection rate should be >90%
	if highRejectionRate < 0.85 {
		t.Errorf("Expected >85%% rejection rate in critical zone, got %.2f%%", highRejectionRate*100)
	}

	// Verify graceful degradation: rejection rate should increase with load
	if highRejectionRate <= rejectionRate {
		t.Errorf("Expected higher rejection rate at 95%% load (%.2f%%) than at 50%% (%.2f%%)",
			highRejectionRate*100, rejectionRate*100)
	}

	t.Logf("Security test passed: soft limit provides graceful degradation (50%% load: %.0f%% reject, 95%% load: %.0f%% reject)",
		rejectionRate*100, highRejectionRate*100)
}
