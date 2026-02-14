package tunnel

import (
	"testing"
	"time"

	"github.com/go-i2p/crypto/tunnel"
	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/stretchr/testify/assert"
)

// mockTunnelEncryptor is a simple mock for testing
type mockTunnelEncryptor struct{}

func (m *mockTunnelEncryptor) Encrypt(data []byte) ([]byte, error) {
	// Return a copy of the data (no actual encryption)
	result := make([]byte, len(data))
	copy(result, data)
	return result, nil
}

func (m *mockTunnelEncryptor) Decrypt(data []byte) ([]byte, error) {
	// Return a copy of the data (no actual decryption)
	result := make([]byte, len(data))
	copy(result, data)
	return result, nil
}

func (m *mockTunnelEncryptor) Type() tunnel.TunnelEncryptionType {
	// Return ECIES-X25519-AEAD type
	return tunnel.TunnelEncryptionECIES
}

// TestNewManager verifies manager creation and initialization
func TestNewManager(t *testing.T) {
	m := NewManager()
	defer m.Stop()

	if m == nil {
		t.Fatal("NewManager returned nil")
	}

	if m.participants == nil {
		t.Error("Manager participants map not initialized")
	}

	if m.ParticipantCount() != 0 {
		t.Errorf("Expected 0 participants, got %d", m.ParticipantCount())
	}
}

// TestAddParticipant verifies adding participants to the manager
func TestAddParticipant(t *testing.T) {
	m := NewManager()
	defer m.Stop()

	// Create a mock participant
	p, err := NewParticipant(12345, &mockTunnelEncryptor{})
	if err != nil {
		t.Fatalf("Failed to create participant: %v", err)
	}

	// Add the participant
	err = m.AddParticipant(p)
	if err != nil {
		t.Errorf("Failed to add participant: %v", err)
	}

	// Verify count
	if m.ParticipantCount() != 1 {
		t.Errorf("Expected 1 participant, got %d", m.ParticipantCount())
	}

	// Verify retrieval
	retrieved := m.GetParticipant(12345)
	if retrieved == nil {
		t.Error("Failed to retrieve added participant")
	}

	if retrieved.TunnelID() != 12345 {
		t.Errorf("Retrieved participant has wrong tunnel ID: expected 12345, got %d", retrieved.TunnelID())
	}
}

// TestAddNilParticipant verifies error handling for nil participants
func TestAddNilParticipant(t *testing.T) {
	m := NewManager()
	defer m.Stop()

	err := m.AddParticipant(nil)
	if err == nil {
		t.Error("Expected error when adding nil participant, got nil")
	}

	if m.ParticipantCount() != 0 {
		t.Errorf("Expected 0 participants after nil add, got %d", m.ParticipantCount())
	}
}

// TestAddDuplicateParticipant verifies handling of duplicate tunnel IDs
func TestAddDuplicateParticipant(t *testing.T) {
	m := NewManager()
	defer m.Stop()

	tunnelID := TunnelID(99999)

	// Add first participant
	p1, _ := NewParticipant(tunnelID, &mockTunnelEncryptor{})
	err := m.AddParticipant(p1)
	if err != nil {
		t.Fatalf("Failed to add first participant: %v", err)
	}

	// Add second participant with same ID (should return error)
	p2, _ := NewParticipant(tunnelID, &mockTunnelEncryptor{})
	err = m.AddParticipant(p2)
	if err == nil {
		t.Errorf("Expected error when adding duplicate participant, got nil")
	}

	// Should still have only 1 participant (the original)
	if m.ParticipantCount() != 1 {
		t.Errorf("Expected 1 participant after duplicate add, got %d", m.ParticipantCount())
	}
}

// TestRemoveParticipant verifies participant removal
func TestRemoveParticipant(t *testing.T) {
	m := NewManager()
	defer m.Stop()

	tunnelID := TunnelID(54321)

	// Add a participant
	p, _ := NewParticipant(tunnelID, &mockTunnelEncryptor{})
	err := m.AddParticipant(p)
	if err != nil {
		t.Fatalf("Failed to add participant: %v", err)
	}

	// Verify it exists
	if m.ParticipantCount() != 1 {
		t.Fatal("Participant not added correctly")
	}

	// Remove it
	removed := m.RemoveParticipant(tunnelID)
	if !removed {
		t.Error("RemoveParticipant returned false for existing participant")
	}

	// Verify it's gone
	if m.ParticipantCount() != 0 {
		t.Errorf("Expected 0 participants after removal, got %d", m.ParticipantCount())
	}

	// Verify GetParticipant returns nil
	if m.GetParticipant(tunnelID) != nil {
		t.Error("GetParticipant returned non-nil for removed participant")
	}
}

// TestRemoveNonexistentParticipant verifies removal of nonexistent participants
func TestRemoveNonexistentParticipant(t *testing.T) {
	m := NewManager()
	defer m.Stop()

	removed := m.RemoveParticipant(99999)
	if removed {
		t.Error("RemoveParticipant returned true for nonexistent participant")
	}
}

// TestGetNonexistentParticipant verifies retrieval of nonexistent participants
func TestGetNonexistentParticipant(t *testing.T) {
	m := NewManager()
	defer m.Stop()

	p := m.GetParticipant(88888)
	if p != nil {
		t.Error("GetParticipant returned non-nil for nonexistent participant")
	}
}

// TestParticipantCount verifies participant counting
func TestParticipantCount(t *testing.T) {
	m := NewManager()
	defer m.Stop()

	// Start with 0
	if m.ParticipantCount() != 0 {
		t.Errorf("Expected 0 participants initially, got %d", m.ParticipantCount())
	}

	// Add 3 participants
	for i := TunnelID(1); i <= 3; i++ {
		p, _ := NewParticipant(i, &mockTunnelEncryptor{})
		if err := m.AddParticipant(p); err != nil {
			t.Fatalf("Failed to add participant %d: %v", i, err)
		}
	}

	if m.ParticipantCount() != 3 {
		t.Errorf("Expected 3 participants, got %d", m.ParticipantCount())
	}

	// Remove 1
	m.RemoveParticipant(2)

	if m.ParticipantCount() != 2 {
		t.Errorf("Expected 2 participants after removal, got %d", m.ParticipantCount())
	}
}

// TestCleanupExpiredParticipants verifies automatic cleanup of expired participants
func TestCleanupExpiredParticipants(t *testing.T) {
	m := NewManager()
	defer m.Stop()

	// Create a participant that's already expired
	p, _ := NewParticipant(11111, &mockTunnelEncryptor{})
	p.createdAt = time.Now().Add(-11 * time.Minute) // Expired (10min lifetime)
	if err := m.AddParticipant(p); err != nil {
		t.Fatalf("Failed to add expired participant: %v", err)
	}

	// Create a participant that's not expired
	p2, _ := NewParticipant(22222, &mockTunnelEncryptor{})
	if err := m.AddParticipant(p2); err != nil {
		t.Fatalf("Failed to add participant: %v", err)
	}

	// Verify both were added
	if m.ParticipantCount() != 2 {
		t.Fatalf("Expected 2 participants, got %d", m.ParticipantCount())
	}

	// Trigger cleanup
	m.cleanupExpiredParticipants()

	// Should have only 1 participant left (the non-expired one)
	if m.ParticipantCount() != 1 {
		t.Errorf("Expected 1 participant after cleanup, got %d", m.ParticipantCount())
	}

	// Verify the correct one remains
	if m.GetParticipant(11111) != nil {
		t.Error("Expired participant was not cleaned up")
	}

	if m.GetParticipant(22222) == nil {
		t.Error("Non-expired participant was incorrectly removed")
	}
}

// TestManagerConcurrency verifies thread-safe concurrent access
func TestManagerConcurrency(t *testing.T) {
	m := NewManager()
	defer m.Stop()

	const numGoroutines = 10
	done := make(chan bool, numGoroutines)

	// Launch multiple goroutines to add participants concurrently
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			p, _ := NewParticipant(TunnelID(id), &mockTunnelEncryptor{})
			if err := m.AddParticipant(p); err != nil {
				t.Errorf("Failed to add participant %d: %v", id, err)
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < numGoroutines; i++ {
		<-done
	}

	// Verify count
	if m.ParticipantCount() != numGoroutines {
		t.Errorf("Expected %d participants, got %d", numGoroutines, m.ParticipantCount())
	}

	// Launch goroutines to remove concurrently
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			m.RemoveParticipant(TunnelID(id))
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < numGoroutines; i++ {
		<-done
	}

	// Verify all removed
	if m.ParticipantCount() != 0 {
		t.Errorf("Expected 0 participants after removal, got %d", m.ParticipantCount())
	}
}

// TestManagerStop verifies graceful shutdown
func TestManagerStop(t *testing.T) {
	m := NewManager()

	// Add some participants
	for i := TunnelID(1); i <= 5; i++ {
		p, _ := NewParticipant(i, &mockTunnelEncryptor{})
		if err := m.AddParticipant(p); err != nil {
			t.Fatalf("Failed to add participant: %v", err)
		}
	}

	// Stop the manager
	m.Stop()

	// Verify all participants cleared
	if m.ParticipantCount() != 0 {
		t.Errorf("Expected 0 participants after stop, got %d", m.ParticipantCount())
	}

	// Verify we can still call methods safely (shouldn't panic)
	_ = m.AddParticipant(nil) // Intentionally ignore error - testing nil handling after stop
}

// TestManagerStopIdempotent verifies that calling Stop() multiple times
// does not panic (regression test for double-close of stopChan).
func TestManagerStopIdempotent(t *testing.T) {
	m := NewManager()

	// Add some participants
	for i := TunnelID(1); i <= 3; i++ {
		p, _ := NewParticipant(i, &mockTunnelEncryptor{})
		_ = m.AddParticipant(p)
	}

	// First stop should work normally
	m.Stop()

	// Second stop should NOT panic
	assert.NotPanics(t, func() {
		m.Stop()
	}, "Second call to Stop() should not panic")

	// Third stop should also be safe
	assert.NotPanics(t, func() {
		m.Stop()
	}, "Third call to Stop() should not panic")

	// Verify all participants still cleared
	assert.Equal(t, 0, m.ParticipantCount(), "Participants should be cleared after stop")
}

// TestCleanupIdleParticipants verifies automatic cleanup of idle participants
// This helps mitigate resource exhaustion attacks where attackers request
// excessive tunnels but send no data through them.
func TestCleanupIdleParticipants(t *testing.T) {
	m := NewManager()
	defer m.Stop()

	// Create a participant that has been idle too long (no activity for 3 minutes)
	idleParticipant, _ := NewParticipant(11111, &mockTunnelEncryptor{})
	idleParticipant.lastActivity = time.Now().Add(-3 * time.Minute) // Idle for 3 minutes
	if err := m.AddParticipant(idleParticipant); err != nil {
		t.Fatalf("Failed to add idle participant: %v", err)
	}

	// Create an active participant (recent activity)
	activeParticipant, _ := NewParticipant(22222, &mockTunnelEncryptor{})
	// lastActivity is already set to now by NewParticipant
	if err := m.AddParticipant(activeParticipant); err != nil {
		t.Fatalf("Failed to add active participant: %v", err)
	}

	// Create a participant that's idle but not yet past the threshold
	almostIdleParticipant, _ := NewParticipant(33333, &mockTunnelEncryptor{})
	almostIdleParticipant.lastActivity = time.Now().Add(-1 * time.Minute) // Only idle for 1 minute
	if err := m.AddParticipant(almostIdleParticipant); err != nil {
		t.Fatalf("Failed to add almost-idle participant: %v", err)
	}

	// Verify all three were added
	if m.ParticipantCount() != 3 {
		t.Fatalf("Expected 3 participants, got %d", m.ParticipantCount())
	}

	// Trigger cleanup
	m.cleanupExpiredParticipants()

	// Should have only 2 participants left (the active and almost-idle ones)
	if m.ParticipantCount() != 2 {
		t.Errorf("Expected 2 participants after cleanup, got %d", m.ParticipantCount())
	}

	// Verify the idle one was removed
	if m.GetParticipant(11111) != nil {
		t.Error("Idle participant was not cleaned up")
	}

	// Verify the active one remains
	if m.GetParticipant(22222) == nil {
		t.Error("Active participant was incorrectly removed")
	}

	// Verify the almost-idle one remains
	if m.GetParticipant(33333) == nil {
		t.Error("Almost-idle participant was incorrectly removed")
	}
}

// TestIdleAndExpiredParticipantCleanup verifies that both idle and expired
// participants are cleaned up in the same pass
func TestIdleAndExpiredParticipantCleanup(t *testing.T) {
	m := NewManager()
	defer m.Stop()

	// Create an expired participant
	expiredParticipant, _ := NewParticipant(11111, &mockTunnelEncryptor{})
	expiredParticipant.createdAt = time.Now().Add(-11 * time.Minute) // Expired (past 10min lifetime)
	if err := m.AddParticipant(expiredParticipant); err != nil {
		t.Fatalf("Failed to add expired participant: %v", err)
	}

	// Create an idle participant
	idleParticipant, _ := NewParticipant(22222, &mockTunnelEncryptor{})
	idleParticipant.lastActivity = time.Now().Add(-3 * time.Minute) // Idle
	if err := m.AddParticipant(idleParticipant); err != nil {
		t.Fatalf("Failed to add idle participant: %v", err)
	}

	// Create a healthy participant
	healthyParticipant, _ := NewParticipant(33333, &mockTunnelEncryptor{})
	if err := m.AddParticipant(healthyParticipant); err != nil {
		t.Fatalf("Failed to add healthy participant: %v", err)
	}

	// Verify all three were added
	if m.ParticipantCount() != 3 {
		t.Fatalf("Expected 3 participants, got %d", m.ParticipantCount())
	}

	// Trigger cleanup
	m.cleanupExpiredParticipants()

	// Should have only 1 participant left (the healthy one)
	if m.ParticipantCount() != 1 {
		t.Errorf("Expected 1 participant after cleanup, got %d", m.ParticipantCount())
	}

	// Verify only the healthy one remains
	if m.GetParticipant(11111) != nil {
		t.Error("Expired participant was not cleaned up")
	}
	if m.GetParticipant(22222) != nil {
		t.Error("Idle participant was not cleaned up")
	}
	if m.GetParticipant(33333) == nil {
		t.Error("Healthy participant was incorrectly removed")
	}
}

// TestNewManagerWithConfig verifies manager creation with custom configuration
func TestNewManagerWithConfig(t *testing.T) {
	cfg := testTunnelConfig()
	cfg.MaxParticipatingTunnels = 500
	cfg.ParticipatingLimitsEnabled = true

	m := NewManagerWithConfig(cfg)
	defer m.Stop()

	maxP, softL, enabled := m.GetLimitConfig()
	if maxP != 500 {
		t.Errorf("Expected maxParticipants=500, got %d", maxP)
	}
	if softL != 250 {
		t.Errorf("Expected softLimit=250 (50%% of 500), got %d", softL)
	}
	if !enabled {
		t.Error("Expected limits to be enabled")
	}
}

// TestCanAcceptParticipant_LimitsDisabled verifies that when limits are disabled,
// all requests are accepted
func TestCanAcceptParticipant_LimitsDisabled(t *testing.T) {
	cfg := testTunnelConfig()
	cfg.MaxParticipatingTunnels = 100
	cfg.ParticipatingLimitsEnabled = false

	m := NewManagerWithConfig(cfg)
	defer m.Stop()

	// Add participants up to and beyond the "limit"
	for i := 0; i < 150; i++ {
		p, err := NewParticipant(TunnelID(i), &mockTunnelEncryptor{})
		if err != nil {
			t.Fatalf("Failed to create participant: %v", err)
		}
		if err := m.AddParticipant(p); err != nil {
			t.Fatalf("Failed to add participant: %v", err)
		}
	}

	// Should still accept (limits disabled)
	canAccept, reason := m.CanAcceptParticipant()
	if !canAccept {
		t.Errorf("Expected acceptance with limits disabled, got rejection: %s", reason)
	}
}

// TestCanAcceptParticipant_HardLimit verifies that requests are rejected at hard limit
func TestCanAcceptParticipant_HardLimit(t *testing.T) {
	cfg := testTunnelConfig()
	cfg.MaxParticipatingTunnels = 100
	cfg.ParticipatingLimitsEnabled = true

	m := NewManagerWithConfig(cfg)
	defer m.Stop()

	// Add participants up to the hard limit
	for i := 0; i < 100; i++ {
		p, err := NewParticipant(TunnelID(i), &mockTunnelEncryptor{})
		if err != nil {
			t.Fatalf("Failed to create participant: %v", err)
		}
		if err := m.AddParticipant(p); err != nil {
			t.Fatalf("Failed to add participant: %v", err)
		}
	}

	// Should reject at hard limit
	canAccept, reason := m.CanAcceptParticipant()
	if canAccept {
		t.Error("Expected rejection at hard limit")
	}
	if reason != "hard_limit_reached" {
		t.Errorf("Expected reason 'hard_limit_reached', got '%s'", reason)
	}

	// Verify rejection stats were incremented
	total, _ := m.GetRejectStats()
	if total == 0 {
		t.Error("Expected rejection count to be incremented")
	}
}

// TestCanAcceptParticipant_BelowSoftLimit verifies that requests are always accepted below soft limit
func TestCanAcceptParticipant_BelowSoftLimit(t *testing.T) {
	cfg := testTunnelConfig()
	cfg.MaxParticipatingTunnels = 1000
	cfg.ParticipatingLimitsEnabled = true

	m := NewManagerWithConfig(cfg)
	defer m.Stop()

	// Add participants to 40% capacity (below 50% soft limit)
	for i := 0; i < 400; i++ {
		p, err := NewParticipant(TunnelID(i), &mockTunnelEncryptor{})
		if err != nil {
			t.Fatalf("Failed to create participant: %v", err)
		}
		if err := m.AddParticipant(p); err != nil {
			t.Fatalf("Failed to add participant: %v", err)
		}
	}

	// Should always accept below soft limit
	for i := 0; i < 100; i++ {
		canAccept, reason := m.CanAcceptParticipant()
		if !canAccept {
			t.Errorf("Expected acceptance below soft limit, got rejection: %s", reason)
		}
	}
}

// TestCanAcceptParticipant_SoftLimitProbabilistic verifies probabilistic rejection at soft limit
func TestCanAcceptParticipant_SoftLimitProbabilistic(t *testing.T) {
	cfg := testTunnelConfig()
	cfg.MaxParticipatingTunnels = 1000
	cfg.ParticipatingLimitsEnabled = true

	m := NewManagerWithConfig(cfg)
	defer m.Stop()

	// Add participants to 70% capacity (above soft limit but below hard limit)
	for i := 0; i < 700; i++ {
		p, err := NewParticipant(TunnelID(i), &mockTunnelEncryptor{})
		if err != nil {
			t.Fatalf("Failed to create participant: %v", err)
		}
		if err := m.AddParticipant(p); err != nil {
			t.Fatalf("Failed to add participant: %v", err)
		}
	}

	// At 70% capacity, some requests should be rejected probabilistically
	// Run many trials to verify probabilistic behavior
	accepted := 0
	rejected := 0
	trials := 1000

	for i := 0; i < trials; i++ {
		canAccept, _ := m.CanAcceptParticipant()
		if canAccept {
			accepted++
		} else {
			rejected++
		}
	}

	// At 70% capacity (20% into soft limit zone), reject probability should be ~58%
	// Allow wide margin for randomness: expect some but not all to be rejected
	if rejected == 0 {
		t.Error("Expected some probabilistic rejections above soft limit, got none")
	}
	if accepted == 0 {
		t.Error("Expected some acceptances above soft limit, got none")
	}

	// Verify rejection rate is reasonable (between 30% and 80%)
	rejectRate := float64(rejected) / float64(trials)
	if rejectRate < 0.30 || rejectRate > 0.80 {
		t.Errorf("Unexpected rejection rate: %.2f (expected 0.30-0.80)", rejectRate)
	}
}

// TestCanAcceptParticipant_CriticalZone verifies high rejection rate near hard limit
func TestCanAcceptParticipant_CriticalZone(t *testing.T) {
	cfg := testTunnelConfig()
	cfg.MaxParticipatingTunnels = 1000
	cfg.ParticipatingLimitsEnabled = true

	m := NewManagerWithConfig(cfg)
	defer m.Stop()

	// Add participants to 95% capacity (in critical zone, last 100 before hard limit)
	for i := 0; i < 950; i++ {
		p, err := NewParticipant(TunnelID(i), &mockTunnelEncryptor{})
		if err != nil {
			t.Fatalf("Failed to create participant: %v", err)
		}
		if err := m.AddParticipant(p); err != nil {
			t.Fatalf("Failed to add participant: %v", err)
		}
	}

	// In critical zone, rejection rate should be very high (90%+)
	accepted := 0
	rejected := 0
	trials := 500

	for i := 0; i < trials; i++ {
		canAccept, _ := m.CanAcceptParticipant()
		if canAccept {
			accepted++
		} else {
			rejected++
		}
	}

	// Expect very high rejection rate in critical zone
	rejectRate := float64(rejected) / float64(trials)
	if rejectRate < 0.85 {
		t.Errorf("Expected rejection rate >= 85%% in critical zone, got %.2f", rejectRate)
	}
}

// TestRejectStats verifies rejection statistics tracking
func TestRejectStats(t *testing.T) {
	cfg := testTunnelConfig()
	cfg.MaxParticipatingTunnels = 10
	cfg.ParticipatingLimitsEnabled = true

	m := NewManagerWithConfig(cfg)
	defer m.Stop()

	// Fill to hard limit
	for i := 0; i < 10; i++ {
		p, err := NewParticipant(TunnelID(i), &mockTunnelEncryptor{})
		if err != nil {
			t.Fatalf("Failed to create participant: %v", err)
		}
		if err := m.AddParticipant(p); err != nil {
			t.Fatalf("Failed to add participant: %v", err)
		}
	}

	// Trigger several rejections
	for i := 0; i < 5; i++ {
		m.CanAcceptParticipant()
	}

	total, recent := m.GetRejectStats()
	if total != 5 {
		t.Errorf("Expected 5 total rejections, got %d", total)
	}
	if recent != 5 {
		t.Errorf("Expected 5 recent rejections, got %d", recent)
	}

	// Reset recent counter
	m.ResetRecentRejectCount()
	total, recent = m.GetRejectStats()
	if total != 5 {
		t.Errorf("Expected total rejections unchanged at 5, got %d", total)
	}
	if recent != 0 {
		t.Errorf("Expected recent rejections reset to 0, got %d", recent)
	}
}

// testTunnelConfig returns a TunnelDefaults config suitable for testing
func testTunnelConfig() config.TunnelDefaults {
	return config.TunnelDefaults{
		MinPoolSize:                4,
		MaxPoolSize:                6,
		TunnelLength:               3,
		TunnelLifetime:             10 * time.Minute,
		TunnelTestInterval:         60 * time.Second,
		TunnelTestTimeout:          5 * time.Second,
		BuildTimeout:               90 * time.Second,
		BuildRetries:               3,
		ReplaceBeforeExpiration:    2 * time.Minute,
		MaintenanceInterval:        30 * time.Second,
		MaxParticipatingTunnels:    15000,
		ParticipatingLimitsEnabled: true,
		PerSourceRateLimitEnabled:  true,
		MaxBuildRequestsPerMinute:  10,
		BuildRequestBurstSize:      3,
		SourceBanDuration:          5 * time.Minute,
	}
}
