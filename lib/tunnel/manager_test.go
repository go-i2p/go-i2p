package tunnel

import (
	"testing"
	"time"

	"github.com/go-i2p/crypto/tunnel"
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

	// Add second participant with same ID (should replace)
	p2, _ := NewParticipant(tunnelID, &mockTunnelEncryptor{})
	err = m.AddParticipant(p2)
	if err != nil {
		t.Errorf("Failed to add duplicate participant: %v", err)
	}

	// Should still have only 1 participant
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
	m.AddParticipant(p)

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
		m.AddParticipant(p)
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
	m.AddParticipant(p)

	// Create a participant that's not expired
	p2, _ := NewParticipant(22222, &mockTunnelEncryptor{})
	m.AddParticipant(p2)

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
			m.AddParticipant(p)
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
		m.AddParticipant(p)
	}

	// Stop the manager
	m.Stop()

	// Verify all participants cleared
	if m.ParticipantCount() != 0 {
		t.Errorf("Expected 0 participants after stop, got %d", m.ParticipantCount())
	}

	// Verify we can still call methods safely (shouldn't panic)
	m.AddParticipant(nil) // Should handle gracefully
}
