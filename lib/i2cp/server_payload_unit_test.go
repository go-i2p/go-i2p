package i2cp

import (
	"encoding/binary"
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/go-i2p/lib/tunnel"
)

// TestDestroySessionPayloadFormat verifies that handleDestroySession returns
// a 3-byte SessionStatus payload (SessionID + Status) per the I2CP spec,
// not a 1-byte payload.
func TestDestroySessionPayloadFormat(t *testing.T) {
	config := &ServerConfig{
		ListenAddr:  "localhost:17680",
		Network:     "tcp",
		MaxSessions: 100,
	}

	server, err := NewServer(config)
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	// Create a session directly via the manager
	session, err := server.manager.CreateSession(nil, nil)
	if err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}

	sessionID := session.ID()
	sessionCopy := session

	// Call handleDestroySession
	destroyMsg := &Message{
		Type:      MessageTypeDestroySession,
		SessionID: sessionID,
	}

	response, err := server.handleDestroySession(destroyMsg, &sessionCopy)
	if err != nil {
		t.Fatalf("handleDestroySession() error = %v", err)
	}

	if response == nil {
		t.Fatal("handleDestroySession() returned nil response")
	}

	// Verify payload is 3 bytes: SessionID(2) + Status(1)
	if len(response.Payload) != 3 {
		t.Fatalf("SessionStatus payload length = %d, want 3", len(response.Payload))
	}

	// Verify the session ID is correctly encoded in the payload
	payloadSessionID := binary.BigEndian.Uint16(response.Payload[0:2])
	if payloadSessionID != sessionID {
		t.Errorf("Payload SessionID = %d, want %d", payloadSessionID, sessionID)
	}

	// Verify the status byte is 0 (Destroyed)
	if response.Payload[2] != 0x00 {
		t.Errorf("Payload status byte = %d, want 0 (Destroyed)", response.Payload[2])
	}
}

// TestBuildRequestVariableLeaseSetPayload_FilteredCount verifies that the
// lease count byte in the payload matches the number of leases actually
// written, not the unfiltered tunnel count.
func TestBuildRequestVariableLeaseSetPayload_FilteredCount(t *testing.T) {
	server := &Server{}

	// Create a mix of valid, nil, and zero-hop tunnels
	hash1 := common.Hash{}
	copy(hash1[:], []byte("abcdefghijklmnopqrstuvwxyz012345"))
	hash2 := common.Hash{}
	copy(hash2[:], []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"))

	tunnels := []*tunnel.TunnelState{
		{
			ID:        1,
			Hops:      []common.Hash{hash1},
			CreatedAt: time.Now(),
		},
		nil, // nil tunnel — should be filtered
		{
			ID:        2,
			Hops:      []common.Hash{}, // zero-hop — should be filtered
			CreatedAt: time.Now(),
		},
		{
			ID:        3,
			Hops:      []common.Hash{hash2},
			CreatedAt: time.Now(),
		},
	}

	payload, err := server.buildRequestVariableLeaseSetPayload(tunnels)
	if err != nil {
		t.Fatalf("buildRequestVariableLeaseSetPayload() error = %v", err)
	}

	// The count byte should be 2 (only the valid tunnels), not 4
	leaseCount := int(payload[0])
	if leaseCount != 2 {
		t.Errorf("Lease count = %d, want 2 (should exclude nil and zero-hop tunnels)", leaseCount)
	}

	// Verify payload size matches: 1 + 2*44 = 89 bytes
	expectedSize := 1 + 2*44
	if len(payload) != expectedSize {
		t.Errorf("Payload size = %d, want %d", len(payload), expectedSize)
	}

	// Verify first lease gateway hash
	if string(payload[1:1+32]) != string(hash1[:]) {
		t.Error("First lease gateway hash does not match hash1")
	}

	// Verify second lease gateway hash (offset: 1 + 44)
	if string(payload[45:45+32]) != string(hash2[:]) {
		t.Error("Second lease gateway hash does not match hash2")
	}
}

// TestBuildRequestVariableLeaseSetPayload_AllFilteredReturnsError verifies
// that when all tunnels are nil or zero-hop, an error is returned.
func TestBuildRequestVariableLeaseSetPayload_AllFilteredReturnsError(t *testing.T) {
	server := &Server{}

	tunnels := []*tunnel.TunnelState{
		nil,
		{ID: 1, Hops: []common.Hash{}}, // zero-hop
		nil,
	}

	_, err := server.buildRequestVariableLeaseSetPayload(tunnels)
	if err == nil {
		t.Error("Expected error when all tunnels are filtered out, got nil")
	}
}

// TestBuildRequestVariableLeaseSetPayload_AllValid verifies correct behavior
// when all tunnels are valid (no filtering needed).
func TestBuildRequestVariableLeaseSetPayload_AllValid(t *testing.T) {
	server := &Server{}

	hash := common.Hash{}
	copy(hash[:], []byte("abcdefghijklmnopqrstuvwxyz012345"))

	tunnels := []*tunnel.TunnelState{
		{ID: 1, Hops: []common.Hash{hash}, CreatedAt: time.Now()},
		{ID: 2, Hops: []common.Hash{hash}, CreatedAt: time.Now()},
		{ID: 3, Hops: []common.Hash{hash}, CreatedAt: time.Now()},
	}

	payload, err := server.buildRequestVariableLeaseSetPayload(tunnels)
	if err != nil {
		t.Fatalf("buildRequestVariableLeaseSetPayload() error = %v", err)
	}

	leaseCount := int(payload[0])
	if leaseCount != 3 {
		t.Errorf("Lease count = %d, want 3", leaseCount)
	}

	expectedSize := 1 + 3*44
	if len(payload) != expectedSize {
		t.Errorf("Payload size = %d, want %d", len(payload), expectedSize)
	}
}
