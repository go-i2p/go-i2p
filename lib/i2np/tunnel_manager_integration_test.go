package i2np

import (
	"testing"

	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/stretchr/testify/assert"
)

// TestTunnelManager_ProcessTunnelReply_WithPool tests the enhanced ProcessTunnelReply with pool integration
func TestTunnelManager_ProcessTunnelReply_WithPool(t *testing.T) {
	// Create TunnelManager with pool
	peerSelector := &SimpleMockPeerSelector{}
	tm := NewTunnelManager(peerSelector)

	// Create a successful tunnel build reply
	reply := createSuccessfulTunnelBuildReply()

	// Process the reply
	err := tm.ProcessTunnelReply(reply)

	// Should succeed (even without tunnel correlation, the ProcessReply method should work)
	assert.NoError(t, err, "ProcessTunnelReply should succeed with successful reply")
}

// TestTunnelManager_ProcessTunnelReply_WithFailure tests ProcessTunnelReply with failed reply
func TestTunnelManager_ProcessTunnelReply_WithFailure(t *testing.T) {
	// Create TunnelManager with pool
	peerSelector := &SimpleMockPeerSelector{}
	tm := NewTunnelManager(peerSelector)

	// Create a failed tunnel build reply
	reply := createRejectedTunnelBuildReply()

	// Process the reply
	err := tm.ProcessTunnelReply(reply)

	// Should fail due to rejections
	assert.Error(t, err, "ProcessTunnelReply should fail with rejected reply")
	assert.Contains(t, err.Error(), "tunnel build failed")
}

// TestTunnelManager_ProcessTunnelReply_VariableTunnel tests ProcessTunnelReply with variable tunnel
func TestTunnelManager_ProcessTunnelReply_VariableTunnel(t *testing.T) {
	// Create TunnelManager with pool
	peerSelector := &SimpleMockPeerSelector{}
	tm := NewTunnelManager(peerSelector)

	// Create a successful variable tunnel build reply
	reply := createSuccessfulVariableTunnelBuildReply(3)

	// Process the reply
	err := tm.ProcessTunnelReply(reply)

	// Should succeed
	assert.NoError(t, err, "ProcessTunnelReply should succeed with successful variable reply")
}

// TestTunnelManager_ProcessTunnelReply_NoPool tests ProcessTunnelReply without pool
func TestTunnelManager_ProcessTunnelReply_NoPool(t *testing.T) {
	// Create TunnelManager without pool (nil peerSelector results in nil pool)
	tm := NewTunnelManager(nil)

	// Create a successful tunnel build reply
	reply := createSuccessfulTunnelBuildReply()

	// Process the reply
	err := tm.ProcessTunnelReply(reply)

	// Should succeed (ProcessReply still works without pool)
	assert.NoError(t, err, "ProcessTunnelReply should succeed even without pool")
}

// TestTunnelManager_UpdateTunnelStatesFromReply tests tunnel state update logic
func TestTunnelManager_UpdateTunnelStatesFromReply(t *testing.T) {
	// Create TunnelManager with pool
	peerSelector := &SimpleMockPeerSelector{}
	tm := NewTunnelManager(peerSelector)

	// Create test records
	records := []BuildResponseRecord{
		createValidResponseRecord(),
		createValidResponseRecord(),
	}

	// Test with successful reply (no error)
	tm.updateTunnelStatesFromReply(records, nil)
	// This should not panic even without matching tunnel

	// Test with failed reply (error)
	tm.updateTunnelStatesFromReply(records, assert.AnError)
	// This should not panic even without matching tunnel
}

// TestTunnelManager_FindMatchingBuildingTunnel tests tunnel matching logic
func TestTunnelManager_FindMatchingBuildingTunnel(t *testing.T) {
	// Create TunnelManager with pool
	peerSelector := &SimpleMockPeerSelector{}
	tm := NewTunnelManager(peerSelector)

	// Test finding matching tunnel (should return nil with current implementation)
	matchingTunnel := tm.findMatchingBuildingTunnel(3)
	assert.Nil(t, matchingTunnel, "Current implementation should return nil (TODO: proper correlation)")
}

// TestTunnelManager_CleanupFailedTunnel tests failed tunnel cleanup
func TestTunnelManager_CleanupFailedTunnel(t *testing.T) {
	// Create TunnelManager with pool
	peerSelector := &SimpleMockPeerSelector{}
	tm := NewTunnelManager(peerSelector)

	// Test cleanup (should not panic)
	testTunnelID := tunnel.TunnelID(12345)
	go tm.cleanupFailedTunnel(testTunnelID)

	// Give goroutine time to execute (this is primarily a no-panic test)
	// In practice, we can't easily verify the tunnel was removed without
	// better pool access methods
}
