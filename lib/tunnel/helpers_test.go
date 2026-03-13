package tunnel

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// setupManagerWithParticipant creates a new Manager, adds a Participant with the
// given tunnel ID, and registers cleanup. Used by manager_unit_test.go.
func setupManagerWithParticipant(t *testing.T, tunnelID TunnelID) (*Manager, *Participant) {
	t.Helper()
	m := NewManager()
	t.Cleanup(m.Stop)
	p, _ := NewParticipant(tunnelID, &mockTunnelEncryptor{})
	err := m.AddParticipant(p)
	if err != nil {
		t.Fatalf("Failed to add participant: %v", err)
	}
	return m, p
}

// buildTestTunnelMsg creates a Gateway with fixed IDs and builds a tunnel message
// from a "test" payload. Returns the gateway, delivery instructions, and message.
func buildTestTunnelMsg(t *testing.T) (*Gateway, []byte, []byte) {
	t.Helper()
	gw := &Gateway{
		tunnelID:  TunnelID(12345),
		nextHopID: TunnelID(67890),
	}
	testMsg := []byte("test")
	instructions, err := gw.createDeliveryInstructions(testMsg)
	require.NoError(t, err)
	tunnelMsg, err := gw.buildTunnelMessage(instructions, testMsg)
	require.NoError(t, err)
	return gw, instructions, tunnelMsg
}
