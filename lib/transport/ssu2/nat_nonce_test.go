package ssu2

// nat_nonce_test.go tests nonce verification in PeerTest observation handling
// to prevent address-confirmation poisoning via injection attacks.

import (
	"net"
	"testing"
	"time"

	ssu2noise "github.com/go-i2p/go-noise/ssu2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPeerTestObservation_UnknownNonce verifies that handlePeerTestAsAlice
// rejects observations with nonces that don't belong to a test this node initiated.
// This prevents an attacker from sending unsolicited PeerTest replies to poison
// the address-confirmation cache (RD-1 security bug).
func TestPeerTestObservation_UnknownNonce(t *testing.T) {
	tr, cleanup := makeTestTransportWithListener(t)
	defer cleanup()

	// Start with a clean nat state cache to observe any poisoning attempts
	require.NotNil(t, tr.natStateCache)
	initial := tr.natStateCache.getExternal()
	require.Empty(t, initial, "should start with no confirmed external address")

	// Attacker sends a PeerTest reply with an arbitrary nonce (not initiated by us)
	attackerNonce := uint32(0xdeadbeef)
	attackerIP := net.ParseIP("203.0.113.42") // TEST-NET-3
	attackerBlock := &ssu2noise.PeerTestBlock{
		MessageCode: ssu2noise.PeerTestReply,
		Nonce:       attackerNonce,
		AliceIP:     attackerIP.To4(),
		AlicePort:   12345,
		Version:     2,
	}

	// Get the manager under lock (HIGH-1.2 fix)
	tr.natManagerMu.RLock()
	mgr := tr.peerTestManager
	tr.natManagerMu.RUnlock()

	// Call handlePeerTestAsAlice with the attacker's block
	err := tr.handlePeerTestAsAlice(attackerBlock, mgr)
	assert.NoError(t, err, "handlePeerTestAsAlice should not error on unknown nonce")

	// Verify the observation was NOT recorded in the nat state cache
	// (the attacker's address should not appear in observations)
	after := tr.natStateCache.getExternal()
	assert.Empty(t, after, "attacker's observation should not be confirmed")

	// Double-check: even if the attacker sends multiple observations with the
	// same bogus nonce and matching IPs, they should not accumulate toward
	// confirmation threshold.
	for i := 0; i < peerTestConfirmThreshold+1; i++ {
		_ = tr.handlePeerTestAsAlice(attackerBlock, mgr)
	}
	final := tr.natStateCache.getExternal()
	assert.Empty(t, final, "repeated attacker observations should not confirm address")
}

// TestPeerTestObservation_ValidNonce verifies that observations with legitimate
// nonces (from tests this node initiated) ARE recorded and can confirm an address.
func TestPeerTestObservation_ValidNonce(t *testing.T) {
	tr, cleanup := makeTestTransportWithListener(t)
	defer cleanup()

	require.NotNil(t, tr.peerTestManager)

	// Initiate a legitimate peer test to get a valid nonce
	bobAddr := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 19001} // TEST-NET-2
	legitimateNonce, err := tr.InitiateNATDetection(bobAddr)
	require.NoError(t, err)
	require.NotZero(t, legitimateNonce)

	// Verify the nonce is registered
	test := tr.peerTestManager.GetTest(legitimateNonce)
	require.NotNil(t, test, "legitimate nonce should be registered")

	// Get the manager under lock (HIGH-1.2 fix)
	tr.natManagerMu.RLock()
	mgr := tr.peerTestManager
	tr.natManagerMu.RUnlock()

	// Send peer test replies with the legitimate nonce and a consistent external address
	observedIP := net.ParseIP("192.0.2.99") // TEST-NET-1
	observedPort := uint16(54321)
	block := &ssu2noise.PeerTestBlock{
		MessageCode: ssu2noise.PeerTestReply,
		Nonce:       legitimateNonce,
		AliceIP:     observedIP.To4(),
		AlicePort:   observedPort,
		Version:     2,
	}

	// Send peerTestConfirmThreshold observations with the legitimate nonce
	// to trigger address confirmation
	for i := 0; i < peerTestConfirmThreshold; i++ {
		err := tr.handlePeerTestAsAlice(block, mgr)
		assert.NoError(t, err)
		// Small delay to ensure observations have distinct timestamps
		time.Sleep(1 * time.Millisecond)
	}

	// The address should now be confirmed
	confirmed := tr.natStateCache.getExternal()
	expected := net.JoinHostPort(observedIP.String(), "54321")
	assert.Equal(t, expected, confirmed, "legitimate observations should confirm the address")
}

// TestPeerTestObservation_MixedNonces verifies that observations with unknown
// nonces do not interfere with legitimate observations using valid nonces.
func TestPeerTestObservation_MixedNonces(t *testing.T) {
	tr, cleanup := makeTestTransportWithListener(t)
	defer cleanup()

	require.NotNil(t, tr.peerTestManager)

	// Initiate a legitimate peer test
	bobAddr := &net.UDPAddr{IP: net.ParseIP("198.51.100.2"), Port: 19002}
	legitimateNonce, err := tr.InitiateNATDetection(bobAddr)
	require.NoError(t, err)

	// Get the manager under lock (HIGH-1.2 fix)
	tr.natManagerMu.RLock()
	mgr := tr.peerTestManager
	tr.natManagerMu.RUnlock()

	legitimateIP := net.ParseIP("192.0.2.100")
	attackerIP := net.ParseIP("203.0.113.50")

	// Interleave legitimate and attacker observations
	for i := 0; i < peerTestConfirmThreshold; i++ {
		// Attacker observation (unknown nonce)
		attackerBlock := &ssu2noise.PeerTestBlock{
			MessageCode: ssu2noise.PeerTestReply,
			Nonce:       uint32(0xcafebabe),
			AliceIP:     attackerIP.To4(),
			AlicePort:   9999,
			Version:     2,
		}
		_ = tr.handlePeerTestAsAlice(attackerBlock, mgr)

		// Legitimate observation (known nonce)
		legitimateBlock := &ssu2noise.PeerTestBlock{
			MessageCode: ssu2noise.PeerTestReply,
			Nonce:       legitimateNonce,
			AliceIP:     legitimateIP.To4(),
			AlicePort:   55555,
			Version:     2,
		}
		err := tr.handlePeerTestAsAlice(legitimateBlock, mgr)
		assert.NoError(t, err)
		time.Sleep(1 * time.Millisecond)
	}

	// Only the legitimate address should be confirmed
	confirmed := tr.natStateCache.getExternal()
	expected := net.JoinHostPort(legitimateIP.String(), "55555")
	assert.Equal(t, expected, confirmed, "only legitimate observations should confirm")

	// Verify attacker's address did NOT get confirmed
	assert.NotContains(t, confirmed, attackerIP.String(), "attacker IP should not appear in confirmed address")
}
