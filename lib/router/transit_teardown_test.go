// Tests for transit-tunnel teardown when the next hop's RouterInfo / session
// cannot be resolved. Regression coverage for the per-packet
// "failed to receive RouterInfo for peer" error spam: a transit tunnel whose
// next hop is unresolvable must fail once, mark itself failed, and be torn
// down — not log an error for every arriving record.

package router

import (
	"fmt"
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/session_key"
	"github.com/go-i2p/crypto/rand"
	cryptotunnel "github.com/go-i2p/crypto/tunnel"
	"github.com/go-i2p/go-i2p/lib/i2cp"
	"github.com/go-i2p/go-i2p/lib/i2np"
	tunnelpkg "github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// failingSessionProvider returns an error for every GetSessionByHash,
// simulating a next hop whose RouterInfo / session cannot be resolved. It
// counts invocations so tests can assert the failure is bounded to once per
// tunnel rather than once per record.
type failingSessionProvider struct {
	calls int
}

func (p *failingSessionProvider) GetSessionByHash(hash common.Hash) (i2np.I2NPTransportSession, error) {
	p.calls++
	return nil, fmt.Errorf("failed to get session to relay to %x: no RouterInfo available", hash[:8])
}

// TestTransitTunnel_NextHopUnresolvableFailsOnceAndTearsDown feeds several
// transit records for a tunnel whose next hop cannot be resolved and asserts:
//   - the first record fails cleanly (HandleTunnelData returns nil so the
//     caller does not log the same failure again),
//   - the participant is marked failed and treated as expired (so the manager's
//     cleanup loop tears the tunnel down),
//   - the next-hop session is attempted exactly once across all records (the
//     failure is bounded to once per tunnel, not per packet),
//   - subsequent records are dropped silently (return nil).
func TestTransitTunnel_NextHopUnresolvableFailsOnceAndTearsDown(t *testing.T) {
	sessionManager := i2cp.NewSessionManager()
	handler := NewInboundMessageHandler(sessionManager)

	pm := tunnelpkg.NewManager()
	defer pm.Stop()
	handler.SetParticipantManager(pm)

	const transitTunnelID = tunnelpkg.TunnelID(9999)
	const nextHopTunnelID = tunnelpkg.TunnelID(8888)

	var nextHopHash common.Hash
	for i := 0; i < 32; i++ {
		nextHopHash[i] = byte(i + 1)
	}

	// Real AES encryptor so Participant.Process succeeds and we reach the
	// forwarding stage (where the next-hop resolution fails).
	var layerKey, ivKey cryptotunnel.TunnelKey
	_, err := rand.Read(layerKey[:])
	require.NoError(t, err)
	_, err = rand.Read(ivKey[:])
	require.NoError(t, err)

	aesEncryptor, err := cryptotunnel.NewAESEncryptor(layerKey, ivKey)
	require.NoError(t, err)

	var sessionLayerKey, sessionIVKey session_key.SessionKey
	copy(sessionLayerKey[:], layerKey[:])
	copy(sessionIVKey[:], ivKey[:])

	expiry := time.Now().Add(10 * time.Minute)
	err = pm.RegisterParticipant(
		transitTunnelID,
		nextHopHash,
		expiry,
		sessionLayerKey,
		sessionIVKey,
		nextHopHash,
		nextHopTunnelID,
	)
	require.NoError(t, err)

	participant := pm.GetParticipant(transitTunnelID)
	require.NotNil(t, participant)

	// Build a valid encrypted transit record. A helper varies the IV per record
	// so Participant.Process accepts each one (the IV-bloom would otherwise
	// drop identical-IV records before the forwarding stage), ensuring the
	// IsFailed guard — not duplicate suppression — is what bounds the next-hop
	// attempts.
	buildMsg := func(ivByte byte) i2np.Message {
		inner := make([]byte, 1028)
		for i := 4; i < 20; i++ {
			inner[i] = ivByte // distinct IV per record
		}
		for i := 20; i < len(inner); i++ {
			inner[i] = byte(i % 256)
		}
		encryptedMsg, err := aesEncryptor.Encrypt(inner)
		require.NoError(t, err)
		require.Equal(t, 1028, len(encryptedMsg))
		var payload [1024]byte
		copy(payload[:], encryptedMsg[4:])
		return i2np.NewTunnelDataMessage(transitTunnelID, payload)
	}

	// Next hop is unresolvable.
	provider := &failingSessionProvider{}
	handler.SetSessionProvider(provider)

	// First record: fails cleanly. HandleTunnelData must return nil so the
	// router's message loop does not log the failure a second time.
	err = handler.HandleTunnelData(buildMsg(0x10))
	require.NoError(t, err, "first transit record must fail cleanly (nil) so the caller does not double-log")

	// The participant is marked failed and treated as expired (teardown).
	assert.True(t, participant.IsFailed(), "participant must be marked failed after next-hop resolution failure")
	assert.True(t, participant.IsExpired(time.Now()), "failed participant must be treated as expired so the manager tears it down")

	// Subsequent records (distinct IVs, so Process accepts them) drop silently
	// and never re-attempt the next hop.
	for i := 1; i < 5; i++ {
		err = handler.HandleTunnelData(buildMsg(byte(0x20 + i)))
		require.NoError(t, err, "subsequent records for a failed tunnel must drop silently (nil)")
	}

	// The next-hop session was attempted exactly once across all five records:
	// the failure is bounded to once per tunnel, not per packet.
	assert.Equal(t, 1, provider.calls, "next-hop session resolution must be attempted once, not per packet")
}
