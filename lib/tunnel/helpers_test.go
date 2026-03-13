package tunnel

import (
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/stretchr/testify/assert"
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

// exhaustBurstAndBan exhausts the burst token and triggers auto-ban by
// generating enough rejections (11+). Used by source_limiter_unit_test.go.
func exhaustBurstAndBan(t *testing.T, sl *SourceLimiter, hash common.Hash) {
	t.Helper()
	sl.AllowRequest(hash)
	for i := 0; i < 11; i++ {
		sl.AllowRequest(hash)
	}
}

// createTestGatewayPassthrough creates a Gateway with a passthroughEncryptor
// (identity encryption). Used by gateway_delivery_unit_test.go.
func createTestGatewayPassthrough(t *testing.T) *Gateway {
	t.Helper()
	enc := &passthroughEncryptor{}
	gw, err := NewGateway(TunnelID(1), enc, TunnelID(2))
	require.NoError(t, err)
	return gw
}

// createSpecGateway creates a Gateway with specMockEncryptor for spec
// compliance tests. Used by spec_compliance_validation_test.go.
func createSpecGateway(t *testing.T) *Gateway {
	t.Helper()
	enc := &specMockEncryptor{}
	gw, err := NewGateway(TunnelID(1), enc, TunnelID(2))
	require.NoError(t, err)
	return gw
}

// buildSpecGatewayMsg creates a Gateway with specMockEncryptor and builds a
// standard test tunnel message (DI=[0x00,0x00,0x05], payload=[1,2,3,4,5]).
func buildSpecGatewayMsg(t *testing.T) (*Gateway, []byte) {
	t.Helper()
	gw := createSpecGateway(t)
	di := []byte{0x00, 0x00, 0x05}
	payload := []byte{1, 2, 3, 4, 5}
	msg, err := gw.buildTunnelMessage(di, payload)
	require.NoError(t, err)
	return gw, msg
}

// setupPoolWithFailingPeerBuilder creates a TunnelPool with a PeerTrackingBuilder
// configured to fail, using the given peer hash seeds. Returns the pool, builder,
// and generated peer hashes.
func setupPoolWithFailingPeerBuilder(t *testing.T, peerSeeds ...byte) (*Pool, *PeerTrackingBuilder, []common.Hash) {
	t.Helper()
	pool := NewTunnelPool(&MockPeerSelector{})
	t.Cleanup(pool.Stop)
	peers := make([]common.Hash, len(peerSeeds))
	for i, seed := range peerSeeds {
		peers[i] = makePeerHash(seed)
	}
	builder := &PeerTrackingBuilder{
		shouldFail:  true,
		failedPeers: peers,
	}
	pool.SetTunnelBuilder(builder)
	return pool, builder, peers
}

// reassembleTestFragments creates a fragmentAssembler, reassembles fragments,
// and delivers the result. Returns the delivery error.
func reassembleTestFragments(t *testing.T, ep *Endpoint, msgID uint32, deliveryType byte, tunnelID uint32, hash [32]byte, fragments map[int][]byte) error {
	t.Helper()
	mask := uint64(0)
	for i := range fragments {
		mask |= 1 << uint(i)
	}
	assembler := &fragmentAssembler{
		fragments:    fragments,
		deliveryType: deliveryType,
		tunnelID:     tunnelID,
		hash:         hash,
		totalCount:   len(fragments),
		receivedMask: mask,
	}
	ep.fragmentsMutex.Lock()
	ep.fragments[msgID] = assembler
	result := ep.reassembleFragments(msgID, assembler)
	ep.fragmentsMutex.Unlock()
	return ep.deliverReassembled(result)
}

// assertDeliveryInstructionsRoundTrip serializes and deserializes the given
// DeliveryInstructions, asserts common fields match, and returns the parsed result.
func assertDeliveryInstructionsRoundTrip(t *testing.T, original *DeliveryInstructions) *DeliveryInstructions {
	t.Helper()
	data, err := original.Bytes()
	require.NoError(t, err, "Serialization should succeed")
	parsed, err := NewDeliveryInstructions(data)
	require.NoError(t, err, "Deserialization should succeed")
	assert.Equal(t, original.fragmentType, parsed.fragmentType)
	assert.Equal(t, original.deliveryType, parsed.deliveryType)
	assert.Equal(t, original.fragmentSize, parsed.fragmentSize)
	return parsed
}

// assertDeliveryInstructionHash builds a raw delivery instruction from the given
// flag byte, optional tunnel ID bytes, and a generated hash, then asserts that
// Hash() returns the expected hash.
func assertDeliveryInstructionHash(t *testing.T, flagByte byte, tunnelIDBytes []byte, hashFn func(int) byte) {
	t.Helper()
	expectedHash := make([]byte, HASH_SIZE)
	for i := 0; i < HASH_SIZE; i++ {
		expectedHash[i] = hashFn(i)
	}
	data := []byte{flagByte}
	if tunnelIDBytes != nil {
		data = append(data, tunnelIDBytes...)
	}
	data = append(data, expectedHash...)
	data = append(data, 0x00, 0x10) // fragment size = 16
	di, err := NewDeliveryInstructions(data)
	require.NoError(t, err, "Failed to create DeliveryInstructions")
	resultHash, err := di.Hash()
	require.NoError(t, err, "Hash() should not return an error")
	assert.Equal(t, expectedHash, resultHash[:], "Hash should match the stored hash value")
}

// createTestPoolWithDefaultConfig creates a TunnelPool with standard test config
// (min=4, max=6, lifetime=10m, rebuild=2m, hops=3, outbound).
func createTestPoolWithDefaultConfig(t *testing.T) *Pool {
	t.Helper()
	config := PoolConfig{
		MinTunnels:       4,
		MaxTunnels:       6,
		TunnelLifetime:   10 * time.Minute,
		RebuildThreshold: 2 * time.Minute,
		HopCount:         3,
		IsInbound:        false,
	}
	pool := NewTunnelPoolWithConfig(&MockPeerSelector{}, config)
	t.Cleanup(pool.Stop)
	return pool
}
