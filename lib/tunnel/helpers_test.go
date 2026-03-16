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
	expectedHash := make([]byte, HashSize)
	for i := 0; i < HashSize; i++ {
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

// createLimiterWithTwoHashes creates a SourceLimiter with the given params,
// registers cleanup, and returns it along with two deterministic test hashes.
// Used by source_limiter_unit_test.go.
func createLimiterWithTwoHashes(t *testing.T, maxPerMin, burstSize int, banDuration time.Duration) (*SourceLimiter, common.Hash, common.Hash) {
	t.Helper()
	sl := createTestSourceLimiter(maxPerMin, burstSize, banDuration)
	t.Cleanup(sl.Stop)
	return sl, createTestHash(1), createTestHash(2)
}

// assertSendProducesSingleMsg sends msg with delivery config dc via the gateway,
// and asserts a single 1028-byte tunnel message is produced.
// Used by gateway_delivery_unit_test.go.
func assertSendProducesSingleMsg(t *testing.T, gw *Gateway, msg []byte, dc DeliveryConfig) {
	t.Helper()
	result, err := gw.SendWithDelivery(msg, dc)
	assert.NoError(t, err)
	require.NotNil(t, result)
	assert.Len(t, result, 1)
	assert.Len(t, result[0], 1028)
}

// assertTunnelForwarded locks the mock forwarder and asserts exactly one tunnel
// forwarding call with the expected tunnel ID, gateway hash, and message bytes.
// Used by endpoint_forwarding_unit_test.go.
func assertTunnelForwarded(t *testing.T, fwd *mockForwarder, expectedTunnelID uint32, expectedHash [32]byte, expectedMsg []byte) {
	t.Helper()
	fwd.mu.Lock()
	defer fwd.mu.Unlock()
	require.Len(t, fwd.tunnelCalls, 1)
	assert.Equal(t, expectedTunnelID, fwd.tunnelCalls[0].tunnelID)
	assert.Equal(t, expectedHash, fwd.tunnelCalls[0].gatewayHash)
	assert.Equal(t, expectedMsg, fwd.tunnelCalls[0].msgBytes)
}

// assertRouterForwarded locks the mock forwarder and asserts exactly one router
// forwarding call with the expected router hash and message bytes.
// Used by endpoint_forwarding_unit_test.go.
func assertRouterForwarded(t *testing.T, fwd *mockForwarder, expectedHash [32]byte, expectedMsg []byte) {
	t.Helper()
	fwd.mu.Lock()
	defer fwd.mu.Unlock()
	require.Len(t, fwd.routerCalls, 1)
	assert.Equal(t, expectedHash, fwd.routerCalls[0].routerHash)
	assert.Equal(t, expectedMsg, fwd.routerCalls[0].msgBytes)
}

// createSpecEndpointWithCapture creates an Endpoint backed by specMockEncryptor
// with a handler that captures delivered bytes. Returns the endpoint and a getter
// for the captured message. Used by spec_compliance_validation_test.go.
func createSpecEndpointWithCapture(t *testing.T) (*Endpoint, func() []byte) {
	t.Helper()
	enc := &specMockEncryptor{}
	var received []byte
	handler := func(msgBytes []byte) error {
		received = msgBytes
		return nil
	}
	ep, err := NewEndpoint(TunnelID(1), enc, handler)
	require.NoError(t, err)
	t.Cleanup(ep.Stop)
	return ep, func() []byte { return received }
}

// createSpecEndpointWithForwarder creates an Endpoint backed by specMockEncryptor
// with a no-op handler and an attached specMockForwarder. Used by
// spec_compliance_validation_test.go.
func createSpecEndpointWithForwarder(t *testing.T) (*Endpoint, *specMockForwarder) {
	t.Helper()
	enc := &specMockEncryptor{}
	handler := func(msgBytes []byte) error { return nil }
	ep, err := NewEndpoint(TunnelID(1), enc, handler)
	require.NoError(t, err)
	t.Cleanup(ep.Stop)
	fwd := &specMockForwarder{}
	ep.SetForwarder(fwd)
	return ep, fwd
}

// newBuildTunnelRequest creates a BuildTunnelRequest with the given hop count
// and direction. Used by peer_selector_integration_test.go.
func newBuildTunnelRequest(hopCount int, isInbound bool) BuildTunnelRequest {
	return BuildTunnelRequest{
		HopCount:  hopCount,
		IsInbound: isInbound,
	}
}

// waitForBuildRetries drains count items from completionChan (waiting for
// retried builds to complete) and sleeps briefly for goroutine state updates.
// Used by pool_integration_test.go.
func waitForBuildRetries(completionChan chan struct{}, count int) {
	for i := 0; i < count; i++ {
		<-completionChan
	}
	time.Sleep(10 * time.Millisecond)
}
