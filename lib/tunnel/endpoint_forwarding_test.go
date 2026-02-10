package tunnel

import (
	"errors"
	"sync"
	"testing"

	"github.com/go-i2p/crypto/tunnel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockForwarder records all forwarding calls for verification.
type mockForwarder struct {
	mu          sync.Mutex
	tunnelCalls []forwardTunnelCall
	routerCalls []forwardRouterCall
	tunnelErr   error
	routerErr   error
}

type forwardTunnelCall struct {
	tunnelID    uint32
	gatewayHash [32]byte
	msgBytes    []byte
}

type forwardRouterCall struct {
	routerHash [32]byte
	msgBytes   []byte
}

func (f *mockForwarder) ForwardToTunnel(tunnelID uint32, gatewayHash [32]byte, msgBytes []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tunnelCalls = append(f.tunnelCalls, forwardTunnelCall{tunnelID, gatewayHash, msgBytes})
	return f.tunnelErr
}

func (f *mockForwarder) ForwardToRouter(routerHash [32]byte, msgBytes []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.routerCalls = append(f.routerCalls, forwardRouterCall{routerHash, msgBytes})
	return f.routerErr
}

// TestSetForwarder tests the SetForwarder method.
func TestSetForwarder(t *testing.T) {
	mockEncryptor := &tunnel.AESEncryptor{}
	handler := func(msgBytes []byte) error { return nil }

	ep, err := NewEndpoint(TunnelID(1), mockEncryptor, handler)
	require.NoError(t, err)
	defer ep.Stop()

	// Initially nil
	assert.Nil(t, ep.forwarder)

	fwd := &mockForwarder{}
	ep.SetForwarder(fwd)
	assert.NotNil(t, ep.forwarder)
}

// TestDeliverWithInstructionsLocal tests DT_LOCAL delivery goes to handler.
func TestDeliverWithInstructionsLocal(t *testing.T) {
	mockEncryptor := &tunnel.AESEncryptor{}
	var received []byte
	handler := func(msgBytes []byte) error {
		received = msgBytes
		return nil
	}

	ep, err := NewEndpoint(TunnelID(1), mockEncryptor, handler)
	require.NoError(t, err)
	defer ep.Stop()

	msg := []byte("hello local delivery")
	di := &DeliveryInstructions{}

	err = ep.deliverWithInstructions(DT_LOCAL, di, msg)
	assert.NoError(t, err)
	assert.Equal(t, msg, received, "DT_LOCAL should deliver to handler")
}

// TestDeliverWithInstructionsTunnel tests DT_TUNNEL delivery forwards via MessageForwarder.
func TestDeliverWithInstructionsTunnel(t *testing.T) {
	mockEncryptor := &tunnel.AESEncryptor{}
	handler := func(msgBytes []byte) error { return nil }

	ep, err := NewEndpoint(TunnelID(1), mockEncryptor, handler)
	require.NoError(t, err)
	defer ep.Stop()

	fwd := &mockForwarder{}
	ep.SetForwarder(fwd)

	var hash [32]byte
	copy(hash[:], []byte("gateway_hash_for_tunnel_fwd_test"))
	di := &DeliveryInstructions{
		tunnelID: 42,
		hash:     hash,
	}

	msg := []byte("tunnel delivery message")
	err = ep.deliverWithInstructions(DT_TUNNEL, di, msg)
	assert.NoError(t, err)

	fwd.mu.Lock()
	defer fwd.mu.Unlock()
	require.Len(t, fwd.tunnelCalls, 1)
	assert.Equal(t, uint32(42), fwd.tunnelCalls[0].tunnelID)
	assert.Equal(t, hash, fwd.tunnelCalls[0].gatewayHash)
	assert.Equal(t, msg, fwd.tunnelCalls[0].msgBytes)
}

// TestDeliverWithInstructionsRouter tests DT_ROUTER delivery forwards via MessageForwarder.
func TestDeliverWithInstructionsRouter(t *testing.T) {
	mockEncryptor := &tunnel.AESEncryptor{}
	handler := func(msgBytes []byte) error { return nil }

	ep, err := NewEndpoint(TunnelID(1), mockEncryptor, handler)
	require.NoError(t, err)
	defer ep.Stop()

	fwd := &mockForwarder{}
	ep.SetForwarder(fwd)

	var hash [32]byte
	copy(hash[:], []byte("router_hash_for_router_fwd_test!"))
	di := &DeliveryInstructions{
		hash: hash,
	}

	msg := []byte("router delivery message")
	err = ep.deliverWithInstructions(DT_ROUTER, di, msg)
	assert.NoError(t, err)

	fwd.mu.Lock()
	defer fwd.mu.Unlock()
	require.Len(t, fwd.routerCalls, 1)
	assert.Equal(t, hash, fwd.routerCalls[0].routerHash)
	assert.Equal(t, msg, fwd.routerCalls[0].msgBytes)
}

// TestDeliverViaForwarderNoForwarder tests graceful handling when no forwarder is set.
func TestDeliverViaForwarderNoForwarder(t *testing.T) {
	mockEncryptor := &tunnel.AESEncryptor{}
	handler := func(msgBytes []byte) error { return nil }

	ep, err := NewEndpoint(TunnelID(1), mockEncryptor, handler)
	require.NoError(t, err)
	defer ep.Stop()

	// No forwarder set — should not error, just silently skip
	var hash [32]byte
	err = ep.deliverViaForwarder(DT_TUNNEL, 42, hash, []byte("test"))
	assert.NoError(t, err, "No forwarder should be a no-op, not an error")

	err = ep.deliverViaForwarder(DT_ROUTER, 0, hash, []byte("test"))
	assert.NoError(t, err, "No forwarder should be a no-op for router too")
}

// TestDeliverViaForwarderError tests error propagation from forwarder.
func TestDeliverViaForwarderError(t *testing.T) {
	mockEncryptor := &tunnel.AESEncryptor{}
	handler := func(msgBytes []byte) error { return nil }

	ep, err := NewEndpoint(TunnelID(1), mockEncryptor, handler)
	require.NoError(t, err)
	defer ep.Stop()

	fwd := &mockForwarder{
		tunnelErr: errors.New("tunnel forward failed"),
		routerErr: errors.New("router forward failed"),
	}
	ep.SetForwarder(fwd)

	var hash [32]byte
	err = ep.deliverViaForwarder(DT_TUNNEL, 42, hash, []byte("test"))
	assert.Error(t, err, "Should propagate tunnel forwarding error")

	err = ep.deliverViaForwarder(DT_ROUTER, 0, hash, []byte("test"))
	assert.Error(t, err, "Should propagate router forwarding error")
}

// TestDeliverViaForwarderUnknownType tests unknown delivery type handling.
func TestDeliverViaForwarderUnknownType(t *testing.T) {
	mockEncryptor := &tunnel.AESEncryptor{}
	handler := func(msgBytes []byte) error { return nil }

	ep, err := NewEndpoint(TunnelID(1), mockEncryptor, handler)
	require.NoError(t, err)
	defer ep.Stop()

	fwd := &mockForwarder{}
	ep.SetForwarder(fwd)

	var hash [32]byte
	err = ep.deliverViaForwarder(DT_UNUSED, 0, hash, []byte("test"))
	assert.NoError(t, err, "Unknown delivery type should be silently skipped")

	fwd.mu.Lock()
	defer fwd.mu.Unlock()
	assert.Empty(t, fwd.tunnelCalls, "No tunnel calls for unknown type")
	assert.Empty(t, fwd.routerCalls, "No router calls for unknown type")
}

// TestStoreFirstFragmentWithDI tests storing first fragment with routing info.
func TestStoreFirstFragmentWithDI(t *testing.T) {
	mockEncryptor := &tunnel.AESEncryptor{}
	handler := func(msgBytes []byte) error { return nil }

	ep, err := NewEndpoint(TunnelID(1), mockEncryptor, handler)
	require.NoError(t, err)
	defer ep.Stop()

	var hash [32]byte
	copy(hash[:], []byte("gateway_hash_for_first_frag_test"))
	di := &DeliveryInstructions{
		tunnelID: 42,
		hash:     hash,
	}

	err = ep.storeFirstFragmentWithDI(1, DT_TUNNEL, di, []byte("fragment data"))
	assert.NoError(t, err)

	// Verify assembler has routing info
	ep.fragmentsMutex.Lock()
	assembler, exists := ep.fragments[1]
	ep.fragmentsMutex.Unlock()

	require.True(t, exists, "Assembler should exist for message ID 1")
	assert.Equal(t, byte(DT_TUNNEL), assembler.deliveryType)
	assert.Equal(t, uint32(42), assembler.tunnelID)
	assert.Equal(t, hash, assembler.hash)
}

// TestStoreFirstFragmentWithDIRouter tests storing first fragment with router routing info.
func TestStoreFirstFragmentWithDIRouter(t *testing.T) {
	mockEncryptor := &tunnel.AESEncryptor{}
	handler := func(msgBytes []byte) error { return nil }

	ep, err := NewEndpoint(TunnelID(1), mockEncryptor, handler)
	require.NoError(t, err)
	defer ep.Stop()

	var hash [32]byte
	copy(hash[:], []byte("router_hash_for_first_frag_test!"))
	di := &DeliveryInstructions{
		hash: hash,
	}

	err = ep.storeFirstFragmentWithDI(2, DT_ROUTER, di, []byte("router fragment"))
	assert.NoError(t, err)

	ep.fragmentsMutex.Lock()
	assembler, exists := ep.fragments[2]
	ep.fragmentsMutex.Unlock()

	require.True(t, exists)
	assert.Equal(t, byte(DT_ROUTER), assembler.deliveryType)
	assert.Equal(t, hash, assembler.hash)
}

// TestReassembleAndDeliverTunnel tests reassembly delivers to forwarder for DT_TUNNEL.
func TestReassembleAndDeliverTunnel(t *testing.T) {
	mockEncryptor := &tunnel.AESEncryptor{}
	handler := func(msgBytes []byte) error { return nil }

	ep, err := NewEndpoint(TunnelID(1), mockEncryptor, handler)
	require.NoError(t, err)
	defer ep.Stop()

	fwd := &mockForwarder{}
	ep.SetForwarder(fwd)

	var hash [32]byte
	copy(hash[:], []byte("gateway_for_reassemble_delivery!"))

	assembler := &fragmentAssembler{
		fragments: map[int][]byte{
			0: []byte("part1"),
			1: []byte("part2"),
		},
		deliveryType: DT_TUNNEL,
		tunnelID:     42,
		hash:         hash,
		totalCount:   2,
		receivedMask: 0x03,
	}

	ep.fragmentsMutex.Lock()
	ep.fragments[99] = assembler
	ep.fragmentsMutex.Unlock()

	err = ep.reassembleAndDeliver(99, assembler)
	assert.NoError(t, err)

	fwd.mu.Lock()
	defer fwd.mu.Unlock()
	require.Len(t, fwd.tunnelCalls, 1)
	assert.Equal(t, uint32(42), fwd.tunnelCalls[0].tunnelID)
	assert.Equal(t, hash, fwd.tunnelCalls[0].gatewayHash)
	assert.Equal(t, []byte("part1part2"), fwd.tunnelCalls[0].msgBytes)
}

// TestReassembleAndDeliverRouter tests reassembly delivers to forwarder for DT_ROUTER.
func TestReassembleAndDeliverRouter(t *testing.T) {
	mockEncryptor := &tunnel.AESEncryptor{}
	handler := func(msgBytes []byte) error { return nil }

	ep, err := NewEndpoint(TunnelID(1), mockEncryptor, handler)
	require.NoError(t, err)
	defer ep.Stop()

	fwd := &mockForwarder{}
	ep.SetForwarder(fwd)

	var hash [32]byte
	copy(hash[:], []byte("router_for_reassemble_delivery!!"))

	assembler := &fragmentAssembler{
		fragments: map[int][]byte{
			0: []byte("router_part1"),
			1: []byte("router_part2"),
		},
		deliveryType: DT_ROUTER,
		hash:         hash,
		totalCount:   2,
		receivedMask: 0x03,
	}

	ep.fragmentsMutex.Lock()
	ep.fragments[100] = assembler
	ep.fragmentsMutex.Unlock()

	err = ep.reassembleAndDeliver(100, assembler)
	assert.NoError(t, err)

	fwd.mu.Lock()
	defer fwd.mu.Unlock()
	require.Len(t, fwd.routerCalls, 1)
	assert.Equal(t, hash, fwd.routerCalls[0].routerHash)
	assert.Equal(t, []byte("router_part1router_part2"), fwd.routerCalls[0].msgBytes)
}

// TestReassembleAndDeliverNoForwarder tests reassembly skips gracefully without forwarder.
func TestReassembleAndDeliverNoForwarder(t *testing.T) {
	mockEncryptor := &tunnel.AESEncryptor{}
	handler := func(msgBytes []byte) error { return nil }

	ep, err := NewEndpoint(TunnelID(1), mockEncryptor, handler)
	require.NoError(t, err)
	defer ep.Stop()

	// No forwarder set
	assembler := &fragmentAssembler{
		fragments: map[int][]byte{
			0: []byte("data"),
		},
		deliveryType: DT_TUNNEL,
		totalCount:   1,
		receivedMask: 0x01,
	}

	ep.fragmentsMutex.Lock()
	ep.fragments[101] = assembler
	ep.fragmentsMutex.Unlock()

	err = ep.reassembleAndDeliver(101, assembler)
	assert.NoError(t, err, "Should not error without forwarder")
}

// TestReassembleAndDeliverLocal tests reassembly delivers to handler for DT_LOCAL.
func TestReassembleAndDeliverLocal(t *testing.T) {
	mockEncryptor := &tunnel.AESEncryptor{}
	var received []byte
	handler := func(msgBytes []byte) error {
		received = msgBytes
		return nil
	}

	ep, err := NewEndpoint(TunnelID(1), mockEncryptor, handler)
	require.NoError(t, err)
	defer ep.Stop()

	assembler := &fragmentAssembler{
		fragments: map[int][]byte{
			0: []byte("local_"),
			1: []byte("msg"),
		},
		deliveryType: DT_LOCAL,
		totalCount:   2,
		receivedMask: 0x03,
	}

	ep.fragmentsMutex.Lock()
	ep.fragments[102] = assembler
	ep.fragmentsMutex.Unlock()

	err = ep.reassembleAndDeliver(102, assembler)
	assert.NoError(t, err)
	assert.Equal(t, []byte("local_msg"), received)
}

// TestMessageForwarderInterface tests that mockForwarder correctly implements the interface.
func TestMessageForwarderInterface(t *testing.T) {
	var _ MessageForwarder = (*mockForwarder)(nil)
}

// TestFragmentAssemblerRoutingFields tests the tunnelID and hash fields on fragmentAssembler.
func TestFragmentAssemblerRoutingFields(t *testing.T) {
	var hash [32]byte
	copy(hash[:], []byte("routing_hash_for_assembler_test!"))

	assembler := &fragmentAssembler{
		fragments:    make(map[int][]byte),
		deliveryType: DT_TUNNEL,
		tunnelID:     123,
		hash:         hash,
	}

	assert.Equal(t, byte(DT_TUNNEL), assembler.deliveryType)
	assert.Equal(t, uint32(123), assembler.tunnelID)
	assert.Equal(t, hash, assembler.hash)
}
